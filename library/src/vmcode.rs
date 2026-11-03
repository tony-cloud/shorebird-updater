//! Checks that an installed iOS "linked AOT" patch (a `vmcode` container, see
//! docs/ios-linker/COMPILER_LINKER.md section 6) belongs to the release it was
//! reconstructed against.
//!
//! The updater reconstructs every patch with bidiff+zstd against the base the
//! engine serves: the release's data image followed by its text image, the
//! same bytes `ios_linker diff-base` wrote. For a `vmcode` the reconstructed
//! file therefore ends up bit-exact only if the installed release matches, and
//! the hash the server signed already proves that. This module adds the
//! defense in depth the runtime cannot do cheaply on the hot path: the header
//! must name the text image of exactly this release, and the embedded ELF must
//! hash to the header's value. The runtime repeats the text hash over the
//! mapped `_kDartSnapshotText` before it executes anything.

use anyhow::{bail, Context};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::updater::ReadSeek;

/// `OSBVMC\0\x01`.
pub(crate) const VMCODE_MAGIC: [u8; 8] = [0x4f, 0x53, 0x42, 0x56, 0x4d, 0x43, 0x00, 0x01];
const HEADER_FIXED: usize = 128;
const LINK_ENTRY: u32 = 16;
const ELF_ALIGNMENT: u64 = 16384;

/// The fields of a `vmcode` header the updater checks.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VmcodeHeader {
    pub elf_offset: u64,
    pub elf_size: u64,
    pub release_text_sha256: [u8; 32],
    pub elf_sha256: [u8; 32],
    pub release_text_size: u32,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Whether the file at `path` starts with the `vmcode` magic.
pub(crate) fn is_vmcode(path: &Path) -> anyhow::Result<bool> {
    let mut file = std::fs::File::open(path).with_context(|| format!("Failed to open {path:?}"))?;
    let mut magic = [0u8; 8];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == VMCODE_MAGIC),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e).with_context(|| format!("Failed to read {path:?}")),
    }
}

/// Parses and validates the geometry of the header at the start of `file`,
/// whose total length is `file_len`.
pub(crate) fn parse_header(file: &mut impl Read, file_len: u64) -> anyhow::Result<VmcodeHeader> {
    let mut b = [0u8; HEADER_FIXED];
    file.read_exact(&mut b)
        .context("vmcode: truncated header")?;
    if b[..8] != VMCODE_MAGIC {
        bail!("vmcode: bad magic");
    }
    if u32_at(&b, 8) != 1 {
        bail!("vmcode: unsupported version {}", u32_at(&b, 8));
    }
    let header_bytes = u32_at(&b, 12) as u64;
    let elf_offset = u64_at(&b, 16);
    let elf_size = u64_at(&b, 24);
    let link_count = u32_at(&b, 32) as u64;
    if u32_at(&b, 36) != LINK_ENTRY
        || u32_at(&b, 40) as usize != HEADER_FIXED
        || u32_at(&b, 44) != 0
        || header_bytes != elf_offset
        || elf_offset % ELF_ALIGNMENT != 0
        || HEADER_FIXED as u64 + link_count * LINK_ENTRY as u64 > elf_offset
        || elf_size == 0
        || elf_offset.checked_add(elf_size) != Some(file_len)
    {
        bail!("vmcode: inconsistent header geometry");
    }
    if u32_at(&b, 120) > u32_at(&b, 124) {
        bail!("vmcode: linked bytes exceed code bytes");
    }
    Ok(VmcodeHeader {
        elf_offset,
        elf_size,
        release_text_sha256: b[48..80].try_into().unwrap(),
        elf_sha256: b[80..112].try_into().unwrap(),
        release_text_size: u32_at(&b, 112),
    })
}

fn hash_range(
    file: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    len: u64,
) -> anyhow::Result<[u8; 32]> {
    file.seek(SeekFrom::Start(offset))?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            bail!("unexpected end of data");
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize().into())
}

/// Verifies the installed `vmcode` at `vmcode_path` against `base`, the
/// release's data+text stream.
///
/// * the header is well formed and the embedded ELF hashes to the header's
///   value;
/// * the last `release_text_size` bytes of the base (its text image) hash to
///   the header's release text hash.
pub(crate) fn verify_against_base(
    vmcode_path: &Path,
    base: &mut dyn ReadSeek,
) -> anyhow::Result<()> {
    let mut file = std::fs::File::open(vmcode_path)
        .with_context(|| format!("Failed to open {vmcode_path:?}"))?;
    let len = file.metadata()?.len();
    let header = parse_header(&mut file, len)?;

    let elf = hash_range(&mut file, header.elf_offset, header.elf_size)
        .context("vmcode: reading the embedded ELF")?;
    if elf != header.elf_sha256 {
        bail!("vmcode: embedded ELF hash mismatch");
    }

    let base_len = base.seek(SeekFrom::End(0))?;
    let text_len = header.release_text_size as u64;
    if text_len == 0 || text_len > base_len {
        bail!(
            "vmcode: the patch was linked to a {text_len}-byte release text \
             but the installed release has {base_len} bytes of snapshot"
        );
    }
    let text = hash_range(base, base_len - text_len, text_len)
        .context("vmcode: reading the installed release text")?;
    if text != header.release_text_sha256 {
        bail!(
            "vmcode: the patch was linked to a different release \
             (installed text {}, patch expects {})",
            hex::encode(text),
            hex::encode(header.release_text_sha256)
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A well-formed `vmcode` linked to a release whose text image is
    /// `base_text`, embedding `elf`.
    pub(crate) fn vmcode(base_text: &[u8], elf: &[u8]) -> Vec<u8> {
        let elf_offset = ELF_ALIGNMENT as usize;
        let mut v = vec![0u8; elf_offset + elf.len()];
        v[..8].copy_from_slice(&VMCODE_MAGIC);
        v[8..12].copy_from_slice(&1u32.to_le_bytes());
        v[12..16].copy_from_slice(&(elf_offset as u32).to_le_bytes());
        v[16..24].copy_from_slice(&(elf_offset as u64).to_le_bytes());
        v[24..32].copy_from_slice(&(elf.len() as u64).to_le_bytes());
        v[36..40].copy_from_slice(&16u32.to_le_bytes());
        v[40..44].copy_from_slice(&128u32.to_le_bytes());
        v[48..80].copy_from_slice(&Sha256::digest(base_text));
        v[80..112].copy_from_slice(&Sha256::digest(elf));
        v[112..116].copy_from_slice(&(base_text.len() as u32).to_le_bytes());
        v[116..120].copy_from_slice(&8192u32.to_le_bytes());
        v[120..124].copy_from_slice(&60u32.to_le_bytes());
        v[124..128].copy_from_slice(&100u32.to_le_bytes());
        v[elf_offset..].copy_from_slice(elf);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::vmcode;
    use super::*;
    use std::io::Cursor;

    fn base(data: &[u8], text: &[u8]) -> Cursor<Vec<u8>> {
        Cursor::new([data, text].concat())
    }

    fn write(dir: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join("vmcode");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn accepts_a_patch_linked_to_the_installed_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &vmcode(b"release text image", b"\x7fELFpatch"));
        assert!(is_vmcode(&path).unwrap());
        verify_against_base(&path, &mut base(b"data image....", b"release text image")).unwrap();
    }

    #[test]
    fn rejects_a_different_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &vmcode(b"release text image", b"\x7fELFpatch"));
        let err = verify_against_base(&path, &mut base(b"data", b"another text image!"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("different release"), "{err}");
    }

    #[test]
    fn rejects_a_base_shorter_than_the_release_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &vmcode(b"release text image", b"\x7fELFpatch"));
        let err = verify_against_base(&path, &mut Cursor::new(b"short".to_vec()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("installed release has"), "{err}");
    }

    #[test]
    fn rejects_a_tampered_elf_and_bad_geometry() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vmcode(b"release text image", b"\x7fELFpatch");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let path = write(&dir, &bytes);
        let err = verify_against_base(&path, &mut base(b"d", b"release text image"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ELF hash mismatch"), "{err}");

        let mut bytes = vmcode(b"release text image", b"\x7fELFpatch");
        bytes[8] = 2; // version
        let path = write(&dir, &bytes);
        assert!(verify_against_base(&path, &mut base(b"d", b"release text image")).is_err());

        let mut bytes = vmcode(b"release text image", b"\x7fELFpatch");
        bytes.truncate(bytes.len() - 1); // ELF extends past the file
        let path = write(&dir, &bytes);
        assert!(verify_against_base(&path, &mut base(b"d", b"release text image")).is_err());
    }

    #[test]
    fn other_files_are_not_vmcode() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_vmcode(&write(&dir, b"\x7fELF....more")).unwrap());
        assert!(!is_vmcode(&write(&dir, b"abc")).unwrap());
        assert!(!is_vmcode(&write(&dir, b"")).unwrap());
    }
}
