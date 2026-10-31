//! Authenticated transport persistence and bounded native reconstruction.
//! No plaintext writer in this module is backed by a filesystem pathname.
use crate::{config::UpdateConfig, network::Patch};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug)]
pub(crate) struct ResourceLimit;
impl std::fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Native image exceeds configured reconstruction budget")
    }
}
impl std::error::Error for ResourceLimit {}

#[cfg(target_os = "windows")]
mod windows_memory;
#[cfg(not(target_os = "windows"))]
use memmap2::{Mmap as ReadOnlyMapping, MmapMut as WritableMapping};
#[cfg(target_os = "windows")]
use windows_memory::{ReadOnlyMapping, WritableMapping};

fn writable_mapping(length: usize) -> std::io::Result<WritableMapping> {
    #[cfg(target_os = "windows")]
    {
        // memmap2's Windows map_anon initially creates an executable section.
        // This dedicated allocator only requests data-page permissions.
        WritableMapping::new(length)
    }
    #[cfg(not(target_os = "windows"))]
    {
        memmap2::MmapOptions::new().len(length).map_anon()
    }
}

/// Immutable anonymous data, never executable and never backed by a pathname.
/// The writable mapping is consumed before authentication of these exact bytes.
pub(crate) struct VerifiedMemory(ReadOnlyMapping);
impl VerifiedMemory {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

struct MemoryWriter {
    mapping: WritableMapping,
    written: usize,
}
impl MemoryWriter {
    fn new(size: u64, budget: u64) -> Result<Self> {
        ensure!(
            size > 0 && size <= budget && size <= isize::MAX as u64,
            ResourceLimit
        );
        let length = usize::try_from(size).map_err(|_| ResourceLimit)?;
        Ok(Self {
            mapping: writable_mapping(length)?,
            written: 0,
        })
    }
    fn verify(self, patch: &Patch, size: u64, public_key: Option<&str>) -> Result<VerifiedMemory> {
        ensure!(
            size == self.mapping.len() as u64 && size == self.written as u64,
            crate::UpdateError::CorruptPatch
        );
        // make_read_only consumes the only writable view; no alias is retained.
        let mapping = self.mapping.make_read_only()?;
        let hash = hex::encode(Sha256::digest(&mapping[..]));
        ensure!(hash == patch.hash, crate::UpdateError::CorruptPatch);
        crate::cache::check_patch_signature(&hash, patch.hash_signature.as_deref(), public_key)
            .context(crate::UpdateError::InvalidSignature)?;
        Ok(VerifiedMemory(mapping))
    }
}
impl Write for MemoryWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.mapping.len() - self.written {
            return Err(std::io::Error::other(ResourceLimit));
        }
        let end = self.written + bytes.len();
        self.mapping[self.written..end].copy_from_slice(bytes);
        self.written = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn reconstruct_memory(
    config: &UpdateConfig,
    patch: &Patch,
    client_id: &str,
    ciphertext: &Path,
    size_hint: u64,
) -> Result<VerifiedMemory> {
    let output = MemoryWriter::new(size_hint, config.native_options.max_image_bytes)?;
    let (output, size) = reconstruct(config, patch, client_id, ciphertext, output)?;
    output.verify(patch, size, config.patch_public_key.as_deref())
}

pub(crate) struct BoundedHashWriter<W> {
    inner: W,
    limit: u64,
    written: u64,
    hash: Sha256,
}
impl<W: Write> BoundedHashWriter<W> {
    pub(crate) fn new(inner: W, limit: u64) -> Result<Self> {
        ensure!(limit > 0, "Native reconstruction budget must be nonzero");
        Ok(Self {
            inner,
            limit,
            written: 0,
            hash: Sha256::new(),
        })
    }
    pub(crate) fn finish(self) -> (W, u64, String) {
        (self.inner, self.written, hex::encode(self.hash.finalize()))
    }
}
impl<W: Write> Write for BoundedHashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.written {
            return Err(std::io::Error::other(ResourceLimit));
        }
        let count = self.inner.write(bytes)?;
        self.hash.update(&bytes[..count]);
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn is_resource_error(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.is::<ResourceLimit>()
            || e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                e.get_ref().is_some_and(|e| e.is::<ResourceLimit>())
                    || !matches!(
                        e.kind(),
                        std::io::ErrorKind::InvalidData
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                    )
            })
    })
}

pub(crate) fn transport_path(config: &UpdateConfig, number: usize) -> PathBuf {
    config
        .storage_dir
        .join("patches")
        .join(number.to_string())
        .join("transport.aesgcm")
}

pub(crate) fn reconstruct<W: Write>(
    config: &UpdateConfig,
    patch: &Patch,
    client_id: &str,
    ciphertext: &Path,
    output: W,
) -> Result<(W, u64)> {
    let plaintext = crate::encrypted_patch::decrypt(config, patch, client_id, ciphertext)?;
    let compressed_size = plaintext.len();
    let base = crate::updater::patch_base(config)?;
    let mut output = BoundedHashWriter::new(output, config.native_options.max_image_bytes)?;
    crate::updater::inflate_reader_to_writer(plaintext, compressed_size, base, &mut output)?;
    let (output, size, hash) = output.finish();
    ensure!(hash == patch.hash, crate::UpdateError::CorruptPatch);
    crate::cache::check_patch_signature(
        &hash,
        patch.hash_signature.as_deref(),
        config.patch_public_key.as_deref(),
    )
    .context(crate::UpdateError::InvalidSignature)?;
    Ok((output, size))
}

/// Copy across filesystems; only a synced, rehashed private sibling is renamed.
fn persist_ciphertext(config: &UpdateConfig, patch: &Patch, download: &Path) -> Result<u64> {
    let path = transport_path(config, patch.number);
    let parent = path.parent().context("Missing patch directory")?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let temporary = parent.join(format!("transport.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut destination = options.open(&temporary)?;
        let size = std::io::copy(&mut File::open(download)?, &mut destination)?;
        destination.flush()?;
        destination.sync_all()?;
        let expected = &patch
            .encryption
            .as_ref()
            .context("Missing encryption metadata")?
            .encrypted_hash;
        ensure!(
            crate::cache::hash_file(&temporary)? == *expected,
            "Ciphertext copy hash mismatch"
        );
        std::fs::rename(&temporary, &path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(size)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn install(
    config: &UpdateConfig,
    patch: &Patch,
    download: &Path,
) -> Result<crate::UpdateStatus> {
    let client_id = crate::with_state(|s| Ok(s.client_id()))?;
    let size = match reconstruct(config, patch, &client_id, download, std::io::sink()) {
        Ok((_, size)) => size,
        Err(error) => {
            if !error.is::<crate::encrypted_patch::KeyResolutionFailed>()
                && !is_resource_error(&error)
            {
                crate::with_mut_state(|s| {
                    s.lifecycle_mut().mark_bad(
                        patch.number,
                        crate::cache::lifecycle::BadReason::InvalidPatchBytes,
                    )?;
                    s.lifecycle_mut().recompute_next_boot()
                })?;
            }
            return Err(error);
        }
    };
    let ciphertext_size = persist_ciphertext(config, patch, download)?;
    crate::with_mut_state(|state| {
        state.lifecycle_mut().record_encrypted_install_complete(
            patch.number,
            size,
            ciphertext_size,
        )?;
        state.lifecycle_mut().promote_to_next_boot(patch.number)?;
        let event = crate::events::PatchEvent::new(
            config,
            crate::events::EventType::PatchDownload,
            patch.number,
            state.client_id(),
            None,
        );
        crate::updater::queue_or_send_event(state, config, event);
        Ok(())
    })?;
    crate::updater::spawn_event_flush();
    Ok(crate::UpdateStatus::UpdateInstalled)
}

/// A source name is an observation/provenance label, never a loading path or
/// cryptographic authority. Do not reuse it for another memfd in this process.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn source_name(counter: &std::sync::atomic::AtomicU64) -> Result<std::ffi::CString> {
    use std::sync::atomic::Ordering;
    let number = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |number| {
            number.checked_add(1)
        })
        .map_err(|_| std::io::Error::other("Native source identity counter exhausted"))?;
    std::ffi::CString::new(format!("shorebird-native-{}-{number}", std::process::id()))
        .context("Invalid native source identity")
}

/// Anonymous executable backing only. Android uses syscall to avoid linking
/// the API-30 libc memfd_create symbol on older supported Android releases.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn create_source() -> Result<File> {
    use std::os::fd::FromRawFd;
    static NEXT_SOURCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let name = source_name(&NEXT_SOURCE)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn create_source() -> Result<File> {
    anyhow::bail!("Sealed native FD source unsupported on this platform")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn seal_and_verify(
    file: &mut File,
    patch: &Patch,
    size: u64,
    config: &UpdateConfig,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } & seals == seals,
            "Native source sealing incomplete"
        );
    }
    {
        ensure!(file.metadata()?.len() == size, "Native source size changed");
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 32768];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        let hash = hex::encode(hash.finalize());
        ensure!(hash == patch.hash, crate::UpdateError::CorruptPatch);
        crate::cache::check_patch_signature(
            &hash,
            patch.hash_signature.as_deref(),
            config.patch_public_key.as_deref(),
        )
        .context(crate::UpdateError::InvalidSignature)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn seal_and_verify(
    _file: &mut File,
    _patch: &Patch,
    _size: u64,
    _config: &UpdateConfig,
) -> Result<()> {
    anyhow::bail!("Sealed native FD source unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anonymous_writer_rejects_invalid_sizes_and_overrun_before_mutation() {
        for (size, budget) in [(0, 1), (2, 1), (u64::MAX, u64::MAX)] {
            let error = MemoryWriter::new(size, budget).err().unwrap();
            assert!(error.is::<ResourceLimit>());
        }
        let mut writer = MemoryWriter::new(4, 4).unwrap();
        writer.write_all(b"abc").unwrap();
        assert!(is_resource_error(
            &writer.write_all(b"de").unwrap_err().into()
        ));
        assert_eq!(&writer.mapping[..], b"abc\0");
        assert_eq!(writer.written, 3);
        writer.write_all(b"d").unwrap();
        assert_eq!(&writer.mapping[..], b"abcd");
    }
    #[test]
    fn immutable_final_mapping_is_rehashed_and_publisher_signature_checked() {
        let hash = hex::encode(Sha256::digest(b"verified"));
        let mut patch = Patch {
            number: 1,
            hash_signature: Some(crate::test_utils::sign_test_message(hash.as_bytes())),
            hash,
            download_url: "unused".into(),
            encryption: None,
        };
        let key = crate::test_utils::response_test_public_key();
        let writer = || {
            let mut writer = MemoryWriter::new(8, 8).unwrap();
            writer.write_all(b"verified").unwrap();
            writer
        };
        let verified = writer().verify(&patch, 8, Some(&key)).unwrap();
        assert_eq!(verified.bytes(), b"verified");
        let mut changed = writer();
        changed.mapping[0] = b'x';
        assert!(changed
            .verify(&patch, 8, Some(&key))
            .err()
            .unwrap()
            .is::<crate::UpdateError>());
        assert!(writer().verify(&patch, 7, Some(&key)).is_err());
        patch.hash_signature = Some(crate::test_utils::sign_test_message(b"other hash"));
        assert!(matches!(
            writer()
                .verify(&patch, 8, Some(&key))
                .err()
                .unwrap()
                .downcast_ref::<crate::UpdateError>(),
            Some(crate::UpdateError::InvalidSignature)
        ));
    }
    #[test]
    fn bounded_writer_checks_each_write_before_sink_and_rejects_zero_limit() {
        assert!(BoundedHashWriter::new(Vec::new(), 0).is_err());
        let mut writer = BoundedHashWriter::new(Vec::new(), 4).unwrap();
        writer.write_all(b"abcd").unwrap();
        let error = writer.write_all(b"e").unwrap_err();
        assert!(error.get_ref().unwrap().is::<ResourceLimit>());
        let (bytes, size, _) = writer.finish();
        assert_eq!(bytes, b"abcd");
        assert_eq!(size, 4);
    }
    #[test]
    fn overflowing_output_is_rejected_without_writing() {
        let mut writer = BoundedHashWriter::new(std::io::sink(), u64::MAX).unwrap();
        writer.written = u64::MAX - 1;
        assert!(writer.write(b"ab").is_err());
        assert_eq!(writer.written, u64::MAX - 1);
    }
    #[test]
    fn source_identity_counter_exhaustion_fails_without_wrapping() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = AtomicU64::new(u64::MAX - 1);
        assert!(source_name(&counter).is_ok());
        assert!(source_name(&counter).is_err());
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert!(source_name(&counter).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_memfd_sources_have_unique_names_and_duplicates_keep_identity() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let first = create_source().unwrap();
        let second = create_source().unwrap();
        let duplicate = first.try_clone().unwrap();
        let identity = |file: &File| {
            std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
        };
        let first_identity = identity(&first);
        assert_ne!(first_identity, identity(&second));
        assert_eq!(first_identity, identity(&duplicate));
        assert!(first_identity
            .to_string_lossy()
            .contains(&format!("shorebird-native-{}-", std::process::id())));
        assert_eq!(
            first.metadata().unwrap().ino(),
            duplicate.metadata().unwrap().ino()
        );
        assert_ne!(
            first.metadata().unwrap().ino(),
            second.metadata().unwrap().ino()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn real_memfd_is_cloexec_and_seals_reject_mutation() {
        use std::os::fd::AsRawFd;
        let mut file = create_source().unwrap();
        file.write_all(b"verified").unwrap();
        let fd = file.as_raw_fd();
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
        assert!(file.write_all(b"x").is_err());
        assert!(file.set_len(0).is_err());
        assert!(file.set_len(100).is_err());
        assert_eq!(file.metadata().unwrap().len(), 8);
    }
}
