//! Platform package identity adapters (hardening stage P3, contract
//! `docs/HARDENING_CONTRACTS.md` §9 in the workspace).
//!
//! | Platform | Adapter | Status |
//! | --- | --- | --- |
//! | Android | SHA-256 of each signer certificate in the installed `base.apk`'s APK Signature Scheme v3.1/v3/v2 block | implemented |
//! | macOS | `SecCodeCheckValidity` of the running process, then its signing team identifier | implemented |
//! | iOS | no public API exposes the running app's team identifier | unsupported |
//! | Windows | Authenticode signer of the loaded module | unsupported (P6) |
//! | Linux | none; deployment/OS trust (package manager, ownership) | unsupported |
//!
//! Trust assumption: the OS verified the package signature at install time
//! and the installed package is read-only to the app and to other apps. The
//! Android adapter therefore reads the signer certificates the OS verified
//! without re-verifying the APK; it is not a substitute for that verification.

/// Signer certificate digests (lowercase hex SHA-256 of the DER certificate)
/// of an APK, from the strongest signature scheme block present.
pub fn apk_signer_certificate_digests(apk: &[u8]) -> Result<Vec<String>, String> {
    use sha2::{Digest, Sha256};
    let pairs = apk_signing_block_pairs(apk)?;
    // v3.1, v3, then v2: the OS verifies the newest scheme it supports, and
    // every scheme block of one APK names the same current signer.
    const SCHEMES: [u32; 3] = [0x1b93_ad61, 0xf053_68c0, 0x7109_871a];
    let value = SCHEMES
        .iter()
        .find_map(|id| pairs.iter().find(|(pair, _)| pair == id).map(|(_, v)| *v))
        .ok_or("APK has no v2/v3 signature scheme block")?;
    let mut reader = LengthPrefixed::new(value);
    let mut signers = LengthPrefixed::new(reader.next()?.ok_or("empty signer list")?);
    if reader.next()?.is_some() {
        return Err("trailing data after signer list".into());
    }
    let mut digests = Vec::new();
    while let Some(signer) = signers.next()? {
        let mut signer = LengthPrefixed::new(signer);
        let signed_data = signer.next()?.ok_or("signer without signed data")?;
        let mut signed_data = LengthPrefixed::new(signed_data);
        signed_data.next()?.ok_or("signed data without digests")?;
        let certificates = signed_data
            .next()?
            .ok_or("signed data without certificates")?;
        let certificate = LengthPrefixed::new(certificates)
            .next()?
            .ok_or("signer without a certificate")?;
        let digest = hex::encode(Sha256::digest(certificate));
        if !digests.contains(&digest) {
            digests.push(digest);
        }
    }
    if digests.is_empty() {
        return Err("APK has no signer".into());
    }
    Ok(digests)
}

/// u32-length-prefixed records, as used throughout the APK signing block.
struct LengthPrefixed<'a> {
    rest: &'a [u8],
}

impl<'a> LengthPrefixed<'a> {
    fn new(rest: &'a [u8]) -> Self {
        LengthPrefixed { rest }
    }

    fn next(&mut self) -> Result<Option<&'a [u8]>, String> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let len = self
            .rest
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
            .ok_or("truncated length prefix")?;
        let value = self
            .rest
            .get(4..4 + len)
            .ok_or("length prefix exceeds its record")?;
        self.rest = &self.rest[4 + len..];
        Ok(Some(value))
    }
}

/// The (id, value) pairs of the APK Signing Block that precedes the ZIP
/// central directory.
fn apk_signing_block_pairs(apk: &[u8]) -> Result<Vec<(u32, &[u8])>, String> {
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const MAGIC: &[u8; 16] = b"APK Sig Block 42";
    if apk.len() < 22 {
        return Err("no ZIP end of central directory".into());
    }
    let search_from = apk.len().saturating_sub(22 + 0xffff);
    let eocd = (search_from..=apk.len().saturating_sub(22))
        .rev()
        .find(|&at| {
            apk[at..at + 4] == EOCD
                && at + 22 + u16::from_le_bytes([apk[at + 20], apk[at + 21]]) as usize == apk.len()
        })
        .ok_or("no ZIP end of central directory")?;
    let central_directory =
        u32::from_le_bytes(apk[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    if central_directory == 0xffff_ffff || central_directory < 32 || central_directory > eocd {
        return Err("no APK signing block".into());
    }
    if &apk[central_directory - 16..central_directory] != MAGIC {
        return Err("no APK signing block".into());
    }
    let size = u64::from_le_bytes(
        apk[central_directory - 24..central_directory - 16]
            .try_into()
            .unwrap(),
    );
    let size = usize::try_from(size).map_err(|_| "APK signing block too large")?;
    let start = central_directory
        .checked_sub(size)
        .and_then(|s| s.checked_sub(8))
        .ok_or("APK signing block size out of range")?;
    if u64::from_le_bytes(apk[start..start + 8].try_into().unwrap()) != size as u64 {
        return Err("APK signing block sizes disagree".into());
    }
    let mut pairs = Vec::new();
    let mut at = start + 8;
    let end = central_directory - 24;
    while at < end {
        let len = apk
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .ok_or("truncated signing block pair")?;
        let len = usize::try_from(len).map_err(|_| "signing block pair too large")?;
        if len < 4 || at + 8 + len > end {
            return Err("signing block pair out of range".into());
        }
        let id = u32::from_le_bytes(apk[at + 8..at + 12].try_into().unwrap());
        pairs.push((id, &apk[at + 12..at + 8 + len]));
        at += 8 + len;
    }
    Ok(pairs)
}

/// The signing team identifier of the running process after checking the
/// process's dynamic code signature. `Ok(None)` means validly signed without
/// a team (ad-hoc or unsigned-but-allowed).
#[cfg(target_os = "macos")]
pub fn macos_running_team_id() -> Result<Option<String>, String> {
    use std::os::raw::{c_char, c_void};
    type OSStatus = i32;
    type CFTypeRef = *const c_void;
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecCodeCopySelf(flags: u32, code: *mut CFTypeRef) -> OSStatus;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: CFTypeRef,
            flags: u32,
            information: *mut CFTypeRef,
        ) -> OSStatus;
        static kSecCodeInfoTeamIdentifier: CFTypeRef;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFGetTypeID(value: CFTypeRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFStringGetCString(
            string: CFTypeRef,
            buffer: *mut c_char,
            size: isize,
            encoding: u32,
        ) -> u8;
        fn CFRelease(value: CFTypeRef);
    }
    const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    struct Owned(CFTypeRef);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: we own one reference from a Copy/Create call.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    // SAFETY: plain Security/CoreFoundation calls on objects we own; every
    // returned reference is released by `Owned`.
    unsafe {
        let mut code: CFTypeRef = std::ptr::null();
        let status = SecCodeCopySelf(0, &mut code);
        let code = Owned(code);
        if status != 0 || code.0.is_null() {
            return Err(format!("SecCodeCopySelf failed ({status})"));
        }
        let status = SecCodeCheckValidity(code.0, 0, std::ptr::null());
        if status != 0 {
            return Err(format!("running code signature is invalid ({status})"));
        }
        let mut info: CFTypeRef = std::ptr::null();
        let status = SecCodeCopySigningInformation(code.0, K_SEC_CS_SIGNING_INFORMATION, &mut info);
        let info = Owned(info);
        if status != 0 || info.0.is_null() {
            return Err(format!("SecCodeCopySigningInformation failed ({status})"));
        }
        let team = CFDictionaryGetValue(info.0, kSecCodeInfoTeamIdentifier);
        if team.is_null() {
            return Ok(None);
        }
        if CFGetTypeID(team) != CFStringGetTypeID() {
            return Err("team identifier is not a string".into());
        }
        let mut buffer = [0 as c_char; 64];
        if CFStringGetCString(
            team,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        ) == 0
        {
            return Err("team identifier is not representable".into());
        }
        Ok(Some(
            std::ffi::CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned(),
        ))
    }
}

/// Lowercase hex SHA-256 of the DER leaf certificate of the primary
/// Authenticode signer of the PE file at `path` (hardening P6, contract §12).
///
/// The file is opened once, without write or delete sharing, so it cannot be
/// replaced while it is checked. Its bytes must measure to
/// `expected_measurement` (the measurement of the loaded module), which ties
/// the signer to the module the gate measured, and `WinVerifyTrust` then
/// verifies the signature of that same open handle: the file digest, the
/// signature and a chain to a trusted root, with revocation checking off and
/// no network retrieval, so the check never blocks startup on the network.
/// Only full success is accepted. A signature without an RFC 3161 timestamp
/// stops verifying once its certificate expires, so release signing must
/// timestamp (`signtool sign /tr ... /td sha256`).
#[cfg(target_os = "windows")]
pub fn windows_module_signers(
    path: &std::path::Path,
    expected_measurement: &str,
) -> Result<Vec<String>, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    const FILE_SHARE_READ: u32 = 0x1;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|e| format!("cannot open the engine module: {e}"))?;
    let mut image = Vec::new();
    file.read_to_end(&mut image)
        .map_err(|e| format!("cannot read the engine module: {e}"))?;
    let measured = crate::module_measurement::measure_pe_file(&image).map_err(|e| e.to_string())?;
    if measured != expected_measurement {
        return Err("the engine module file differs from the loaded module".into());
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.as_raw_handle() as HANDLE,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data`, `file_info`, `wide` and `file` outlive both calls; the
    // state opened by STATEACTION_VERIFY is closed below on every path, and
    // the provider pointers are read only while it is open.
    unsafe {
        let status = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
        let result = if status != 0 {
            Err(format!(
                "Authenticode verification failed (0x{:08x})",
                status as u32
            ))
        } else {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = if provider.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            };
            let certificate = if signer.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvCertFromChain(signer, 0)
            };
            if certificate.is_null() || (*certificate).pCert.is_null() {
                Err("Authenticode signature has no signer certificate".into())
            } else {
                let context = &*(*certificate).pCert;
                let der = std::slice::from_raw_parts(
                    context.pbCertEncoded,
                    context.cbCertEncoded as usize,
                );
                Ok(vec![hex::encode(Sha256::digest(der))])
            }
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn prefixed(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// A minimal APK: one stored entry, a signing block with the given
    /// scheme ids each naming `certificate`, then the central directory.
    pub fn apk_with_signers(blocks: &[(u32, &[u8])]) -> Vec<u8> {
        let mut apk = b"PK\x03\x04 local entry bytes".to_vec();
        let mut pairs = Vec::new();
        for (id, certificate) in blocks {
            let signed_data = prefixed(&[&prefixed(&[b"digest"]), &prefixed(&[certificate])]);
            let signer = prefixed(&[&signed_data, &prefixed(&[b"sig"]), b"public key"]);
            let value = prefixed(&[&prefixed(&[&signer])]);
            pairs.extend_from_slice(&((value.len() + 4) as u64).to_le_bytes());
            pairs.extend_from_slice(&id.to_le_bytes());
            pairs.extend_from_slice(&value);
        }
        let size = (pairs.len() + 8 + 16) as u64;
        apk.extend_from_slice(&size.to_le_bytes());
        apk.extend_from_slice(&pairs);
        apk.extend_from_slice(&size.to_le_bytes());
        apk.extend_from_slice(b"APK Sig Block 42");
        let central_directory = apk.len() as u32;
        apk.extend_from_slice(b"PK\x01\x02 central directory");
        let mut eocd = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0];
        eocd.extend_from_slice(&20u32.to_le_bytes());
        eocd.extend_from_slice(&central_directory.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        apk.extend_from_slice(&eocd);
        apk
    }

    pub fn digest(certificate: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(certificate))
    }

    #[test]
    fn reads_the_signer_of_the_newest_scheme() {
        let apk = apk_with_signers(&[(0x7109_871a, b"old v2 cert"), (0xf053_68c0, b"v3 cert")]);
        assert_eq!(
            apk_signer_certificate_digests(&apk).unwrap(),
            vec![digest(b"v3 cert")]
        );
        let v2_only = apk_with_signers(&[(0x7109_871a, b"v2 cert")]);
        assert_eq!(
            apk_signer_certificate_digests(&v2_only).unwrap(),
            vec![digest(b"v2 cert")]
        );
    }

    #[test]
    fn unsigned_or_corrupt_apks_have_no_identity() {
        // v1 (JAR) signing only: no block, so no identity is inferred.
        assert!(apk_signer_certificate_digests(&apk_with_signers(&[(0x42, b"x")])).is_err());
        assert!(apk_signer_certificate_digests(b"not a zip").is_err());
        let mut apk = apk_with_signers(&[(0xf053_68c0, b"cert")]);
        let magic = apk
            .windows(16)
            .position(|w| w == b"APK Sig Block 42")
            .unwrap();
        apk[magic] ^= 1;
        assert!(apk_signer_certificate_digests(&apk).is_err());
        let mut apk = apk_with_signers(&[(0xf053_68c0, b"cert")]);
        apk[magic - 8] ^= 1; // footer size disagrees with header size
        assert!(apk_signer_certificate_digests(&apk).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_adapter_reads_the_running_signature() {
        // On Apple silicon the linker ad-hoc signs cargo's test binaries:
        // valid, but without a team. On Intel it leaves them unsigned, which
        // SecCodeCheckValidity reports as errSecCSUnsigned (-67062). Either
        // way no team is attested, so a manifest naming one rejects them.
        let result = macos_running_team_id();
        if cfg!(target_arch = "aarch64") {
            assert_eq!(result, Ok(None));
        } else {
            assert!(
                result == Ok(None) || result.as_ref().is_err_and(|e| e.contains("(-67062)")),
                "{result:?}"
            );
        }
    }
}
