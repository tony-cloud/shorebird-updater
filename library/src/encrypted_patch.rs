//! Optional authenticated AES-GCM transport, with application-owned key lookup.
//! Downloaded ciphertext stays resumable on disk; decrypted transport is held in
//! a bounded, wiped buffer until inflation completes. Installed executable code
//! is necessarily plaintext and remains protected by the usual boot signatures.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::aead;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Mutex;

use crate::c_api::engine::PatchDecryptionKeyProvider;
use crate::config::UpdateConfig;
use crate::network::{Patch, PatchCheckRequest, PatchCheckResponse};
use crate::yaml::{PatchResponseVerificationMode, PatchVerificationMode};

// The existing single-tag transport requires authenticated whole-buffer decrypt.
// Reject oversized objects before allocation; a chunked future format must have
// independently authenticated ordering/context rather than bypass this bound.
const MAX_CIPHERTEXT_BYTES: u64 = 128 * 1024 * 1024 + 16;
static PROVIDER: Mutex<Option<PatchDecryptionKeyProvider>> = Mutex::new(None);

pub(crate) fn provider() -> Option<PatchDecryptionKeyProvider> {
    *PROVIDER.lock().expect("patch key provider lock poisoned")
}

pub(crate) fn set_provider(provider: Option<PatchDecryptionKeyProvider>) -> bool {
    crate::config::with_config_mut(|config| {
        if config.is_some() {
            return false;
        }
        *PROVIDER.lock().expect("patch key provider lock poisoned") = provider;
        true
    })
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn reset_provider() {
    *PROVIDER.lock().expect("patch key provider lock poisoned") = None;
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub kdf: String,
    pub key_id: String,
    pub nonce: String,
    pub aad: String,
    pub aad_hash: String,
    pub encrypted_hash: String,
    pub device_id_hash: String,
    pub cache_key: String,
}

// Device hashes, cache paths and key identifiers are routing metadata, but must
// not escape through the updater's routine response Debug logging.
impl std::fmt::Debug for EncryptionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionMetadata")
            .field("algorithm", &self.algorithm)
            .field("context", &"<redacted>")
            .finish()
    }
}

pub(crate) fn validate_config(config: &UpdateConfig) -> Result<()> {
    if config.patch_decryption_key_provider.is_some() {
        ensure!(
            config.patch_response_verification == PatchResponseVerificationMode::Required
                && config.patch_verification == PatchVerificationMode::Strict
                && config.patch_public_key.is_some(),
            "Encrypted delivery requires strict boot verification and required signed responses"
        );
    }
    Ok(())
}

pub(crate) fn validate_offer(
    request: &PatchCheckRequest,
    response: &PatchCheckResponse,
    config: &UpdateConfig,
) -> Result<()> {
    validate_config(config)?;
    if let Some(patch) = &response.patch {
        match (&patch.encryption, config.patch_decryption_key_provider) {
            (None, Some(_)) => {
                bail!("Encrypted delivery was required but the server offered plaintext")
            }
            (Some(_), None) => bail!("Encrypted delivery has no application key provider"),
            (Some(metadata), Some(_)) => {
                validate_context(
                    metadata,
                    patch,
                    &request.app_id,
                    &request.platform,
                    &request.arch,
                    &request.client_id,
                )?;
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn validate_context(
    metadata: &EncryptionMetadata,
    patch: &Patch,
    app_id: &str,
    platform: &str,
    arch: &str,
    client_id: &str,
) -> Result<(Vec<u8>, [u8; 12], String)> {
    ensure!(
        metadata.algorithm == "AES-256-GCM" && metadata.kdf == "HMAC-SHA256",
        "Unsupported encrypted patch format"
    );
    ensure!(
        !metadata.key_id.is_empty()
            && metadata.key_id.len() <= 128
            && !metadata.key_id.contains('\0'),
        "Invalid patch key identifier"
    );
    ensure!(
        metadata.aad.len() <= 8192
            && is_hash(&metadata.aad_hash)
            && is_hash(&metadata.encrypted_hash),
        "Invalid encryption context encoding"
    );
    let aad = URL_SAFE_NO_PAD
        .decode(&metadata.aad)
        .context("Invalid encryption AAD")?;
    ensure!(
        digest(&aad) == metadata.aad_hash,
        "Encryption AAD hash mismatch"
    );
    let aad_text = std::str::from_utf8(&aad).context("Encryption AAD must be UTF-8")?;
    let lines: Vec<&str> = aad_text.split('\n').collect();
    ensure!(
        lines.len() == 9 && lines[0] == "open-aot-patch-delivery-v2",
        "Unsupported encryption AAD schema"
    );
    let value = |index: usize, prefix: &str| -> Result<&str> {
        lines[index]
            .strip_prefix(prefix)
            .context("Invalid encryption AAD field")
    };
    let release_id = value(2, "release_id=")?;
    ensure!(
        !release_id.is_empty()
            && release_id.bytes().all(|c| c.is_ascii_digit())
            && release_id.parse::<u64>().is_ok_and(|id| id > 0),
        "Invalid encrypted release identifier"
    );
    let transport_hash = value(5, "transport_hash=")?;
    let device_hash = digest(client_id.as_bytes());
    ensure!(
        value(1, "app_id=")? == app_id
            && value(3, "patch_number=")? == patch.number.to_string()
            && value(4, "patch_hash=")? == patch.hash
            && is_hash(transport_hash)
            && value(6, "platform=")? == platform
            && value(7, "arch=")? == arch
            && value(8, "device_id_hash=")? == device_hash
            && metadata.device_id_hash == device_hash,
        "Encrypted patch context does not match this app, patch, platform or install"
    );
    let nonce: [u8; 12] = URL_SAFE_NO_PAD
        .decode(&metadata.nonce)
        .context("Invalid encryption nonce")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid encryption nonce length"))?;
    let transport_hash = transport_hash.to_owned();
    Ok((aad, nonce, transport_hash))
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[derive(Debug)]
pub(crate) struct KeyResolutionFailed;
impl std::fmt::Display for KeyResolutionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Application patch key unavailable or did not authenticate the encrypted patch")
    }
}
impl std::error::Error for KeyResolutionFailed {}

struct SecretKey([u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) struct Plaintext(Cursor<Vec<u8>>);
impl Plaintext {
    pub(crate) fn len(&self) -> u64 {
        self.0.get_ref().len() as u64
    }
}
impl Read for Plaintext {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(out)
    }
}
impl Drop for Plaintext {
    fn drop(&mut self) {
        wipe(self.0.get_mut());
    }
}

pub(crate) fn decrypt(
    config: &UpdateConfig,
    patch: &Patch,
    client_id: &str,
    path: &Path,
) -> Result<Plaintext> {
    decrypt_with_context(
        config,
        patch,
        client_id,
        path,
        crate::config::current_platform(),
        crate::config::current_arch(),
    )
}

fn decrypt_with_context(
    config: &UpdateConfig,
    patch: &Patch,
    client_id: &str,
    path: &Path,
    platform: &str,
    arch: &str,
) -> Result<Plaintext> {
    validate_config(config)?;
    let metadata = patch
        .encryption
        .as_ref()
        .context("Missing encryption metadata")?;
    let (aad, nonce, transport_hash) =
        validate_context(metadata, patch, &config.app_id, platform, arch, client_id)?;
    let size = std::fs::metadata(path)?.len();
    ensure!(
        (16..=MAX_CIPHERTEXT_BYTES).contains(&size),
        "Encrypted patch exceeds supported size bounds"
    );
    let mut bytes = Plaintext(Cursor::new(vec![0; size as usize]));
    let mut file = std::fs::File::open(path)?;
    file.read_exact(bytes.0.get_mut())?;
    let mut extra = [0; 1];
    ensure!(
        file.read(&mut extra)? == 0 && digest(bytes.0.get_ref()) == metadata.encrypted_hash,
        "Encrypted patch hash mismatch"
    );
    let provider = config
        .patch_decryption_key_provider
        .context("Missing patch key provider")?;
    let key_id = std::ffi::CString::new(metadata.key_id.as_str())?;
    let aad_c = std::ffi::CString::new(aad.as_slice())?;
    let mut key = SecretKey([0; 32]);
    let mut written = 0;
    // No configuration/provider mutex is held here; update serialization is
    // still held. The provider must not reenter updater operations.
    let found = unsafe {
        provider(
            key_id.as_ptr(),
            aad_c.as_ptr(),
            key.0.as_mut_ptr(),
            key.0.len(),
            &mut written,
        )
    };
    if !found || written != key.0.len() {
        return Err(KeyResolutionFailed.into());
    }
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key.0)
        .map_err(|_| anyhow::anyhow!("Invalid patch decryption key"))?;
    let key = aead::LessSafeKey::new(key);
    let decrypted_size = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            bytes.0.get_mut(),
        )
        .map_err(|_| KeyResolutionFailed)?
        .len();
    bytes.0.get_mut().truncate(decrypted_size);
    ensure!(
        digest(bytes.0.get_ref()) == transport_hash,
        "Decrypted transport hash mismatch"
    );
    ensure!(
        bytes.0.get_ref().starts_with(&[0x28, 0xB5, 0x2F, 0xFD]),
        "Decrypted patch is not a compressed patch"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{current_arch, current_platform};
    use crate::network::NetworkHooks;
    use crate::{AppConfig, ExternalFileProvider, ReadSeek};
    use serial_test::serial;

    #[derive(Clone, Debug)]
    struct BaseProvider;
    impl ExternalFileProvider for BaseProvider {
        fn open(&self) -> Result<Box<dyn ReadSeek>> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
    }
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../test_fixtures/server_encrypted_native_v2.json"
        ))
        .unwrap()
    }
    unsafe extern "C" fn resolve_key(
        _id: *const libc::c_char,
        _aad: *const libc::c_char,
        out: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> bool {
        let key = base64::prelude::BASE64_STANDARD
            .decode(fixture()["derived_key_base64"].as_str().unwrap())
            .unwrap();
        if capacity < key.len() {
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), out, key.len());
            *written = key.len();
        }
        true
    }
    unsafe extern "C" fn wrong_key(
        _id: *const libc::c_char,
        _aad: *const libc::c_char,
        out: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> bool {
        if capacity < 32 {
            return false;
        }
        unsafe {
            std::ptr::write_bytes(out, 42, 32);
            *written = 32;
        }
        true
    }
    fn config(directory: &Path) -> UpdateConfig {
        let data = fixture();
        UpdateConfig {
            storage_dir: directory.to_path_buf(),
            download_dir: directory.to_path_buf(),
            auto_update: false,
            channel: "stable".to_string(),
            app_id: data["request"]["app_id"].as_str().unwrap().to_string(),
            release_version: data["request"]["release_version"]
                .as_str()
                .unwrap()
                .to_string(),
            libapp_path: directory.join("base"),
            base_url: "http://localhost".to_string(),
            network_hooks: NetworkHooks::default(),
            file_provider: Box::new(BaseProvider),
            patch_public_key: Some(data["public_key_der_base64"].as_str().unwrap().to_string()),
            patch_verification: PatchVerificationMode::Strict,
            patch_response_verification: PatchResponseVerificationMode::Required,
            patch_decryption_key_provider: Some(resolve_key),
        }
    }
    fn response() -> PatchCheckResponse {
        serde_json::from_value(fixture()["response"].clone()).unwrap()
    }
    fn request() -> PatchCheckRequest {
        serde_json::from_value(fixture()["request"].clone()).unwrap()
    }
    fn bytes(field: &str) -> Vec<u8> {
        base64::prelude::BASE64_STANDARD
            .decode(fixture()[field].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn real_go_response_decrypts_and_reconstructs_native_binary() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let response = response();
        let request = request();
        crate::response_auth::verify_response(&request, &response, &config).unwrap();
        let patch = response.patch.unwrap();
        let path = directory.path().join("download");
        let ciphertext = bytes("ciphertext_base64");
        std::fs::write(&path, &ciphertext).unwrap();
        let plaintext = decrypt_with_context(
            &config,
            &patch,
            &request.client_id,
            &path,
            &request.platform,
            &request.arch,
        )
        .unwrap();
        assert_eq!(plaintext.0.get_ref(), &bytes("transport_base64"));
        let output = directory.path().join("installed");
        crate::updater::inflate_reader(
            plaintext,
            bytes("transport_base64").len() as u64,
            Cursor::new(bytes("base_binary_base64")),
            &output,
        )
        .unwrap();
        let installed = std::fs::read(output).unwrap();
        assert_eq!(installed, bytes("target_binary_base64"));
        assert_eq!(digest(&installed), patch.hash);
        assert_eq!(
            std::fs::read(path).unwrap(),
            ciphertext,
            "download stays encrypted on disk"
        );
        crate::cache::check_patch_signature(
            &patch.hash,
            patch.hash_signature.as_deref(),
            config.patch_public_key.as_deref(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_wrong_key_ciphertext_and_context_without_releasing_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        let request = request();
        let patch = response().patch.unwrap();
        let path = directory.path().join("download");
        let ciphertext = bytes("ciphertext_base64");
        std::fs::write(&path, &ciphertext).unwrap();
        let decrypt = |config: &UpdateConfig, patch: &Patch, client: &str| {
            decrypt_with_context(
                config,
                patch,
                client,
                &path,
                &request.platform,
                &request.arch,
            )
        };
        config.patch_decryption_key_provider = Some(wrong_key);
        assert!(decrypt(&config, &patch, &request.client_id).is_err());
        config.patch_decryption_key_provider = Some(resolve_key);
        assert!(decrypt(&config, &patch, "different-device").is_err());
        config.app_id = "different-app".to_string();
        assert!(decrypt(&config, &patch, &request.client_id).is_err());
        config.app_id = request.app_id.clone();
        let mut wrong_patch = patch.clone();
        wrong_patch.number += 1;
        assert!(decrypt(&config, &wrong_patch, &request.client_id).is_err());
        let mut wrong_patch = patch.clone();
        wrong_patch.encryption.as_mut().unwrap().nonce = URL_SAFE_NO_PAD.encode([0; 12]);
        assert!(decrypt(&config, &wrong_patch, &request.client_id).is_err());
        let mut corrupt = ciphertext.clone();
        corrupt[0] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(decrypt(&config, &patch, &request.client_id).is_err());
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "no plaintext temp file"
        );
    }

    #[test]
    fn signed_response_binds_all_encryption_fields_and_rejects_downgrade() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let request = request();
        let original = serde_json::to_value(response()).unwrap();
        for field in [
            "algorithm",
            "kdf",
            "key_id",
            "nonce",
            "aad",
            "aad_hash",
            "encrypted_hash",
            "device_id_hash",
            "cache_key",
        ] {
            let mut changed = original.clone();
            changed["patch"]["encryption"][field] = "changed".into();
            let changed: PatchCheckResponse = serde_json::from_value(changed).unwrap();
            assert!(
                crate::response_auth::verify_response(&request, &changed, &config).is_err(),
                "{field}"
            );
        }
        let mut changed = response();
        changed.patch.as_mut().unwrap().encryption = None;
        assert!(validate_offer(&request, &changed, &config).is_err());
        let mut no_provider = config.clone();
        no_provider.patch_decryption_key_provider = None;
        assert!(validate_offer(&request, &response(), &no_provider).is_err());
        let mut optional = config.clone();
        optional.patch_response_verification = PatchResponseVerificationMode::Optional;
        assert!(validate_config(&optional).is_err());
        let outgoing = PatchCheckRequest::new(&config, "private-client", None);
        assert!(outgoing.accept_encrypted_patch);
        assert_eq!(outgoing.platform, current_platform());
        assert_eq!(outgoing.arch, current_arch());
        assert!(!format!("{:?}", response()).contains(&request.client_id));
        assert!(!format!("{:?}", response()).contains(
            response()
                .patch
                .unwrap()
                .encryption
                .unwrap()
                .key_id
                .as_str()
        ));
    }

    #[test]
    #[serial]
    fn c_provider_registration_is_frozen_by_initialization() {
        crate::config::testing_reset_config();
        assert!(
            crate::c_api::engine::shorebird_set_patch_decryption_key_provider(Some(resolve_key))
        );
        let directory = tempfile::tempdir().unwrap();
        let key = fixture()["public_key_der_base64"]
            .as_str()
            .unwrap()
            .to_string();
        let yaml = crate::yaml::YamlConfig::from_yaml(&format!("app_id: test\npatch_public_key: {key}\npatch_verification: strict\npatch_response_verification: required\n")).unwrap();
        let app = AppConfig {
            app_storage_dir: directory.path().to_string_lossy().to_string(),
            code_cache_dir: directory.path().to_string_lossy().to_string(),
            release_version: "1".to_string(),
            original_libapp_paths: vec![],
        };
        crate::config::set_config(
            app,
            Box::new(BaseProvider),
            directory.path().join("base"),
            &yaml,
            NetworkHooks::default(),
        )
        .unwrap();
        assert!(!crate::c_api::engine::shorebird_set_patch_decryption_key_provider(None));
        crate::config::with_config(|config| {
            assert!(config.patch_decryption_key_provider.is_some());
            Ok(())
        })
        .unwrap();
        crate::config::testing_reset_config();
    }
    #[test]
    fn rejects_oversized_ciphertext_before_allocation_or_key_lookup() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let request = request();
        let patch = response().patch.unwrap();
        let path = directory.path().join("oversized-ciphertext");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_CIPHERTEXT_BYTES + 1)
            .unwrap();
        let error = decrypt_with_context(
            &config,
            &patch,
            &request.client_id,
            &path,
            &request.platform,
            &request.arch,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("size bounds"));
    }
}
