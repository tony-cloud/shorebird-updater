//! Authenticating a complete patch-check decision before applying any of it.
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    config::UpdateConfig,
    network::{Patch, PatchCheckRequest, PatchCheckResponse},
    updater::UpdateError,
    yaml::PatchResponseVerificationMode,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseAuthentication {
    /// Standard base64 of the exact JSON UTF-8 bytes signed by the server.
    pub payload: String,
    /// RSA PKCS#1 v1.5 SHA-256 signature of the decoded payload bytes.
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPatch {
    number: usize,
    hash: String,
    download_url: String,
    hash_signature: Option<String>,
}

impl From<&Patch> for AuthenticatedPatch {
    fn from(patch: &Patch) -> Self {
        Self {
            number: patch.number,
            hash: patch.hash.clone(),
            download_url: patch.download_url.clone(),
            hash_signature: patch.hash_signature.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthenticatedResponse {
    version: u32,
    app_id: String,
    release_version: String,
    platform: String,
    arch: String,
    channel: String,
    nonce: String,
    patch_available: bool,
    patch: Option<AuthenticatedPatch>,
    rolled_back_patch_numbers: Vec<usize>,
}

impl AuthenticatedResponse {
    fn expected(request: &PatchCheckRequest, response: &PatchCheckResponse) -> Self {
        Self {
            version: 1,
            app_id: request.app_id.clone(),
            release_version: request.release_version.clone(),
            platform: request.platform.clone(),
            arch: request.arch.clone(),
            channel: request.channel.clone(),
            nonce: request.nonce.clone(),
            patch_available: response.patch_available,
            patch: response.patch.as_ref().map(AuthenticatedPatch::from),
            rolled_back_patch_numbers: response
                .rolled_back_patch_numbers
                .clone()
                .unwrap_or_default(),
        }
    }
}

/// Legacy responses remain accepted only when the app explicitly permits them.
/// Supplied authentication is always checked, even in optional mode. The nonce
/// ties a response to this check; context and every decision field are compared
/// before either update or rollback code can consume the response.
pub fn verify_response(
    request: &PatchCheckRequest,
    response: &PatchCheckResponse,
    config: &UpdateConfig,
) -> Result<()> {
    verify_inner(
        request,
        response,
        config.patch_public_key.as_deref(),
        config.patch_response_verification,
    )
    .context(UpdateError::InvalidSignature)
}

fn verify_inner(
    request: &PatchCheckRequest,
    response: &PatchCheckResponse,
    public_key: Option<&str>,
    mode: PatchResponseVerificationMode,
) -> Result<()> {
    let Some(auth) = response.authentication.as_ref() else {
        if mode == PatchResponseVerificationMode::Required {
            bail!("Patch response authentication is missing");
        }
        return Ok(());
    };
    let public_key =
        public_key.context("Patch response authentication requires patch_public_key")?;
    let authenticated = decode_authenticated_response(auth, public_key)?;
    if authenticated != AuthenticatedResponse::expected(request, response) {
        bail!("Authenticated patch response does not match request context or response decision");
    }
    Ok(())
}

fn decode_authenticated_response(
    auth: &ResponseAuthentication,
    public_key: &str,
) -> Result<AuthenticatedResponse> {
    let payload = base64::prelude::BASE64_STANDARD
        .decode(&auth.payload)
        .context("Invalid patch response authentication payload")?;
    let payload = std::str::from_utf8(&payload).context("Patch response payload is not UTF-8")?;
    // Check the original bytes, not a reserialization whose representation may
    // differ between Go and Rust. Parsing below rejects duplicate/unknown keys.
    crate::cache::signing::check_signature(payload, &auth.signature, public_key)?;
    serde_json::from_str(payload).context("Invalid authenticated patch response")
}

fn authentication_path(config: &UpdateConfig, patch_number: usize) -> PathBuf {
    config
        .storage_dir
        .join("patches")
        .join(patch_number.to_string())
        .join("authentication.json")
}

/// Store the already-verified response before making its artifact bootable.
/// The lifecycle owns this directory, so failed installs and rollback cleanup
/// remove this record together with the corresponding artifact.
pub fn persist_patch_authentication(
    config: &UpdateConfig,
    patch_number: usize,
    authentication: Option<&ResponseAuthentication>,
) -> Result<()> {
    let path = authentication_path(config, patch_number);
    if let Some(authentication) = authentication {
        crate::cache::disk_io::write(authentication, &path)?;
    } else if path.exists() {
        // A legacy reoffer must not inherit context from another installation.
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// At boot the historical nonce is signed but cannot be compared with a fresh
/// request. Recheck the pinned signature, current immutable app identity and
/// selected patch number/hash instead. This prevents context transplant; it
/// does not provide a monotonic counter against a complete device-storage reset.
pub fn verify_boot_patch(config: &UpdateConfig, patch: &crate::cache::PatchInfo) -> Result<()> {
    verify_boot_patch_inner(config, patch).context(UpdateError::InvalidSignature)
}

fn verify_boot_patch_inner(config: &UpdateConfig, patch: &crate::cache::PatchInfo) -> Result<()> {
    let path = authentication_path(config, patch.number);
    if !path.exists() {
        if config.patch_response_verification == PatchResponseVerificationMode::Required {
            bail!("Installed patch authentication is missing");
        }
        return Ok(());
    }
    let authentication: ResponseAuthentication = crate::cache::disk_io::read(&path)?;
    let key = config
        .patch_public_key
        .as_deref()
        .context("Installed patch authentication requires patch_public_key")?;
    let authenticated = decode_authenticated_response(&authentication, key)?;
    if authenticated.version != 1
        || authenticated.app_id != config.app_id
        || authenticated.release_version != config.release_version
        || authenticated.platform != crate::config::current_platform()
        || authenticated.arch != crate::config::current_arch()
        || !authenticated.patch_available
        || authenticated
            .rolled_back_patch_numbers
            .contains(&patch.number)
    {
        bail!("Installed patch authentication does not match current app context");
    }
    let signed_patch = authenticated
        .patch
        .context("Installed patch authentication has no patch")?;
    if signed_patch.number != patch.number
        || signed_patch.hash != crate::cache::hash_file(&patch.path)?
    {
        bail!("Installed patch authentication does not match selected patch number or bytes");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn authenticate_test_response(
    request: &PatchCheckRequest,
    response: &mut PatchCheckResponse,
) {
    let payload = serde_json::to_vec(&AuthenticatedResponse::expected(request, response)).unwrap();
    response.authentication = Some(ResponseAuthentication {
        signature: crate::test_utils::sign_test_message(&payload),
        payload: base64::prelude::BASE64_STANDARD.encode(payload),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::response_test_public_key;

    fn request() -> PatchCheckRequest {
        PatchCheckRequest {
            nonce: "25828b34-0d5f-490e-8213-72b8672b660d".to_string(),
            app_id: "app".to_string(),
            release_version: "1.0.0+1".to_string(),
            platform: "ios".to_string(),
            arch: "aarch64".to_string(),
            channel: "stable".to_string(),
            client_id: "private".to_string(),
            current_patch_number: None,
        }
    }
    fn response() -> PatchCheckResponse {
        PatchCheckResponse {
            authentication: None,
            patch_available: true,
            patch: Some(Patch {
                number: 7,
                hash: "a".repeat(64),
                download_url: "https://example.com/7".to_string(),
                hash_signature: None,
            }),
            rolled_back_patch_numbers: Some(vec![1, 2]),
        }
    }
    fn verify(request: &PatchCheckRequest, response: &PatchCheckResponse) -> Result<()> {
        verify_inner(
            request,
            response,
            Some(&response_test_public_key()),
            PatchResponseVerificationMode::Required,
        )
    }

    #[test]
    fn accepts_real_go_server_signed_response_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test_fixtures/server_response_v1.json")).unwrap();
        let wire_request = &fixture["request"];
        let mut request = request();
        request.app_id = wire_request["app_id"].as_str().unwrap().to_string();
        request.release_version = wire_request["release_version"]
            .as_str()
            .unwrap()
            .to_string();
        request.platform = wire_request["platform"].as_str().unwrap().to_string();
        request.arch = wire_request["arch"].as_str().unwrap().to_string();
        request.channel = wire_request["channel"].as_str().unwrap().to_string();
        request.nonce = wire_request["nonce"].as_str().unwrap().to_string();
        let response: PatchCheckResponse =
            serde_json::from_value(fixture["response"].clone()).unwrap();
        let public_key = base64::prelude::BASE64_STANDARD.encode(include_bytes!(
            "../test_fixtures/server_response_public.der"
        ));
        verify_inner(
            &request,
            &response,
            Some(&public_key),
            PatchResponseVerificationMode::Required,
        )
        .unwrap();
        let patch = response.patch.as_ref().unwrap();
        crate::cache::check_patch_signature(
            &patch.hash,
            patch.hash_signature.as_deref(),
            Some(&public_key),
        )
        .unwrap();
    }

    #[test]
    fn authenticates_patch_and_rollback_only_decisions() {
        let request = request();
        let mut response = response();
        authenticate_test_response(&request, &mut response);
        verify(&request, &response).unwrap();
        response.patch_available = false;
        response.patch = None;
        authenticate_test_response(&request, &mut response);
        verify(&request, &response).unwrap();
    }

    #[test]
    fn signed_decision_cannot_be_replayed_or_retargeted() {
        let request = request();
        let mut response = response();
        authenticate_test_response(&request, &mut response);
        for field in [
            "nonce",
            "app_id",
            "release_version",
            "platform",
            "arch",
            "channel",
        ] {
            let mut changed = request.clone();
            match field {
                "nonce" => changed.nonce.push('x'),
                "app_id" => changed.app_id.push('x'),
                "release_version" => changed.release_version.push('x'),
                "platform" => changed.platform.push('x'),
                "arch" => changed.arch.push('x'),
                "channel" => changed.channel.push('x'),
                _ => unreachable!(),
            }
            assert!(verify(&changed, &response).is_err(), "{field}");
        }
        response
            .rolled_back_patch_numbers
            .as_mut()
            .unwrap()
            .push(99);
        assert!(verify(&request, &response).is_err());
        response.rolled_back_patch_numbers = Some(vec![1, 2]);
        response.patch.as_mut().unwrap().number = 99999;
        assert!(verify(&request, &response).is_err());
        response.patch.as_mut().unwrap().number = 7;
        response.patch.as_mut().unwrap().hash.push('0');
        assert!(verify(&request, &response).is_err());
    }

    #[test]
    fn authentication_never_silently_downgrades() {
        let request = request();
        let mut response = response();
        assert!(verify(&request, &response).is_err());
        assert!(verify_inner(
            &request,
            &response,
            None,
            PatchResponseVerificationMode::Optional
        )
        .is_ok());
        authenticate_test_response(&request, &mut response);
        assert!(verify_inner(
            &request,
            &response,
            None,
            PatchResponseVerificationMode::Optional
        )
        .is_err());
        response
            .authentication
            .as_mut()
            .unwrap()
            .signature
            .replace_range(..1, "!");
        assert!(verify(&request, &response).is_err());
    }

    #[test]
    fn authenticated_payload_rejects_duplicate_and_unknown_fields() {
        let request = request();
        for extra in ["\"version\":1,", "\"future\":true,"] {
            let mut response = response();
            let json = serde_json::to_string(&AuthenticatedResponse::expected(&request, &response))
                .unwrap();
            let payload = format!("{{{extra}{}", &json[1..]);
            response.authentication = Some(ResponseAuthentication {
                signature: crate::test_utils::sign_test_message(payload.as_bytes()),
                payload: base64::prelude::BASE64_STANDARD.encode(payload.as_bytes()),
            });
            assert!(verify(&request, &response).is_err());
        }
    }
}
