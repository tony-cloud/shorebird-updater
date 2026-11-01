//! Explicit signed variant grants. Content numbers identify bytes; only epochs
//! order authorization. This module never infers v2 from a server response.
use anyhow::{ensure, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub use crate::encrypted_patch::EncryptionMetadata;
const MAX_JSON: usize = 64 * 1024;
const MAX_TIME: u64 = 253402300799;

// Unlike ordinary serde Option fields, nullable protocol members are required.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
fn decimal(s: &str, min: u64, max: u64) -> Result<u64> {
    ensure!(
        !s.is_empty() && (s == "0" || !s.starts_with('0')) && s.bytes().all(|b| b.is_ascii_digit()),
        "Noncanonical decimal"
    );
    let n: u64 = s.parse()?;
    ensure!((min..=max).contains(&n), "Decimal out of range");
    Ok(n)
}
fn hash(s: &str) -> Result<()> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid SHA-256"
    );
    Ok(())
}
fn text(s: &str, max: usize) -> Result<()> {
    ensure!(
        !s.is_empty() && s.len() <= max && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}'),
        "Invalid protocol string"
    );
    Ok(())
}
fn identifier(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()[0].is_ascii_lowercase()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'),
        "Invalid identifier"
    );
    Ok(())
}
fn uuid(s: &str, require_v4: bool) -> Result<()> {
    let value = uuid::Uuid::parse_str(s)?;
    ensure!(
        value.to_string() == s
            && (!require_v4
                || (value.get_version_num() == 4 && value.get_variant() == uuid::Variant::RFC4122)),
        "Invalid canonical UUID"
    );
    Ok(())
}

/// Immutable compiled release binding. Supplied by the installed host, never
/// copied from a network response. The native initializer measures the baseline.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseScope {
    pub app_id: String,
    pub release_version: String,
    pub platform: String,
    pub arch: String,
    pub base_artifact_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub host_abi_hash: Option<String>,
    pub runtime_profile: String,
}
impl ReleaseScope {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_JSON, "Release scope too large");
        let scope: Self = serde_json::from_slice(bytes)?;
        scope.validate()?;
        Ok(scope)
    }
    pub fn validate(&self) -> Result<()> {
        uuid(&self.app_id, false)?;
        text(&self.release_version, 256)?;
        ensure!(
            ["android", "ios", "macos", "windows", "linux"].contains(&self.platform.as_str()),
            "Invalid platform"
        );
        ensure!(
            ["arm", "aarch64", "x86", "x86_64"].contains(&self.arch.as_str()),
            "Invalid architecture"
        );
        hash(&self.base_artifact_hash)?;
        ensure!(
            [
                "native-aot",
                "interpreter-body",
                "interpreter-structural",
                "interpreter-full"
            ]
            .contains(&self.runtime_profile.as_str()),
            "Invalid runtime profile"
        );
        if self.runtime_profile == "interpreter-full" {
            hash(self.host_abi_hash.as_deref().context("Missing host ABI")?)?;
        } else {
            ensure!(self.host_abi_hash.is_none(), "Unexpected host ABI");
        }
        Ok(())
    }
    pub fn for_client(&self, client_id: &str) -> Scope {
        Scope {
            app_id: self.app_id.clone(),
            release_version: self.release_version.clone(),
            platform: self.platform.clone(),
            arch: self.arch.clone(),
            client_id_hash: hex::encode(Sha256::digest(client_id.as_bytes())),
            base_artifact_hash: self.base_artifact_hash.clone(),
            host_abi_hash: self.host_abi_hash.clone(),
            runtime_profile: self.runtime_profile.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub app_id: String,
    pub release_version: String,
    pub platform: String,
    pub arch: String,
    pub client_id_hash: String,
    pub base_artifact_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub host_abi_hash: Option<String>,
    pub runtime_profile: String,
}
impl Scope {
    fn release(&self) -> ReleaseScope {
        ReleaseScope {
            app_id: self.app_id.clone(),
            release_version: self.release_version.clone(),
            platform: self.platform.clone(),
            arch: self.arch.clone(),
            base_artifact_hash: self.base_artifact_hash.clone(),
            host_abi_hash: self.host_abi_hash.clone(),
            runtime_profile: self.runtime_profile.clone(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.release().validate()?;
        hash(&self.client_id_hash)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub kind: String,
    #[serde(deserialize_with = "nullable")]
    pub patch_number: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub artifact_hash: Option<String>,
    pub encryption: String,
    #[serde(deserialize_with = "nullable")]
    pub artifact_key_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fallback {
    pub kind: String,
    pub variant_id: String,
    pub license_type: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub epoch: String,
    pub scope: Scope,
    pub channel: String,
    pub variant_id: String,
    pub license_type: String,
    pub entitlement_revision: String,
    pub target: Target,
    pub not_before: String,
    #[serde(deserialize_with = "nullable")]
    pub offline_valid_until: Option<String>,
    pub fallback: Fallback,
}
impl Descriptor {
    pub fn validate(&self) -> Result<()> {
        decimal(&self.epoch, 1, i64::MAX as u64)?;
        self.scope.validate()?;
        identifier(&self.channel)?;
        identifier(&self.variant_id)?;
        identifier(&self.license_type)?;
        text(&self.entitlement_revision, 128)?;
        let start = decimal(&self.not_before, 0, MAX_TIME)?;
        if let Some(end) = &self.offline_valid_until {
            ensure!(decimal(end, 0, MAX_TIME)? > start, "Invalid lease");
        }
        ensure!(
            self.fallback.kind == "base"
                && self.fallback.variant_id == "free"
                && self.fallback.license_type == "free",
            "Invalid fallback"
        );
        match self.target.kind.as_str() {
            "base" => ensure!(
                self.variant_id == "free"
                    && self.license_type == "free"
                    && self.target.patch_number.is_none()
                    && self.target.artifact_hash.is_none()
                    && self.target.artifact_key_id.is_none()
                    && self.target.encryption == "none",
                "Invalid base target"
            ),
            "patch" => {
                decimal(
                    self.target
                        .patch_number
                        .as_deref()
                        .context("Missing patch number")?,
                    1,
                    i32::MAX as u64,
                )?;
                hash(
                    self.target
                        .artifact_hash
                        .as_deref()
                        .context("Missing artifact hash")?,
                )?;
                if self.scope.runtime_profile == "native-aot" {
                    ensure!(
                        self.target.encryption == "transport-aes-256-gcm"
                            && self.target.artifact_key_id.is_none(),
                        "Invalid native encryption"
                    );
                } else {
                    ensure!(
                        self.target.encryption == "artifact-aes-256-gcm",
                        "Invalid interpreter encryption"
                    );
                    text(
                        self.target
                            .artifact_key_id
                            .as_deref()
                            .context("Missing artifact key")?,
                        128,
                    )?;
                }
            }
            _ => anyhow::bail!("Invalid target kind"),
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let s = &self.scope;
        let t = &self.target;
        let f = &self.fallback;
        let fields = [
            Some(self.epoch.as_str()),
            Some(s.app_id.as_str()),
            Some(s.release_version.as_str()),
            Some(s.platform.as_str()),
            Some(s.arch.as_str()),
            Some(s.client_id_hash.as_str()),
            Some(s.base_artifact_hash.as_str()),
            s.host_abi_hash.as_deref(),
            Some(s.runtime_profile.as_str()),
            Some(self.channel.as_str()),
            Some(self.variant_id.as_str()),
            Some(self.license_type.as_str()),
            Some(self.entitlement_revision.as_str()),
            Some(t.kind.as_str()),
            t.patch_number.as_deref(),
            t.artifact_hash.as_deref(),
            Some(t.encryption.as_str()),
            t.artifact_key_id.as_deref(),
            Some(self.not_before.as_str()),
            self.offline_valid_until.as_deref(),
            Some(f.kind.as_str()),
            Some(f.variant_id.as_str()),
            Some(f.license_type.as_str()),
        ];
        let mut out = b"shorebird-selection-v2\0\x01".to_vec();
        for field in fields {
            match field {
                None => out.push(0),
                Some(value) => {
                    out.push(1);
                    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
                    out.extend_from_slice(value.as_bytes());
                }
            }
        }
        Ok(out)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
    pub fn activation(&self, now: u64) -> Activation {
        if now
            < self
                .not_before
                .parse::<u64>()
                .expect("validated descriptor")
        {
            Activation::NotYetValid
        } else if self
            .offline_valid_until
            .as_ref()
            .is_some_and(|end| now >= end.parse::<u64>().expect("validated descriptor"))
        {
            Activation::Expired
        } else if self.target.kind == "base" {
            Activation::Base
        } else {
            Activation::Patch
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    pub app_id: String,
    pub release_version: String,
    pub platform: String,
    pub arch: String,
    pub channel: String,
    pub client_id_hash: String,
    pub nonce: String,
    pub base_artifact_hash: String,
    #[serde(deserialize_with = "nullable")]
    pub host_abi_hash: Option<String>,
    pub runtime_profile: String,
    pub accepted_selection_epoch: String,
    #[serde(deserialize_with = "nullable")]
    pub accepted_selection_digest: Option<String>,
}
impl RequestContext {
    pub fn new(
        scope: &Scope,
        channel: Option<&str>,
        epoch: u64,
        digest: Option<String>,
    ) -> Result<Self> {
        let request = Self {
            app_id: scope.app_id.clone(),
            release_version: scope.release_version.clone(),
            platform: scope.platform.clone(),
            arch: scope.arch.clone(),
            channel: channel.unwrap_or("stable").to_owned(),
            client_id_hash: scope.client_id_hash.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
            base_artifact_hash: scope.base_artifact_hash.clone(),
            host_abi_hash: scope.host_abi_hash.clone(),
            runtime_profile: scope.runtime_profile.clone(),
            accepted_selection_epoch: epoch.to_string(),
            accepted_selection_digest: digest,
        };
        request.validate()?;
        Ok(request)
    }
    pub fn scope(&self) -> Scope {
        Scope {
            app_id: self.app_id.clone(),
            release_version: self.release_version.clone(),
            platform: self.platform.clone(),
            arch: self.arch.clone(),
            client_id_hash: self.client_id_hash.clone(),
            base_artifact_hash: self.base_artifact_hash.clone(),
            host_abi_hash: self.host_abi_hash.clone(),
            runtime_profile: self.runtime_profile.clone(),
        }
    }
    fn validate(&self) -> Result<()> {
        self.scope().validate()?;
        identifier(&self.channel)?;
        uuid(&self.nonce, true)?;
        let epoch = decimal(&self.accepted_selection_epoch, 0, i64::MAX as u64)?;
        if epoch == 0 {
            ensure!(
                self.accepted_selection_digest.is_none(),
                "Fresh request digest must be null"
            );
        } else {
            hash(
                self.accepted_selection_digest
                    .as_deref()
                    .context("Missing accepted digest")?,
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub number: String,
    pub hash: String,
    pub download_url: String,
    pub hash_signature: String,
    #[serde(deserialize_with = "nullable")]
    pub encryption: Option<EncryptionMetadata>,
}
impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Delivery { <redacted> }")
    }
}
impl Delivery {
    pub(crate) fn patch(&self) -> crate::network::Patch {
        crate::network::Patch {
            number: self.number.parse().expect("validated patch"),
            hash: self.hash.clone(),
            download_url: self.download_url.clone(),
            hash_signature: Some(self.hash_signature.clone()),
            encryption: self.encryption.clone(),
        }
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Authentication {
    payload: String,
    signature: String,
}
impl std::fmt::Debug for Authentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authentication { <redacted> }")
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    selection: Descriptor,
    selection_digest: String,
    #[serde(deserialize_with = "nullable")]
    delivery: Option<Delivery>,
    authentication: Authentication,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u32,
    request: RequestContext,
    selection: Descriptor,
    selection_digest: String,
    #[serde(deserialize_with = "nullable")]
    delivery: Option<Delivery>,
}

/// A fully verified signed grant, including the exact bytes needed at boot.
/// Construction is private so key providers cannot receive caller-invented context.
#[derive(Clone, Debug)]
pub struct VerifiedSelection {
    payload: Payload,
    authentication: Authentication,
}
impl VerifiedSelection {
    pub fn context_json(&self) -> Result<String> {
        Ok(serde_json::to_string(
            &serde_json::json!({"version":2,"selection":self.descriptor(),"selection_digest":self.digest()}),
        )?)
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.payload.selection
    }
    pub fn digest(&self) -> &str {
        &self.payload.selection_digest
    }
    pub fn delivery(&self) -> Option<&Delivery> {
        self.payload.delivery.as_ref()
    }
    pub fn epoch(&self) -> u64 {
        self.payload
            .selection
            .epoch
            .parse()
            .expect("validated epoch")
    }
    pub fn activation(&self, now: u64) -> Activation {
        self.descriptor().activation(now)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    Patch,
    Base,
    Expired,
    NotYetValid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Refresh,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    InvalidSchema,
    InvalidSignature,
    ContextMismatch,
    ResponseMismatch,
    InvalidDescriptor,
    InvalidDelivery,
    Replay,
    EpochConflict,
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rejected v2 selection: {:?}", self)
    }
}
impl std::error::Error for Rejection {}

fn decode(auth: &Authentication, key: &str) -> std::result::Result<Payload, Rejection> {
    if auth.payload.len() > MAX_JSON.div_ceil(3) * 4 || auth.signature.len() > 2048 {
        return Err(Rejection::InvalidSchema);
    }
    let bytes = BASE64_STANDARD
        .decode(&auth.payload)
        .map_err(|_| Rejection::InvalidSchema)?;
    if bytes.len() > MAX_JSON {
        return Err(Rejection::InvalidSchema);
    }
    let utf8 = std::str::from_utf8(&bytes).map_err(|_| Rejection::InvalidSchema)?;
    crate::cache::signing::check_signature(utf8, &auth.signature, key)
        .map_err(|_| Rejection::InvalidSignature)?;
    serde_json::from_str(utf8).map_err(|_| Rejection::InvalidSchema)
}
fn validate_payload(
    payload: &Payload,
    scope: &Scope,
    key: &str,
) -> std::result::Result<(), Rejection> {
    if payload.version != 2 || payload.request.validate().is_err() {
        return Err(Rejection::InvalidSchema);
    }
    if payload.request.scope() != *scope
        || payload.selection.scope != *scope
        || payload.request.channel != payload.selection.channel
    {
        return Err(Rejection::ContextMismatch);
    }
    if !payload
        .selection
        .digest()
        .is_ok_and(|digest| digest == payload.selection_digest)
    {
        return Err(Rejection::InvalidDescriptor);
    }
    let validate = || -> Result<()> {
        match (&payload.delivery, payload.selection.target.kind.as_str()) {
            (None, "base") => (),
            (Some(delivery), "patch") => {
                ensure!(
                    Some(&delivery.number) == payload.selection.target.patch_number.as_ref()
                        && Some(&delivery.hash) == payload.selection.target.artifact_hash.as_ref(),
                    "Delivery target mismatch"
                );
                ensure!(
                    !delivery.download_url.is_empty()
                        && delivery.download_url.len() <= 8192
                        && !delivery.download_url.chars().any(char::is_control),
                    "Invalid URL"
                );
                crate::cache::signing::check_signature(
                    &delivery.hash,
                    &delivery.hash_signature,
                    key,
                )?;
                if scope.runtime_profile == "native-aot" {
                    crate::encrypted_patch::validate_selection_context(
                        delivery
                            .encryption
                            .as_ref()
                            .context("Missing native encryption")?,
                        &delivery.patch(),
                        scope,
                    )?;
                } else {
                    ensure!(
                        delivery.encryption.is_none(),
                        "Interpreter transport must not be encrypted"
                    );
                }
            }
            _ => anyhow::bail!("Invalid delivery"),
        }
        Ok(())
    };
    validate().map_err(|_| Rejection::InvalidDelivery)
}
/// Verifies original signed JSON, outstanding request, immutable installation,
/// outer equality, digest and artifact/transport context before any mutation.
pub fn verify_response(
    bytes: &[u8],
    request: &RequestContext,
    installed: &Scope,
    key: &str,
) -> std::result::Result<VerifiedSelection, Rejection> {
    if bytes.len() > MAX_JSON {
        return Err(Rejection::InvalidSchema);
    }
    let response: Response = serde_json::from_slice(bytes).map_err(|_| Rejection::InvalidSchema)?;
    let payload = decode(&response.authentication, key)?;
    if request.validate().is_err()
        || payload.request != *request
        || request.scope() != *installed
        || payload.selection.scope != *installed
    {
        return Err(Rejection::ContextMismatch);
    }
    if response.version != 2
        || payload.version != response.version
        || payload.selection != response.selection
        || payload.selection_digest != response.selection_digest
        || payload.delivery != response.delivery
    {
        return Err(Rejection::ResponseMismatch);
    }
    validate_payload(&payload, installed, key)?;
    Ok(VerifiedSelection {
        payload,
        authentication: response.authentication,
    })
}
pub fn compare(
    candidate: &VerifiedSelection,
    accepted: Option<(u64, &str)>,
) -> std::result::Result<Action, Rejection> {
    match accepted {
        Some((epoch, _)) if candidate.epoch() < epoch => Err(Rejection::Replay),
        Some((epoch, digest)) if candidate.epoch() == epoch => {
            if candidate.digest() == digest {
                Ok(Action::Refresh)
            } else {
                Err(Rejection::EpochConflict)
            }
        }
        _ => Ok(Action::Accept),
    }
}

/// A release-scoped authority outside patch directories. All callers must use
/// the updater operation lock when accepting/recovering to serialize CAS and
/// pointer changes; this module never holds a lock across application callbacks.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    epoch: String,
    digest: String,
    time_floor: u64,
    authentication: Authentication,
}
static JOURNAL_WRITES: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Serialize final unbegun boot commitment against authorization replacement.
/// Lock order is selection -> config -> authority; journal acceptance releases
/// authority before acquiring config. No external callback may run in `f`.
pub(crate) fn with_authority_guard<T>(
    config: &crate::config::UpdateConfig,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let _guard = if config.selection_scope.is_some() {
        Some(
            JOURNAL_WRITES
                .lock()
                .map_err(|_| anyhow::anyhow!("Selection journal lock poisoned"))?,
        )
    } else {
        None
    };
    f()
}

pub struct SelectionJournal {
    path: PathBuf,
}
impl SelectionJournal {
    pub fn new(root: &Path, scope: &Scope) -> Result<Self> {
        scope.validate()?;
        let name = hex::encode(Sha256::digest(serde_json::to_vec(scope)?));
        Ok(Self {
            path: root.join("selections-v2").join(format!("{name}.json")),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Missing/corrupt state is an error. Callers must choose BASE and may
    /// recover only through a fresh online authorization, never v1 pointers.
    pub fn load(&self, scope: &Scope, key: &str) -> Result<(VerifiedSelection, u64)> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)?
            .take((MAX_JSON * 2 + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_JSON * 2, "Selection journal too large");
        let journal: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            journal.version == 2 && journal.time_floor <= MAX_TIME,
            "Invalid selection journal"
        );
        let payload = decode(&journal.authentication, key)?;
        validate_payload(&payload, scope, key)?;
        ensure!(
            payload.selection.epoch == journal.epoch && payload.selection_digest == journal.digest,
            "Journal high-water mismatch"
        );
        Ok((
            VerifiedSelection {
                payload,
                authentication: journal.authentication,
            },
            journal.time_floor,
        ))
    }
    /// Persist authority durably before exposing a target. A refresh can rotate
    /// delivery but cannot change the stable grant, including lease/fallback.
    pub fn accept(
        &self,
        candidate: &VerifiedSelection,
        scope: &Scope,
        key: &str,
        now: u64,
    ) -> Result<(Action, Activation)> {
        let _serialization = JOURNAL_WRITES
            .lock()
            .map_err(|_| anyhow::anyhow!("Selection journal lock poisoned"))?;
        ensure!(now <= MAX_TIME, "Time out of range");
        validate_payload(&candidate.payload, scope, key)?;
        // Recheck signature even for a cloned verified object at this boundary.
        let checked = decode(&candidate.authentication, key)?;
        ensure!(checked == candidate.payload, "Verified selection mismatch");
        let prior = match self.load(scope, key) {
            Ok(prior) => Some(prior),
            Err(error) => {
                // An unreadable high-water mark is not an empty scope. Only
                // missing/corrupt authority can recover through an online grant.
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() != std::io::ErrorKind::NotFound)
                }) {
                    return Err(error);
                }
                None
            }
        };
        let action = compare(
            candidate,
            prior.as_ref().map(|(p, _)| (p.epoch(), p.digest())),
        )?;
        let time_floor = now.max(prior.as_ref().map_or(0, |(_, t)| *t));
        self.write(&Journal {
            version: 2,
            epoch: candidate.descriptor().epoch.clone(),
            digest: candidate.digest().to_owned(),
            time_floor,
            authentication: candidate.authentication.clone(),
        })?;
        Ok((action, candidate.activation(time_floor)))
    }
    fn write(&self, journal: &Journal) -> Result<()> {
        let parent = self.path.parent().context("Journal parent missing")?;
        // A first grant must also durably create its directory entry in the
        // storage root, not only sync the final journal filename inside it.
        #[cfg(unix)]
        let mut missing = Vec::new();
        #[cfg(unix)]
        {
            let mut ancestor = parent;
            while !ancestor.exists() {
                missing.push(ancestor.to_path_buf());
                ancestor = ancestor
                    .parent()
                    .context("Journal storage ancestor missing")?;
            }
        }
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        for directory in missing.iter().rev() {
            std::fs::File::open(directory)?.sync_all()?;
            std::fs::File::open(
                directory
                    .parent()
                    .context("Journal directory parent missing")?,
            )?
            .sync_all()?;
        }
        // Unique sibling avoids clobbering an interrupted temp file. Authority
        // is only the final filename; orphan staging files are never read.
        let temp = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            serde_json::to_writer(&mut file, journal)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &self.path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn fixtures() -> Value {
        serde_json::from_str(include_str!("../test_fixtures/variant_selection_v2.json")).unwrap()
    }
    fn reason(error: Rejection) -> &'static str {
        match error {
            Rejection::InvalidSignature => "invalid_signature",
            Rejection::ContextMismatch => "context_mismatch",
            Rejection::ResponseMismatch => "response_mismatch",
            Rejection::Replay => "replay",
            Rejection::EpochConflict => "epoch_conflict",
            _ => "invalid",
        }
    }
    #[test]
    fn every_golden_canonical_encoding_signature_and_decision() {
        let f = fixtures();
        let key = f["signature"]["public_key_der_base64"].as_str().unwrap();
        for (id, entry) in f["descriptors"].as_object().unwrap() {
            let descriptor: Descriptor =
                serde_json::from_value(entry["descriptor"].clone()).unwrap();
            let bytes = descriptor.canonical_bytes().unwrap();
            assert_eq!(hex::encode(&bytes), entry["canonical_hex"], "{id}");
            assert_eq!(
                BASE64_STANDARD.encode(&bytes),
                entry["canonical_base64"],
                "{id}"
            );
            assert_eq!(bytes.len() as u64, entry["canonical_length"], "{id}");
            assert_eq!(descriptor.digest().unwrap(), entry["sha256"], "{id}");
        }
        for vector in f["vectors"].as_array().unwrap() {
            let id = vector["id"].as_str().unwrap();
            let request: RequestContext =
                serde_json::from_value(vector["actual_request_context"].clone()).unwrap();
            let outer = serde_json::to_vec(&vector["response"]).unwrap();
            let auth: Authentication =
                serde_json::from_value(vector["response"]["authentication"].clone()).unwrap();
            let payload = BASE64_STANDARD.decode(&auth.payload).unwrap();
            assert_eq!(
                std::str::from_utf8(&payload).unwrap(),
                vector["signed_payload_utf8"],
                "{id}"
            );
            assert_eq!(
                hex::encode(Sha256::digest(&payload)),
                vector["signed_payload_sha256"],
                "{id}"
            );
            assert_eq!(
                decode(&auth, key).is_ok(),
                vector["expected"]["signature_valid"].as_bool().unwrap(),
                "{id}"
            );
            let prior = vector["prior_descriptor_ref"].as_str().map(|name| {
                serde_json::from_value::<Descriptor>(f["descriptors"][name]["descriptor"].clone())
                    .unwrap()
            });
            let mut epoch = prior
                .as_ref()
                .map_or(0, |d| d.epoch.parse::<u64>().unwrap());
            let mut digest = prior.as_ref().map(|d| d.digest().unwrap());
            let result =
                verify_response(&outer, &request, &request.scope(), key).and_then(|candidate| {
                    compare(&candidate, digest.as_deref().map(|d| (epoch, d)))
                        .map(|action| (candidate, action))
                });
            match result {
                Ok((candidate, action)) => {
                    assert_eq!(
                        if action == Action::Accept {
                            "accept"
                        } else {
                            "refresh"
                        },
                        vector["expected"]["authorization_action"],
                        "{id}"
                    );
                    let activation = candidate.activation(
                        vector["now_unix_seconds"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap(),
                    );
                    assert_eq!(
                        if activation == Activation::Patch {
                            "selected_patch"
                        } else {
                            "base"
                        },
                        vector["expected"]["activation"],
                        "{id}"
                    );
                    assert_eq!(
                        match activation {
                            Activation::Patch => "ok",
                            Activation::Base => "selected_base",
                            Activation::Expired => "expired",
                            Activation::NotYetValid => "not_yet_valid",
                        },
                        vector["expected"]["reason"],
                        "{id}"
                    );
                    epoch = candidate.epoch();
                    digest = Some(candidate.digest().to_owned());
                }
                Err(error) => {
                    assert_eq!("reject", vector["expected"]["authorization_action"], "{id}");
                    assert_eq!("unchanged", vector["expected"]["activation"], "{id}");
                    assert_eq!(
                        reason(error),
                        vector["expected"]["reason"],
                        "{id}: {error:?}"
                    );
                }
            }
            assert_eq!(
                epoch.to_string(),
                vector["expected"]["accepted_epoch"],
                "{id}"
            );
            assert_eq!(
                digest.as_deref(),
                vector["expected"]["accepted_digest"].as_str(),
                "{id}"
            );
        }
    }
    #[test]
    fn strict_schema_requires_nullable_members_and_rejects_duplicates_unknowns_and_bad_utf8() {
        let f = fixtures();
        let original = f["descriptors"]["pro_11"]["descriptor"].clone();
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove("offline_valid_until");
        assert!(serde_json::from_value::<Descriptor>(value).is_err());
        let mut value = original.clone();
        value["scope"]
            .as_object_mut()
            .unwrap()
            .remove("host_abi_hash");
        assert!(serde_json::from_value::<Descriptor>(value).is_err());
        let mut value = original.clone();
        value["target"]["extra"] = json!(null);
        assert!(serde_json::from_value::<Descriptor>(value).is_err());
        let bytes = serde_json::to_string(&original).unwrap().replacen(
            "\"epoch\":\"11\"",
            "\"epoch\":\"11\",\"epoch\":\"11\"",
            1,
        );
        assert!(serde_json::from_str::<Descriptor>(&bytes).is_err());
        assert!(serde_json::from_slice::<Descriptor>(b"{\"epoch\":\"\xff\"}").is_err());
        assert!(serde_json::from_str::<Descriptor>(r#"{"epoch":"\ud800"}"#).is_err());
        for (field, bad) in [
            ("epoch", "0"),
            ("epoch", "01"),
            ("epoch", "+1"),
            ("epoch", "9223372036854775808"),
            ("not_before", "253402300800"),
            ("not_before", "1.5"),
            ("variant_id", "Pro"),
            ("entitlement_revision", "bad\u{7f}"),
        ] {
            let mut value = original.clone();
            value[field] = json!(bad);
            assert!(
                serde_json::from_value::<Descriptor>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field} {bad}"
            );
        }
        let mut max = original;
        max["epoch"] = json!("9223372036854775807");
        max["target"]["patch_number"] = json!("2147483647");
        max["not_before"] = json!("253402300798");
        max["offline_valid_until"] = json!("253402300799");
        assert!(serde_json::from_value::<Descriptor>(max.clone())
            .unwrap()
            .validate()
            .is_ok());
        max["target"]["patch_number"] = json!("2147483648");
        assert!(serde_json::from_value::<Descriptor>(max)
            .unwrap()
            .validate()
            .is_err());
    }
    fn candidate(index: usize) -> (VerifiedSelection, Scope, String) {
        let f = fixtures();
        let vector = &f["vectors"][index];
        let request: RequestContext =
            serde_json::from_value(vector["actual_request_context"].clone()).unwrap();
        let key = f["signature"]["public_key_der_base64"]
            .as_str()
            .unwrap()
            .to_owned();
        (
            verify_response(
                &serde_json::to_vec(&vector["response"]).unwrap(),
                &request,
                &request.scope(),
                &key,
            )
            .unwrap(),
            request.scope(),
            key,
        )
    }
    #[test]
    fn journal_survives_patch_cleanup_restarts_expiry_and_rejects_replay_without_mutation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (pro, scope, key) = candidate(0);
        let journal = SelectionJournal::new(tmp.path(), &scope).unwrap();
        assert!(journal.load(&scope, &key).is_err());
        assert_eq!(
            journal.accept(&pro, &scope, &key, 1793491300).unwrap(),
            (Action::Accept, Activation::Patch)
        );
        std::fs::create_dir_all(tmp.path().join("patches/2")).unwrap();
        std::fs::remove_dir_all(tmp.path().join("patches")).unwrap();
        let recovered = SelectionJournal::new(tmp.path(), &scope).unwrap();
        assert_eq!(
            recovered.load(&scope, &key).unwrap().0.digest(),
            pro.digest()
        );
        let original = std::fs::read(journal.path()).unwrap();
        let (replay, _, _) = candidate(5);
        assert!(journal.accept(&replay, &scope, &key, 1793491301).is_err());
        assert_eq!(std::fs::read(journal.path()).unwrap(), original);
        let (conflict, _, _) = candidate(3);
        assert!(journal.accept(&conflict, &scope, &key, 1793491301).is_err());
        assert_eq!(std::fs::read(journal.path()).unwrap(), original);
        let (expired, _, _) = candidate(6);
        assert_eq!(
            journal.accept(&expired, &scope, &key, 1793491500).unwrap(),
            (Action::Accept, Activation::Expired)
        );
        assert_eq!(
            journal.accept(&expired, &scope, &key, 1).unwrap(),
            (Action::Refresh, Activation::Expired)
        );
        assert_eq!(journal.load(&scope, &key).unwrap().0.epoch(), 13);
        let mut bad: Value =
            serde_json::from_slice(&std::fs::read(journal.path()).unwrap()).unwrap();
        bad["epoch"] = json!("12");
        std::fs::write(journal.path(), serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(journal.load(&scope, &key).is_err());
    }
    #[test]
    fn concurrent_journal_acceptance_retains_highest_epoch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (pro, scope, key) = candidate(0);
        let (free, _, _) = candidate(1);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for grant in [pro, free] {
            let root = tmp.path().to_path_buf();
            let scope = scope.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                SelectionJournal::new(&root, &scope)
                    .unwrap()
                    .accept(&grant, &scope, &key, 1793491300)
            }));
        }
        barrier.wait();
        for worker in workers {
            let _ = worker.join().unwrap();
        }
        let journal = SelectionJournal::new(tmp.path(), &scope).unwrap();
        assert_eq!(journal.load(&scope, &key).unwrap().0.epoch(), 12);
    }

    #[test]
    fn signed_payload_schema_is_strict_and_network_is_bounded_and_explicit_v2() {
        let f = fixtures();
        let vector = &f["vectors"][0];
        let request: RequestContext =
            serde_json::from_value(vector["actual_request_context"].clone()).unwrap();
        let key = f["signature"]["public_key_der_base64"].as_str().unwrap();
        let mut response: Response = serde_json::from_value(vector["response"].clone()).unwrap();
        for suffix in [r#","version":2}"#, r#","extra":null}"#] {
            let original = vector["signed_payload_utf8"].as_str().unwrap();
            let malformed = format!("{}{}", &original[..original.len() - 1], suffix);
            response.authentication = Authentication {
                signature: crate::test_utils::sign_test_message(malformed.as_bytes()),
                payload: BASE64_STANDARD.encode(malformed.as_bytes()),
            };
            assert_eq!(
                verify_response(
                    &serde_json::to_vec(&response).unwrap(),
                    &request,
                    &request.scope(),
                    key
                )
                .unwrap_err(),
                Rejection::InvalidSchema
            );
        }
        let mut server = mockito::Server::new();
        let mock = server.mock("POST", "/api/v1/patches/check")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({"selection_protocol":2,"accepted_selection_epoch":"10","accepted_selection_digest":request.accepted_selection_digest,"base_artifact_hash":request.base_artifact_hash,"runtime_profile":"interpreter-structural","host_abi_hash":null,"client_id":"test-install","nonce":request.nonce})))
            .with_body(serde_json::to_vec(&vector["response"]).unwrap()).create();
        let bytes = crate::network::patch_check_v2(
            &format!("{}/api/v1/patches/check", server.url()),
            &request,
            "test-install",
            Some(3),
        )
        .unwrap();
        assert!(verify_response(&bytes, &request, &request.scope(), key).is_ok());
        mock.assert();
        mock.remove();
        let oversized = server
            .mock("POST", "/api/v1/patches/check")
            .with_body(vec![b' '; MAX_JSON + 1])
            .create();
        assert!(crate::network::patch_check_v2(
            &format!("{}/api/v1/patches/check", server.url()),
            &request,
            "test-install",
            None
        )
        .is_err());
        oversized.assert();
    }

    #[test]
    fn oversized_and_cross_scope_data_is_refused_before_authorization() {
        let (candidate, scope, key) = candidate(0);
        let request = candidate.payload.request.clone();
        assert_eq!(
            verify_response(&vec![b' '; MAX_JSON + 1], &request, &scope, &key).unwrap_err(),
            Rejection::InvalidSchema
        );
        for field in ["client_id_hash", "base_artifact_hash", "platform", "arch"] {
            let mut wrong = serde_json::to_value(&scope).unwrap();
            wrong[field] = json!(if field.ends_with("hash") {
                "0".repeat(64)
            } else {
                "wrong".to_owned()
            });
            let wrong: Scope = serde_json::from_value(wrong).unwrap();
            let response = Response {
                version: 2,
                selection: candidate.payload.selection.clone(),
                selection_digest: candidate.digest().to_owned(),
                delivery: candidate.payload.delivery.clone(),
                authentication: candidate.authentication.clone(),
            };
            assert_eq!(
                verify_response(
                    &serde_json::to_vec(&response).unwrap(),
                    &request,
                    &wrong,
                    &key
                )
                .unwrap_err(),
                Rejection::ContextMismatch
            );
        }
    }
}

fn installed_scope(config: &crate::config::UpdateConfig, client_id: &str) -> Result<Scope> {
    let release = config
        .selection_scope
        .as_ref()
        .context("Release is not v2")?;
    Ok(release.for_client(client_id))
}
fn journal_for(config: &crate::config::UpdateConfig, scope: &Scope) -> Result<SelectionJournal> {
    SelectionJournal::new(&config.storage_dir, scope)
}
pub(crate) fn accepted_grant(
    config: &crate::config::UpdateConfig,
) -> Result<(VerifiedSelection, u64)> {
    let client_id =
        crate::cache::UpdaterState::read_client_id(&config.storage_dir, &config.release_version)?;
    let scope = installed_scope(config, &client_id)?;
    journal_for(config, &scope)?.load(
        &scope,
        config
            .patch_public_key
            .as_deref()
            .context("Missing v2 pinned key")?,
    )
}

#[derive(Debug)]
pub(crate) struct AuthorizationUnavailable;
impl std::fmt::Display for AuthorizationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Accepted selection no longer authorizes native key resolution")
    }
}
impl std::error::Error for AuthorizationUnavailable {}

/// Only verified, current and byte-for-byte matching delivery can release a
/// native key. No updater/config/selection/authority lock is acquired here.
pub(crate) fn grant_for_patch(
    config: &crate::config::UpdateConfig,
    patch: &crate::network::Patch,
    client_id: &str,
) -> Result<VerifiedSelection> {
    let result = (|| -> Result<VerifiedSelection> {
        let (grant, floor) = accepted_grant(config)?;
        ensure!(
            grant.activation(crate::time::unix_timestamp().max(floor)) == Activation::Patch,
            "V2 grant is not usable"
        );
        ensure!(
            grant.descriptor().scope == installed_scope(config, client_id)?
                && grant.descriptor().scope.runtime_profile == "native-aot",
            "V2 key installation scope mismatch"
        );
        ensure!(
            grant
                .delivery()
                .is_some_and(|delivery| delivery.patch() == *patch),
            "V2 key delivery mismatch"
        );
        Ok(grant)
    })();
    result.context(AuthorizationUnavailable)
}

/// Revalidate the accepted authority at every cold selection. A historical
/// nonce is checked structurally and remains signed; it is not a fresh request.
pub(crate) fn boot_grant(
    config: &crate::config::UpdateConfig,
) -> Result<Option<VerifiedSelection>> {
    if config.selection_scope.is_none() {
        return Ok(None);
    }
    let (grant, floor) = accepted_grant(config)?;
    if grant.activation(crate::time::unix_timestamp().max(floor)) != Activation::Patch {
        return Ok(None);
    }
    Ok(Some(grant))
}

pub(crate) enum ContentReadiness {
    Ready(usize),
    Missing(usize),
    Invalid(usize),
    Unavailable,
}
/// Inspect cached content without mutating pointers, quarantine or identity.
pub(crate) fn content_readiness(
    config: &crate::config::UpdateConfig,
    state: &crate::cache::UpdaterState,
    grant: &VerifiedSelection,
) -> Result<ContentReadiness> {
    use crate::cache::lifecycle::PatchState;
    let Some(delivery) = grant.delivery() else {
        return Ok(ContentReadiness::Unavailable);
    };
    let number: usize = delivery.number.parse()?;
    match state.lifecycle().read_state(number) {
        Some(PatchState::Installed { size, .. })
            if grant.descriptor().scope.runtime_profile != "native-aot" =>
        {
            let path = state.lifecycle().installed_artifact_path(number);
            match std::fs::metadata(&path) {
                Ok(meta)
                    if meta.len() == size && crate::cache::hash_file(&path)? == delivery.hash =>
                {
                    Ok(ContentReadiness::Ready(number))
                }
                Ok(_) => Ok(ContentReadiness::Invalid(number)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(ContentReadiness::Missing(number))
                }
                Err(error) => Err(error.into()),
            }
        }
        Some(PatchState::InstalledEncryptedTransportV1 {
            ciphertext_size, ..
        }) if grant.descriptor().scope.runtime_profile == "native-aot" => {
            let path = crate::native_cache::transport_path(config, number);
            match std::fs::metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(ContentReadiness::Missing(number))
                }
                Err(error) => return Err(error.into()),
                Ok(_) => (),
            }
            match crate::encrypted_patch::validate_ciphertext(
                config,
                &delivery.patch(),
                &state.client_id(),
                &path,
            ) {
                Ok(actual) if actual == ciphertext_size => Ok(ContentReadiness::Ready(number)),
                Err(error) if error.chain().any(|cause| cause.is::<std::io::Error>()) => Err(error),
                // A refreshed signed delivery may rotate nonce/key/ciphertext
                // without changing immutable content. Discard this transport
                // cache for redownload; it does not prove the artifact bad.
                _ => Ok(ContentReadiness::Missing(number)),
            }
        }
        _ => Ok(ContentReadiness::Unavailable),
    }
}

/// Recover only the journal's exact selected content. V1 pointers and stale
/// per-patch authentication never grant a fallback to another paid artifact.
pub(crate) fn recover_target(
    config: &crate::config::UpdateConfig,
    state: &mut crate::cache::UpdaterState,
) -> Result<()> {
    use crate::cache::lifecycle::BadReason;
    let mut target = None;
    let mut authorized_content = None;
    if let Ok((grant, floor)) = accepted_grant(config) {
        authorized_content = grant
            .descriptor()
            .target
            .patch_number
            .as_ref()
            .map(|n| n.parse().expect("verified patch"));
        if grant.activation(crate::time::unix_timestamp().max(floor)) == Activation::Patch {
            match content_readiness(config, state, &grant)? {
                ContentReadiness::Ready(number) => target = Some(number),
                ContentReadiness::Missing(number) => state.lifecycle().cleanup(number)?,
                ContentReadiness::Invalid(number) => state
                    .lifecycle()
                    .mark_bad(number, BadReason::ValidationFailed)?,
                ContentReadiness::Unavailable => (),
            }
        }
    }
    state.lifecycle_mut().select_authorized_target(target)?;
    state
        .lifecycle()
        .prune_selection_content(authorized_content);
    Ok(())
}

fn accept_check(
    config: &crate::config::UpdateConfig,
) -> Result<(VerifiedSelection, Activation, Option<usize>)> {
    let state = crate::updater::with_state(|s| {
        Ok((
            s.client_id(),
            s.running_patch().map(|p| p.number),
            s.next_boot_patch().map(|p| p.number),
        ))
    })?;
    let scope = installed_scope(config, &state.0)?;
    let key = config
        .patch_public_key
        .as_deref()
        .context("Missing v2 pinned key")?;
    let journal = journal_for(config, &scope)?;
    let prior = journal.load(&scope, key).ok();
    let request = RequestContext::new(
        &scope,
        Some(&config.channel),
        prior.as_ref().map_or(0, |(p, _)| p.epoch()),
        prior.as_ref().map(|(p, _)| p.digest().to_owned()),
    )?;
    let response = crate::network::patch_check_v2(
        &crate::network::patches_check_url(&config.base_url),
        &request,
        &state.0,
        state.1,
    )?;
    let candidate = verify_response(&response, &request, &scope, key)?;
    // Authorization commits before any content lookup, download or pointers.
    let (_, activation) = journal.accept(&candidate, &scope, key, crate::time::unix_timestamp())?;
    crate::updater::with_mut_state(|_| Ok(()))?; // Reconcile pointers from durable authority.
    Ok((candidate, activation, state.2))
}

pub(crate) fn check(config: &crate::config::UpdateConfig) -> Result<bool> {
    crate::config::ensure_launch_deferral_resolved()?;
    let (candidate, activation, _) = accept_check(config)?;
    if activation != Activation::Patch {
        return Ok(false);
    }
    let patch = candidate
        .delivery()
        .context("Missing selected delivery")?
        .patch();
    crate::updater::with_state(|s| {
        Ok(matches!(
            s.lifecycle().decide_start(
                patch.number,
                &patch.download_identity(),
                &patch.hash,
                patch.hash_signature.as_deref()
            ),
            crate::cache::lifecycle::DownloadAction::Fresh
                | crate::cache::lifecycle::DownloadAction::Resume { .. }
                | crate::cache::lifecycle::DownloadAction::Complete
        ))
    })
}

pub(crate) fn update(config: &crate::config::UpdateConfig) -> Result<crate::UpdateStatus> {
    use crate::cache::lifecycle::{DownloadAction, SkipReason};
    let (candidate, activation, previous_target) = accept_check(config)?;
    if activation != Activation::Patch {
        return Ok(if previous_target.is_some() {
            crate::UpdateStatus::UpdateInstalled
        } else {
            crate::UpdateStatus::NoUpdate
        });
    }
    let patch = candidate
        .delivery()
        .context("Missing selected delivery")?
        .patch();
    let action = crate::updater::with_state(|s| {
        Ok(s.lifecycle().decide_start(
            patch.number,
            &patch.download_identity(),
            &patch.hash,
            patch.hash_signature.as_deref(),
        ))
    })?;
    match action {
        DownloadAction::Skip(SkipReason::KnownBad) => Ok(crate::UpdateStatus::UpdateIsBadPatch),
        DownloadAction::Skip(SkipReason::AlreadyInstalled) => {
            Ok(if previous_target != Some(patch.number) {
                crate::UpdateStatus::UpdateInstalled
            } else {
                crate::UpdateStatus::NoUpdate
            })
        }
        action => crate::updater::download_and_install_patch(config, &patch, action, None),
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        cache::lifecycle::{BadReason, PatchState},
        native_boot::NativeOptions,
    };
    use serial_test::serial;
    fn baseline_callbacks() -> crate::c_api::engine::FileCallbacks {
        extern "C" fn open() -> *mut libc::c_void {
            Box::into_raw(Box::new(std::io::Cursor::new(
                b"original baseline".to_vec(),
            )))
            .cast()
        }
        extern "C" fn read(handle: *mut libc::c_void, output: *mut u8, length: usize) -> usize {
            unsafe {
                (&mut *handle.cast::<std::io::Cursor<Vec<u8>>>())
                    .read(std::slice::from_raw_parts_mut(output, length))
                    .unwrap()
            }
        }
        extern "C" fn seek(handle: *mut libc::c_void, offset: i64, whence: i32) -> i64 {
            use std::io::{Seek, SeekFrom};
            let position = match whence {
                libc::SEEK_SET => SeekFrom::Start(offset as u64),
                libc::SEEK_CUR => SeekFrom::Current(offset),
                _ => SeekFrom::End(offset),
            };
            unsafe {
                (&mut *handle.cast::<std::io::Cursor<Vec<u8>>>())
                    .seek(position)
                    .unwrap() as i64
            }
        }
        extern "C" fn close(handle: *mut libc::c_void) {
            unsafe { drop(Box::from_raw(handle.cast::<std::io::Cursor<Vec<u8>>>())) }
        }
        crate::c_api::engine::FileCallbacks {
            open,
            read,
            seek,
            close,
        }
    }
    fn setup(tmp: &tempfile::TempDir) -> ReleaseScope {
        crate::testing_reset_config();
        let path = tmp.path().join("lib/arch/libapp.so");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"original baseline").unwrap();
        crate::test_utils::write_fake_apk(
            tmp.path().join("base.apk").to_str().unwrap(),
            b"original baseline",
        );
        let scope = ReleaseScope {
            app_id: "11111111-1111-4111-8111-111111111111".into(),
            release_version: "1".into(),
            platform: crate::config::current_platform().into(),
            arch: crate::config::current_arch().into(),
            base_artifact_hash: hex::encode(Sha256::digest(b"original baseline")),
            host_abi_hash: None,
            runtime_profile: "interpreter-structural".into(),
        };
        let app = crate::AppConfig {
            app_storage_dir: tmp.path().to_str().unwrap().into(),
            code_cache_dir: tmp.path().to_str().unwrap().into(),
            release_version: "1".into(),
            original_libapp_paths: vec![path.to_str().unwrap().into()],
        };
        let yaml = format!("app_id: {}\npatch_public_key: {}\npatch_verification: strict\npatch_response_verification: required", scope.app_id, crate::test_utils::response_test_public_key());
        crate::native_boot::initialize_with_scope(
            app,
            crate::c_api::engine::FileCallbacks::new(),
            yaml,
            NativeOptions::default(),
            Some(scope.clone()),
            Some(baseline_callbacks()),
        )
        .unwrap();
        scope
    }
    fn grant(
        config: &crate::config::UpdateConfig,
        epoch: u64,
        number: Option<usize>,
        bytes: &[u8],
    ) -> VerifiedSelection {
        grant_with_encryption(config, epoch, number, bytes, None)
    }
    fn grant_with_encryption(
        config: &crate::config::UpdateConfig,
        epoch: u64,
        number: Option<usize>,
        bytes: &[u8],
        encryption: Option<EncryptionMetadata>,
    ) -> VerifiedSelection {
        let client = crate::updater::with_state(|state| Ok(state.client_id())).unwrap();
        let scope = config.selection_scope.as_ref().unwrap().for_client(&client);
        let request = RequestContext::new(&scope, None, 0, None).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let hash_signature = crate::test_utils::sign_test_message(hash.as_bytes());
        let descriptor = Descriptor {
            epoch: epoch.to_string(),
            scope: scope.clone(),
            channel: "stable".into(),
            variant_id: if number.is_some() { "pro" } else { "free" }.into(),
            license_type: if number.is_some() { "pro" } else { "free" }.into(),
            entitlement_revision: "test-grant".into(),
            target: Target {
                kind: if number.is_some() { "patch" } else { "base" }.into(),
                patch_number: number.map(|n| n.to_string()),
                artifact_hash: number.map(|_| hash.clone()),
                encryption: if number.is_some() {
                    if scope.runtime_profile == "native-aot" {
                        "transport-aes-256-gcm"
                    } else {
                        "artifact-aes-256-gcm"
                    }
                } else {
                    "none"
                }
                .into(),
                artifact_key_id: number
                    .filter(|_| scope.runtime_profile != "native-aot")
                    .map(|_| "test-key".into()),
            },
            not_before: "0".into(),
            offline_valid_until: None,
            fallback: Fallback {
                kind: "base".into(),
                variant_id: "free".into(),
                license_type: "free".into(),
            },
        };
        let payload = Payload {
            version: 2,
            request: request.clone(),
            selection_digest: descriptor.digest().unwrap(),
            selection: descriptor.clone(),
            delivery: number.map(|n| Delivery {
                number: n.to_string(),
                hash,
                download_url: format!("https://example.invalid/{n}"),
                hash_signature,
                encryption,
            }),
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let response = Response {
            version: 2,
            selection: descriptor,
            selection_digest: payload.selection_digest.clone(),
            delivery: payload.delivery.clone(),
            authentication: Authentication {
                signature: crate::test_utils::sign_test_message(&bytes),
                payload: BASE64_STANDARD.encode(bytes),
            },
        };
        verify_response(
            &serde_json::to_vec(&response).unwrap(),
            &request,
            &scope,
            config.patch_public_key.as_deref().unwrap(),
        )
        .unwrap()
    }
    fn accept(config: &crate::config::UpdateConfig, grant: &VerifiedSelection) {
        SelectionJournal::new(&config.storage_dir, &grant.descriptor().scope)
            .unwrap()
            .accept(
                grant,
                &grant.descriptor().scope,
                config.patch_public_key.as_deref().unwrap(),
                0,
            )
            .unwrap();
    }
    fn install(config: &crate::config::UpdateConfig, grant: &VerifiedSelection, bytes: &[u8]) {
        let delivery = grant.delivery().unwrap();
        let n = delivery.number.parse().unwrap();
        let mut state = crate::updater::load_state(config).unwrap();
        let path = state.lifecycle().installed_artifact_path(n);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        state
            .lifecycle_mut()
            .write_state(
                n,
                &PatchState::Installed {
                    signature: Some(delivery.hash_signature.clone()),
                    size: bytes.len() as u64,
                },
            )
            .unwrap();
    }
    #[test]
    #[serial]
    fn explicit_reselection_base_quarantine_and_cached_content_ignore_number_order() {
        let tmp = tempfile::TempDir::new().unwrap();
        setup(&tmp);
        let config = crate::config::with_config(|c| Ok(c.clone())).unwrap();
        let enterprise = grant(&config, 10, Some(3), b"enterprise");
        install(&config, &enterprise, b"enterprise");
        accept(&config, &enterprise);
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            3
        );
        crate::updater::with_mut_state(|state| {
            state.record_boot_start_for_patch(3)?;
            state.record_boot_success()
        })
        .unwrap();
        let pro = grant(&config, 11, Some(2), b"pro");
        install(&config, &pro, b"pro");
        accept(&config, &pro);
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            2
        );
        crate::updater::validate_next_boot_patch().unwrap();
        let prepared = crate::native_boot::prepare().unwrap();
        assert_eq!(prepared.patch, Some(2));
        assert!(crate::native_boot::begin(prepared.id).unwrap());
        let frozen = crate::native_boot::selection_context_json(prepared.id)
            .unwrap()
            .unwrap();
        let free = grant(&config, 12, None, b"");
        accept(&config, &free);
        let pointer_bytes = std::fs::read(tmp.path().join("pointers.json")).unwrap();
        assert!(status()["next_boot"]["patch_number"].is_null());
        assert_eq!(
            std::fs::read(tmp.path().join("pointers.json")).unwrap(),
            pointer_bytes
        );
        assert!(crate::updater::next_boot_patch().unwrap().is_none());
        assert_eq!(crate::native_boot::prepare().unwrap().id, prepared.id);
        assert_eq!(
            crate::native_boot::selection_context_json(prepared.id)
                .unwrap()
                .unwrap(),
            frozen
        );
        assert_eq!(crate::config::running_patch_number(), Some(2));
        let enterprise = grant(&config, 13, Some(3), b"enterprise");
        accept(&config, &enterprise);
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            3
        );
        crate::updater::with_mut_state(|s| s.lifecycle_mut().mark_bad(3, BadReason::BootCrash))
            .unwrap();
        assert!(crate::updater::next_boot_patch().unwrap().is_none());
        let journal = SelectionJournal::new(&config.storage_dir, &pro.descriptor().scope).unwrap();
        assert_eq!(
            journal
                .load(
                    &pro.descriptor().scope,
                    config.patch_public_key.as_deref().unwrap()
                )
                .unwrap()
                .0
                .epoch(),
            13
        );
        std::fs::remove_file(journal.path()).unwrap();
        assert!(crate::updater::next_boot_patch().unwrap().is_none());
        assert!(crate::set_client_id_override("other-install").is_err());
        crate::testing_reset_config();
    }
    fn resign(mut grant: VerifiedSelection) -> VerifiedSelection {
        grant.payload.selection_digest = grant.payload.selection.digest().unwrap();
        let bytes = serde_json::to_vec(&grant.payload).unwrap();
        grant.authentication = Authentication {
            signature: crate::test_utils::sign_test_message(&bytes),
            payload: BASE64_STANDARD.encode(bytes),
        };
        grant
    }

    #[test]
    #[serial]
    fn same_content_new_epoch_invalidates_unbegun_context_and_boot_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        setup(&tmp);
        let config = crate::config::with_config(|c| Ok(c.clone())).unwrap();
        let pro = grant(&config, 11, Some(2), b"pro");
        install(&config, &pro, b"pro");
        accept(&config, &pro);
        let prepared = crate::native_boot::prepare().unwrap();
        let refresh = grant(&config, 11, Some(2), b"pro");
        accept(&config, &refresh);
        assert!(crate::native_boot::selection_context_json(prepared.id)
            .unwrap()
            .is_some());
        let changed = grant(&config, 12, Some(2), b"pro");
        accept(&config, &changed);
        assert!(crate::native_boot::selection_context_json(prepared.id).is_err());
        assert!(!crate::native_boot::begin(prepared.id).unwrap());
        let base = crate::native_boot::prepare().unwrap();
        assert!(base.patch.is_none());
        assert!(crate::native_boot::selection_context_json(base.id)
            .unwrap()
            .is_none());
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            2
        );
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn expired_and_future_authorization_advance_high_water_and_boot_base() {
        let tmp = tempfile::TempDir::new().unwrap();
        setup(&tmp);
        let config = crate::config::with_config(|c| Ok(c.clone())).unwrap();
        let pro = grant(&config, 11, Some(2), b"pro");
        install(&config, &pro, b"pro");
        accept(&config, &pro);
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            2
        );
        let mut expired = grant(&config, 13, Some(2), b"pro");
        expired.payload.selection.offline_valid_until = Some("1".into());
        let expired = resign(expired);
        let journal =
            SelectionJournal::new(&config.storage_dir, &expired.descriptor().scope).unwrap();
        assert_eq!(
            journal
                .accept(
                    &expired,
                    &expired.descriptor().scope,
                    config.patch_public_key.as_deref().unwrap(),
                    1
                )
                .unwrap()
                .1,
            Activation::Expired
        );
        assert!(crate::updater::next_boot_patch().unwrap().is_none());
        assert!(crate::native_boot::prepare().unwrap().patch.is_none());
        assert!(journal
            .accept(
                &pro,
                &pro.descriptor().scope,
                config.patch_public_key.as_deref().unwrap(),
                0
            )
            .is_err());
        let mut future = grant(&config, 14, Some(2), b"pro");
        future.payload.selection.not_before = (MAX_TIME - 1).to_string();
        let future = resign(future);
        accept(&config, &future);
        assert!(crate::updater::next_boot_patch().unwrap().is_none());
        assert_eq!(
            journal
                .load(
                    &pro.descriptor().scope,
                    config.patch_public_key.as_deref().unwrap()
                )
                .unwrap()
                .0
                .epoch(),
            14
        );
        crate::testing_reset_config();
    }

    static NATIVE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static NATIVE_MODE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static REENTRY_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    unsafe extern "C" fn native_key(
        key_id: *const libc::c_char,
        aad: *const libc::c_char,
        context: *const libc::c_char,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        NATIVE_CALLS.fetch_add(1, SeqCst);
        let text = unsafe { std::ffi::CStr::from_ptr(context) }
            .to_str()
            .unwrap_or("");
        let Some(value) = serde_json::from_str::<serde_json::Value>(text).ok() else {
            return false;
        };
        if value["version"] != 2
            || value["selection"]["scope"]["runtime_profile"] != "native-aot"
            || value["selection"]["variant_id"] != "pro"
            || unsafe { std::ffi::CStr::from_ptr(key_id) }.to_bytes() != b"native-key"
            || !unsafe { std::ffi::CStr::from_ptr(aad) }
                .to_bytes()
                .starts_with(b"open-aot-patch-delivery-v2\n")
        {
            return false;
        }
        let mode = NATIVE_MODE.load(SeqCst);
        if mode == 3 {
            let id_ok = crate::updater::installation_id().is_ok_and(|id| !id.is_empty());
            let status_ok = crate::native_boot::selection_status_json().is_ok_and(|s| s.is_some());
            let update_ok = crate::updater::update(None)
                .is_ok_and(|s| s == crate::UpdateStatus::UpdateInProgress);
            let source = crate::native_boot::prepare();
            let prepare_ok =
                source.is_ok_and(|source| crate::native_boot::begin(source.id).unwrap_or(false));
            REENTRY_OK.store(id_ok && status_ok && update_ok && prepare_ok, SeqCst);
        }
        if capacity != 32 {
            return false;
        }
        unsafe {
            std::ptr::write_bytes(output, if mode == 2 { 99 } else { 37 }, 32);
            *written = if mode == 1 { 31 } else { 32 };
        }
        true
    }
    unsafe extern "C" fn unused_v1(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u8,
        _: usize,
        _: *mut usize,
    ) -> bool {
        false
    }

    fn native_fixture(
        config: &crate::config::UpdateConfig,
        epoch: u64,
    ) -> (VerifiedSelection, Vec<u8>) {
        native_fixture_with_nonce(config, epoch, [7; 12])
    }
    fn native_fixture_with_nonce(
        config: &crate::config::UpdateConfig,
        epoch: u64,
        nonce: [u8; 12],
    ) -> (VerifiedSelection, Vec<u8>) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let client = crate::updater::installation_id().unwrap();
        let scope = config.selection_scope.as_ref().unwrap().for_client(&client);
        let target = b"native candidate bytes";
        let hash = hex::encode(Sha256::digest(target));
        let mut transport = std::io::Cursor::new(Vec::new());
        patch::make_patch(
            b"original baseline".to_vec(),
            target.to_vec(),
            &mut transport,
        );
        let transport = transport.into_inner();
        let aad = format!("open-aot-patch-delivery-v2\napp_id={}\nrelease_id=1\npatch_number=2\npatch_hash={}\ntransport_hash={}\nplatform={}\narch={}\ndevice_id_hash={}", scope.app_id, hash, hex::encode(Sha256::digest(&transport)), scope.platform, scope.arch, scope.client_id_hash);
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &[37; 32]).unwrap(),
        );
        let mut ciphertext = transport;
        key.seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad.as_bytes()),
            &mut ciphertext,
        )
        .unwrap();
        let metadata = EncryptionMetadata {
            algorithm: "AES-256-GCM".into(),
            kdf: "HMAC-SHA256".into(),
            key_id: "native-key".into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            aad: URL_SAFE_NO_PAD.encode(aad.as_bytes()),
            aad_hash: hex::encode(Sha256::digest(aad.as_bytes())),
            encrypted_hash: hex::encode(Sha256::digest(&ciphertext)),
            device_id_hash: scope.client_id_hash,
            cache_key: "fixture".into(),
        };
        (
            grant_with_encryption(config, epoch, Some(2), target, Some(metadata)),
            ciphertext,
        )
    }
    fn native_config(tmp: &tempfile::TempDir) -> crate::config::UpdateConfig {
        setup(tmp);
        // Exercise portable crypto/cache/source bookkeeping on the host; this
        // does not bypass production NativeOptions platform checks in init.
        crate::config::with_config_mut(|config| {
            let config = config.as_mut().unwrap();
            config.selection_scope.as_mut().unwrap().runtime_profile = "native-aot".into();
            config.selection_baseline = None;
            config.native_options = NativeOptions {
                capability: 2,
                max_image_bytes: 4096,
            };
            config.patch_decryption_key_provider_v2 = Some(native_key);
        });
        crate::config::with_config(|c| Ok(c.clone())).unwrap()
    }
    fn status() -> serde_json::Value {
        serde_json::from_str(
            &crate::native_boot::selection_status_json()
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    fn stage_native_download(
        config: &crate::config::UpdateConfig,
        grant: &VerifiedSelection,
        ciphertext: &[u8],
    ) -> PathBuf {
        let patch = grant.delivery().unwrap().patch();
        let path = config.download_dir.join(patch.number.to_string());
        crate::updater::with_mut_state(|state| {
            state.lifecycle_mut().record_download_started(
                patch.number,
                &patch.download_identity(),
                &patch.hash,
                patch.hash_signature.as_deref(),
            )?;
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, ciphertext)?;
            state
                .lifecycle_mut()
                .record_download_complete(patch.number, ciphertext.len() as u64)
        })
        .unwrap();
        path
    }

    #[test]
    #[serial]
    fn native_v2_provider_binding_exact_key_retry_and_reentrant_source_identity() {
        use std::sync::atomic::Ordering::SeqCst;
        let tmp = tempfile::TempDir::new().unwrap();
        let config = native_config(&tmp);
        let (grant, ciphertext) = native_fixture(&config, 11);
        accept(&config, &grant);
        let patch = grant.delivery().unwrap().patch();
        let client = crate::updater::installation_id().unwrap();
        let path = stage_native_download(&config, &grant, &ciphertext);
        NATIVE_CALLS.store(0, SeqCst);
        for mode in [1, 2] {
            NATIVE_MODE.store(mode, SeqCst);
            let error = crate::updater_lock::with_updater_thread_lock(|_| {
                crate::native_cache::install(&config, &patch, &path)
            })
            .unwrap_err();
            assert!(error.is::<crate::encrypted_patch::KeyResolutionFailed>());
            assert!(matches!(
                crate::updater::load_state(&config)
                    .unwrap()
                    .lifecycle()
                    .read_state(2),
                Some(PatchState::Downloaded { .. })
            ));
            assert_eq!(accepted_grant(&config).unwrap().0.epoch(), 11);
            assert!(path.exists());
            assert_eq!(
                crate::updater::load_state(&config)
                    .unwrap()
                    .lifecycle()
                    .decide_start(
                        2,
                        &patch.download_identity(),
                        &patch.hash,
                        patch.hash_signature.as_deref()
                    ),
                crate::cache::lifecycle::DownloadAction::Complete
            );
        }
        let calls = NATIVE_CALLS.load(SeqCst);
        let mut wrong = patch.clone();
        wrong.download_url.push_str("?altered=1");
        assert!(crate::encrypted_patch::decrypt(&config, &wrong, &client, &path).is_err());
        assert_eq!(NATIVE_CALLS.load(SeqCst), calls);
        NATIVE_MODE.store(3, SeqCst);
        REENTRY_OK.store(false, SeqCst);
        crate::updater_lock::with_updater_thread_lock(|_| {
            crate::native_cache::install(&config, &patch, &path)
        })
        .unwrap();
        assert!(REENTRY_OK.load(SeqCst));
        assert!(crate::native_boot::prepare().unwrap().patch.is_none()); // Reentry froze this process BASE.
        assert_eq!(status()["current"]["epoch"], "11");
        assert!(status()["current"]["patch_number"].is_null());
        assert_eq!(status()["next_boot"]["patch_number"], "2");
        assert_eq!(status()["restart_required"], true);
        assert!(!tmp.path().join("patches/2/dlc.vmcode").exists());
        NATIVE_MODE.store(0, SeqCst);
        crate::native_boot::reset();
        let prepared = crate::native_boot::prepare().unwrap();
        assert_eq!(prepared.patch, Some(2));
        assert_eq!(
            crate::native_boot::acquire_memory(prepared.id)
                .unwrap()
                .bytes(),
            b"native candidate bytes"
        );
        assert!(crate::native_boot::begin(prepared.id).unwrap());
        assert_eq!(status()["restart_required"], false);
        let frozen = crate::native_boot::selection_context_json(prepared.id)
            .unwrap()
            .unwrap();
        let (newer, _) = native_fixture(&config, 12);
        accept(&config, &newer);
        assert_eq!(status()["current"]["epoch"], "11");
        assert_eq!(status()["accepted"]["epoch"], "12");
        assert_eq!(status()["restart_required"], true);
        NATIVE_MODE.store(3, SeqCst);
        REENTRY_OK.store(false, SeqCst);
        let encrypted = crate::native_cache::transport_path(&config, 2);
        crate::updater_lock::with_updater_thread_lock(|_| {
            crate::encrypted_patch::decrypt(
                &config,
                &newer.delivery().unwrap().patch(),
                &client,
                &encrypted,
            )
        })
        .unwrap();
        assert!(REENTRY_OK.load(SeqCst));
        assert_eq!(crate::native_boot::prepare().unwrap().id, prepared.id);
        assert_eq!(
            crate::native_boot::selection_context_json(prepared.id)
                .unwrap()
                .unwrap(),
            frozen
        );
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn provider_registration_is_mutually_exclusive_and_readonly_status_preserves_identity() {
        crate::testing_reset_config();
        assert!(crate::encrypted_patch::set_provider_v2(Some(native_key)));
        assert!(!crate::encrypted_patch::set_provider(Some(unused_v1)));
        assert!(!crate::encrypted_patch::set_provider(None));
        assert!(crate::encrypted_patch::set_provider_v2(None));
        assert!(crate::encrypted_patch::set_provider(Some(unused_v1)));
        assert!(!crate::encrypted_patch::set_provider_v2(Some(native_key)));
        crate::testing_reset_config();
        let tmp = tempfile::TempDir::new().unwrap();
        setup(&tmp);
        assert!(!crate::encrypted_patch::set_provider_v2(Some(native_key)));
        let id = crate::updater::installation_id().unwrap();
        let before = std::fs::read(tmp.path().join("state.json")).unwrap();
        let snapshot = status();
        assert_eq!(snapshot["current"]["epoch"], "0");
        assert_eq!(snapshot["accepted"]["epoch"], "0");
        assert_eq!(snapshot["restart_required"], false);
        assert_eq!(crate::updater::installation_id().unwrap(), id);
        assert_eq!(
            std::fs::read(tmp.path().join("state.json")).unwrap(),
            before
        );
        std::fs::write(tmp.path().join("state.json"), b"corrupt identity state").unwrap();
        assert!(crate::updater::installation_id().is_err());
        assert!(crate::native_boot::selection_status_json().is_err());
        assert_eq!(
            std::fs::read(tmp.path().join("state.json")).unwrap(),
            b"corrupt identity state"
        );
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn native_delivery_rotation_is_a_cache_miss_without_content_quarantine() {
        use std::sync::atomic::Ordering::SeqCst;
        let tmp = tempfile::TempDir::new().unwrap();
        let config = native_config(&tmp);
        NATIVE_MODE.store(0, SeqCst);
        let (initial, ciphertext) = native_fixture(&config, 11);
        accept(&config, &initial);
        let path = stage_native_download(&config, &initial, &ciphertext);
        crate::updater_lock::with_updater_thread_lock(|_| {
            crate::native_cache::install(&config, &initial.delivery().unwrap().patch(), &path)
        })
        .unwrap();
        let (refreshed, rotated) = native_fixture_with_nonce(&config, 11, [8; 12]);
        assert_eq!(refreshed.digest(), initial.digest());
        assert_ne!(rotated, ciphertext);
        accept(&config, &refreshed);
        let state = crate::updater::load_state(&config).unwrap();
        assert!(state.next_boot_patch().is_none());
        assert!(state.lifecycle().read_state(2).is_none());
        let patch = refreshed.delivery().unwrap().patch();
        assert_eq!(
            state.lifecycle().decide_start(
                2,
                &patch.download_identity(),
                &patch.hash,
                patch.hash_signature.as_deref()
            ),
            crate::cache::lifecycle::DownloadAction::Fresh
        );
        let path = stage_native_download(&config, &refreshed, &rotated);
        crate::updater_lock::with_updater_thread_lock(|_| {
            crate::native_cache::install(&config, &patch, &path)
        })
        .unwrap();
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            2
        );
        assert!(matches!(
            crate::updater::load_state(&config)
                .unwrap()
                .lifecycle()
                .read_state(2),
            Some(PatchState::InstalledEncryptedTransportV1 { .. })
        ));
        assert_eq!(accepted_grant(&config).unwrap().0.epoch(), 11);
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn native_expiry_after_download_keeps_candidate_and_renewal_recovers() {
        use std::sync::atomic::Ordering::SeqCst;
        let tmp = tempfile::TempDir::new().unwrap();
        let config = native_config(&tmp);
        let (mut grant, ciphertext) = native_fixture(&config, 11);
        grant.payload.selection.offline_valid_until = Some("1".into());
        let grant = resign(grant);
        accept(&config, &grant);
        let path = stage_native_download(&config, &grant, &ciphertext);
        let journal =
            SelectionJournal::new(&config.storage_dir, &grant.descriptor().scope).unwrap();
        journal
            .accept(
                &grant,
                &grant.descriptor().scope,
                config.patch_public_key.as_deref().unwrap(),
                1,
            )
            .unwrap();
        NATIVE_CALLS.store(0, SeqCst);
        NATIVE_MODE.store(0, SeqCst);
        let error = crate::updater_lock::with_updater_thread_lock(|_| {
            crate::native_cache::install(&config, &grant.delivery().unwrap().patch(), &path)
        })
        .unwrap_err();
        assert!(error.is::<AuthorizationUnavailable>(), "{error:#}");
        assert_eq!(NATIVE_CALLS.load(SeqCst), 0);
        assert!(path.exists());
        assert!(matches!(
            crate::updater::load_state(&config)
                .unwrap()
                .lifecycle()
                .read_state(2),
            Some(PatchState::Downloaded { .. })
        ));
        assert_eq!(status()["next_boot"]["reason"], "expired");
        let (renewed, _) = native_fixture(&config, 12);
        accept(&config, &renewed);
        crate::updater_lock::with_updater_thread_lock(|_| {
            crate::native_cache::install(&config, &renewed.delivery().unwrap().patch(), &path)
        })
        .unwrap();
        assert_eq!(NATIVE_CALLS.load(SeqCst), 1);
        assert_eq!(
            crate::updater::next_boot_patch().unwrap().unwrap().number,
            2
        );
        assert_eq!(accepted_grant(&config).unwrap().0.epoch(), 12);
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn native_init_uses_original_aot_stream_and_supported_source_policy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut scope = setup(&tmp);
        crate::testing_reset_config();
        // Dedicated interpreter baseline callbacks still return different bytes.
        // Native measurement must use the installed original AOT/APK resolver.
        crate::test_utils::write_fake_apk(
            tmp.path().join("base.apk").to_str().unwrap(),
            b"original native image",
        );
        scope.runtime_profile = "native-aot".into();
        scope.base_artifact_hash = hex::encode(Sha256::digest(b"original native image"));
        assert!(crate::encrypted_patch::set_provider_v2(Some(native_key)));
        let app = crate::AppConfig {
            app_storage_dir: tmp.path().to_str().unwrap().into(),
            code_cache_dir: tmp.path().to_str().unwrap().into(),
            release_version: "1".into(),
            original_libapp_paths: vec![tmp
                .path()
                .join("lib/arch/libapp.so")
                .to_str()
                .unwrap()
                .into()],
        };
        let yaml = format!(
            "app_id: {}\npatch_public_key: {}\npatch_response_verification: required",
            scope.app_id,
            crate::test_utils::response_test_public_key()
        );
        let options = NativeOptions {
            capability: if cfg!(target_os = "windows") { 2 } else { 1 },
            max_image_bytes: 4096,
        };
        let result = crate::native_boot::initialize_with_scope(
            app,
            crate::c_api::engine::FileCallbacks::new(),
            yaml,
            options,
            Some(scope),
            Some(baseline_callbacks()),
        );
        if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows"
        )) {
            result.unwrap();
            crate::config::with_config(|config| {
                assert!(config.selection_baseline.is_none());
                assert!(config.patch_decryption_key_provider_v2.is_some());
                Ok(())
            })
            .unwrap();
        } else {
            assert!(result.is_err());
            assert!(crate::config::with_config(|_| Ok(())).is_err());
        }
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn status_snapshot_is_atomic_during_assignment_and_keeps_running_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        setup(&tmp);
        let config = crate::config::with_config(|c| Ok(c.clone())).unwrap();
        let pro = grant(&config, 11, Some(2), b"pro");
        install(&config, &pro, b"pro");
        accept(&config, &pro);
        let prepared = crate::native_boot::prepare().unwrap();
        assert!(crate::native_boot::begin(prepared.id).unwrap());
        let grants: Vec<_> = (12..32)
            .map(|epoch| {
                grant(
                    &config,
                    epoch,
                    if epoch % 2 == 0 { None } else { Some(2) },
                    b"pro",
                )
            })
            .collect();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writer_barrier = barrier.clone();
        let config_copy = config.clone();
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for grant in grants {
                accept(&config_copy, &grant);
            }
        });
        barrier.wait();
        for _ in 0..60 {
            let snapshot = status();
            let epoch: u64 = snapshot["accepted"]["epoch"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(snapshot["current"]["epoch"], "11");
            assert_eq!(snapshot["current"]["patch_number"], "2");
            assert_eq!(
                snapshot["next_boot"]["patch_number"].as_str(),
                if epoch % 2 == 0 { None } else { Some("2") }
            );
            assert_eq!(snapshot["restart_required"], epoch != 11);
        }
        writer.join().unwrap();
        assert_eq!(status()["accepted"]["epoch"], "31");
        crate::testing_reset_config();
    }

    #[test]
    #[serial]
    fn wrong_compiled_baseline_refuses_init_and_cannot_downgrade_to_v1() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut scope = setup(&tmp);
        crate::testing_reset_config();
        scope.base_artifact_hash = "0".repeat(64);
        let app = crate::AppConfig {
            app_storage_dir: tmp.path().to_str().unwrap().into(),
            code_cache_dir: tmp.path().to_str().unwrap().into(),
            release_version: "1".into(),
            original_libapp_paths: vec![tmp
                .path()
                .join("lib/arch/libapp.so")
                .to_str()
                .unwrap()
                .into()],
        };
        let yaml = format!(
            "app_id: {}\npatch_public_key: {}\npatch_response_verification: required",
            scope.app_id,
            crate::test_utils::response_test_public_key()
        );
        assert!(crate::native_boot::initialize_with_scope(
            app.clone(),
            crate::c_api::engine::FileCallbacks::new(),
            yaml.clone(),
            NativeOptions::default(),
            Some(scope),
            Some(baseline_callbacks())
        )
        .is_err());
        assert!(crate::config::with_config(|_| Ok(())).is_err());
        assert!(crate::native_boot::initialize(
            app,
            crate::c_api::engine::FileCallbacks::new(),
            yaml,
            NativeOptions::default()
        )
        .is_err());
        crate::testing_reset_config();
    }
}
