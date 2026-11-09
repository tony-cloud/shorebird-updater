//! Startup integrity gate for hardened releases (hardening stage P3,
//! contract `docs/HARDENING_CONTRACTS.md` §9; release root of trust from
//! stage P4, contract v2, §10; hardened-diversified from stage P5, contract
//! v3, §11 in the workspace).
//!
//! A hardened build appends one line to the bundled shorebird.yaml:
//!
//! ```text
//! shorebird_build_manifest: v2.<b64url(manifest JSON)>.<b64url(Ed25519 signature)>.<b64url(release-trust JSON)>
//! ```
//!
//! A hardened-diversified build writes the same line with the `v3.` prefix;
//! its manifest also binds `diversification_profile_id`. The signature
//! domain is unchanged: the token prefix and the manifest's contract version
//! separate the versions, and each gate accepts exactly one of them.
//!
//! The manifest is signed by a `build-manifest` key that the release-trust
//! bundle delegates under the release root compiled into the engine (GN
//! `shorebird_release_root`), never by a key the package alone vouches for.
//! The manifest binds the digest of the delegations it was signed under.
//! It binds the compiled policy (profile, toolchain, development exceptions),
//! the SHA-256 of every shorebird.yaml byte before its own line, the
//! measurement of the engine module for each platform/architecture, and
//! optional platform package identities.
//!
//! [`check`] runs in hardened builds on every initialization path, before
//! any configuration is published. It verifies the exact bytes the engine
//! handed over and that the updater parses (read once: the digest and the
//! parse come from the same string), measures the module actually loaded,
//! and asks the platform for the package identity. A failure publishes no
//! configuration, so no key provider is called and no patch is activated;
//! the engine boots the bundled base and no data is deleted. Legacy builds
//! never call it.
//!
//! These are in-process checks. On a compromised OS, or in a process whose
//! code was modified to skip them, they detect nothing; see the contract for
//! what is detection and what is prevention.
use crate::module_measurement::{measure_running_module, MeasureError, RunningModule};
use crate::release_trust;
use crate::security::CompiledPolicy;
use crate::security_inputs::is_sha256_id;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The YAML key carrying the signed manifest; always the last line.
pub const MANIFEST_KEY: &str = "shorebird_build_manifest";
/// Token version prefix (contract v2, hardened).
pub const TOKEN_PREFIX: &str = "v2.";
/// Token version prefix (contract v3, hardened-diversified).
pub const TOKEN_PREFIX_V3: &str = "v3.";
/// Ed25519 signs this prefix followed by the lowercase hex SHA-256 of the
/// manifest JSON bytes.
pub const SIGNATURE_DOMAIN: &str = "open-shorebird.build-manifest-signature.v2:";
pub const MANIFEST_SCHEMA: &str = "open-shorebird.build-manifest";
const MAX_MANIFEST_BYTES: usize = 16 * 1024;

/// What the YAML parser records about the manifest line, computed from the
/// same string it parses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestSource {
    /// SHA-256 of the YAML bytes before the manifest line (all bytes when
    /// there is no manifest line).
    pub config_sha256: [u8; 32],
    pub token: Option<String>,
    /// Why the manifest line is malformed, if it is.
    pub problem: Option<&'static str>,
}

/// Splits `yaml` into the signed configuration bytes and the manifest token.
/// The manifest line must be the final line, appear once, start at a line
/// start, and the text must contain no carriage return (writers emit `\n`
/// only, and every engine embedder passes those bytes through unchanged).
pub fn split_source(yaml: &str) -> ManifestSource {
    let mut source = ManifestSource::default();
    let occurrences: Vec<usize> = yaml.match_indices(MANIFEST_KEY).map(|(i, _)| i).collect();
    let Some(&at) = occurrences.first() else {
        source.config_sha256 = Sha256::digest(yaml.as_bytes()).into();
        if yaml.contains('\r') {
            source.problem = Some("carriage return in shorebird.yaml");
        }
        return source;
    };
    let prefix = &yaml[..at];
    source.config_sha256 = Sha256::digest(prefix.as_bytes()).into();
    let line = &yaml[at..];
    let line = line.strip_suffix('\n').unwrap_or(line);
    source.problem = if occurrences.len() > 1 {
        Some("manifest key repeated")
    } else if yaml.contains('\r') {
        Some("carriage return in shorebird.yaml")
    } else if at != 0 && !prefix.ends_with('\n') {
        Some("manifest key is not at a line start")
    } else if line.contains('\n') {
        Some("manifest line is not the last line")
    } else {
        match line
            .strip_prefix(MANIFEST_KEY)
            .and_then(|r| r.strip_prefix(": "))
        {
            Some(token)
                if !token.is_empty()
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
            {
                source.token = Some(token.to_string());
                None
            }
            _ => Some("malformed manifest line"),
        }
    };
    source
}

/// Stable, typed reasons. `code()` values are part of the contract and are
/// what the engine logs and `shorebird_integrity_status` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityFailure {
    ManifestMissing,
    ManifestMalformed(String),
    UntrustedSigner,
    /// The signer is listed as revoked by the delegations.
    SignerRevoked,
    /// The signer is a root key or a key delegated for another role.
    SignerRole,
    BadSignature,
    /// No release root is compiled into this hardened updater.
    TrustRootMissing,
    /// The release-trust bundle (or the compiled pin) cannot be parsed.
    TrustMalformed(String),
    /// A root rotation or the delegations are not signed by the root.
    TrustUnverified(&'static str),
    /// The delegations are older than the compiled minimum version.
    TrustRollback,
    PolicyMismatch(&'static str),
    ConfigDigestMismatch,
    ModuleUnbound,
    ModuleUnmeasurable(String),
    ModuleMismatch,
    PackageIdentityUnavailable(String),
    PackageIdentityMismatch,
    PackageIdentityUnsupported,
}

impl IntegrityFailure {
    pub fn code(&self) -> &'static str {
        match self {
            IntegrityFailure::ManifestMissing => "manifest_missing",
            IntegrityFailure::ManifestMalformed(_) => "manifest_malformed",
            IntegrityFailure::UntrustedSigner => "manifest_untrusted_signer",
            IntegrityFailure::SignerRevoked => "manifest_signer_revoked",
            IntegrityFailure::SignerRole => "manifest_signer_role",
            IntegrityFailure::BadSignature => "manifest_bad_signature",
            IntegrityFailure::TrustRootMissing => "trust_root_missing",
            IntegrityFailure::TrustMalformed(_) => "trust_malformed",
            IntegrityFailure::TrustUnverified(_) => "trust_unverified",
            IntegrityFailure::TrustRollback => "trust_rollback",
            IntegrityFailure::PolicyMismatch(_) => "manifest_policy_mismatch",
            IntegrityFailure::ConfigDigestMismatch => "config_digest_mismatch",
            IntegrityFailure::ModuleUnbound => "module_unbound",
            IntegrityFailure::ModuleUnmeasurable(_) => "module_unmeasurable",
            IntegrityFailure::ModuleMismatch => "module_mismatch",
            IntegrityFailure::PackageIdentityUnavailable(_) => "package_identity_unavailable",
            IntegrityFailure::PackageIdentityMismatch => "package_identity_mismatch",
            IntegrityFailure::PackageIdentityUnsupported => "package_identity_unsupported",
        }
    }
}

impl std::fmt::Display for IntegrityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Details never include keys, signatures, URLs or digests.
        match self {
            IntegrityFailure::ManifestMalformed(why)
            | IntegrityFailure::TrustMalformed(why)
            | IntegrityFailure::ModuleUnmeasurable(why)
            | IntegrityFailure::PackageIdentityUnavailable(why) => {
                write!(f, "integrity check failed: {} ({why})", self.code())
            }
            IntegrityFailure::PolicyMismatch(field) | IntegrityFailure::TrustUnverified(field) => {
                write!(f, "integrity check failed: {} ({field})", self.code())
            }
            _ => write!(f, "integrity check failed: {}", self.code()),
        }
    }
}

impl std::error::Error for IntegrityFailure {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    pub platform: String,
    pub arch: String,
    pub measurement: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    /// Lowercase hex SHA-256 of the DER signer certificate(s) the installed
    /// APK may be signed with (several allow key rotation or Play signing).
    pub android_signing_cert_sha256: Vec<String>,
    /// Apple team identifiers the running macOS app may be signed by.
    pub apple_team_ids: Vec<String>,
    /// Lowercase hex SHA-256 of the DER leaf certificate(s) the loaded
    /// Windows engine module's Authenticode signer may have (contract §12,
    /// P6). Optional: absent means no Windows identity, and a manifest
    /// without it is byte-identical to the pre-P6 form. Present, it must not
    /// be empty.
    #[serde(default, deserialize_with = "present_list")]
    pub windows_signing_cert_sha256: Option<Vec<String>>,
}

impl PackageIdentity {
    /// The declared Windows signer digests (empty when none is declared).
    pub fn windows_signers(&self) -> &[String] {
        self.windows_signing_cert_sha256.as_deref().unwrap_or(&[])
    }
}

fn present_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}

/// Build manifest, contract v2 (or v3: v2 plus `diversification_profile_id`).
/// Every field is required; unknown fields and duplicate fields are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema: String,
    pub contract_version: u32,
    pub security_profile: String,
    pub toolchain_id: String,
    pub development_exceptions: bool,
    pub signer_key_id: String,
    /// Lowercase hex SHA-256 of the delegations payload bytes the signer was
    /// delegated by.
    pub delegations_sha256: String,
    pub config_sha256: String,
    pub modules: Vec<ModuleEntry>,
    pub package_identity: PackageIdentity,
    /// Contract v3 only. `None` when the key is absent; a present key (even
    /// `null`) is `Some`, so a v2 manifest cannot carry it at all.
    #[serde(default, deserialize_with = "present")]
    pub diversification_profile_id: Option<serde_json::Value>,
}

fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl BuildManifest {
    /// The declared diversification profile ID (shape checked by
    /// [`verify_token`]).
    pub fn diversification_profile_id(&self) -> Option<&str> {
        self.diversification_profile_id
            .as_ref()
            .and_then(|value| value.as_str())
    }
}

/// The one token prefix a policy accepts: `v3.` for hardened-diversified,
/// `v2.` otherwise.
pub fn token_prefix(policy: &CompiledPolicy) -> &'static str {
    if policy.profile == crate::security::SecurityProfile::HardenedDiversified {
        TOKEN_PREFIX_V3
    } else {
        TOKEN_PREFIX
    }
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const PLATFORMS: [&str; 5] = ["android", "ios", "linux", "macos", "windows"];
const ARCHES: [&str; 4] = ["aarch64", "arm", "x86", "x86_64"];

/// Decodes and authenticates a manifest token: the release-trust bundle
/// against the compiled release root, then the manifest signature against
/// the key the bundle delegates for the `build-manifest` role. The signature
/// is checked before any other manifest field is trusted.
pub fn verify_token(
    policy: &CompiledPolicy,
    token: &str,
) -> Result<BuildManifest, IntegrityFailure> {
    let malformed = |why: &str| IntegrityFailure::ManifestMalformed(why.to_string());
    // A hardened gate refuses a v3 token and a diversified gate a v2 one.
    let v3 = token_prefix(policy) == TOKEN_PREFIX_V3;
    let body = token
        .strip_prefix(token_prefix(policy))
        .ok_or_else(|| malformed("unknown token version"))?;
    let mut parts = body.split('.');
    let (Some(manifest_b64), Some(signature_b64), Some(trust_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("token needs manifest, signature and trust"));
    };
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let manifest_bytes = b64
        .decode(manifest_b64)
        .map_err(|_| malformed("manifest is not base64url"))?;
    let signature = b64
        .decode(signature_b64)
        .map_err(|_| malformed("signature is not base64url"))?;
    let trust_bytes = b64
        .decode(trust_b64)
        .map_err(|_| malformed("trust is not base64url"))?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES || signature.len() != 64 {
        return Err(malformed("manifest or signature size"));
    }
    let pinned = policy
        .release_root
        .as_deref()
        .ok_or(IntegrityFailure::TrustRootMissing)?;
    let pinned = base64::engine::general_purpose::STANDARD
        .decode(pinned)
        .map_err(|_| IntegrityFailure::TrustMalformed("compiled release root".into()))?;
    let trust =
        release_trust::verify_bundle(&pinned, policy.min_delegations_version, &trust_bytes)?;
    // Only the signer selector is read before verification.
    #[derive(Deserialize)]
    struct Selector {
        signer_key_id: String,
    }
    let selector: Selector =
        serde_json::from_slice(&manifest_bytes).map_err(|_| malformed("manifest JSON"))?;
    let key = trust.role_key(release_trust::Role::BuildManifest, &selector.signer_key_id)?;
    let message = format!(
        "{SIGNATURE_DOMAIN}{}",
        hex::encode(Sha256::digest(&manifest_bytes))
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message.as_bytes(), &signature)
        .map_err(|_| IntegrityFailure::BadSignature)?;
    let manifest: BuildManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| malformed("manifest fields"))?;
    if manifest.signer_key_id != selector.signer_key_id {
        return Err(malformed("signer_key_id"));
    }
    validate_shape(&manifest, v3)?;
    // The manifest names the delegations it was signed under; another
    // (older or newer) delegations document is not a substitute.
    if manifest.delegations_sha256 != hex::encode(trust.delegations_sha256) {
        return Err(IntegrityFailure::PolicyMismatch("delegations_sha256"));
    }
    Ok(manifest)
}

fn validate_shape(manifest: &BuildManifest, v3: bool) -> Result<(), IntegrityFailure> {
    let malformed = |why: &str| Err(IntegrityFailure::ManifestMalformed(why.to_string()));
    // v3 requires a `sha256:` profile ID; v2 must not mention the key.
    match (&manifest.diversification_profile_id, v3) {
        (None, false) => {}
        (Some(serde_json::Value::String(id)), true) if is_sha256_id(id) => {}
        _ => return malformed("diversification_profile_id"),
    }
    if !is_lower_hex(&manifest.config_sha256, 64) {
        return malformed("config_sha256");
    }
    if !is_lower_hex(&manifest.delegations_sha256, 64) {
        return malformed("delegations_sha256");
    }
    let mut seen = Vec::new();
    for module in &manifest.modules {
        if !PLATFORMS.contains(&module.platform.as_str())
            || !ARCHES.contains(&module.arch.as_str())
            || !is_sha256_id(&module.measurement)
        {
            return malformed("module entry");
        }
        let key = (module.platform.as_str(), module.arch.as_str());
        if seen.contains(&key) {
            return malformed("duplicate module entry");
        }
        seen.push(key);
    }
    let identity = &manifest.package_identity;
    if !identity
        .android_signing_cert_sha256
        .iter()
        .all(|d| is_lower_hex(d, 64))
        || !identity.apple_team_ids.iter().all(|t| {
            t.len() == 10
                && t.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
        || identity
            .windows_signing_cert_sha256
            .as_ref()
            .is_some_and(|list| list.is_empty() || !list.iter().all(|d| is_lower_hex(d, 64)))
    {
        return malformed("package identity");
    }
    Ok(())
}

/// What the platform reports about the running installation.
pub trait Observer {
    fn running_module(&self) -> Result<RunningModule, MeasureError>;
    /// Signer certificate digests of the installed Android package.
    fn android_signers(&self) -> Result<Vec<String>, String>;
    /// Team identifier of the running macOS process, after checking its
    /// code signature.
    fn apple_team_id(&self) -> Result<Option<String>, String>;
    /// Leaf certificate digests of the Authenticode signer of the loaded
    /// Windows engine module `module` (whose bytes must still measure to
    /// its measurement).
    fn windows_signers(&self, module: &RunningModule) -> Result<Vec<String>, String>;
}

/// The real platform observer.
pub struct PlatformObserver<'a> {
    /// On Android, the installed APK directory (`UpdateConfig::libapp_path`).
    pub install_dir: &'a Path,
}

impl Observer for PlatformObserver<'_> {
    fn running_module(&self) -> Result<RunningModule, MeasureError> {
        // The loaded module does not change during the process; measure once.
        static MEASURED: std::sync::OnceLock<Result<RunningModule, MeasureError>> =
            std::sync::OnceLock::new();
        MEASURED.get_or_init(measure_running_module).clone()
    }

    fn android_signers(&self) -> Result<Vec<String>, String> {
        // Read once; the digest comes from the bytes read.
        let apk = std::fs::read(self.install_dir.join("base.apk")).map_err(|e| e.to_string())?;
        crate::package_identity::apk_signer_certificate_digests(&apk)
    }

    fn apple_team_id(&self) -> Result<Option<String>, String> {
        #[cfg(target_os = "macos")]
        return crate::package_identity::macos_running_team_id();
        #[cfg(not(target_os = "macos"))]
        Err("unsupported".to_string())
    }

    fn windows_signers(&self, module: &RunningModule) -> Result<Vec<String>, String> {
        #[cfg(target_os = "windows")]
        return crate::package_identity::windows_module_signers(
            Path::new(&module.path),
            &module.measurement,
        );
        #[cfg(not(target_os = "windows"))]
        {
            let _ = module;
            Err("unsupported".to_string())
        }
    }
}

/// The gate. `platform`/`arch` are the updater's `current_platform()` and
/// `current_arch()`; tests pass others to exercise each platform's rules.
pub fn evaluate(
    policy: &CompiledPolicy,
    source: &ManifestSource,
    platform: &str,
    arch: &str,
    observer: &dyn Observer,
) -> Result<(), IntegrityFailure> {
    if let Some(problem) = source.problem {
        return Err(IntegrityFailure::ManifestMalformed(problem.to_string()));
    }
    let token = source
        .token
        .as_deref()
        .ok_or(IntegrityFailure::ManifestMissing)?;
    let manifest = verify_token(policy, token)?;

    if manifest.schema != MANIFEST_SCHEMA {
        return Err(IntegrityFailure::PolicyMismatch("schema"));
    }
    if manifest.contract_version != policy.contract_version() {
        return Err(IntegrityFailure::PolicyMismatch("contract_version"));
    }
    if manifest.security_profile != policy.profile.as_str() {
        return Err(IntegrityFailure::PolicyMismatch("security_profile"));
    }
    if manifest.diversification_profile_id() != policy.diversification_profile_id.as_deref() {
        return Err(IntegrityFailure::PolicyMismatch(
            "diversification_profile_id",
        ));
    }
    if Some(&manifest.toolchain_id) != policy.toolchain_id.as_ref() {
        return Err(IntegrityFailure::PolicyMismatch("toolchain_id"));
    }
    if manifest.development_exceptions != policy.development_exceptions {
        return Err(IntegrityFailure::PolicyMismatch("development_exceptions"));
    }
    if manifest.config_sha256 != hex::encode(source.config_sha256) {
        return Err(IntegrityFailure::ConfigDigestMismatch);
    }

    // Every platform binds its engine module. Android has done so since P6
    // (contract §12): flutter_tools measures the `libflutter.so` that Gradle
    // resolves from Maven and packages.
    let entry = manifest
        .modules
        .iter()
        .find(|m| m.platform == platform && m.arch == arch)
        .ok_or(IntegrityFailure::ModuleUnbound)?;
    let running = observer
        .running_module()
        .map_err(|e| IntegrityFailure::ModuleUnmeasurable(e.to_string()))?;
    if running.measurement != entry.measurement {
        return Err(IntegrityFailure::ModuleMismatch);
    }

    let identity = &manifest.package_identity;
    match platform {
        "android" if !identity.android_signing_cert_sha256.is_empty() => {
            let signers = observer
                .android_signers()
                .map_err(IntegrityFailure::PackageIdentityUnavailable)?;
            if signers.is_empty()
                || !signers
                    .iter()
                    .all(|s| identity.android_signing_cert_sha256.contains(s))
            {
                return Err(IntegrityFailure::PackageIdentityMismatch);
            }
        }
        "macos" if !identity.apple_team_ids.is_empty() => {
            match observer
                .apple_team_id()
                .map_err(IntegrityFailure::PackageIdentityUnavailable)?
            {
                Some(team) if identity.apple_team_ids.contains(&team) => {}
                _ => return Err(IntegrityFailure::PackageIdentityMismatch),
            }
        }
        "windows" if !identity.windows_signers().is_empty() => {
            let signers = observer
                .windows_signers(&running)
                .map_err(IntegrityFailure::PackageIdentityUnavailable)?;
            if signers.is_empty()
                || !signers
                    .iter()
                    .all(|s| identity.windows_signers().contains(s))
            {
                return Err(IntegrityFailure::PackageIdentityMismatch);
            }
        }
        // A declared identity that this platform cannot verify fails closed.
        "ios" if !identity.apple_team_ids.is_empty() => {
            return Err(IntegrityFailure::PackageIdentityUnsupported)
        }
        _ => {}
    }
    Ok(())
}

static STATUS: std::sync::Mutex<&'static str> = std::sync::Mutex::new("not_checked");

/// The last gate result in this process: `not_checked` (legacy, or before
/// initialization), `ok`, or an [`IntegrityFailure::code`].
pub fn status() -> &'static str {
    *STATUS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs the gate for a hardened policy and records the typed result.
/// Legacy policies return immediately and leave the status `not_checked`.
pub fn check(
    policy: &CompiledPolicy,
    source: &ManifestSource,
    install_dir: &Path,
) -> Result<(), IntegrityFailure> {
    if !policy.is_hardened() {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let result = evaluate(
        policy,
        source,
        crate::config::current_platform(),
        crate::config::current_arch(),
        &PlatformObserver { install_dir },
    );
    // Startup cost of the gate (P6 measurement): a monotonic duration, never
    // a wall-clock reading, logged in a stable form the device runbooks parse.
    let micros = started.elapsed().as_micros();
    *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = match &result {
        Ok(()) => "ok",
        Err(failure) => failure.code(),
    };
    match &result {
        Ok(()) => shorebird_info!("Integrity check passed ({} us)", micros),
        Err(failure) => shorebird_error!(
            "{} ({} us). Patches and protected keys are disabled; the bundled \
             release runs. Reinstall the app from its original source.",
            failure,
            micros
        ),
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::module_measurement::RunningModule;
    use crate::release_trust::tests as trust;
    use crate::security::tests::{
        diversified, diversified_yaml_text, hardened, hardened_yaml_text, PROFILE_ID, TOOLCHAIN,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// The delegated build-manifest key of the default test trust.
    pub const SEED: [u8; 32] = trust::MANIFEST_SEED;
    const OTHER_SEED: [u8; 32] = trust::STRANGER_SEED;

    pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec()
    }

    /// The hardened test policy with the test release root compiled in.
    pub fn hardened_with_key() -> CompiledPolicy {
        policy_with_root(&trust::default_root(), 1)
    }

    pub fn policy_with_root(root_payload: &str, min_delegations_version: u64) -> CompiledPolicy {
        CompiledPolicy {
            release_root: Some(
                base64::engine::general_purpose::STANDARD.encode(root_payload.as_bytes()),
            ),
            min_delegations_version,
            ..hardened()
        }
    }

    pub fn manifest_json(config: &str, modules: &str, identity: &str) -> String {
        manifest_json_for(
            &SEED,
            &trust::default_delegations(),
            config,
            modules,
            identity,
        )
    }

    /// A manifest naming `signer` and the delegations payload it signs under.
    pub fn manifest_json_for(
        signer: &[u8; 32],
        delegations: &str,
        config: &str,
        modules: &str,
        identity: &str,
    ) -> String {
        format!(
            "{{\"schema\":\"{MANIFEST_SCHEMA}\",\"contract_version\":2,\
             \"security_profile\":\"hardened\",\"toolchain_id\":\"{TOOLCHAIN}\",\
             \"development_exceptions\":false,\"signer_key_id\":\"{}\",\
             \"delegations_sha256\":\"{}\",\
             \"config_sha256\":\"{}\",\"modules\":[{modules}],\"package_identity\":{identity}}}",
            crate::release_trust::key_id(&public_key(signer)),
            hex::encode(Sha256::digest(delegations.as_bytes())),
            hex::encode(Sha256::digest(config.as_bytes())),
        )
    }

    /// A v2 token carrying the default test trust bundle.
    pub fn token(seed: &[u8; 32], manifest: &str) -> String {
        token_with_trust(seed, manifest, &trust::default_bundle())
    }

    pub fn token_with_trust(seed: &[u8; 32], manifest: &str, bundle: &str) -> String {
        token_with_prefix(TOKEN_PREFIX, seed, manifest, bundle)
    }

    pub fn token_with_prefix(
        prefix: &str,
        seed: &[u8; 32],
        manifest: &str,
        bundle: &str,
    ) -> String {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let message = format!(
            "{SIGNATURE_DOMAIN}{}",
            hex::encode(Sha256::digest(manifest.as_bytes()))
        );
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{prefix}{}.{}.{}",
            b64.encode(manifest),
            b64.encode(pair.sign(message.as_bytes())),
            b64.encode(bundle)
        )
    }

    pub fn module_entry(platform: &str, arch: &str, measurement: &str) -> String {
        format!(
            "{{\"platform\":\"{platform}\",\"arch\":\"{arch}\",\"measurement\":\"{measurement}\"}}"
        )
    }

    pub const NO_IDENTITY: &str = "{\"android_signing_cert_sha256\":[],\"apple_team_ids\":[]}";

    /// A YAML exactly as a hardened build writes it, bound to the module
    /// this test process actually runs from.
    pub fn signed_yaml(config: &str) -> String {
        let measurement = PlatformObserver {
            install_dir: Path::new("."),
        }
        .running_module()
        .unwrap()
        .measurement;
        let modules = module_entry(
            crate::config::current_platform(),
            crate::config::current_arch(),
            &measurement,
        );
        let config = format!("{config}\n");
        let manifest = manifest_json(&config, &modules, NO_IDENTITY);
        format!("{config}{MANIFEST_KEY}: {}\n", token(&SEED, &manifest))
    }

    pub fn signed_hardened_yaml() -> String {
        signed_yaml(&hardened_yaml_text())
    }

    /// The hardened-diversified test policy with the test release root.
    pub fn diversified_with_key() -> CompiledPolicy {
        CompiledPolicy {
            release_root: hardened_with_key().release_root,
            ..diversified()
        }
    }

    /// A hardened manifest turned into the contract v3 manifest a
    /// diversified build signs (`id` is the declared profile ID).
    pub fn v3_manifest(manifest: &str, id: &str) -> String {
        manifest
            .replacen("\"contract_version\":2", "\"contract_version\":3", 1)
            .replacen(
                "\"security_profile\":\"hardened\"",
                "\"security_profile\":\"hardened-diversified\"",
                1,
            )
            .replacen(
                "\"development_exceptions\":false,",
                &format!(
                    "\"development_exceptions\":false,\"diversification_profile_id\":\"{id}\","
                ),
                1,
            )
    }

    pub fn v3_token(seed: &[u8; 32], manifest: &str) -> String {
        token_with_prefix(TOKEN_PREFIX_V3, seed, manifest, &trust::default_bundle())
    }

    /// A diversified YAML as the build writes it, bound to this process's
    /// module.
    pub fn signed_diversified_yaml(config: &str) -> String {
        let signed = signed_yaml(config);
        let (head, token) = signed.rsplit_once(&format!("{MANIFEST_KEY}: ")).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let manifest = b64
            .decode(token.trim_end().split('.').nth(1).unwrap())
            .unwrap();
        let manifest = v3_manifest(std::str::from_utf8(&manifest).unwrap(), PROFILE_ID);
        format!("{head}{MANIFEST_KEY}: {}\n", v3_token(&SEED, &manifest))
    }

    struct Fake {
        module: Result<RunningModule, MeasureError>,
        signers: Result<Vec<String>, String>,
        team: Result<Option<String>, String>,
        windows: Result<Vec<String>, String>,
    }

    const MEASUREMENT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    impl Fake {
        fn new() -> Self {
            Fake {
                module: Ok(RunningModule {
                    path: "libflutter.so".into(),
                    measurement: MEASUREMENT.into(),
                }),
                signers: Ok(vec!["aa".repeat(32)]),
                team: Ok(Some("ABCDE12345".into())),
                windows: Ok(vec!["dd".repeat(32)]),
            }
        }
    }

    impl Observer for Fake {
        fn running_module(&self) -> Result<RunningModule, MeasureError> {
            self.module.clone()
        }
        fn android_signers(&self) -> Result<Vec<String>, String> {
            self.signers.clone()
        }
        fn apple_team_id(&self) -> Result<Option<String>, String> {
            self.team.clone()
        }
        fn windows_signers(&self, module: &RunningModule) -> Result<Vec<String>, String> {
            assert_eq!(
                module.measurement, MEASUREMENT,
                "signer read for another module"
            );
            self.windows.clone()
        }
    }

    /// (yaml text, its manifest source) for a config bound by a manifest.
    fn build(config: &str, modules: &str, identity: &str, seed: &[u8; 32]) -> String {
        let manifest = manifest_json(config, modules, identity);
        format!("{config}{MANIFEST_KEY}: {}\n", token(seed, &manifest))
    }

    fn run(text: &str, platform: &str, arch: &str, fake: &Fake) -> Result<(), IntegrityFailure> {
        evaluate(
            &hardened_with_key(),
            &split_source(text),
            platform,
            arch,
            fake,
        )
    }

    fn config() -> String {
        format!("{}\n", hardened_yaml_text())
    }

    fn linux_text() -> String {
        build(
            &config(),
            &module_entry("linux", "x86_64", MEASUREMENT),
            NO_IDENTITY,
            &SEED,
        )
    }

    #[test]
    fn accepts_the_build_output() {
        assert_eq!(run(&linux_text(), "linux", "x86_64", &Fake::new()), Ok(()));
        // Java's line reader re-adds the final newline; both forms verify.
        let text = linux_text();
        assert_eq!(
            run(text.trim_end_matches('\n'), "linux", "x86_64", &Fake::new()),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_missing_or_malformed_manifest() {
        let fake = Fake::new();
        assert_eq!(
            run(&config(), "linux", "x86_64", &fake),
            Err(IntegrityFailure::ManifestMissing)
        );
        let text = linux_text();
        for bad in [
            text.replace("\n", "\r\n"),
            format!("{text}{MANIFEST_KEY}: v1.a.b\n"),
            format!("{text}extra: line\n"),
            text.replace(
                &format!("\n{MANIFEST_KEY}: "),
                &format!("\n {MANIFEST_KEY}: "),
            ),
            // A contract v1 (P3) token, and a v2 token without its trust.
            text.replace(
                &format!("{MANIFEST_KEY}: v2."),
                &format!("{MANIFEST_KEY}: v1."),
            ),
            {
                let (head, _) = text.trim_end().rsplit_once('.').unwrap();
                format!("{head}\n")
            },
            text.replace(&format!("{MANIFEST_KEY}: "), &format!("{MANIFEST_KEY}:  ")),
            format!("{}# {MANIFEST_KEY}\n{}", config(), &text[config().len()..]),
        ] {
            assert!(
                matches!(
                    run(&bad, "linux", "x86_64", &fake),
                    Err(IntegrityFailure::ManifestMalformed(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_a_manifest_not_signed_by_a_compiled_key() {
        // Internally consistent repack: config, key and manifest all
        // replaced, re-signed with the repacker's own key.
        let repacked = build(
            &config().replace("AQID", "BAUG"),
            &module_entry("linux", "x86_64", MEASUREMENT),
            NO_IDENTITY,
            &OTHER_SEED,
        );
        // The manifest still names the compiled key ID, but the signature
        // is the repacker's.
        assert_eq!(
            run(&repacked, "linux", "x86_64", &Fake::new()),
            Err(IntegrityFailure::BadSignature)
        );
        // Naming the repacker's own key instead is an untrusted signer.
        let manifest = manifest_json(
            &config(),
            &module_entry("linux", "x86_64", MEASUREMENT),
            NO_IDENTITY,
        )
        .replace(
            &crate::release_trust::key_id(&public_key(&SEED)),
            &crate::release_trust::key_id(&public_key(&OTHER_SEED)),
        );
        let own_signed = format!(
            "{}{MANIFEST_KEY}: {}\n",
            config(),
            token(&OTHER_SEED, &manifest)
        );
        assert_eq!(
            run(&own_signed, "linux", "x86_64", &Fake::new()),
            Err(IntegrityFailure::UntrustedSigner)
        );
        // A hardened updater without a compiled release root trusts nothing.
        assert_eq!(
            evaluate(
                &hardened(),
                &split_source(&linux_text()),
                "linux",
                "x86_64",
                &Fake::new()
            ),
            Err(IntegrityFailure::TrustRootMissing)
        );
        // A legitimately signed manifest with one flipped signature bit.
        let text = linux_text();
        let flipped = {
            let mut bytes = text.into_bytes();
            let at = bytes.len() - 3;
            bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
            String::from_utf8(bytes).unwrap()
        };
        assert!(run(&flipped, "linux", "x86_64", &Fake::new()).is_err());
    }

    #[test]
    fn rejects_a_config_changed_after_signing() {
        // Replaced shorebird.yaml / key, consistent with each other, under
        // the original (valid) manifest.
        let text = linux_text();
        for (from, to) in [
            ("patch_public_key: AQID", "patch_public_key: BAUG"),
            (
                "https://updates.example.com",
                "https://attacker.example.com",
            ),
            ("app_id: app", "app_id: other"),
        ] {
            assert_eq!(
                run(&text.replacen(from, to, 1), "linux", "x86_64", &Fake::new()),
                Err(IntegrityFailure::ConfigDigestMismatch),
                "{to}"
            );
        }
        // An added key above the manifest line is a change too.
        let added = text.replacen("app_id: app\n", "app_id: app\nauto_update: false\n", 1);
        assert_eq!(
            run(&added, "linux", "x86_64", &Fake::new()),
            Err(IntegrityFailure::ConfigDigestMismatch)
        );
    }

    #[test]
    fn rejects_a_manifest_for_another_policy() {
        let modules = module_entry("linux", "x86_64", MEASUREMENT);
        for (from, to, field) in [
            ("\"hardened\"", "\"legacy\"", "security_profile"),
            (
                TOOLCHAIN,
                &TOOLCHAIN.replace("sha256:7", "sha256:8"),
                "toolchain_id",
            ),
            (
                "\"development_exceptions\":false",
                "\"development_exceptions\":true",
                "development_exceptions",
            ),
            (
                "\"contract_version\":2",
                "\"contract_version\":1",
                "contract_version",
            ),
            (
                "\"contract_version\":2",
                "\"contract_version\":3",
                "contract_version",
            ),
        ] {
            let manifest = manifest_json(&config(), &modules, NO_IDENTITY).replace(from, to);
            let text = format!("{}{MANIFEST_KEY}: {}\n", config(), token(&SEED, &manifest));
            assert_eq!(
                run(&text, "linux", "x86_64", &Fake::new()),
                Err(IntegrityFailure::PolicyMismatch(field))
            );
        }
        // Unknown and duplicated fields are malformed even when signed.
        for manifest in [
            manifest_json(&config(), &modules, NO_IDENTITY)
                .replace("{\"schema\"", "{\"x\":1,\"schema\""),
            manifest_json(&config(), &modules, NO_IDENTITY)
                .replace("{\"schema\"", "{\"contract_version\":1,\"schema\""),
        ] {
            let text = format!("{}{MANIFEST_KEY}: {}\n", config(), token(&SEED, &manifest));
            assert!(matches!(
                run(&text, "linux", "x86_64", &Fake::new()),
                Err(IntegrityFailure::ManifestMalformed(_))
            ));
        }
    }

    #[test]
    fn rejects_a_replaced_or_unmeasurable_engine_module() {
        let text = linux_text();
        let mut fake = Fake::new();
        fake.module = Ok(RunningModule {
            path: "libflutter_linux_gtk.so".into(),
            measurement: MEASUREMENT.replace('1', "2"),
        });
        assert_eq!(
            run(&text, "linux", "x86_64", &fake),
            Err(IntegrityFailure::ModuleMismatch)
        );
        fake.module = Err(MeasureError::Truncated);
        assert!(matches!(
            run(&text, "linux", "x86_64", &fake),
            Err(IntegrityFailure::ModuleUnmeasurable(_))
        ));
        // A build for another architecture (or platform) binds nothing here.
        // Since P6 that includes Android (contract §12): flutter_tools binds
        // the Maven libflutter.so, so a missing entry is a refusal there too.
        for (platform, arch) in [
            ("linux", "aarch64"),
            ("windows", "x86_64"),
            ("ios", "aarch64"),
            ("macos", "x86_64"),
            ("android", "aarch64"),
            ("android", "arm"),
        ] {
            assert_eq!(
                run(&text, platform, arch, &Fake::new()),
                Err(IntegrityFailure::ModuleUnbound)
            );
        }
        let android = build(
            &config(),
            &module_entry("android", "aarch64", MEASUREMENT),
            NO_IDENTITY,
            &SEED,
        );
        assert!(matches!(
            run(&android, "android", "aarch64", &fake),
            Err(IntegrityFailure::ModuleUnmeasurable(_))
        ));
        assert_eq!(run(&android, "android", "aarch64", &Fake::new()), Ok(()));
        // An entry for another ABI does not bind this one.
        assert_eq!(
            run(&android, "android", "x86_64", &Fake::new()),
            Err(IntegrityFailure::ModuleUnbound)
        );
        fake.module = Ok(RunningModule {
            path: "libflutter.so".into(),
            measurement: MEASUREMENT.replace('1', "3"),
        });
        assert_eq!(
            run(&android, "android", "aarch64", &fake),
            Err(IntegrityFailure::ModuleMismatch)
        );
    }

    #[test]
    fn package_identity_rejects_a_re_signed_package() {
        let fake = Fake::new();
        let ours = "aa".repeat(32);
        let identity = format!(
            "{{\"android_signing_cert_sha256\":[\"{ours}\",\"{}\"],\"apple_team_ids\":[\"ABCDE12345\"]}}",
            "bb".repeat(32)
        );
        let modules = [
            module_entry("macos", "aarch64", MEASUREMENT),
            module_entry("ios", "aarch64", MEASUREMENT),
            module_entry("android", "aarch64", MEASUREMENT),
        ]
        .join(",");
        let text = build(&config(), &modules, &identity, &SEED);
        assert_eq!(run(&text, "android", "aarch64", &fake), Ok(()));
        assert_eq!(run(&text, "macos", "aarch64", &fake), Ok(()));
        // Repacked and re-signed by someone else.
        let mut resigned = Fake::new();
        resigned.signers = Ok(vec!["cc".repeat(32)]);
        resigned.team = Ok(Some("ZZZZZ99999".into()));
        assert_eq!(
            run(&text, "android", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        assert_eq!(
            run(&text, "macos", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        // An extra unlisted signer alongside ours is also a mismatch.
        resigned.signers = Ok(vec![ours, "cc".repeat(32)]);
        assert_eq!(
            run(&text, "android", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        // Ad-hoc / unsigned, invalid signature, unreadable APK.
        resigned.team = Ok(None);
        assert_eq!(
            run(&text, "macos", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        resigned.team = Err("invalid".into());
        resigned.signers = Err("missing".into());
        assert!(matches!(
            run(&text, "macos", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityUnavailable(_))
        ));
        assert!(matches!(
            run(&text, "android", "aarch64", &resigned),
            Err(IntegrityFailure::PackageIdentityUnavailable(_))
        ));
        // iOS cannot verify a team ID: declaring one fails closed.
        assert_eq!(
            run(&text, "ios", "aarch64", &fake),
            Err(IntegrityFailure::PackageIdentityUnsupported)
        );
    }

    /// A manifest bound to the Windows x86_64 module with `identity`.
    fn windows_text(identity: &str) -> String {
        build(
            &config(),
            &module_entry("windows", "x86_64", MEASUREMENT),
            identity,
            &SEED,
        )
    }

    fn windows_identity(digests: &str) -> String {
        format!(
            "{{\"android_signing_cert_sha256\":[],\"apple_team_ids\":[],\
             \"windows_signing_cert_sha256\":{digests}}}"
        )
    }

    #[test]
    fn windows_authenticode_identity_binds_the_module_signer() {
        let ours = "dd".repeat(32);
        let rotated = "ee".repeat(32);
        let text = windows_text(&windows_identity(&format!("[\"{ours}\",\"{rotated}\"]")));
        assert_eq!(run(&text, "windows", "x86_64", &Fake::new()), Ok(()));
        let mut fake = Fake::new();
        fake.windows = Ok(vec![rotated.clone()]);
        assert_eq!(run(&text, "windows", "x86_64", &fake), Ok(()));
        // Re-signed by another publisher.
        fake.windows = Ok(vec!["cc".repeat(32)]);
        assert_eq!(
            run(&text, "windows", "x86_64", &fake),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        fake.windows = Ok(vec![]);
        assert_eq!(
            run(&text, "windows", "x86_64", &fake),
            Err(IntegrityFailure::PackageIdentityMismatch)
        );
        // Unsigned, a broken signature, an untrusted chain, or a file that
        // differs from the loaded module: no identity can be established.
        fake.windows = Err("Authenticode verification failed (0x800b0100)".into());
        assert!(matches!(
            run(&text, "windows", "x86_64", &fake),
            Err(IntegrityFailure::PackageIdentityUnavailable(_))
        ));
        // The identity is checked only after the module binding.
        fake.module = Ok(RunningModule {
            path: "flutter_windows.dll".into(),
            measurement: MEASUREMENT.replace('1', "2"),
        });
        assert_eq!(
            run(&text, "windows", "x86_64", &fake),
            Err(IntegrityFailure::ModuleMismatch)
        );
        // Without a declaration the signer is never read (the Fake would
        // fail its assertion), and other platforms ignore a Windows identity.
        let mut unread = Fake::new();
        unread.windows = Err("must not be read".into());
        assert_eq!(
            run(&windows_text(NO_IDENTITY), "windows", "x86_64", &unread),
            Ok(())
        );
        let linux = build(
            &config(),
            &module_entry("linux", "x86_64", MEASUREMENT),
            &windows_identity(&format!("[\"{ours}\"]")),
            &SEED,
        );
        assert_eq!(run(&linux, "linux", "x86_64", &unread), Ok(()));
    }

    #[test]
    fn windows_identity_shape_is_checked() {
        for digests in [
            "[]".to_string(),
            format!("[\"{}\"]", "DD".repeat(32)),
            format!("[\"{}\"]", "d".repeat(63)),
            "null".to_string(),
            "\"dd\"".to_string(),
        ] {
            let text = windows_text(&windows_identity(&digests));
            assert!(
                matches!(
                    run(&text, "windows", "x86_64", &Fake::new()),
                    Err(IntegrityFailure::ManifestMalformed(_))
                ),
                "{digests}"
            );
        }
        // An unknown identity key is still refused.
        let text =
            windows_text("{\"android_signing_cert_sha256\":[],\"apple_team_ids\":[],\"linux\":[]}");
        assert!(matches!(
            run(&text, "windows", "x86_64", &Fake::new()),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_adapter_verifies_authenticode_on_the_open_file() {
        use crate::module_measurement::measure_pe_file;
        use crate::package_identity::windows_module_signers;
        // Cargo's test binaries are unsigned: no identity.
        let exe = std::env::current_exe().unwrap();
        let measurement = measure_pe_file(&std::fs::read(&exe).unwrap()).unwrap();
        let unsigned = windows_module_signers(&exe, &measurement);
        assert!(
            unsigned.as_ref().is_err_and(|e| e.contains("0x800b0100")),
            "{unsigned:?}"
        );
        // A file that is not the measured module is refused before WinVerifyTrust.
        let other = windows_module_signers(&exe, MEASUREMENT);
        assert!(
            other.as_ref().is_err_and(|e| e.contains("differs")),
            "{other:?}"
        );
        // Boot-critical system images carry embedded Authenticode signatures
        // that chain to a trusted root on every Windows installation.
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let signed = std::path::Path::new(&system).join(r"System32\ntoskrnl.exe");
        let image = std::fs::read(&signed).unwrap();
        let measurement = measure_pe_file(&image).unwrap();
        let signers = windows_module_signers(&signed, &measurement).unwrap();
        assert_eq!(signers.len(), 1);
        assert!(is_lower_hex(&signers[0], 64), "{signers:?}");
        assert_eq!(
            windows_module_signers(&signed, &measurement).unwrap(),
            signers
        );
    }

    #[test]
    fn android_adapter_reads_the_installed_apk() {
        use crate::package_identity::tests::{apk_with_signers, digest};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("base.apk"),
            apk_with_signers(&[(0xf053_68c0, b"release cert")]),
        )
        .unwrap();
        let observer = PlatformObserver {
            install_dir: dir.path(),
        };
        assert_eq!(
            observer.android_signers(),
            Ok(vec![digest(b"release cert")])
        );
    }

    #[test]
    fn verifies_the_bytes_it_parses() {
        // The digest and the parse come from one string: a YAML whose
        // signed prefix differs from what follows cannot pass, and the
        // parsed values are those of the verified bytes.
        let text = linux_text();
        let source = split_source(&text);
        let parsed = crate::yaml::YamlConfig::from_yaml(&text).unwrap();
        assert_eq!(parsed.build_manifest, source);
        assert_eq!(
            parsed.base_url.as_deref(),
            Some("https://updates.example.com")
        );
        assert_eq!(
            source.config_sha256,
            <[u8; 32]>::from(Sha256::digest(config().as_bytes()))
        );
    }

    #[test]
    fn real_module_binding_accepts_this_process_and_rejects_other_bytes() {
        let text = signed_hardened_yaml();
        let observer = PlatformObserver {
            install_dir: Path::new("."),
        };
        let platform = crate::config::current_platform();
        let arch = crate::config::current_arch();
        let source = split_source(&text);
        assert_eq!(
            evaluate(&hardened_with_key(), &source, platform, arch, &observer),
            Ok(())
        );
        // The same manifest bound to the file measurement of a different
        // module (a changed loader target) is rejected by the real observer.
        let other = crate::module_measurement::measure_file_image(
            &crate::module_measurement::tests::elf64_fixture(),
        )
        .unwrap();
        let config = config();
        let manifest = manifest_json(&config, &module_entry(platform, arch, &other), NO_IDENTITY);
        let text = format!("{config}{MANIFEST_KEY}: {}\n", token(&SEED, &manifest));
        assert_eq!(
            evaluate(
                &hardened_with_key(),
                &split_source(&text),
                platform,
                arch,
                &observer
            ),
            Err(IntegrityFailure::ModuleMismatch)
        );
    }

    /// Host startup-cost evidence (P6): the uncached module measurement of
    /// this test binary and the complete gate (trust chain, signature,
    /// digests, cached measurement). The numbers are printed for the record;
    /// the bound only catches a pathological regression. Device numbers come
    /// from the "Integrity check passed (N us)" log line (contract §12).
    #[test]
    fn integrity_gate_startup_cost_on_this_host() {
        let started = std::time::Instant::now();
        let measured = measure_running_module().unwrap();
        let measure_us = started.elapsed().as_micros();
        let text = signed_hardened_yaml();
        let observer = PlatformObserver {
            install_dir: Path::new("."),
        };
        let platform = crate::config::current_platform();
        let arch = crate::config::current_arch();
        let mut gate_us = Vec::new();
        for _ in 0..20 {
            let started = std::time::Instant::now();
            assert_eq!(
                evaluate(
                    &hardened_with_key(),
                    &split_source(&text),
                    platform,
                    arch,
                    &observer
                ),
                Ok(())
            );
            gate_us.push(started.elapsed().as_micros());
        }
        gate_us.sort_unstable();
        eprintln!(
            "integrity startup cost on {platform}/{arch}: module measurement {measure_us} us \
             (module {}), gate p50 {} us, max {} us",
            measured.path, gate_us[10], gate_us[19]
        );
        assert!(measure_us < 10_000_000 && gate_us[19] < 10_000_000);
    }

    /// A linux build output signed by `signer` under `delegations`, carried
    /// in `bundle`.
    fn signed_under(signer: &[u8; 32], delegations: &str, bundle: &str) -> String {
        let manifest = manifest_json_for(
            signer,
            delegations,
            &config(),
            &module_entry("linux", "x86_64", MEASUREMENT),
            NO_IDENTITY,
        );
        format!(
            "{}{MANIFEST_KEY}: {}\n",
            config(),
            token_with_trust(signer, &manifest, bundle)
        )
    }

    fn delegations_bundle(delegations: &str) -> String {
        trust::trust_bundle(
            &[],
            &trust::envelope(
                crate::release_trust::DELEGATIONS_SIGNATURE_DOMAIN,
                delegations,
                &[trust::ROOT_SEED],
            ),
        )
    }

    #[test]
    fn manifest_signer_must_be_a_delegated_build_manifest_key() {
        let fake = Fake::new();
        let default = trust::default_delegations();
        let bundle = trust::default_bundle();
        assert_eq!(
            run(
                &signed_under(&SEED, &default, &bundle),
                "linux",
                "x86_64",
                &fake
            ),
            Ok(())
        );
        // Role confusion: the artifact-catalog key and the root key itself
        // sign a manifest that names them.
        for confused in [trust::CATALOG_SEED, trust::ROOT_SEED] {
            assert_eq!(
                run(
                    &signed_under(&confused, &default, &bundle),
                    "linux",
                    "x86_64",
                    &fake
                ),
                Err(IntegrityFailure::SignerRole)
            );
        }
        // Wrong key ID: a key the delegations never name.
        assert_eq!(
            run(
                &signed_under(&OTHER_SEED, &default, &bundle),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::UntrustedSigner)
        );
    }

    #[test]
    fn revoked_rotated_out_and_rolled_back_signers_are_refused() {
        let fake = Fake::new();
        // Delegations v2 rotate the manifest key to [8;32] and revoke [7;32].
        let rotated = trust::delegations_payload(
            2,
            1,
            &[trust::NEXT_MANIFEST_SEED],
            &[trust::CATALOG_SEED],
            &[trust::id(&SEED)],
        );
        let bundle = delegations_bundle(&rotated);
        let policy = policy_with_root(&trust::default_root(), 2);
        let check = |text: &str| evaluate(&policy, &split_source(text), "linux", "x86_64", &fake);
        assert_eq!(
            check(&signed_under(&trust::NEXT_MANIFEST_SEED, &rotated, &bundle)),
            Ok(())
        );
        assert_eq!(
            check(&signed_under(&SEED, &rotated, &bundle)),
            Err(IntegrityFailure::SignerRevoked)
        );
        // Rotated out without revocation.
        let dropped = trust::delegations_payload(2, 1, &[trust::NEXT_MANIFEST_SEED], &[], &[]);
        assert_eq!(
            check(&signed_under(
                &SEED,
                &dropped,
                &delegations_bundle(&dropped)
            )),
            Err(IntegrityFailure::UntrustedSigner)
        );
        // The old key with the old delegations that still list it: the
        // compiled floor (2) refuses the rollback.
        assert_eq!(
            check(&signed_under(
                &SEED,
                &trust::default_delegations(),
                &trust::default_bundle()
            )),
            Err(IntegrityFailure::TrustRollback)
        );
    }

    #[test]
    fn manifest_binds_the_delegations_it_was_signed_under() {
        let fake = Fake::new();
        // Signed naming the default delegations, shipped with another
        // delegations version that also delegates the same key.
        let other = trust::delegations_payload(2, 1, &[SEED], &[], &[]);
        assert_eq!(
            run(
                &signed_under(
                    &SEED,
                    &trust::default_delegations(),
                    &delegations_bundle(&other)
                ),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::PolicyMismatch("delegations_sha256"))
        );
        // A tampered or unsigned bundle is refused before the signer is used.
        let unsigned = trust::trust_bundle(
            &[],
            &trust::envelope(
                crate::release_trust::DELEGATIONS_SIGNATURE_DOMAIN,
                &trust::default_delegations(),
                &[SEED],
            ),
        );
        assert_eq!(
            run(
                &signed_under(&SEED, &trust::default_delegations(), &unsigned),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::TrustUnverified("delegations signature"))
        );
        assert!(matches!(
            run(
                &signed_under(&SEED, &trust::default_delegations(), "{}"),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::TrustMalformed(_))
        ));
    }

    #[test]
    fn a_planned_root_rotation_is_followed() {
        // The engine pins root v1; the build was made after the operator
        // rotated to root v2 (cross-signed) and re-delegated under it.
        let next = trust::root_payload(2, 1, &[trust::NEXT_ROOT_SEED]);
        let delegations = trust::delegations_payload(1, 2, &[SEED], &[], &[]);
        let bundle = trust::trust_bundle(
            &[trust::envelope(
                crate::release_trust::ROOT_SIGNATURE_DOMAIN,
                &next,
                &[trust::ROOT_SEED, trust::NEXT_ROOT_SEED],
            )],
            &trust::envelope(
                crate::release_trust::DELEGATIONS_SIGNATURE_DOMAIN,
                &delegations,
                &[trust::NEXT_ROOT_SEED],
            ),
        );
        assert_eq!(
            run(
                &signed_under(&SEED, &delegations, &bundle),
                "linux",
                "x86_64",
                &Fake::new()
            ),
            Ok(())
        );
    }

    /// The exact output of flutter_tools' `appendShorebirdBuildManifest` for
    /// a fixed key and input (`shorebird_build_manifest_test.dart`, "matches
    /// the token the updater verifies"), carrying the DEVELOPMENT-ONLY
    /// release-trust bundle `scripts/release_trust.py` produced. Proves the
    /// three implementations agree on the line format, the config digest, the
    /// delegations digest, key IDs, envelopes and signatures.
    const FLUTTER_TOOLS_OUTPUT: &str = concat!(
        "app_id: app\nbase_url: https://updates.example.com\n",
        "shorebird_build_manifest: ",
        "v2.eyJzY2hlbWEiOiJvcGVuLXNob3JlYmlyZC5idWlsZC1tYW5pZmVzdCIsImNvbnRyYWN0X3ZlcnNpb24iOjIsInNlY3VyaXR5X3Byb2ZpbGUiOiJoYXJkZW5lZCIsInRvb2xjaGFpbl9pZCI6InNoYTI1Njo3MDIyOWU0MDdlNTMxMTQwMWFhMzI1MTQxOGVmZjEwNjQ2N2E3NTBjY2ZjYjdlOGZlN2I2MWM0NDQyNzAwMDQwIiwiZGV2ZWxvcG1lbnRfZXhjZXB0aW9ucyI6ZmFsc2UsInNpZ25lcl9rZXlfaWQiOiJzaGEyNTY6ZmU4MTJjMTJmM2FiNGNlNmFjNWRiNjlhYzM1MmY5MDZjYjFiMTFlZjQzZmIzM2UyNTJlZjdmZjU1MjI2Mzg4OSIsImRlbGVnYXRpb25zX3NoYTI1NiI6Ijc5YTYwNGZmOTFkNjhhYWRjYmQxMmM0ZmE0YTNlNDJjNWRjZTJiNGQ5Y2U3MWExZWYyMmRjMzk3N2NiOTk0ZGYiLCJjb25maWdfc2hhMjU2IjoiMDg0YzhkNjU0Mjg0YzBmY2Y5MmVkOWU4MTQxNGExNWRkMTk1MzI2MTJlNjMwMWQ5ZTE4NGU0ZTBlNjI0MjZjNCIsIm1vZHVsZXMiOlt7InBsYXRmb3JtIjoibGludXgiLCJhcmNoIjoieDg2XzY0IiwibWVhc3VyZW1lbnQiOiJzaGEyNTY6ZjE3NzE2OTI0NTE4NmJlOGUwZmEyZThlNmZmYjlkZjcwZjhkZDA4MjRjOGYzMDVjMDZlMTdmMzBmNjM5OTFjZCJ9XSwicGFja2FnZV9pZGVudGl0eSI6eyJhbmRyb2lkX3NpZ25pbmdfY2VydF9zaGEyNTYiOltdLCJhcHBsZV90ZWFtX2lkcyI6W119fQ.HK-FpA4qt5auJPBUoqhL0ixlBNl5kabAz_RW80B_ZLjc1anfgGMyzGNmAZAJyF8NCCeQurW91yB1aw6bxa2wCw.eyJjb250cmFjdF92ZXJzaW9uIjoyLCJkZWxlZ2F0aW9ucyI6eyJwYXlsb2FkIjoiZXlKamIyNTBjbUZqZEY5MlpYSnphVzl1SWpveUxDSmxlSEJwY21WelgyRjBJam9pTWpBek5pMHhNUzB3TVZRd01Eb3dNRG93TUZvaUxDSnBjM04xWldSZllYUWlPaUl5TURJMkxURXhMVEF4VkRBd09qQXdPakF3V2lJc0luSmxkbTlyWldSZmEyVjVYMmxrY3lJNlcxMHNJbkp2YkdWeklqcDdJbUZ5ZEdsbVlXTjBMV05oZEdGc2IyY2lPbHQ3SW10bGVWOXBaQ0k2SW5Ob1lUSTFOam80Tm1RME5tVXdPV1E1TW1JME1UTXhNREJpWWpZMVl6Rm1NRGs0TWpNMVpXUXlNMlJrWWpnMFpUQTRNV0kxTnpSak1qQmlaVEV4WkRFMVptUTJOVGcwSWl3aWJtOTBYMkZtZEdWeUlqb2lNakF6TmkweE1TMHdNVlF3TURvd01Eb3dNRm9pTENKdWIzUmZZbVZtYjNKbElqb2lNakF5TmkweE1TMHdNVlF3TURvd01Eb3dNRm9pTENKd2RXSnNhV05mYTJWNUlqb2lWblp6ZEVkMkwydGlNemxZTm5JelJqUjZWSEJZYUV0a1IyMTNVMEZHYTFkQ09YbzRMMUpyVVZoMGJ6MGlmVjBzSW1KMWFXeGtMVzFoYm1sbVpYTjBJanBiZXlKclpYbGZhV1FpT2lKemFHRXlOVFk2Wm1VNE1USmpNVEptTTJGaU5HTmxObUZqTldSaU5qbGhZek0xTW1ZNU1EWmpZakZpTVRGbFpqUXpabUl6TTJVeU5USmxaamRtWmpVMU1qSTJNemc0T1NJc0ltNXZkRjloWm5SbGNpSTZJakl3TXpZdE1URXRNREZVTURBNk1EQTZNREJhSWl3aWJtOTBYMkpsWm05eVpTSTZJakl3TWpZdE1URXRNREZVTURBNk1EQTZNREJhSWl3aWNIVmliR2xqWDJ0bGVTSTZJalpyY0hOWkswdGpWV2R4S3psV1FqZEZlVGRHSzFwV1NHUnhOaXQyYm5WVFVXZzNjV0ZTVWtjd2FYYzlJbjFkZlN3aWNtOXZkRjkyWlhKemFXOXVJam94TENKelkyaGxiV0VpT2lKdmNHVnVMWE5vYjNKbFltbHlaQzV5Wld4bFlYTmxMV1JsYkdWbllYUnBiMjV6SWl3aWRtVnljMmx2YmlJNk1YMD0iLCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiJzaGEyNTY6MzQ3NTBmOThiZDU5ZmNmYzk0NmRhNDVhYWFiZTkzM2JlMTU0YTRiNTA5NGUxYzRhYmY0Mjg2NjUwNWYzYzk3ZSIsInNpZ25hdHVyZSI6ImI2NzQ1cFFFS2k4WHR4cHg3VzM5NlZqb1pWUWUxUXRNcUthWlJWeFJJcVJobk85NldnUngrK1lxdzFZeE1NR05XZEZYNlhwVnlDQkpQOGtjbEt3WUJBPT0ifV19LCJyb290X2NoYWluIjpbeyJwYXlsb2FkIjoiZXlKamIyNTBjbUZqZEY5MlpYSnphVzl1SWpveUxDSmxlSEJwY21WelgyRjBJam9pTWpBek5pMHhNUzB3T1ZRd01Eb3dNRG93TUZvaUxDSnJaWGx6SWpwYmV5SnJaWGxmYVdRaU9pSnphR0V5TlRZNk16UTNOVEJtT1RoaVpEVTVabU5tWXprME5tUmhORFZoWVdGaVpUa3pNMkpsTVRVMFlUUmlOVEE1TkdVeFl6UmhZbVkwTWpnMk5qVXdOV1l6WXprM1pTSXNJbkIxWW14cFkxOXJaWGtpT2lKcGIycHFNMWhSU2poYVdEbFZkSE4wVUV4d1pHTnpjRzVEWWpoa2JFSkpZamd6VTBsQllsRlFZakYzUFNKOVhTd2ljMk5vWlcxaElqb2liM0JsYmkxemFHOXlaV0pwY21RdWNtVnNaV0Z6WlMxeWIyOTBJaXdpZEdoeVpYTm9iMnhrSWpveExDSjJaWEp6YVc5dUlqb3hmUT09Iiwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoic2hhMjU2OjM0NzUwZjk4YmQ1OWZjZmM5NDZkYTQ1YWFhYmU5MzNiZTE1NGE0YjUwOTRlMWM0YWJmNDI4NjY1MDVmM2M5N2UiLCJzaWduYXR1cmUiOiJENE5KdWpSL3NZZHNHYWw4VS96VjhFUVY4ck1lZlc4UUR2NnNYdUMvVEd0Lys2YnArZGlpVS9VMjBwYit1VWEyaGxwaVZDTGxtcU1wb29UL2FycldEZz09In1dfV0sInNjaGVtYSI6Im9wZW4tc2hvcmViaXJkLnJlbGVhc2UtdHJ1c3QifQ\n",
    );

    #[test]
    fn flutter_tools_output_verifies() {
        let mut fake = Fake::new();
        fake.module = Ok(RunningModule {
            path: "libflutter_linux_gtk.so".into(),
            measurement: crate::module_measurement::tests::ELF64_GOLDEN.into(),
        });
        let source = split_source(FLUTTER_TOOLS_OUTPUT);
        assert_eq!(
            evaluate(&hardened_with_key(), &source, "linux", "x86_64", &fake),
            Ok(())
        );
        // The same build output under another compiled root is refused.
        let other = policy_with_root(&trust::root_payload(1, 1, &[OTHER_SEED]), 1);
        assert_eq!(
            evaluate(&other, &source, "linux", "x86_64", &fake),
            Err(IntegrityFailure::TrustUnverified("delegations signature"))
        );
        // And under a compiled delegations floor above its delegations.
        let raised = policy_with_root(&trust::default_root(), 2);
        assert_eq!(
            evaluate(&raised, &source, "linux", "x86_64", &fake),
            Err(IntegrityFailure::TrustRollback)
        );
    }

    /// The exact output of flutter_tools' `appendShorebirdBuildManifest` for
    /// the same input as [`FLUTTER_TOOLS_OUTPUT`] built hardened-diversified
    /// with the DEVELOPMENT-ONLY diversification profile
    /// (`shorebird_build_manifest_test.dart`, "matches the v3 token the
    /// updater verifies"): the v3 token format, the profile binding and the
    /// unchanged signature domain agree across the two implementations.
    const FLUTTER_TOOLS_V3_OUTPUT: &str = concat!(
        "app_id: app\nbase_url: https://updates.example.com\n",
        "shorebird_build_manifest: ",
        "v3.eyJzY2hlbWEiOiJvcGVuLXNob3JlYmlyZC5idWlsZC1tYW5pZmVzdCIsImNvbnRyYWN0X3ZlcnNpb24iOjMsInNlY3VyaXR5X3Byb2ZpbGUiOiJoYXJkZW5lZC1kaXZlcnNpZmllZCIsInRvb2xjaGFpbl9pZCI6InNoYTI1Njo3MDIyOWU0MDdlNTMxMTQwMWFhMzI1MTQxOGVmZjEwNjQ2N2E3NTBjY2ZjYjdlOGZlN2I2MWM0NDQyNzAwMDQwIiwiZGV2ZWxvcG1lbnRfZXhjZXB0aW9ucyI6ZmFsc2UsImRpdmVyc2lmaWNhdGlvbl9wcm9maWxlX2lkIjoic2hhMjU2OjgzMjg1NmQwYmVkMjc4MzM0MzRlM2YyNmI2NWQwM2NlZGMzMTNmOTg1MGMyNTc3Y2E3NTY1YzRkYzY0NGY0NmQiLCJzaWduZXJfa2V5X2lkIjoic2hhMjU2OmZlODEyYzEyZjNhYjRjZTZhYzVkYjY5YWMzNTJmOTA2Y2IxYjExZWY0M2ZiMzNlMjUyZWY3ZmY1NTIyNjM4ODkiLCJkZWxlZ2F0aW9uc19zaGEyNTYiOiI3OWE2MDRmZjkxZDY4YWFkY2JkMTJjNGZhNGEzZTQyYzVkY2UyYjRkOWNlNzFhMWVmMjJkYzM5NzdjYjk5NGRmIiwiY29uZmlnX3NoYTI1NiI6IjA4NGM4ZDY1NDI4NGMwZmNmOTJlZDllODE0MTRhMTVkZDE5NTMyNjEyZTYzMDFkOWUxODRlNGUwZTYyNDI2YzQiLCJtb2R1bGVzIjpbeyJwbGF0Zm9ybSI6ImxpbnV4IiwiYXJjaCI6Ing4Nl82NCIsIm1lYXN1cmVtZW50Ijoic2hhMjU2OmYxNzcxNjkyNDUxODZiZThlMGZhMmU4ZTZmZmI5ZGY3MGY4ZGQwODI0YzhmMzA1YzA2ZTE3ZjMwZjYzOTkxY2QifV0sInBhY2thZ2VfaWRlbnRpdHkiOnsiYW5kcm9pZF9zaWduaW5nX2NlcnRfc2hhMjU2IjpbXSwiYXBwbGVfdGVhbV9pZHMiOltdfX0.7ENISJNDkATY08LKzMmG06cTNqDolWt8yE7q516TfjdapJmY-H0tlhT2s5JekK5N0vRyUuyHVF_FjJZb7JDBAw.eyJjb250cmFjdF92ZXJzaW9uIjoyLCJkZWxlZ2F0aW9ucyI6eyJwYXlsb2FkIjoiZXlKamIyNTBjbUZqZEY5MlpYSnphVzl1SWpveUxDSmxlSEJwY21WelgyRjBJam9pTWpBek5pMHhNUzB3TVZRd01Eb3dNRG93TUZvaUxDSnBjM04xWldSZllYUWlPaUl5TURJMkxURXhMVEF4VkRBd09qQXdPakF3V2lJc0luSmxkbTlyWldSZmEyVjVYMmxrY3lJNlcxMHNJbkp2YkdWeklqcDdJbUZ5ZEdsbVlXTjBMV05oZEdGc2IyY2lPbHQ3SW10bGVWOXBaQ0k2SW5Ob1lUSTFOam80Tm1RME5tVXdPV1E1TW1JME1UTXhNREJpWWpZMVl6Rm1NRGs0TWpNMVpXUXlNMlJrWWpnMFpUQTRNV0kxTnpSak1qQmlaVEV4WkRFMVptUTJOVGcwSWl3aWJtOTBYMkZtZEdWeUlqb2lNakF6TmkweE1TMHdNVlF3TURvd01Eb3dNRm9pTENKdWIzUmZZbVZtYjNKbElqb2lNakF5TmkweE1TMHdNVlF3TURvd01Eb3dNRm9pTENKd2RXSnNhV05mYTJWNUlqb2lWblp6ZEVkMkwydGlNemxZTm5JelJqUjZWSEJZYUV0a1IyMTNVMEZHYTFkQ09YbzRMMUpyVVZoMGJ6MGlmVjBzSW1KMWFXeGtMVzFoYm1sbVpYTjBJanBiZXlKclpYbGZhV1FpT2lKemFHRXlOVFk2Wm1VNE1USmpNVEptTTJGaU5HTmxObUZqTldSaU5qbGhZek0xTW1ZNU1EWmpZakZpTVRGbFpqUXpabUl6TTJVeU5USmxaamRtWmpVMU1qSTJNemc0T1NJc0ltNXZkRjloWm5SbGNpSTZJakl3TXpZdE1URXRNREZVTURBNk1EQTZNREJhSWl3aWJtOTBYMkpsWm05eVpTSTZJakl3TWpZdE1URXRNREZVTURBNk1EQTZNREJhSWl3aWNIVmliR2xqWDJ0bGVTSTZJalpyY0hOWkswdGpWV2R4S3psV1FqZEZlVGRHSzFwV1NHUnhOaXQyYm5WVFVXZzNjV0ZTVWtjd2FYYzlJbjFkZlN3aWNtOXZkRjkyWlhKemFXOXVJam94TENKelkyaGxiV0VpT2lKdmNHVnVMWE5vYjNKbFltbHlaQzV5Wld4bFlYTmxMV1JsYkdWbllYUnBiMjV6SWl3aWRtVnljMmx2YmlJNk1YMD0iLCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiJzaGEyNTY6MzQ3NTBmOThiZDU5ZmNmYzk0NmRhNDVhYWFiZTkzM2JlMTU0YTRiNTA5NGUxYzRhYmY0Mjg2NjUwNWYzYzk3ZSIsInNpZ25hdHVyZSI6ImI2NzQ1cFFFS2k4WHR4cHg3VzM5NlZqb1pWUWUxUXRNcUthWlJWeFJJcVJobk85NldnUngrK1lxdzFZeE1NR05XZEZYNlhwVnlDQkpQOGtjbEt3WUJBPT0ifV19LCJyb290X2NoYWluIjpbeyJwYXlsb2FkIjoiZXlKamIyNTBjbUZqZEY5MlpYSnphVzl1SWpveUxDSmxlSEJwY21WelgyRjBJam9pTWpBek5pMHhNUzB3T1ZRd01Eb3dNRG93TUZvaUxDSnJaWGx6SWpwYmV5SnJaWGxmYVdRaU9pSnphR0V5TlRZNk16UTNOVEJtT1RoaVpEVTVabU5tWXprME5tUmhORFZoWVdGaVpUa3pNMkpsTVRVMFlUUmlOVEE1TkdVeFl6UmhZbVkwTWpnMk5qVXdOV1l6WXprM1pTSXNJbkIxWW14cFkxOXJaWGtpT2lKcGIycHFNMWhSU2poYVdEbFZkSE4wVUV4d1pHTnpjRzVEWWpoa2JFSkpZamd6VTBsQllsRlFZakYzUFNKOVhTd2ljMk5vWlcxaElqb2liM0JsYmkxemFHOXlaV0pwY21RdWNtVnNaV0Z6WlMxeWIyOTBJaXdpZEdoeVpYTm9iMnhrSWpveExDSjJaWEp6YVc5dUlqb3hmUT09Iiwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoic2hhMjU2OjM0NzUwZjk4YmQ1OWZjZmM5NDZkYTQ1YWFhYmU5MzNiZTE1NGE0YjUwOTRlMWM0YWJmNDI4NjY1MDVmM2M5N2UiLCJzaWduYXR1cmUiOiJENE5KdWpSL3NZZHNHYWw4VS96VjhFUVY4ck1lZlc4UUR2NnNYdUMvVEd0Lys2YnArZGlpVS9VMjBwYit1VWEyaGxwaVZDTGxtcU1wb29UL2FycldEZz09In1dfV0sInNjaGVtYSI6Im9wZW4tc2hvcmViaXJkLnJlbGVhc2UtdHJ1c3QifQ\n",
    );

    #[test]
    fn flutter_tools_v3_output_verifies() {
        let mut fake = Fake::new();
        fake.module = Ok(RunningModule {
            path: "libflutter_linux_gtk.so".into(),
            measurement: crate::module_measurement::tests::ELF64_GOLDEN.into(),
        });
        let source = split_source(FLUTTER_TOOLS_V3_OUTPUT);
        assert_eq!(
            evaluate(&diversified_with_key(), &source, "linux", "x86_64", &fake),
            Ok(())
        );
        // A hardened updater refuses the v3 token, and the v2 output is
        // refused by the diversified updater.
        assert!(matches!(
            evaluate(&hardened_with_key(), &source, "linux", "x86_64", &fake),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        assert!(matches!(
            evaluate(
                &diversified_with_key(),
                &split_source(FLUTTER_TOOLS_OUTPUT),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        // A diversified updater compiled with another profile.
        let mut other = diversified_with_key();
        other.diversification_profile_id = Some(format!("sha256:{}", "0".repeat(64)));
        assert_eq!(
            evaluate(&other, &source, "linux", "x86_64", &fake),
            Err(IntegrityFailure::PolicyMismatch(
                "diversification_profile_id"
            ))
        );
    }

    #[test]
    fn legacy_never_runs_the_gate() {
        let policy = CompiledPolicy::legacy();
        assert_eq!(
            check(&policy, &split_source("app_id: app"), Path::new(".")),
            Ok(())
        );
    }

    fn run_diversified(text: &str) -> Result<(), IntegrityFailure> {
        evaluate(
            &diversified_with_key(),
            &split_source(text),
            "linux",
            "x86_64",
            &Fake::new(),
        )
    }

    fn diversified_config() -> String {
        format!("{}\n", diversified_yaml_text())
    }

    /// A linux diversified build output whose (v3) manifest is `edit`ed
    /// before signing.
    fn diversified_text(edit: &dyn Fn(String) -> String, prefix: &str) -> String {
        let config = diversified_config();
        let manifest = edit(v3_manifest(
            &manifest_json(
                &config,
                &module_entry("linux", "x86_64", MEASUREMENT),
                NO_IDENTITY,
            ),
            PROFILE_ID,
        ));
        format!(
            "{config}{MANIFEST_KEY}: {}\n",
            token_with_prefix(prefix, &SEED, &manifest, &trust::default_bundle())
        )
    }

    #[test]
    fn diversified_gate_accepts_the_v3_build_output() {
        let text = diversified_text(&|m| m, TOKEN_PREFIX_V3);
        assert_eq!(run_diversified(&text), Ok(()));
        // Every hardened gate rule applies: a changed config, another module.
        assert_eq!(
            run_diversified(&text.replacen("app_id: app", "app_id: other", 1)),
            Err(IntegrityFailure::ConfigDigestMismatch)
        );
        let mut fake = Fake::new();
        fake.module = Ok(RunningModule {
            path: "libflutter_linux_gtk.so".into(),
            measurement: MEASUREMENT.replace('1', "2"),
        });
        assert_eq!(
            evaluate(
                &diversified_with_key(),
                &split_source(&text),
                "linux",
                "x86_64",
                &fake
            ),
            Err(IntegrityFailure::ModuleMismatch)
        );
        // Without a compiled release root it trusts nothing.
        assert_eq!(
            evaluate(
                &diversified(),
                &split_source(&text),
                "linux",
                "x86_64",
                &Fake::new()
            ),
            Err(IntegrityFailure::TrustRootMissing)
        );
    }

    #[test]
    fn each_gate_accepts_only_its_own_token_version() {
        // A hardened gate refuses a v3 token, a diversified gate a v2 one.
        let v3 = diversified_text(&|m| m, TOKEN_PREFIX_V3);
        assert!(matches!(
            run(&v3, "linux", "x86_64", &Fake::new()),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        assert!(matches!(
            run_diversified(&linux_text()),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        // The v3 manifest under a v2 token, and the v2 manifest under a v3
        // token, are malformed as well (the key's presence follows the
        // token version).
        assert!(matches!(
            run_diversified(&diversified_text(&|m| m, TOKEN_PREFIX)),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        let hardened_manifest = manifest_json(
            &config(),
            &module_entry("linux", "x86_64", MEASUREMENT),
            NO_IDENTITY,
        );
        let v2_under_v3 = format!(
            "{}{MANIFEST_KEY}: {}\n",
            config(),
            v3_token(&SEED, &hardened_manifest)
        );
        assert!(matches!(
            evaluate(
                &hardened_with_key(),
                &split_source(&v2_under_v3),
                "linux",
                "x86_64",
                &Fake::new()
            ),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        assert!(matches!(
            run_diversified(&v2_under_v3),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        // A v2 manifest that names a profile is malformed for a hardened gate.
        let named = v3_manifest(&hardened_manifest, PROFILE_ID)
            .replace("\"contract_version\":3", "\"contract_version\":2")
            .replace("\"hardened-diversified\"", "\"hardened\"");
        let text = format!("{}{MANIFEST_KEY}: {}\n", config(), token(&SEED, &named));
        assert_eq!(
            run(&text, "linux", "x86_64", &Fake::new()),
            Err(IntegrityFailure::ManifestMalformed(
                "diversification_profile_id".to_string()
            ))
        );
    }

    #[test]
    fn diversified_manifest_binds_the_compiled_profile() {
        let other = format!("sha256:{}", "0".repeat(64));
        let id = format!("\"diversification_profile_id\":\"{PROFILE_ID}\"");
        let cases: Vec<(String, IntegrityFailure)> = vec![
            (
                format!("\"diversification_profile_id\":\"{other}\""),
                IntegrityFailure::PolicyMismatch("diversification_profile_id"),
            ),
            (
                "\"diversification_profile_id\":null".to_string(),
                IntegrityFailure::ManifestMalformed("diversification_profile_id".to_string()),
            ),
            (
                format!(
                    "\"diversification_profile_id\":\"{}\"",
                    PROFILE_ID.to_uppercase()
                ),
                IntegrityFailure::ManifestMalformed("diversification_profile_id".to_string()),
            ),
            (
                "\"diversification_profile_id\":1".to_string(),
                IntegrityFailure::ManifestMalformed("diversification_profile_id".to_string()),
            ),
        ];
        for (replacement, expected) in cases {
            let text = diversified_text(&|m| m.replace(&id, &replacement), TOKEN_PREFIX_V3);
            assert_eq!(run_diversified(&text), Err(expected), "{replacement}");
        }
        // Missing and duplicated keys are malformed even when signed.
        let missing = diversified_text(&|m| m.replace(&format!("{id},"), ""), TOKEN_PREFIX_V3);
        assert_eq!(
            run_diversified(&missing),
            Err(IntegrityFailure::ManifestMalformed(
                "diversification_profile_id".to_string()
            ))
        );
        let duplicated =
            diversified_text(&|m| m.replace(&id, &format!("{id},{id}")), TOKEN_PREFIX_V3);
        assert!(matches!(
            run_diversified(&duplicated),
            Err(IntegrityFailure::ManifestMalformed(_))
        ));
        // Another contract or profile inside a v3 token.
        for (from, to, field) in [
            (
                "\"contract_version\":3",
                "\"contract_version\":2",
                "contract_version",
            ),
            (
                "\"security_profile\":\"hardened-diversified\"",
                "\"security_profile\":\"hardened\"",
                "security_profile",
            ),
        ] {
            let text = diversified_text(&|m| m.replace(from, to), TOKEN_PREFIX_V3);
            assert_eq!(
                run_diversified(&text),
                Err(IntegrityFailure::PolicyMismatch(field))
            );
        }
        // The signed YAML must be the diversified declaration it binds: the
        // gate checks the bytes, admission checks the declaration.
        let hardened_config = diversified_text(&|m| m, TOKEN_PREFIX_V3).replacen(
            &format!("diversification_profile_id: {PROFILE_ID}"),
            "",
            1,
        );
        assert_eq!(
            run_diversified(&hardened_config),
            Err(IntegrityFailure::ConfigDigestMismatch)
        );
    }
}
