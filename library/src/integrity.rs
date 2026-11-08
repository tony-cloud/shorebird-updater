//! Startup integrity gate for hardened releases (hardening stage P3,
//! contract `docs/HARDENING_CONTRACTS.md` §9 in the workspace).
//!
//! A hardened build appends one line to the bundled shorebird.yaml:
//!
//! ```text
//! shorebird_build_manifest: v1.<base64url(manifest JSON)>.<base64url(Ed25519 signature)>
//! ```
//!
//! The manifest is signed by a build-manifest key compiled into the engine
//! (GN `shorebird_build_manifest_keys`), never by a key found in the package.
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
use crate::security::CompiledPolicy;
use crate::security_inputs::is_sha256_id;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The YAML key carrying the signed manifest; always the last line.
pub const MANIFEST_KEY: &str = "shorebird_build_manifest";
/// Token version prefix.
pub const TOKEN_PREFIX: &str = "v1.";
/// Ed25519 signs this prefix followed by the lowercase hex SHA-256 of the
/// manifest JSON bytes.
pub const SIGNATURE_DOMAIN: &str = "open-shorebird.build-manifest-signature.v1:";
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
    BadSignature,
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
            IntegrityFailure::BadSignature => "manifest_bad_signature",
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
            | IntegrityFailure::ModuleUnmeasurable(why)
            | IntegrityFailure::PackageIdentityUnavailable(why) => {
                write!(f, "integrity check failed: {} ({why})", self.code())
            }
            IntegrityFailure::PolicyMismatch(field) => {
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
}

/// Build manifest, contract v1. Every field is required; unknown fields and
/// duplicate fields are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema: String,
    pub contract_version: u32,
    pub security_profile: String,
    pub toolchain_id: String,
    pub development_exceptions: bool,
    pub signer_key_id: String,
    pub config_sha256: String,
    pub modules: Vec<ModuleEntry>,
    pub package_identity: PackageIdentity,
}

/// `sha256:` over a raw 32-byte Ed25519 public key (the P2 catalog rule).
pub fn ed25519_key_id(raw: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(raw)))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

const PLATFORMS: [&str; 5] = ["android", "ios", "linux", "macos", "windows"];
const ARCHES: [&str; 4] = ["aarch64", "arm", "x86", "x86_64"];

/// Decodes and authenticates a manifest token against the compiled keys.
/// The signature is checked before any other manifest field is trusted.
pub fn verify_token(
    policy: &CompiledPolicy,
    token: &str,
) -> Result<BuildManifest, IntegrityFailure> {
    let malformed = |why: &str| IntegrityFailure::ManifestMalformed(why.to_string());
    let body = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| malformed("unknown token version"))?;
    let (manifest_b64, signature_b64) = body
        .split_once('.')
        .ok_or_else(|| malformed("token has no signature"))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let manifest_bytes = b64
        .decode(manifest_b64)
        .map_err(|_| malformed("manifest is not base64url"))?;
    let signature = b64
        .decode(signature_b64)
        .map_err(|_| malformed("signature is not base64url"))?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES || signature.len() != 64 {
        return Err(malformed("manifest or signature size"));
    }
    // Only the signer selector is read before verification.
    #[derive(Deserialize)]
    struct Selector {
        signer_key_id: String,
    }
    let selector: Selector =
        serde_json::from_slice(&manifest_bytes).map_err(|_| malformed("manifest JSON"))?;
    let key = policy
        .build_manifest_keys
        .iter()
        .filter_map(|key| base64::engine::general_purpose::STANDARD.decode(key).ok())
        .find(|raw| ed25519_key_id(raw) == selector.signer_key_id)
        .ok_or(IntegrityFailure::UntrustedSigner)?;
    let message = format!(
        "{SIGNATURE_DOMAIN}{}",
        hex::encode(Sha256::digest(&manifest_bytes))
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(message.as_bytes(), &signature)
        .map_err(|_| IntegrityFailure::BadSignature)?;
    let manifest: BuildManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| malformed("manifest fields"))?;
    if manifest.signer_key_id != selector.signer_key_id {
        return Err(malformed("signer_key_id"));
    }
    validate_shape(&manifest)?;
    Ok(manifest)
}

fn validate_shape(manifest: &BuildManifest) -> Result<(), IntegrityFailure> {
    let malformed = |why: &str| Err(IntegrityFailure::ManifestMalformed(why.to_string()));
    if !is_lower_hex(&manifest.config_sha256, 64) {
        return malformed("config_sha256");
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
}

/// Module-measurement binding per platform. flutter_tools binds every
/// platform except Android, whose engine library reaches the build through
/// Gradle (P6); there the APK signer identity anchors the packaged library.
fn module_binding_required(platform: &str) -> bool {
    platform != "android"
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
    if manifest.contract_version != crate::security::SECURITY_CONTRACT_VERSION {
        return Err(IntegrityFailure::PolicyMismatch("contract_version"));
    }
    if manifest.security_profile != policy.profile.as_str() {
        return Err(IntegrityFailure::PolicyMismatch("security_profile"));
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

    match manifest
        .modules
        .iter()
        .find(|m| m.platform == platform && m.arch == arch)
    {
        Some(entry) => {
            let running = observer
                .running_module()
                .map_err(|e| IntegrityFailure::ModuleUnmeasurable(e.to_string()))?;
            if running.measurement != entry.measurement {
                return Err(IntegrityFailure::ModuleMismatch);
            }
        }
        None if module_binding_required(platform) => return Err(IntegrityFailure::ModuleUnbound),
        None => {}
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
    let result = evaluate(
        policy,
        source,
        crate::config::current_platform(),
        crate::config::current_arch(),
        &PlatformObserver { install_dir },
    );
    *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = match &result {
        Ok(()) => "ok",
        Err(failure) => failure.code(),
    };
    match &result {
        Ok(()) => shorebird_info!("Integrity check passed"),
        Err(failure) => shorebird_error!(
            "{}. Patches and protected keys are disabled; the bundled release runs. \
             Reinstall the app from its original source.",
            failure
        ),
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::module_measurement::RunningModule;
    use crate::security::tests::{hardened, hardened_yaml_text, TOOLCHAIN};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub const SEED: [u8; 32] = [7; 32];
    const OTHER_SEED: [u8; 32] = [9; 32];

    pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec()
    }

    pub fn public_key_b64(seed: &[u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(public_key(seed))
    }

    /// The hardened test policy with the test manifest key compiled in.
    pub fn hardened_with_key() -> CompiledPolicy {
        CompiledPolicy {
            build_manifest_keys: vec![public_key_b64(&SEED)],
            ..hardened()
        }
    }

    pub fn manifest_json(config: &str, modules: &str, identity: &str) -> String {
        format!(
            "{{\"schema\":\"{MANIFEST_SCHEMA}\",\"contract_version\":1,\
             \"security_profile\":\"hardened\",\"toolchain_id\":\"{TOOLCHAIN}\",\
             \"development_exceptions\":false,\"signer_key_id\":\"{}\",\
             \"config_sha256\":\"{}\",\"modules\":[{modules}],\"package_identity\":{identity}}}",
            ed25519_key_id(&public_key(&SEED)),
            hex::encode(Sha256::digest(config.as_bytes())),
        )
    }

    pub fn token(seed: &[u8; 32], manifest: &str) -> String {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let message = format!(
            "{SIGNATURE_DOMAIN}{}",
            hex::encode(Sha256::digest(manifest.as_bytes()))
        );
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{TOKEN_PREFIX}{}.{}",
            b64.encode(manifest),
            b64.encode(pair.sign(message.as_bytes()))
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

    struct Fake {
        module: Result<RunningModule, MeasureError>,
        signers: Result<Vec<String>, String>,
        team: Result<Option<String>, String>,
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
            text.replace(
                &format!("{MANIFEST_KEY}: v1."),
                &format!("{MANIFEST_KEY}: v2."),
            ),
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
            &ed25519_key_id(&public_key(&SEED)),
            &ed25519_key_id(&public_key(&OTHER_SEED)),
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
        // No compiled key at all trusts nothing.
        let policy = CompiledPolicy {
            build_manifest_keys: Vec::new(),
            ..hardened()
        };
        assert_eq!(
            evaluate(
                &policy,
                &split_source(&linux_text()),
                "linux",
                "x86_64",
                &Fake::new()
            ),
            Err(IntegrityFailure::UntrustedSigner)
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
                "\"contract_version\":1",
                "\"contract_version\":2",
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
        for (platform, arch) in [
            ("linux", "aarch64"),
            ("windows", "x86_64"),
            ("ios", "aarch64"),
            ("macos", "x86_64"),
        ] {
            assert_eq!(
                run(&text, platform, arch, &Fake::new()),
                Err(IntegrityFailure::ModuleUnbound)
            );
        }
        // Android binds the module when the build supplied it, and relies on
        // the APK signer otherwise.
        assert_eq!(run(&text, "android", "aarch64", &Fake::new()), Ok(()));
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

    /// The exact output of flutter_tools' `appendShorebirdBuildManifest` for
    /// a fixed key and input (`shorebird_build_manifest_test.dart`, "matches
    /// the token the updater verifies"). Proves the two implementations agree
    /// on the line format, the config digest, the key ID and the signature.
    const FLUTTER_TOOLS_OUTPUT: &str = concat!(
        "app_id: app\nbase_url: https://updates.example.com\n",
        "shorebird_build_manifest: ",
        "v1.eyJzY2hlbWEiOiJvcGVuLXNob3JlYmlyZC5idWlsZC1tYW5pZmVzdCIsImNvbnRyYWN0X3ZlcnNpb24iOjEsInNlY3VyaXR5X3Byb2ZpbGUiOiJoYXJkZW5lZCIsInRvb2xjaGFpbl9pZCI6InNoYTI1Njo3MDIyOWU0MDdlNTMxMTQwMWFhMzI1MTQxOGVmZjEwNjQ2N2E3NTBjY2ZjYjdlOGZlN2I2MWM0NDQyNzAwMDQwIiwiZGV2ZWxvcG1lbnRfZXhjZXB0aW9ucyI6ZmFsc2UsInNpZ25lcl9rZXlfaWQiOiJzaGEyNTY6ZmU4MTJjMTJmM2FiNGNlNmFjNWRiNjlhYzM1MmY5MDZjYjFiMTFlZjQzZmIzM2UyNTJlZjdmZjU1MjI2Mzg4OSIsImNvbmZpZ19zaGEyNTYiOiIwODRjOGQ2NTQyODRjMGZjZjkyZWQ5ZTgxNDE0YTE1ZGQxOTUzMjYxMmU2MzAxZDllMTg0ZTRlMGU2MjQyNmM0IiwibW9kdWxlcyI6W3sicGxhdGZvcm0iOiJsaW51eCIsImFyY2giOiJ4ODZfNjQiLCJtZWFzdXJlbWVudCI6InNoYTI1NjpmMTc3MTY5MjQ1MTg2YmU4ZTBmYTJlOGU2ZmZiOWRmNzBmOGRkMDgyNGM4ZjMwNWMwNmUxN2YzMGY2Mzk5MWNkIn1dLCJwYWNrYWdlX2lkZW50aXR5Ijp7ImFuZHJvaWRfc2lnbmluZ19jZXJ0X3NoYTI1NiI6W10sImFwcGxlX3RlYW1faWRzIjpbXX19.ZYBT71bqRnbCzQ61c36AO41gM27qCV_JTwJcMh0GCw8USHsg9wTsefmPQ3bbnZZQl96YEtgUZhIyUOLpi0xcCw\n",
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
        // The same build output under another compiled key is refused.
        let other = CompiledPolicy {
            build_manifest_keys: vec![public_key_b64(&OTHER_SEED)],
            ..hardened()
        };
        assert_eq!(
            evaluate(&other, &source, "linux", "x86_64", &fake),
            Err(IntegrityFailure::UntrustedSigner)
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
}
