//! Compiled security floor and release admission (hardening contract v1;
//! docs/HARDENING_CONTRACTS.md in the workspace, sections 2 and 7).
//!
//! The profile is fixed when the native release is built: `build.rs` turns
//! the `SHOREBIRD_SECURITY_*` build environment (set by the engine's GN args)
//! into constants. The bundled shorebird.yaml only *declares* a profile, and
//! [`admit`] compares that declaration with the compiled floor. YAML, Dart
//! and the network can never select or lower the compiled profile.
//!
//! `legacy` keeps today's behavior unchanged. `hardened` requires a trust
//! root, strict boot verification, signed responses, an explicit HTTPS
//! origin and a matching toolchain identity, and rejects any weaker knob.
use crate::security_inputs::is_sha256_id;
use crate::yaml::{
    DeclaredProfile, PatchResponseVerificationMode, PatchVerificationMode, YamlConfig,
};
use base64::Engine;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/compiled_security_policy.rs"));
}

/// The security contract a hardened bundle must declare (contract v2, P4:
/// the build manifest chains to a compiled release root).
pub const SECURITY_CONTRACT_VERSION: u32 = 2;

/// Declarations a legacy updater accepts. Legacy behavior does not depend on
/// the version; an unknown one still fails closed.
pub const KNOWN_CONTRACT_VERSIONS: [u32; 2] = [1, 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityProfile {
    Legacy,
    Hardened,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityProfile::Legacy => "legacy",
            SecurityProfile::Hardened => "hardened",
        }
    }
}

/// The policy compiled into this updater.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub profile: SecurityProfile,
    pub toolchain_id: Option<String>,
    /// Development-only: allows loopback HTTP. Requires a matching
    /// `security_development_exceptions: true` declaration, which release
    /// packaging never writes.
    pub development_exceptions: bool,
    /// Optional pinned trust-root key IDs. When non-empty, the bundled
    /// `patch_public_key` must be one of them.
    pub trust_root_key_ids: Vec<String>,
    /// The release-root pin (hardening P4, `crate::release_trust`): base64
    /// of one `release-root` payload. Hardened builds have one; legacy none.
    pub release_root: Option<String>,
    /// Lowest `release-delegations` version accepted (1 by default).
    pub min_delegations_version: u64,
}

/// How network requests are restricted under a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRule {
    /// Legacy: unchanged (any scheme, redirects followed).
    Unrestricted,
    /// Every request and every redirect hop must be HTTPS.
    HttpsOnly,
    /// Development exception: loopback HTTP allowed, redirects refused.
    LoopbackDevelopment,
}

impl CompiledPolicy {
    #[cfg(test)]
    pub fn legacy() -> Self {
        CompiledPolicy {
            profile: SecurityProfile::Legacy,
            toolchain_id: None,
            development_exceptions: false,
            trust_root_key_ids: Vec::new(),
            release_root: None,
            min_delegations_version: 1,
        }
    }

    pub fn is_hardened(&self) -> bool {
        self.profile == SecurityProfile::Hardened
    }

    /// Hardened releases never accept unsigned content.
    pub fn requires_signatures(&self) -> bool {
        self.is_hardened()
    }

    pub fn transport_rule(&self) -> TransportRule {
        match (self.profile, self.development_exceptions) {
            (SecurityProfile::Legacy, _) => TransportRule::Unrestricted,
            (SecurityProfile::Hardened, false) => TransportRule::HttpsOnly,
            (SecurityProfile::Hardened, true) => TransportRule::LoopbackDevelopment,
        }
    }
}

fn build_time_policy() -> CompiledPolicy {
    CompiledPolicy {
        // build.rs only ever emits "legacy" or "hardened".
        profile: if generated::COMPILED_SECURITY_PROFILE == "hardened" {
            SecurityProfile::Hardened
        } else {
            SecurityProfile::Legacy
        },
        toolchain_id: generated::COMPILED_TOOLCHAIN_ID.map(str::to_string),
        development_exceptions: generated::COMPILED_DEVELOPMENT_EXCEPTIONS,
        trust_root_key_ids: generated::COMPILED_TRUST_ROOT_KEY_IDS
            .iter()
            .map(|id| id.to_string())
            .collect(),
        release_root: generated::COMPILED_RELEASE_ROOT.map(str::to_string),
        min_delegations_version: generated::COMPILED_MIN_DELEGATIONS_VERSION,
    }
}

/// The compiled profile name, for the engine's cross-check.
pub fn compiled_profile_name() -> &'static str {
    generated::COMPILED_SECURITY_PROFILE
}

#[cfg(test)]
thread_local! {
    // Unit tests only (never compiled into a shipped library, including the
    // `test-hooks` cdylib): lets a test on this thread run under a hardened
    // floor without rebuilding the crate.
    static TEST_POLICY: std::cell::RefCell<Option<CompiledPolicy>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub fn testing_set_compiled_policy(policy: Option<CompiledPolicy>) {
    TEST_POLICY.with(|cell| *cell.borrow_mut() = policy);
}

/// The policy in force for this process.
pub fn compiled() -> CompiledPolicy {
    #[cfg(test)]
    if let Some(policy) = TEST_POLICY.with(|cell| cell.borrow().clone()) {
        return policy;
    }
    build_time_policy()
}

/// Why a configuration or request was refused. Messages never include keys,
/// signatures or URLs (download URLs can be bearer credentials).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityError {
    ReservedProfile,
    UnsupportedContractVersion(u32),
    ProfileMismatch {
        compiled: &'static str,
        declared: &'static str,
    },
    MissingContractVersion,
    MissingToolchainId,
    ToolchainMismatch,
    DevelopmentExceptionsMismatch,
    DuplicateKey(String),
    MissingTrustRoot,
    InvalidTrustRoot,
    UntrustedRoot,
    WeakerThanFloor(&'static str),
    MissingOrigin,
    InsecureOrigin,
    OriginCredentials,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::ReservedProfile => {
                write!(f, "security_profile hardened-diversified is reserved by contract v1")
            }
            SecurityError::UnsupportedContractVersion(v) => {
                write!(f, "unsupported security_contract_version {v}")
            }
            SecurityError::ProfileMismatch { compiled, declared } => write!(
                f,
                "security profile mismatch: updater compiled {compiled}, shorebird.yaml declares {declared}"
            ),
            SecurityError::MissingContractVersion => {
                write!(
                    f,
                    "hardened shorebird.yaml lacks security_contract_version: {SECURITY_CONTRACT_VERSION}"
                )
            }
            SecurityError::MissingToolchainId => {
                write!(f, "hardened shorebird.yaml lacks toolchain_id")
            }
            SecurityError::ToolchainMismatch => {
                write!(f, "toolchain_id differs from the compiled toolchain identity")
            }
            SecurityError::DevelopmentExceptionsMismatch => write!(
                f,
                "security_development_exceptions differs from the compiled policy"
            ),
            SecurityError::DuplicateKey(key) => {
                write!(f, "shorebird.yaml repeats key {key}")
            }
            SecurityError::MissingTrustRoot => {
                write!(f, "hardened release has no patch_public_key trust root")
            }
            SecurityError::InvalidTrustRoot => write!(f, "patch_public_key is not valid base64"),
            SecurityError::UntrustedRoot => {
                write!(f, "patch_public_key is not a compiled trust root")
            }
            SecurityError::WeakerThanFloor(key) => {
                write!(f, "{key} is weaker than the compiled hardened floor")
            }
            SecurityError::MissingOrigin => write!(f, "hardened release needs an explicit base_url"),
            SecurityError::InsecureOrigin => write!(f, "hardened releases require an https origin"),
            SecurityError::OriginCredentials => {
                write!(f, "hardened origins must not embed credentials")
            }
        }
    }
}

impl std::error::Error for SecurityError {}

/// Verification settings that admission grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub patch_verification: PatchVerificationMode,
    pub patch_response_verification: PatchResponseVerificationMode,
}

/// `sha256:` over the DER bytes of a base64 `patch_public_key`.
pub fn trust_root_key_id(patch_public_key: &str) -> Result<String, SecurityError> {
    use sha2::{Digest, Sha256};
    let der = base64::prelude::BASE64_STANDARD
        .decode(patch_public_key)
        .map_err(|_| SecurityError::InvalidTrustRoot)?;
    if der.is_empty() {
        return Err(SecurityError::InvalidTrustRoot);
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&der))))
}

/// Startup admission (contract v1 §2 matrix): compares the bundled
/// declaration with the compiled policy. Runs before any configuration is
/// published, so a refusal means no key is requested and no patch activates.
pub fn admit(policy: &CompiledPolicy, yaml: &YamlConfig) -> Result<Admitted, SecurityError> {
    // Declarations no compiled profile accepts (fail closed, contract §5.7).
    if yaml.security_profile == Some(DeclaredProfile::HardenedDiversified) {
        return Err(SecurityError::ReservedProfile);
    }
    if let Some(version) = yaml.security_contract_version {
        let supported = if policy.is_hardened() {
            version == SECURITY_CONTRACT_VERSION
        } else {
            KNOWN_CONTRACT_VERSIONS.contains(&version)
        };
        if !supported {
            return Err(SecurityError::UnsupportedContractVersion(version));
        }
    }
    if let Some(toolchain_id) = &policy.toolchain_id {
        if yaml
            .toolchain_id
            .as_ref()
            .is_some_and(|d| d != toolchain_id)
        {
            return Err(SecurityError::ToolchainMismatch);
        }
    }

    if !policy.is_hardened() {
        // Legacy: exactly today's behavior, unless the YAML claims a
        // stronger build than this updater is.
        if yaml.security_profile == Some(DeclaredProfile::Hardened) {
            return Err(SecurityError::ProfileMismatch {
                compiled: "legacy",
                declared: "hardened",
            });
        }
        if yaml.security_development_exceptions == Some(true) {
            return Err(SecurityError::DevelopmentExceptionsMismatch);
        }
        return Ok(Admitted {
            patch_verification: yaml.patch_verification.unwrap_or_default(),
            patch_response_verification: yaml.patch_response_verification.unwrap_or_default(),
        });
    }

    if let Some(key) = yaml.duplicate_keys.first() {
        return Err(SecurityError::DuplicateKey(key.clone()));
    }
    if yaml.security_profile != Some(DeclaredProfile::Hardened) {
        return Err(SecurityError::ProfileMismatch {
            compiled: "hardened",
            declared: yaml
                .security_profile
                .map_or("none", DeclaredProfile::as_str),
        });
    }
    if yaml.security_contract_version.is_none() {
        return Err(SecurityError::MissingContractVersion);
    }
    match (&yaml.toolchain_id, &policy.toolchain_id) {
        (None, _) => return Err(SecurityError::MissingToolchainId),
        (Some(declared), Some(compiled)) if declared == compiled && is_sha256_id(declared) => {}
        _ => return Err(SecurityError::ToolchainMismatch),
    }
    if yaml.security_development_exceptions.unwrap_or(false) != policy.development_exceptions {
        return Err(SecurityError::DevelopmentExceptionsMismatch);
    }

    let key = yaml
        .patch_public_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .ok_or(SecurityError::MissingTrustRoot)?;
    let key_id = trust_root_key_id(key)?;
    if !policy.trust_root_key_ids.is_empty() && !policy.trust_root_key_ids.contains(&key_id) {
        return Err(SecurityError::UntrustedRoot);
    }
    if yaml.patch_verification == Some(PatchVerificationMode::InstallOnly) {
        return Err(SecurityError::WeakerThanFloor("patch_verification"));
    }
    if yaml.patch_response_verification == Some(PatchResponseVerificationMode::Optional) {
        return Err(SecurityError::WeakerThanFloor(
            "patch_response_verification",
        ));
    }
    check_origin(
        policy,
        yaml.base_url
            .as_deref()
            .ok_or(SecurityError::MissingOrigin)?,
    )?;
    Ok(Admitted {
        patch_verification: PatchVerificationMode::Strict,
        patch_response_verification: PatchResponseVerificationMode::Required,
    })
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Whether `url` is an acceptable origin under `policy`. Legacy accepts any
/// URL (unchanged). Hardened requires `https://host` without credentials;
/// with development exceptions, `http://` to a loopback host is also allowed.
pub fn check_origin(policy: &CompiledPolicy, url: &str) -> Result<(), SecurityError> {
    if !policy.is_hardened() {
        return Ok(());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(SecurityError::InsecureOrigin);
    }
    let (scheme, rest) = url.split_once("://").ok_or(SecurityError::InsecureOrigin)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(SecurityError::OriginCredentials);
    }
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => (&authority[..=end], &authority[end + 1..]),
            None => return Err(SecurityError::InsecureOrigin),
        }
    } else {
        match authority.find(':') {
            Some(colon) => (&authority[..colon], &authority[colon..]),
            None => (authority, ""),
        }
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if host.is_empty() || host == "[]" || !port_ok {
        return Err(SecurityError::InsecureOrigin);
    }
    if scheme.eq_ignore_ascii_case("https")
        || (scheme.eq_ignore_ascii_case("http")
            && policy.development_exceptions
            && is_loopback_host(host))
    {
        Ok(())
    } else {
        Err(SecurityError::InsecureOrigin)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TOOLCHAIN: &str =
        "sha256:70229e407e5311401aa3251418eff106467a750ccfcb7e8fe7b61c4442700040";
    // Any base64 works as a trust root for admission; signature tests use a
    // real key.
    pub const KEY: &str = "AQID";

    pub fn hardened() -> CompiledPolicy {
        CompiledPolicy {
            profile: SecurityProfile::Hardened,
            toolchain_id: Some(TOOLCHAIN.to_string()),
            development_exceptions: false,
            trust_root_key_ids: Vec::new(),
            release_root: None,
            min_delegations_version: 1,
        }
    }

    /// A bundled shorebird.yaml exactly as the hardened build writes it.
    pub fn hardened_yaml_text() -> String {
        format!(
            "app_id: app\nbase_url: https://updates.example.com\npatch_public_key: {KEY}\n\
             patch_verification: strict\npatch_response_verification: required\n\
             security_profile: hardened\nsecurity_contract_version: 2\ntoolchain_id: {TOOLCHAIN}"
        )
    }

    fn yaml(text: &str) -> YamlConfig {
        YamlConfig::from_yaml(text).unwrap()
    }

    fn admit_text(policy: &CompiledPolicy, text: &str) -> Result<Admitted, SecurityError> {
        admit(policy, &yaml(text))
    }

    /// Replaces (or with `None`, removes) one line of the hardened YAML.
    fn edited(key: &str, value: Option<&str>) -> String {
        let mut lines: Vec<String> = hardened_yaml_text()
            .lines()
            .filter(|line| !line.starts_with(&format!("{key}:")))
            .map(str::to_string)
            .collect();
        if let Some(value) = value {
            lines.push(format!("{key}: {value}"));
        }
        lines.join("\n")
    }

    #[test]
    fn build_environment_selects_the_compiled_policy() {
        // A plain `cargo test` builds legacy. CI/verification also runs this
        // module with SHOREBIRD_SECURITY_PROFILE=hardened to prove build.rs
        // carries the inputs into the constants.
        let build_env = [
            (
                "SHOREBIRD_SECURITY_PROFILE",
                option_env!("SHOREBIRD_SECURITY_PROFILE"),
            ),
            (
                "SHOREBIRD_TOOLCHAIN_ID",
                option_env!("SHOREBIRD_TOOLCHAIN_ID"),
            ),
            (
                "SHOREBIRD_SECURITY_DEVELOPMENT_EXCEPTIONS",
                option_env!("SHOREBIRD_SECURITY_DEVELOPMENT_EXCEPTIONS"),
            ),
            (
                "SHOREBIRD_TRUST_ROOT_KEY_IDS",
                option_env!("SHOREBIRD_TRUST_ROOT_KEY_IDS"),
            ),
            (
                "SHOREBIRD_RELEASE_ROOT",
                option_env!("SHOREBIRD_RELEASE_ROOT"),
            ),
            (
                "SHOREBIRD_RELEASE_MIN_DELEGATIONS_VERSION",
                option_env!("SHOREBIRD_RELEASE_MIN_DELEGATIONS_VERSION"),
            ),
            (
                "SHOREBIRD_BUILD_MANIFEST_KEYS",
                option_env!("SHOREBIRD_BUILD_MANIFEST_KEYS"),
            ),
        ];
        let expected = crate::security_inputs::parse_compiled_inputs(&|name: &str| {
            build_env
                .iter()
                .find(|(n, _)| *n == name)
                .and_then(|(_, v)| v.map(str::to_string))
        })
        .unwrap();
        let policy = build_time_policy();
        assert_eq!(policy.profile.as_str(), expected.profile);
        assert_eq!(compiled_profile_name(), expected.profile);
        assert_eq!(policy.toolchain_id, expected.toolchain_id);
        assert_eq!(
            policy.development_exceptions,
            expected.development_exceptions
        );
        assert_eq!(policy.trust_root_key_ids, expected.trust_root_key_ids);
        assert_eq!(policy.release_root, expected.release_root);
        assert_eq!(
            policy.min_delegations_version,
            expected.min_delegations_version
        );
        if option_env!("SHOREBIRD_SECURITY_PROFILE").is_none() {
            assert_eq!(policy, CompiledPolicy::legacy());
        }
    }

    #[test]
    fn hardened_accepts_the_build_output_and_forces_the_floor() {
        let admitted = admit_text(&hardened(), &hardened_yaml_text()).unwrap();
        assert_eq!(admitted.patch_verification, PatchVerificationMode::Strict);
        assert_eq!(
            admitted.patch_response_verification,
            PatchResponseVerificationMode::Required
        );
        // Omitting a verification key does not lower it: the floor applies.
        let admitted = admit_text(
            &hardened(),
            &edited("patch_response_verification", None)
                .replace("patch_verification: strict\n", ""),
        )
        .unwrap();
        assert_eq!(
            admitted.patch_response_verification,
            PatchResponseVerificationMode::Required
        );
    }

    #[test]
    fn hardened_rejects_missing_or_invalid_trust_root() {
        // With the build's explicit `patch_response_verification: required`,
        // the parser itself already refuses a key-less file.
        assert!(YamlConfig::from_yaml(&edited("patch_public_key", None)).is_err());
        // Without it, admission still refuses: the floor needs a trust root.
        let no_root =
            edited("patch_public_key", None).replace("patch_response_verification: required\n", "");
        assert_eq!(
            admit_text(&hardened(), &no_root),
            Err(SecurityError::MissingTrustRoot)
        );
        assert_eq!(
            admit_text(
                &hardened(),
                &edited("patch_public_key", Some("   "))
                    .replace("patch_response_verification: required\n", "")
            ),
            Err(SecurityError::MissingTrustRoot)
        );
        assert_eq!(
            admit_text(&hardened(), &edited("patch_public_key", Some("not*base64"))),
            Err(SecurityError::InvalidTrustRoot)
        );
    }

    #[test]
    fn compiled_trust_roots_pin_the_bundled_key() {
        let mut policy = hardened();
        policy.trust_root_key_ids = vec![trust_root_key_id("BAUG").unwrap()];
        assert_eq!(
            admit_text(&policy, &hardened_yaml_text()),
            Err(SecurityError::UntrustedRoot)
        );
        policy
            .trust_root_key_ids
            .push(trust_root_key_id(KEY).unwrap());
        assert!(admit_text(&policy, &hardened_yaml_text()).is_ok());
    }

    #[test]
    fn trust_root_key_id_matches_contract_definition() {
        // sha256 over the base64-decoded DER bytes [1, 2, 3].
        assert_eq!(
            trust_root_key_id(KEY).unwrap(),
            "sha256:039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
        );
    }

    #[test]
    fn tampered_yaml_cannot_lower_the_hardened_floor() {
        // install_only next to the build's `required` fails in the parser;
        // with the response key removed as well, admission refuses it.
        assert!(
            YamlConfig::from_yaml(&edited("patch_verification", Some("install_only"))).is_err()
        );
        assert_eq!(
            admit_text(
                &hardened(),
                &edited("patch_verification", Some("install_only"))
                    .replace("patch_response_verification: required\n", "")
            ),
            Err(SecurityError::WeakerThanFloor("patch_verification"))
        );
        assert_eq!(
            admit_text(
                &hardened(),
                &edited("patch_response_verification", Some("optional"))
            ),
            Err(SecurityError::WeakerThanFloor(
                "patch_response_verification"
            ))
        );
        // Downgrading the declaration itself is a profile mismatch.
        for declared in [None, Some("legacy")] {
            assert!(matches!(
                admit_text(&hardened(), &edited("security_profile", declared)),
                Err(SecurityError::ProfileMismatch {
                    compiled: "hardened",
                    ..
                })
            ));
        }
        // A repeated key cannot smuggle a second, weaker value.
        let duplicated = format!("{}\npatch_verification: strict", hardened_yaml_text());
        assert_eq!(
            admit_text(&hardened(), &duplicated),
            Err(SecurityError::DuplicateKey(
                "patch_verification".to_string()
            ))
        );
        // Development exceptions cannot be switched on from YAML.
        assert_eq!(
            admit_text(
                &hardened(),
                &edited("security_development_exceptions", Some("true"))
            ),
            Err(SecurityError::DevelopmentExceptionsMismatch)
        );
    }

    #[test]
    fn hardened_rejects_incompatible_identity_and_versions() {
        let other = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            admit_text(&hardened(), &edited("toolchain_id", Some(&other))),
            Err(SecurityError::ToolchainMismatch)
        );
        assert_eq!(
            admit_text(&hardened(), &edited("toolchain_id", None)),
            Err(SecurityError::MissingToolchainId)
        );
        assert_eq!(
            admit_text(&hardened(), &edited("security_contract_version", None)),
            Err(SecurityError::MissingContractVersion)
        );
        // Contract v1 (a P1-P3 bundle with a bare manifest key) and unknown
        // versions are refused by a contract v2 hardened updater.
        for (version, number) in [("1", 1), ("3", 3)] {
            assert_eq!(
                admit_text(
                    &hardened(),
                    &edited("security_contract_version", Some(version))
                ),
                Err(SecurityError::UnsupportedContractVersion(number))
            );
        }
        assert_eq!(
            admit_text(
                &hardened(),
                &edited("security_profile", Some("hardened-diversified"))
            ),
            Err(SecurityError::ReservedProfile)
        );
    }

    #[test]
    fn legacy_accepts_known_contract_versions_only() {
        let legacy = CompiledPolicy::legacy();
        for version in ["1", "2"] {
            assert!(admit_text(
                &legacy,
                &format!("app_id: app\nsecurity_contract_version: {version}")
            )
            .is_ok());
        }
        assert_eq!(
            admit_text(&legacy, "app_id: app\nsecurity_contract_version: 3"),
            Err(SecurityError::UnsupportedContractVersion(3))
        );
    }

    #[test]
    fn hardened_rejects_http_and_ambiguous_origins() {
        for (url, error) in [
            ("http://updates.example.com", SecurityError::InsecureOrigin),
            ("http://localhost:8080", SecurityError::InsecureOrigin),
            ("ftp://updates.example.com", SecurityError::InsecureOrigin),
            ("https://", SecurityError::InsecureOrigin),
            ("https://:443", SecurityError::InsecureOrigin),
            ("https://host:port", SecurityError::InsecureOrigin),
            ("updates.example.com", SecurityError::InsecureOrigin),
            (
                "https://user:pw@updates.example.com",
                SecurityError::OriginCredentials,
            ),
            (
                "https://@updates.example.com",
                SecurityError::OriginCredentials,
            ),
        ] {
            assert_eq!(
                admit_text(&hardened(), &edited("base_url", Some(url))),
                Err(error),
                "{url}"
            );
        }
        // The legacy default (http://localhost:8080) never applies: hardened
        // needs an explicit origin.
        assert_eq!(
            admit_text(&hardened(), &edited("base_url", None)),
            Err(SecurityError::MissingOrigin)
        );
        for url in [
            "https://updates.example.com",
            "HTTPS://updates.example.com:8443/base",
            "https://[2001:db8::1]:443",
        ] {
            assert!(
                admit_text(&hardened(), &edited("base_url", Some(url))).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn development_exception_allows_only_loopback_http() {
        let mut policy = hardened();
        policy.development_exceptions = true;
        let dev =
            |url: &str| edited("base_url", Some(url)) + "\nsecurity_development_exceptions: true";
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(admit_text(&policy, &dev(url)).is_ok(), "{url}");
        }
        for url in [
            "http://example.com",
            "http://10.0.2.2:8080",
            "http://127.0.0.1.example.com",
        ] {
            assert_eq!(
                admit_text(&policy, &dev(url)),
                Err(SecurityError::InsecureOrigin),
                "{url}"
            );
        }
        // A development updater refuses a production declaration, so release
        // packaging (which never writes the key) cannot ship on it.
        assert_eq!(
            admit_text(&policy, &hardened_yaml_text()),
            Err(SecurityError::DevelopmentExceptionsMismatch)
        );
        assert_eq!(policy.transport_rule(), TransportRule::LoopbackDevelopment);
        assert_eq!(hardened().transport_rule(), TransportRule::HttpsOnly);
    }

    #[test]
    fn legacy_admits_todays_configurations_unchanged() {
        let legacy = CompiledPolicy::legacy();
        assert_eq!(legacy.transport_rule(), TransportRule::Unrestricted);
        for (text, verification, response) in [
            (
                "app_id: a",
                PatchVerificationMode::Strict,
                PatchResponseVerificationMode::Optional,
            ),
            (
                "app_id: a\nbase_url: http://localhost:8080\npatch_verification: install_only",
                PatchVerificationMode::InstallOnly,
                PatchResponseVerificationMode::Optional,
            ),
            (
                "app_id: a\npatch_public_key: AQID\npatch_response_verification: required",
                PatchVerificationMode::Strict,
                PatchResponseVerificationMode::Required,
            ),
            // Duplicates keep their last-wins legacy meaning.
            (
                "app_id: a\npatch_verification: strict\npatch_verification: install_only",
                PatchVerificationMode::InstallOnly,
                PatchResponseVerificationMode::Optional,
            ),
            (
                "app_id: a\nsecurity_profile: legacy",
                PatchVerificationMode::Strict,
                PatchResponseVerificationMode::Optional,
            ),
        ] {
            assert_eq!(
                admit_text(&legacy, text),
                Ok(Admitted {
                    patch_verification: verification,
                    patch_response_verification: response
                }),
                "{text}"
            );
        }
        assert!(check_origin(&legacy, "http://example.com").is_ok());
    }

    #[test]
    fn legacy_updater_refuses_a_hardened_declaration() {
        assert_eq!(
            admit_text(&CompiledPolicy::legacy(), &hardened_yaml_text()),
            Err(SecurityError::ProfileMismatch {
                compiled: "legacy",
                declared: "hardened"
            })
        );
        assert_eq!(
            admit_text(
                &CompiledPolicy::legacy(),
                "app_id: a\nsecurity_development_exceptions: true"
            ),
            Err(SecurityError::DevelopmentExceptionsMismatch)
        );
        assert_eq!(
            admit_text(
                &CompiledPolicy::legacy(),
                "app_id: a\nsecurity_profile: hardened-diversified"
            ),
            Err(SecurityError::ReservedProfile)
        );
    }

    #[test]
    fn error_messages_do_not_leak_urls_or_keys() {
        let secret = "https://user:token@cdn.example.com/bearer";
        let error = admit_text(&hardened(), &edited("base_url", Some(secret))).unwrap_err();
        assert!(!error.to_string().contains("token"));
        assert!(!error.to_string().contains(KEY));
    }
}
