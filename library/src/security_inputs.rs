// Parsing of the build-time security inputs (hardening contract v1,
// docs/HARDENING_CONTRACTS.md in the workspace, sections 2 and 7).
//
// This file is std-only on purpose: build.rs includes it with `#[path]` to
// validate the build environment and generate the compiled policy, and the
// library includes it as a module so the same rules are unit tested. A build
// with an invalid or reserved input fails; nothing at runtime can supply
// these values.

/// Build environment variable selecting the compiled profile.
pub const PROFILE_ENV: &str = "SHOREBIRD_SECURITY_PROFILE";
/// Build environment variable carrying the toolchain identity.
pub const TOOLCHAIN_ID_ENV: &str = "SHOREBIRD_TOOLCHAIN_ID";
/// Build environment variable enabling development-only exceptions.
pub const DEVELOPMENT_EXCEPTIONS_ENV: &str = "SHOREBIRD_SECURITY_DEVELOPMENT_EXCEPTIONS";
/// Build environment variable with comma-separated pinned trust-root key IDs.
pub const TRUST_ROOT_KEY_IDS_ENV: &str = "SHOREBIRD_TRUST_ROOT_KEY_IDS";

/// Retired by contract v2 (P3's bare build-manifest key list). A build that
/// still sets it fails with a pointer to the release root.
pub const BUILD_MANIFEST_KEYS_ENV: &str = "SHOREBIRD_BUILD_MANIFEST_KEYS";

/// Build environment variable with the release-root pin (hardening P4,
/// contract v2): the standard base64 of one `release-root` payload, exactly
/// as `scripts/release_trust.py pin` prints it. Required for hardened.
pub const RELEASE_ROOT_ENV: &str = "SHOREBIRD_RELEASE_ROOT";

/// Build environment variable with the lowest release-delegations version
/// this engine accepts (decimal, default 1). Raising it is how a revocation
/// or key rotation reaches devices.
pub const MIN_DELEGATIONS_VERSION_ENV: &str = "SHOREBIRD_RELEASE_MIN_DELEGATIONS_VERSION";

/// Every input; build.rs emits `rerun-if-env-changed` for each.
pub const ALL_ENV: [&str; 7] = [
    PROFILE_ENV,
    TOOLCHAIN_ID_ENV,
    DEVELOPMENT_EXCEPTIONS_ENV,
    TRUST_ROOT_KEY_IDS_ENV,
    RELEASE_ROOT_ENV,
    MIN_DELEGATIONS_VERSION_ENV,
    BUILD_MANIFEST_KEYS_ENV,
];

/// Public key of the committed DEVELOPMENT-ONLY release root
/// (`scripts/testdata/release-trust/root-1.DEVELOPMENT-ONLY.pem` in the
/// workspace). Its private half is public, so only a visibly development
/// build (development exceptions) may pin a root that contains it.
pub const DEVELOPMENT_ROOT_PUBLIC_KEYS: [&str; 1] =
    ["iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="];

const MAX_RELEASE_ROOT_BYTES: usize = 8 * 1024;

/// Validated build-time inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInputs {
    /// `"legacy"` or `"hardened"`.
    pub profile: &'static str,
    pub toolchain_id: Option<String>,
    pub development_exceptions: bool,
    pub trust_root_key_ids: Vec<String>,
    /// Base64 release-root payload (the pin); hardened only.
    pub release_root: Option<String>,
    /// Lowest accepted delegations version (1 when unset).
    pub min_delegations_version: u64,
}

/// Decodes standard padded base64 (std-only: build.rs shares this file).
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::new();
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut bits = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            let v = if i >= 4 - pad {
                0
            } else {
                ALPHABET.iter().position(|&a| a == b)? as u32
            };
            bits = (bits << 6) | v;
        }
        let decoded = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        out.extend_from_slice(&decoded[..3 - pad]);
    }
    // Canonical encodings only: re-encoding must give the same text.
    let mut canonical = String::new();
    for chunk in out.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                canonical.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                canonical.push('=');
            }
        }
    }
    (canonical == value).then_some(out)
}

/// True for `sha256:` followed by 64 lowercase hex digits.
pub fn is_sha256_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn unset(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// Validates the inputs; `get` returns a build environment variable. `None`
/// and the empty string both mean unset.
pub fn parse_compiled_inputs(
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<CompiledInputs, String> {
    let profile_value = get(PROFILE_ENV);
    let toolchain_value = get(TOOLCHAIN_ID_ENV);
    let development_value = get(DEVELOPMENT_EXCEPTIONS_ENV);
    let roots_value = get(TRUST_ROOT_KEY_IDS_ENV);
    let release_root_value = get(RELEASE_ROOT_ENV);
    let min_version_value = get(MIN_DELEGATIONS_VERSION_ENV);
    if unset(get(BUILD_MANIFEST_KEYS_ENV).as_deref()).is_some() {
        return Err(format!(
            "{BUILD_MANIFEST_KEYS_ENV} was replaced by {RELEASE_ROOT_ENV} in contract v2: \
             compile the release root (scripts/release_trust.py pin) and delegate the \
             build-manifest key under it"
        ));
    }
    let profile = profile_value.as_deref();
    let toolchain_id = toolchain_value.as_deref();
    let development_exceptions = development_value.as_deref();
    let trust_root_key_ids = roots_value.as_deref();
    let profile = match unset(profile) {
        None | Some("legacy") => "legacy",
        Some("hardened") => "hardened",
        Some("hardened-diversified") => {
            return Err(format!(
                "{PROFILE_ENV}=hardened-diversified is reserved and rejected by contract v1"
            ))
        }
        Some(other) => {
            return Err(format!(
                "{PROFILE_ENV} must be legacy or hardened, not {other:?}"
            ))
        }
    };
    let toolchain_id = match unset(toolchain_id) {
        None => None,
        Some(id) if is_sha256_id(id) => Some(id.to_string()),
        Some(id) => {
            return Err(format!(
                "{TOOLCHAIN_ID_ENV} must be sha256:<64 lowercase hex>, not {id:?}"
            ))
        }
    };
    let development_exceptions = match unset(development_exceptions) {
        None | Some("false") => false,
        Some("true") => true,
        Some(other) => {
            return Err(format!(
                "{DEVELOPMENT_EXCEPTIONS_ENV} must be true or false, not {other:?}"
            ))
        }
    };
    let mut root_ids: Vec<String> = Vec::new();
    if let Some(ids) = unset(trust_root_key_ids) {
        for id in ids.split(',') {
            if !is_sha256_id(id) {
                return Err(format!(
                    "{TRUST_ROOT_KEY_IDS_ENV} entries must be sha256:<64 lowercase hex>, not {id:?}"
                ));
            }
            if root_ids.iter().any(|known| known == id) {
                return Err(format!("{TRUST_ROOT_KEY_IDS_ENV} repeats {id}"));
            }
            root_ids.push(id.to_string());
        }
    }
    let trust_root_key_ids = root_ids;
    let release_root = match unset(release_root_value.as_deref()) {
        None => None,
        Some(pin) => {
            check_release_root(pin, development_exceptions)?;
            Some(pin.to_string())
        }
    };
    let min_delegations_version = match unset(min_version_value.as_deref()) {
        None => 1,
        Some(text) => match text.parse::<u64>() {
            Ok(n)
                if n >= 1 && text.bytes().all(|b| b.is_ascii_digit()) && !text.starts_with('0') =>
            {
                n
            }
            _ => {
                return Err(format!(
                    "{MIN_DELEGATIONS_VERSION_ENV} must be a positive decimal integer, not {text:?}"
                ))
            }
        },
    };
    if profile == "hardened" {
        if toolchain_id.is_none() {
            return Err(format!("A hardened updater requires {TOOLCHAIN_ID_ENV}"));
        }
        if release_root.is_none() {
            return Err(format!(
                "A hardened updater requires {RELEASE_ROOT_ENV} (the release-root pin)"
            ));
        }
    } else {
        if development_exceptions {
            return Err(format!(
                "{DEVELOPMENT_EXCEPTIONS_ENV}=true requires {PROFILE_ENV}=hardened"
            ));
        }
        if !trust_root_key_ids.is_empty() {
            return Err(format!(
                "{TRUST_ROOT_KEY_IDS_ENV} requires {PROFILE_ENV}=hardened"
            ));
        }
        if release_root.is_some() || min_version_value.as_deref().is_some_and(|v| !v.is_empty()) {
            return Err(format!(
                "{RELEASE_ROOT_ENV} and {MIN_DELEGATIONS_VERSION_ENV} require {PROFILE_ENV}=hardened"
            ));
        }
    }
    Ok(CompiledInputs {
        profile,
        toolchain_id,
        development_exceptions,
        trust_root_key_ids,
        release_root,
        min_delegations_version,
    })
}

/// Std-only checks of the release-root pin (the library parses it fully):
/// canonical base64 of a canonical-JSON contract v2 `release-root` payload,
/// and no DEVELOPMENT-ONLY key outside a development build.
fn check_release_root(pin: &str, development_exceptions: bool) -> Result<(), String> {
    let raw = decode_base64(pin)
        .filter(|raw| raw.len() <= MAX_RELEASE_ROOT_BYTES)
        .ok_or_else(|| format!("{RELEASE_ROOT_ENV} must be the base64 release-root payload"))?;
    let text = String::from_utf8(raw)
        .map_err(|_| format!("{RELEASE_ROOT_ENV} is not a UTF-8 JSON payload"))?;
    if !text.starts_with("{\"contract_version\":2,")
        || !text.contains("\"schema\":\"open-shorebird.release-root\"")
    {
        return Err(format!(
            "{RELEASE_ROOT_ENV} is not a canonical contract v2 release-root payload"
        ));
    }
    if !development_exceptions
        && DEVELOPMENT_ROOT_PUBLIC_KEYS
            .iter()
            .any(|key| text.contains(&format!("\"{key}\"")))
    {
        return Err(format!(
            "{RELEASE_ROOT_ENV} contains the DEVELOPMENT-ONLY release root key; only a \
             development build ({DEVELOPMENT_EXCEPTIONS_ENV}=true) may pin it"
        ));
    }
    Ok(())
}

/// Rust source for the generated compiled-policy constants. Deterministic for
/// the same inputs so the build stays reproducible.
pub fn render_compiled_policy(inputs: &CompiledInputs) -> String {
    let toolchain_id = match &inputs.toolchain_id {
        Some(id) => format!("Some({id:?})"),
        None => "None".to_string(),
    };
    let roots = inputs
        .trust_root_key_ids
        .iter()
        .map(|id| format!("{id:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let release_root = match &inputs.release_root {
        Some(pin) => format!("Some({pin:?})"),
        None => "None".to_string(),
    };
    format!(
        "// @generated by updater/library/build.rs from the SHOREBIRD_SECURITY_* build\n\
         // environment. Do not edit; nothing at runtime can override these values.\n\
         pub(crate) const COMPILED_SECURITY_PROFILE: &str = {:?};\n\
         pub(crate) const COMPILED_TOOLCHAIN_ID: Option<&str> = {toolchain_id};\n\
         pub(crate) const COMPILED_DEVELOPMENT_EXCEPTIONS: bool = {};\n\
         pub(crate) const COMPILED_TRUST_ROOT_KEY_IDS: &[&str] = &[{roots}];\n\
         pub(crate) const COMPILED_RELEASE_ROOT: Option<&str> = {release_root};\n\
         pub(crate) const COMPILED_MIN_DELEGATIONS_VERSION: u64 = {};\n",
        inputs.profile, inputs.development_exceptions, inputs.min_delegations_version,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sha256:70229e407e5311401aa3251418eff106467a750ccfcb7e8fe7b61c4442700040";

    /// An operator root (not the development key): canonical payload, base64.
    pub fn operator_root() -> String {
        let payload = "{\"contract_version\":2,\"expires_at\":\"2036-11-09T00:00:00Z\",\
             \"keys\":[{\"key_id\":\"sha256:6a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827\",\
             \"public_key\":\"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=\"}],\
             \"schema\":\"open-shorebird.release-root\",\"threshold\":1,\"version\":1}";
        encode(payload.as_bytes())
    }

    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buf = [0u8; 3];
            buf[..chunk.len()].copy_from_slice(chunk);
            let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn parse(values: &[(&str, &str)]) -> Result<CompiledInputs, String> {
        let owned: Vec<(String, String)> = values
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parse_compiled_inputs(&move |name: &str| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    fn hardened(
        extra: &[(&'static str, &'static str)],
        root: &str,
    ) -> Result<CompiledInputs, String> {
        let mut values = vec![
            (PROFILE_ENV, "hardened"),
            (TOOLCHAIN_ID_ENV, ID),
            (RELEASE_ROOT_ENV, root),
        ];
        values.extend_from_slice(extra);
        // Later entries win in `parse`'s lookup only if listed first; keep
        // overrides unique instead.
        let mut seen = Vec::new();
        values.retain(|(k, _)| {
            let keep = !seen.contains(k);
            seen.push(*k);
            keep
        });
        parse(&values)
    }

    #[test]
    fn unset_inputs_build_legacy() {
        for empty in [&[][..], &[(PROFILE_ENV, ""), (TOOLCHAIN_ID_ENV, "")][..]] {
            let inputs = parse(empty).unwrap();
            assert_eq!(inputs.profile, "legacy");
            assert_eq!(inputs.toolchain_id, None);
            assert!(!inputs.development_exceptions);
            assert!(inputs.trust_root_key_ids.is_empty());
            assert_eq!(inputs.release_root, None);
            assert_eq!(inputs.min_delegations_version, 1);
        }
    }

    #[test]
    fn hardened_requires_a_toolchain_identity() {
        let root = operator_root();
        assert!(parse(&[(PROFILE_ENV, "hardened"), (RELEASE_ROOT_ENV, &root)]).is_err());
        let inputs = hardened(&[(DEVELOPMENT_EXCEPTIONS_ENV, "false")], &root).unwrap();
        assert_eq!(inputs.profile, "hardened");
        assert_eq!(inputs.toolchain_id.as_deref(), Some(ID));
        assert_eq!(inputs.release_root.as_deref(), Some(root.as_str()));
    }

    #[test]
    fn reserved_and_unknown_profiles_fail_the_build() {
        let root = operator_root();
        for profile in ["hardened-diversified", "Hardened", "strict", " legacy"] {
            let values = [
                (PROFILE_ENV, profile),
                (TOOLCHAIN_ID_ENV, ID),
                (RELEASE_ROOT_ENV, root.as_str()),
            ];
            assert!(parse(&values).is_err(), "{profile}");
        }
    }

    #[test]
    fn malformed_identities_fail_the_build() {
        let root = operator_root();
        let upper = ID.to_uppercase();
        for id in [
            "sha256:ABC",
            upper.as_str(),
            &ID[..ID.len() - 1],
            "70229e40",
        ] {
            let values = [
                (PROFILE_ENV, "hardened"),
                (TOOLCHAIN_ID_ENV, id),
                (RELEASE_ROOT_ENV, root.as_str()),
            ];
            assert!(parse(&values).is_err());
        }
        let roots = format!("{ID},{ID}");
        let values = [
            (PROFILE_ENV, "hardened"),
            (TOOLCHAIN_ID_ENV, ID),
            (RELEASE_ROOT_ENV, root.as_str()),
            (TRUST_ROOT_KEY_IDS_ENV, roots.as_str()),
        ];
        assert!(parse(&values).is_err());
        assert!(hardened(&[(TRUST_ROOT_KEY_IDS_ENV, "sha256:1")], &root).is_err());
        let inputs = hardened(&[(TRUST_ROOT_KEY_IDS_ENV, ID)], &root).unwrap();
        assert_eq!(inputs.trust_root_key_ids, vec![ID.to_string()]);
    }

    #[test]
    fn hardened_only_options_cannot_be_built_into_legacy() {
        let root = operator_root();
        assert!(parse(&[(DEVELOPMENT_EXCEPTIONS_ENV, "true")]).is_err());
        assert!(parse(&[(PROFILE_ENV, "legacy"), (TRUST_ROOT_KEY_IDS_ENV, ID)]).is_err());
        assert!(parse(&[(PROFILE_ENV, "legacy"), (RELEASE_ROOT_ENV, &root)]).is_err());
        assert!(parse(&[(MIN_DELEGATIONS_VERSION_ENV, "2")]).is_err());
        assert!(hardened(&[(DEVELOPMENT_EXCEPTIONS_ENV, "yes")], &root).is_err());
        // Legacy may record its identity (contract: null or the build's ID).
        assert!(parse(&[(PROFILE_ENV, "legacy"), (TOOLCHAIN_ID_ENV, ID)]).is_ok());
    }

    #[test]
    fn rendering_is_deterministic_rust() {
        let root = operator_root();
        let inputs = hardened(
            &[
                (DEVELOPMENT_EXCEPTIONS_ENV, "true"),
                (TRUST_ROOT_KEY_IDS_ENV, ID),
                (MIN_DELEGATIONS_VERSION_ENV, "3"),
            ],
            &root,
        )
        .unwrap();
        let source = render_compiled_policy(&inputs);
        assert_eq!(source, render_compiled_policy(&inputs));
        assert!(source.contains("COMPILED_SECURITY_PROFILE: &str = \"hardened\";"));
        assert!(source.contains(&format!(
            "COMPILED_TOOLCHAIN_ID: Option<&str> = Some(\"{ID}\");"
        )));
        assert!(source.contains("COMPILED_DEVELOPMENT_EXCEPTIONS: bool = true;"));
        assert!(source.contains(&format!(
            "COMPILED_TRUST_ROOT_KEY_IDS: &[&str] = &[\"{ID}\"];"
        )));
        assert!(source.contains(&format!(
            "COMPILED_RELEASE_ROOT: Option<&str> = Some(\"{root}\");"
        )));
        assert!(source.contains("COMPILED_MIN_DELEGATIONS_VERSION: u64 = 3;"));
    }

    #[test]
    fn hardened_requires_a_valid_release_root_pin() {
        // P4: no hardened updater without a compiled release root.
        assert!(parse(&[(PROFILE_ENV, "hardened"), (TOOLCHAIN_ID_ENV, ID)]).is_err());
        assert!(hardened(&[], "").is_err());
        let not_root =
            encode(b"{\"contract_version\":2,\"schema\":\"open-shorebird.release-delegations\"}");
        let v1 = encode(b"{\"contract_version\":1,\"schema\":\"open-shorebird.release-root\"}");
        let pretty =
            encode(b"{ \"contract_version\": 2, \"schema\": \"open-shorebird.release-root\" }");
        let unpadded = operator_root().trim_end_matches('=').to_string();
        let huge = encode(&vec![b' '; MAX_RELEASE_ROOT_BYTES + 1]);
        for bad in [
            "AAAA",
            not_root.as_str(),
            v1.as_str(),
            pretty.as_str(),
            unpadded.as_str(),
            huge.as_str(),
            "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=", // a bare P3 key
        ] {
            assert!(hardened(&[], bad).is_err(), "{bad}");
        }
        for bad in ["0", "-1", "01", "x", "1.0"] {
            let root = operator_root();
            assert!(
                hardened(&[(MIN_DELEGATIONS_VERSION_ENV, bad)], &root).is_err(),
                "{bad}"
            );
        }
        let root = operator_root();
        let inputs = hardened(&[(MIN_DELEGATIONS_VERSION_ENV, "12")], &root).unwrap();
        assert_eq!(inputs.min_delegations_version, 12);
    }

    #[test]
    fn retired_build_manifest_keys_fail_the_build() {
        let root = operator_root();
        let error = hardened(
            &[(
                BUILD_MANIFEST_KEYS_ENV,
                "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
            )],
            &root,
        )
        .unwrap_err();
        assert!(error.contains(RELEASE_ROOT_ENV), "{error}");
        assert!(parse(&[(BUILD_MANIFEST_KEYS_ENV, "x")]).is_err());
    }

    #[test]
    fn development_root_needs_a_development_build() {
        // The committed DEVELOPMENT-ONLY root (scripts/release_trust.py pin
        // scripts/testdata/release-trust/root.v1.DEVELOPMENT-ONLY.json).
        let development = "eyJjb250cmFjdF92ZXJzaW9uIjoyLCJleHBpcmVzX2F0IjoiMjAzNi0xMS0wOVQwMDowMDowMFoiLCJrZXlzIjpbeyJrZXlfaWQiOiJzaGEyNTY6MzQ3NTBmOThiZDU5ZmNmYzk0NmRhNDVhYWFiZTkzM2JlMTU0YTRiNTA5NGUxYzRhYmY0Mjg2NjUwNWYzYzk3ZSIsInB1YmxpY19rZXkiOiJpb2pqM1hRSjhaWDlVdHN0UExwZGNzcG5DYjhkbEJJYjgzU0lBYlFQYjF3PSJ9XSwic2NoZW1hIjoib3Blbi1zaG9yZWJpcmQucmVsZWFzZS1yb290IiwidGhyZXNob2xkIjoxLCJ2ZXJzaW9uIjoxfQ==";
        let error = hardened(&[], development).unwrap_err();
        assert!(error.contains("DEVELOPMENT-ONLY"), "{error}");
        assert!(hardened(&[(DEVELOPMENT_EXCEPTIONS_ENV, "true")], development).is_ok());
    }
}
