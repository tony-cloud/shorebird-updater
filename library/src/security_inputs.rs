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

/// Build environment variable with comma-separated base64 raw 32-byte
/// Ed25519 public keys that may sign build manifests (hardening P3). A
/// hardened updater requires at least one.
pub const BUILD_MANIFEST_KEYS_ENV: &str = "SHOREBIRD_BUILD_MANIFEST_KEYS";

/// Every input; build.rs emits `rerun-if-env-changed` for each.
pub const ALL_ENV: [&str; 5] = [
    PROFILE_ENV,
    TOOLCHAIN_ID_ENV,
    DEVELOPMENT_EXCEPTIONS_ENV,
    TRUST_ROOT_KEY_IDS_ENV,
    BUILD_MANIFEST_KEYS_ENV,
];

/// Validated build-time inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInputs {
    /// `"legacy"` or `"hardened"`.
    pub profile: &'static str,
    pub toolchain_id: Option<String>,
    pub development_exceptions: bool,
    pub trust_root_key_ids: Vec<String>,
    /// Base64 (standard, padded) raw Ed25519 build-manifest public keys.
    pub build_manifest_keys: Vec<String>,
}

/// Decodes standard padded base64 (std-only: build.rs shares this file).
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
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

/// Validates the five inputs. `None` and the empty string both mean unset.
pub fn parse_compiled_inputs(
    profile: Option<&str>,
    toolchain_id: Option<&str>,
    development_exceptions: Option<&str>,
    trust_root_key_ids: Option<&str>,
    build_manifest_keys: Option<&str>,
) -> Result<CompiledInputs, String> {
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
    let mut manifest_keys: Vec<String> = Vec::new();
    if let Some(keys) = unset(build_manifest_keys) {
        for key in keys.split(',') {
            if decode_base64(key).is_none_or(|raw| raw.len() != 32) {
                return Err(format!(
                    "{BUILD_MANIFEST_KEYS_ENV} entries must be base64 raw 32-byte Ed25519 keys, not {key:?}"
                ));
            }
            if manifest_keys.iter().any(|known| known == key) {
                return Err(format!("{BUILD_MANIFEST_KEYS_ENV} repeats {key}"));
            }
            manifest_keys.push(key.to_string());
        }
    }
    let build_manifest_keys = manifest_keys;
    if profile == "hardened" {
        if toolchain_id.is_none() {
            return Err(format!("A hardened updater requires {TOOLCHAIN_ID_ENV}"));
        }
        if build_manifest_keys.is_empty() {
            return Err(format!(
                "A hardened updater requires {BUILD_MANIFEST_KEYS_ENV} (build-manifest signer)"
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
        if !build_manifest_keys.is_empty() {
            return Err(format!(
                "{BUILD_MANIFEST_KEYS_ENV} requires {PROFILE_ENV}=hardened"
            ));
        }
    }
    Ok(CompiledInputs {
        profile,
        toolchain_id,
        development_exceptions,
        trust_root_key_ids,
        build_manifest_keys,
    })
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
    let manifest_keys = inputs
        .build_manifest_keys
        .iter()
        .map(|key| format!("{key:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "// @generated by updater/library/build.rs from the SHOREBIRD_SECURITY_* build\n\
         // environment. Do not edit; nothing at runtime can override these values.\n\
         pub(crate) const COMPILED_SECURITY_PROFILE: &str = {:?};\n\
         pub(crate) const COMPILED_TOOLCHAIN_ID: Option<&str> = {toolchain_id};\n\
         pub(crate) const COMPILED_DEVELOPMENT_EXCEPTIONS: bool = {};\n\
         pub(crate) const COMPILED_TRUST_ROOT_KEY_IDS: &[&str] = &[{roots}];\n\
         pub(crate) const COMPILED_BUILD_MANIFEST_KEYS: &[&str] = &[{manifest_keys}];\n",
        inputs.profile, inputs.development_exceptions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sha256:70229e407e5311401aa3251418eff106467a750ccfcb7e8fe7b61c4442700040";
    const KEY: Option<&str> = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    #[test]
    fn unset_inputs_build_legacy() {
        for empty in [None, Some("")] {
            let inputs = parse_compiled_inputs(empty, empty, empty, empty, empty).unwrap();
            assert_eq!(inputs.profile, "legacy");
            assert_eq!(inputs.toolchain_id, None);
            assert!(!inputs.development_exceptions);
            assert!(inputs.trust_root_key_ids.is_empty());
        }
    }

    #[test]
    fn hardened_requires_a_toolchain_identity() {
        assert!(parse_compiled_inputs(Some("hardened"), None, None, None, KEY).is_err());
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), Some("false"), None, KEY).unwrap();
        assert_eq!(inputs.profile, "hardened");
        assert_eq!(inputs.toolchain_id.as_deref(), Some(ID));
    }

    #[test]
    fn reserved_and_unknown_profiles_fail_the_build() {
        for profile in ["hardened-diversified", "Hardened", "strict", " legacy"] {
            assert!(
                parse_compiled_inputs(Some(profile), Some(ID), None, None, KEY).is_err(),
                "{profile}"
            );
        }
    }

    #[test]
    fn malformed_identities_fail_the_build() {
        for id in [
            "sha256:ABC",
            &ID.to_uppercase(),
            &ID[..ID.len() - 1],
            "70229e40",
        ] {
            assert!(parse_compiled_inputs(Some("hardened"), Some(id), None, None, KEY).is_err());
        }
        let roots = format!("{ID},{ID}");
        assert!(
            parse_compiled_inputs(Some("hardened"), Some(ID), None, Some(&roots), KEY).is_err()
        );
        assert!(
            parse_compiled_inputs(Some("hardened"), Some(ID), None, Some("sha256:1"), KEY).is_err()
        );
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), None, Some(ID), KEY).unwrap();
        assert_eq!(inputs.trust_root_key_ids, vec![ID.to_string()]);
    }

    #[test]
    fn hardened_only_options_cannot_be_built_into_legacy() {
        assert!(parse_compiled_inputs(None, None, Some("true"), None, None).is_err());
        assert!(parse_compiled_inputs(Some("legacy"), None, None, Some(ID), None).is_err());
        assert!(parse_compiled_inputs(Some("legacy"), None, None, None, KEY).is_err());
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), Some("yes"), None, KEY).is_err());
        // Legacy may record its identity (contract v1: null or the build's ID).
        assert!(parse_compiled_inputs(Some("legacy"), Some(ID), None, None, None).is_ok());
    }

    #[test]
    fn rendering_is_deterministic_rust() {
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), Some("true"), Some(ID), KEY).unwrap();
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
            "COMPILED_BUILD_MANIFEST_KEYS: &[&str] = &[\"{}\"];",
            KEY.unwrap()
        )));
    }

    #[test]
    fn hardened_requires_a_valid_build_manifest_signer() {
        // P3: no hardened updater without a compiled manifest signer.
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), None, None, None).is_err());
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), None, None, Some("")).is_err());
        let two = format!(
            "{},{}",
            KEY.unwrap(),
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
        );
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), None, None, Some(&two)).unwrap();
        assert_eq!(inputs.build_manifest_keys.len(), 2);
        for bad in [
            "AAAA",                                          // 3 bytes
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   // unpadded
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",  // non-canonical
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-=",  // url alphabet
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert!(
                parse_compiled_inputs(Some("hardened"), Some(ID), None, None, Some(bad)).is_err(),
                "{bad}"
            );
        }
        let repeated = format!("{0},{0}", KEY.unwrap());
        assert!(
            parse_compiled_inputs(Some("hardened"), Some(ID), None, None, Some(&repeated)).is_err()
        );
    }
}
