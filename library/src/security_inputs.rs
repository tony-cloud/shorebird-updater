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

/// Every input; build.rs emits `rerun-if-env-changed` for each.
pub const ALL_ENV: [&str; 4] = [
    PROFILE_ENV,
    TOOLCHAIN_ID_ENV,
    DEVELOPMENT_EXCEPTIONS_ENV,
    TRUST_ROOT_KEY_IDS_ENV,
];

/// Validated build-time inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInputs {
    /// `"legacy"` or `"hardened"`.
    pub profile: &'static str,
    pub toolchain_id: Option<String>,
    pub development_exceptions: bool,
    pub trust_root_key_ids: Vec<String>,
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

/// Validates the four inputs. `None` and the empty string both mean unset.
pub fn parse_compiled_inputs(
    profile: Option<&str>,
    toolchain_id: Option<&str>,
    development_exceptions: Option<&str>,
    trust_root_key_ids: Option<&str>,
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
    if profile == "hardened" {
        if toolchain_id.is_none() {
            return Err(format!("A hardened updater requires {TOOLCHAIN_ID_ENV}"));
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
    }
    Ok(CompiledInputs {
        profile,
        toolchain_id,
        development_exceptions,
        trust_root_key_ids,
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
    format!(
        "// @generated by updater/library/build.rs from the SHOREBIRD_SECURITY_* build\n\
         // environment. Do not edit; nothing at runtime can override these values.\n\
         pub(crate) const COMPILED_SECURITY_PROFILE: &str = {:?};\n\
         pub(crate) const COMPILED_TOOLCHAIN_ID: Option<&str> = {toolchain_id};\n\
         pub(crate) const COMPILED_DEVELOPMENT_EXCEPTIONS: bool = {};\n\
         pub(crate) const COMPILED_TRUST_ROOT_KEY_IDS: &[&str] = &[{roots}];\n",
        inputs.profile, inputs.development_exceptions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sha256:70229e407e5311401aa3251418eff106467a750ccfcb7e8fe7b61c4442700040";

    #[test]
    fn unset_inputs_build_legacy() {
        for empty in [None, Some("")] {
            let inputs = parse_compiled_inputs(empty, empty, empty, empty).unwrap();
            assert_eq!(inputs.profile, "legacy");
            assert_eq!(inputs.toolchain_id, None);
            assert!(!inputs.development_exceptions);
            assert!(inputs.trust_root_key_ids.is_empty());
        }
    }

    #[test]
    fn hardened_requires_a_toolchain_identity() {
        assert!(parse_compiled_inputs(Some("hardened"), None, None, None).is_err());
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), Some("false"), None).unwrap();
        assert_eq!(inputs.profile, "hardened");
        assert_eq!(inputs.toolchain_id.as_deref(), Some(ID));
    }

    #[test]
    fn reserved_and_unknown_profiles_fail_the_build() {
        for profile in ["hardened-diversified", "Hardened", "strict", " legacy"] {
            assert!(
                parse_compiled_inputs(Some(profile), Some(ID), None, None).is_err(),
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
            assert!(parse_compiled_inputs(Some("hardened"), Some(id), None, None).is_err());
        }
        let roots = format!("{ID},{ID}");
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), None, Some(&roots)).is_err());
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), None, Some("sha256:1")).is_err());
        let inputs = parse_compiled_inputs(Some("hardened"), Some(ID), None, Some(ID)).unwrap();
        assert_eq!(inputs.trust_root_key_ids, vec![ID.to_string()]);
    }

    #[test]
    fn hardened_only_options_cannot_be_built_into_legacy() {
        assert!(parse_compiled_inputs(None, None, Some("true"), None).is_err());
        assert!(parse_compiled_inputs(Some("legacy"), None, None, Some(ID)).is_err());
        assert!(parse_compiled_inputs(Some("hardened"), Some(ID), Some("yes"), None).is_err());
        // Legacy may record its identity (contract v1: null or the build's ID).
        assert!(parse_compiled_inputs(Some("legacy"), Some(ID), None, None).is_ok());
    }

    #[test]
    fn rendering_is_deterministic_rust() {
        let inputs =
            parse_compiled_inputs(Some("hardened"), Some(ID), Some("true"), Some(ID)).unwrap();
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
    }
}
