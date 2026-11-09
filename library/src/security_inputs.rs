// Parsing of the build-time security inputs (hardening contracts v1-v3,
// docs/HARDENING_CONTRACTS.md in the workspace, sections 2, 7, 10 and 11).
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

/// Build environment variable with the diversification profile (hardening
/// P5, contract v3): the standard base64 of the canonical profile JSON, the
/// value of the Dart GN arg `dart_bytecode_profile`. Required exactly for
/// `hardened-diversified`.
pub const DIVERSIFICATION_PROFILE_ENV: &str = "SHOREBIRD_DIVERSIFICATION_PROFILE";

/// Every input; build.rs emits `rerun-if-env-changed` for each.
pub const ALL_ENV: [&str; 8] = [
    PROFILE_ENV,
    TOOLCHAIN_ID_ENV,
    DEVELOPMENT_EXCEPTIONS_ENV,
    TRUST_ROOT_KEY_IDS_ENV,
    RELEASE_ROOT_ENV,
    MIN_DELEGATIONS_VERSION_ENV,
    BUILD_MANIFEST_KEYS_ENV,
    DIVERSIFICATION_PROFILE_ENV,
];

/// Public key of the committed DEVELOPMENT-ONLY release root
/// (`scripts/testdata/release-trust/root-1.DEVELOPMENT-ONLY.pem` in the
/// workspace). Its private half is public, so only a visibly development
/// build (development exceptions) may pin a root that contains it.
pub const DEVELOPMENT_ROOT_PUBLIC_KEYS: [&str; 1] =
    ["iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="];

const MAX_RELEASE_ROOT_BYTES: usize = 8 * 1024;

/// ID of the committed DEVELOPMENT-ONLY diversification profile
/// (`scripts/testdata/diversification/profile.DEVELOPMENT-ONLY.json` in the
/// workspace). Its seed is public, so only a development build may use it.
pub const DEVELOPMENT_DIVERSIFICATION_PROFILE_IDS: [&str; 1] =
    ["sha256:832856d0bed27833434e3f26b65d03cedc313f9850c2577ca7565c4dc644f46d"];

/// Longest accepted encoded profile (base64 characters), shared with GN and
/// `scripts/diversification_profile.py`.
pub const MAX_ENCODED_PROFILE: usize = 8192;

/// A derived permutation has about one fixed point besides `Trap`; this many
/// means a hand-made or degenerate map (contract §11.2).
pub const MAX_FIXED_POINTS: usize = 16;

/// Validated build-time inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledInputs {
    /// `"legacy"`, `"hardened"` or `"hardened-diversified"`.
    pub profile: &'static str,
    pub toolchain_id: Option<String>,
    pub development_exceptions: bool,
    pub trust_root_key_ids: Vec<String>,
    /// Base64 release-root payload (the pin); hardened only.
    pub release_root: Option<String>,
    /// Lowest accepted delegations version (1 when unset).
    pub min_delegations_version: u64,
    /// `sha256:` ID of the diversification profile; diversified only.
    pub diversification_profile_id: Option<String>,
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
    let diversification_value = get(DIVERSIFICATION_PROFILE_ENV);
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
        Some("hardened-diversified") => "hardened-diversified",
        Some(other) => {
            return Err(format!(
                "{PROFILE_ENV} must be legacy, hardened or hardened-diversified, not {other:?}"
            ))
        }
    };
    let hardened = profile != "legacy";
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
    // hardened-diversified is hardened for every P1-P4 rule (contract §11.5).
    if hardened {
        if toolchain_id.is_none() {
            return Err(format!("A {profile} updater requires {TOOLCHAIN_ID_ENV}"));
        }
        if release_root.is_none() {
            return Err(format!(
                "A {profile} updater requires {RELEASE_ROOT_ENV} (the release-root pin)"
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
    let diversification_profile_id = match unset(diversification_value.as_deref()) {
        None if profile == "hardened-diversified" => {
            return Err(format!(
                "A hardened-diversified updater requires {DIVERSIFICATION_PROFILE_ENV} \
                 (the dart_bytecode_profile GN arg)"
            ))
        }
        None => None,
        Some(_) if profile != "hardened-diversified" => {
            return Err(format!(
                "{DIVERSIFICATION_PROFILE_ENV} requires {PROFILE_ENV}=hardened-diversified"
            ))
        }
        Some(encoded) => Some(check_diversification_profile(
            encoded,
            development_exceptions,
        )?),
    };
    Ok(CompiledInputs {
        profile,
        toolchain_id,
        development_exceptions,
        trust_root_key_ids,
        release_root,
        min_delegations_version,
        diversification_profile_id,
    })
}

// Canonical JSON of a contract v3 diversification profile: sorted keys, no
// whitespace, exactly these fields and constants. A valid profile has exactly
// one encoding, so matching it literally refuses whitespace, unsorted or
// duplicate keys, extra or missing fields and a non-null native_layout.
const PROFILE_HEAD: &str = "{\"bytecode\":{\"format_version\":3,\"opcode_table_sha256\":\"";
const PROFILE_SCHEME: &str = "\",\"scheme\":\"opcode-permutation-v1\",\"wire_opcodes\":[";
const PROFILE_TAIL: &str = "]},\"contract_version\":3,\"native_layout\":null,\
     \"schema\":\"open-shorebird.diversification-profile\"}";

/// Parses canonical profile bytes and returns `wire_opcodes`, enforcing the
/// rules beyond the schema (contract §11.2): a permutation of `0..N-1` with
/// `2 <= N <= 256`, `Trap` (index 0) on wire byte 0, and fewer than
/// [`MAX_FIXED_POINTS`] fixed points besides `Trap`.
pub fn parse_diversification_profile(text: &str) -> Result<Vec<u8>, String> {
    let not_canonical = || {
        format!(
            "{DIVERSIFICATION_PROFILE_ENV} is not the canonical JSON of a contract v3 \
             diversification profile (sorted keys, no whitespace, exact fields, \
             native_layout null)"
        )
    };
    let rest = text.strip_prefix(PROFILE_HEAD).ok_or_else(not_canonical)?;
    let (table_hash, rest) = rest.split_at_checked(64).ok_or_else(not_canonical)?;
    if !table_hash
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(not_canonical());
    }
    let list = rest
        .strip_prefix(PROFILE_SCHEME)
        .and_then(|rest| rest.strip_suffix(PROFILE_TAIL))
        .ok_or_else(not_canonical)?;
    let mut wires = Vec::new();
    for item in list.split(',') {
        let canonical = !item.is_empty()
            && item.bytes().all(|b| b.is_ascii_digit())
            && (item == "0" || !item.starts_with('0'));
        match item.parse::<u8>() {
            Ok(wire) if canonical => wires.push(wire),
            _ => {
                return Err(format!(
                    "{DIVERSIFICATION_PROFILE_ENV}: wire_opcodes must be integers 0..255"
                ))
            }
        }
    }
    let count = wires.len();
    if !(2..=256).contains(&count) {
        return Err(format!(
            "{DIVERSIFICATION_PROFILE_ENV}: wire_opcodes must have 2 to 256 entries"
        ));
    }
    let mut seen = [false; 256];
    for &wire in &wires {
        if usize::from(wire) >= count || std::mem::replace(&mut seen[usize::from(wire)], true) {
            return Err(format!(
                "{DIVERSIFICATION_PROFILE_ENV}: wire_opcodes must be a permutation of 0..N-1"
            ));
        }
    }
    if wires[0] != 0 {
        return Err(format!(
            "{DIVERSIFICATION_PROFILE_ENV}: Trap (wire_opcodes[0]) must keep wire byte 0"
        ));
    }
    let fixed = (1..count).filter(|&i| usize::from(wires[i]) == i).count();
    if fixed >= MAX_FIXED_POINTS {
        return Err(format!(
            "{DIVERSIFICATION_PROFILE_ENV}: {fixed} fixed points; a derived profile has about \
             one (at most {} allowed)",
            MAX_FIXED_POINTS - 1
        ));
    }
    Ok(wires)
}

/// Validates the encoded profile (canonical base64 of canonical JSON, at most
/// [`MAX_ENCODED_PROFILE`] characters) and returns its `sha256:` profile ID.
/// The DEVELOPMENT-ONLY profile needs development exceptions.
pub fn check_diversification_profile(
    encoded: &str,
    development_exceptions: bool,
) -> Result<String, String> {
    if encoded.len() > MAX_ENCODED_PROFILE {
        return Err(format!(
            "{DIVERSIFICATION_PROFILE_ENV} exceeds {MAX_ENCODED_PROFILE} characters"
        ));
    }
    let raw = decode_base64(encoded).ok_or_else(|| {
        format!("{DIVERSIFICATION_PROFILE_ENV} must be the canonical base64 profile encoding")
    })?;
    let text = String::from_utf8(raw)
        .map_err(|_| format!("{DIVERSIFICATION_PROFILE_ENV} is not UTF-8 JSON"))?;
    parse_diversification_profile(&text)?;
    let id = format!("sha256:{}", sha256_hex(text.as_bytes()));
    if !development_exceptions && DEVELOPMENT_DIVERSIFICATION_PROFILE_IDS.contains(&id.as_str()) {
        return Err(format!(
            "{DIVERSIFICATION_PROFILE_ENV} is the DEVELOPMENT-ONLY diversification profile, \
             whose seed is public; only a development build \
             ({DEVELOPMENT_EXCEPTIONS_ENV}=true) may use it"
        ));
    }
    Ok(id)
}

/// Lowercase hex SHA-256 (FIPS 180-4). std-only because build.rs shares this
/// file and has no crypto dependency; tests pin it to the `sha2` crate.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *state = state.wrapping_add(value);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
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
    let diversification_profile_id = match &inputs.diversification_profile_id {
        Some(id) => format!("Some({id:?})"),
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
         pub(crate) const COMPILED_MIN_DELEGATIONS_VERSION: u64 = {};\n\
         pub(crate) const COMPILED_DIVERSIFICATION_PROFILE_ID: Option<&str> = \
         {diversification_profile_id};\n",
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
            assert_eq!(inputs.diversification_profile_id, None);
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
        // hardened-diversified without its profile fails as well (P5).
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
        assert!(source.contains("COMPILED_DIVERSIFICATION_PROFILE_ID: Option<&str> = None;"));
        let profile = operator_profile();
        let inputs = diversified(&[], &root, &profile).unwrap();
        let source = render_compiled_policy(&inputs);
        assert!(source.contains("COMPILED_SECURITY_PROFILE: &str = \"hardened-diversified\";"));
        assert!(source.contains(&format!(
            "COMPILED_DIVERSIFICATION_PROFILE_ID: Option<&str> = Some(\"{}\");",
            inputs.diversification_profile_id.as_deref().unwrap()
        )));
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

    /// The committed DEVELOPMENT-ONLY profile as `scripts/diversification_profile.py
    /// gn-args scripts/testdata/diversification/profile.DEVELOPMENT-ONLY.json`
    /// prints it (`dart_bytecode_profile`).
    pub const DEVELOPMENT_PROFILE: &str = "eyJieXRlY29kZSI6eyJmb3JtYXRfdmVyc2lvbiI6Mywib3Bjb2RlX3RhYmxlX3NoYTI1NiI6IjE0ZWQ4NWZhODkxZDdhN2FkYmYwZTEzOTg2MjIyMzM4YjI4ZDA3YzdlODIxMGY2Nzk4MzlkZjkwY2QxNzkzMzgiLCJzY2hlbWUiOiJvcGNvZGUtcGVybXV0YXRpb24tdjEiLCJ3aXJlX29wY29kZXMiOlswLDE1MCw2NSwyLDQ0LDEyNiw3MCw5MywxNDksMTQyLDY4LDM1LDE2OCwxNTcsMTQ1LDg0LDgwLDEzNSwxMSw4OSwxMjAsOTcsMTY3LDE3MCw2Niw4NiwxMzAsMTU4LDE0NywzMCwxNjQsMTU5LDgzLDcxLDEwNiwxMTYsOTUsNTYsNjcsMTQ4LDg1LDIzLDMsMTUyLDEyMiwxNjMsNTksMTA3LDE4LDMxLDE0MSwxMjksMTM0LDkxLDEwMSwxNiw3NywxMTUsNzksMTIxLDY0LDgxLDk4LDM4LDczLDEwOCwxNjYsOTIsNDksMTE3LDEzNiwyMSw1MywxMzMsMjIsMTI1LDE2Miw4LDYzLDE0NCw4OCwxNzMsMTU0LDgyLDE2OSwxNDMsNjksNzgsMTEzLDM2LDQ3LDc2LDEzLDYyLDExMSw1Miw1LDEzOSw2MCwxMjgsMTUzLDEwMCwxNTYsMzQsMTAzLDE0NiwzMiwxNzEsOSwzNywyNSw1NSw4NywxMDIsOTQsMzksNTAsNzQsOTAsMTEwLDUxLDcsMTYwLDk5LDk2LDI2LDEwNSw1NCw0MSwxMDQsNDMsNCwyNCwyOCwxMzIsNjEsMTksMTY1LDQwLDQ1LDcyLDE2MSwxNTEsNiwxMCw1NywxNSwxMDksMTI0LDExOSwxMiwxNCwyOSwxNzUsMTcsMTM4LDExNCwyNywxMjcsMSwxNTUsMTc0LDEzMSwxMjMsNDgsMTcyLDMzLDU4LDc1LDExMiwxMzcsMjAsNDYsMTE4LDE0MCw0Ml19LCJjb250cmFjdF92ZXJzaW9uIjozLCJuYXRpdmVfbGF5b3V0IjpudWxsLCJzY2hlbWEiOiJvcGVuLXNob3JlYmlyZC5kaXZlcnNpZmljYXRpb24tcHJvZmlsZSJ9";
    pub const DEVELOPMENT_PROFILE_ID: &str =
        "sha256:832856d0bed27833434e3f26b65d03cedc313f9850c2577ca7565c4dc644f46d";
    const TABLE: &str = "14ed85fa891d7a7adbf0e13986222338b28d07c7e8210f679839df90cd179338";

    /// Canonical profile JSON with these wire bytes.
    pub fn profile_json(wires: &[usize]) -> String {
        let list = wires
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"bytecode\":{{\"format_version\":3,\"opcode_table_sha256\":\"{TABLE}\",\
             \"scheme\":\"opcode-permutation-v1\",\"wire_opcodes\":[{list}]}},\
             \"contract_version\":3,\"native_layout\":null,\
             \"schema\":\"open-shorebird.diversification-profile\"}}"
        )
    }

    /// A non-development permutation of 176 opcodes: Trap at 0, every other
    /// opcode moved one place (no fixed points).
    pub fn operator_wires() -> Vec<usize> {
        let mut wires = vec![0];
        wires.extend((1..176).map(|i| if i == 175 { 1 } else { i + 1 }));
        wires
    }

    pub fn operator_profile() -> String {
        encode(profile_json(&operator_wires()).as_bytes())
    }

    fn diversified(
        extra: &[(&'static str, &'static str)],
        root: &str,
        profile: &str,
    ) -> Result<CompiledInputs, String> {
        let mut values = vec![(PROFILE_ENV, "hardened-diversified")];
        values.extend_from_slice(extra);
        values.extend_from_slice(&[
            (TOOLCHAIN_ID_ENV, ID),
            (RELEASE_ROOT_ENV, root),
            (DIVERSIFICATION_PROFILE_ENV, profile),
        ]);
        let mut seen = Vec::new();
        values.retain(|(k, _)| {
            let keep = !seen.contains(k);
            seen.push(*k);
            keep
        });
        parse(&values)
    }

    #[test]
    fn std_sha256_matches_the_sha2_crate() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        for len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(
                sha256_hex(&data),
                hex::encode(Sha256::digest(&data)),
                "{len}"
            );
        }
    }

    #[test]
    fn diversified_compiles_the_profile_id() {
        let root = operator_root();
        let profile = operator_profile();
        let inputs = diversified(&[], &root, &profile).unwrap();
        assert_eq!(inputs.profile, "hardened-diversified");
        assert_eq!(inputs.toolchain_id.as_deref(), Some(ID));
        assert_eq!(inputs.release_root.as_deref(), Some(root.as_str()));
        assert_eq!(
            inputs.diversification_profile_id,
            Some(format!(
                "sha256:{}",
                sha256_hex(profile_json(&operator_wires()).as_bytes())
            ))
        );
        // The Python reference and this parser agree on the committed
        // DEVELOPMENT-ONLY profile and its id.
        let inputs = diversified(
            &[(DEVELOPMENT_EXCEPTIONS_ENV, "true")],
            &root,
            DEVELOPMENT_PROFILE,
        )
        .unwrap();
        assert_eq!(
            inputs.diversification_profile_id.as_deref(),
            Some(DEVELOPMENT_PROFILE_ID)
        );
    }

    #[test]
    fn diversified_has_every_hardened_requirement() {
        let root = operator_root();
        let profile = operator_profile();
        let missing = |drop: &str| {
            let values: Vec<(&str, &str)> = [
                (PROFILE_ENV, "hardened-diversified"),
                (TOOLCHAIN_ID_ENV, ID),
                (RELEASE_ROOT_ENV, root.as_str()),
                (DIVERSIFICATION_PROFILE_ENV, profile.as_str()),
            ]
            .into_iter()
            .filter(|(k, _)| *k != drop)
            .collect();
            parse(&values)
        };
        for drop in [
            TOOLCHAIN_ID_ENV,
            RELEASE_ROOT_ENV,
            DIVERSIFICATION_PROFILE_ENV,
        ] {
            let error = missing(drop).unwrap_err();
            assert!(error.contains(drop), "{error}");
        }
        assert!(missing("none").is_ok());
        // The retired key list fails a diversified build too.
        assert!(diversified(&[(BUILD_MANIFEST_KEYS_ENV, "x")], &root, &profile).is_err());
    }

    #[test]
    fn diversification_profile_is_refused_outside_diversified() {
        let root = operator_root();
        let profile = operator_profile();
        assert!(parse(&[(DIVERSIFICATION_PROFILE_ENV, &profile)]).is_err());
        assert!(parse(&[
            (PROFILE_ENV, "legacy"),
            (DIVERSIFICATION_PROFILE_ENV, &profile)
        ])
        .is_err());
        let error = parse(&[
            (PROFILE_ENV, "hardened"),
            (TOOLCHAIN_ID_ENV, ID),
            (RELEASE_ROOT_ENV, &root),
            (DIVERSIFICATION_PROFILE_ENV, &profile),
        ])
        .unwrap_err();
        assert!(error.contains("hardened-diversified"), "{error}");
    }

    #[test]
    fn development_profile_needs_a_development_build() {
        let root = operator_root();
        let error = diversified(&[], &root, DEVELOPMENT_PROFILE).unwrap_err();
        assert!(error.contains("DEVELOPMENT-ONLY"), "{error}");
        assert!(diversified(
            &[(DEVELOPMENT_EXCEPTIONS_ENV, "true")],
            &root,
            DEVELOPMENT_PROFILE
        )
        .is_ok());
    }

    #[test]
    fn malformed_diversification_profiles_fail_the_build() {
        let root = operator_root();
        let good = profile_json(&operator_wires());
        let wires = |w: &[usize]| profile_json(w);
        let identity: Vec<usize> = (0..176).collect();
        // Exactly 16 fixed points besides Trap: refused; 15: accepted.
        let mut sixteen = operator_wires();
        for i in 1..=16 {
            sixteen[i] = i;
        }
        // Keep it a permutation: the displaced values form one cycle.
        let rest: Vec<usize> = (17..176).collect();
        for (k, i) in rest.iter().enumerate() {
            sixteen[*i] = if k + 1 < rest.len() {
                rest[k + 1]
            } else {
                rest[0]
            };
        }
        let mut fifteen = sixteen.clone();
        fifteen.swap(16, 17);
        let mut swapped_trap = operator_wires();
        swapped_trap.swap(0, 1);
        let mut repeated = operator_wires();
        repeated[5] = repeated[6];
        let too_many: Vec<usize> = (0..257).map(|i| if i == 0 { 0 } else { 257 - i }).collect();
        let cases: Vec<(&str, String)> = vec![
            ("pretty", good.replace(",\"", ", \"")),
            ("trailing newline", format!("{good}\n")),
            (
                "unsorted",
                good.replace(
                    "\"contract_version\":3,\"native_layout\":null,",
                    "\"native_layout\":null,\"contract_version\":3,",
                ),
            ),
            (
                "duplicate key",
                good.replace(
                    "\"contract_version\":3,",
                    "\"contract_version\":3,\"contract_version\":3,",
                ),
            ),
            ("extra field", good.replacen("{", "{\"a\":1,", 1)),
            (
                "native layout",
                good.replace("\"native_layout\":null", "\"native_layout\":{}"),
            ),
            (
                "contract",
                good.replace("\"contract_version\":3", "\"contract_version\":2"),
            ),
            (
                "scheme",
                good.replace("opcode-permutation-v1", "opcode-permutation-v2"),
            ),
            (
                "format",
                good.replace("\"format_version\":3", "\"format_version\":4"),
            ),
            (
                "schema",
                good.replace("diversification-profile", "diversification-seed"),
            ),
            ("table hash", good.replace(TABLE, &TABLE.to_uppercase())),
            ("short table hash", good.replace(TABLE, &TABLE[1..])),
            ("leading zero", good.replace("[0,2,", "[0,02,")),
            ("negative", good.replace("[0,2,", "[0,-2,")),
            ("float", good.replace("[0,2,", "[0,2.0,")),
            ("empty entry", good.replace("[0,2,", "[0,,2,")),
            ("one opcode", wires(&[0])),
            ("too many opcodes", wires(&too_many)),
            ("trap moved", wires(&swapped_trap)),
            ("not a permutation", wires(&repeated)),
            ("out of range", wires(&[0, 2])),
            ("identity", wires(&identity)),
            ("sixteen fixed points", wires(&sixteen)),
        ];
        for (name, json) in &cases {
            assert!(
                diversified(&[], &root, &encode(json.as_bytes())).is_err(),
                "{name}"
            );
        }
        assert!(diversified(&[], &root, &encode(wires(&fifteen).as_bytes())).is_ok());
        assert!(diversified(&[], &root, &encode(wires(&[0, 1]).as_bytes())).is_ok());
        let encoded = encode(good.as_bytes());
        let unpadded = encode(&good.as_bytes()[..good.len() - 1])
            .trim_end_matches('=')
            .to_string();
        let huge = encode(&vec![b' '; MAX_ENCODED_PROFILE]);
        // Unused low bits set in the last character before the padding: the
        // same bytes, but not the canonical text.
        let padded = encode(wires(&[0, 1]).as_bytes());
        assert!(padded.ends_with('='));
        let at = padded.find('=').unwrap() - 1;
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let next = alphabet.as_bytes()[alphabet.find(&padded[at..=at]).unwrap() + 1] as char;
        let non_canonical = format!("{}{next}{}", &padded[..at], &padded[at + 1..]);
        assert!(diversified(&[], &root, &padded).is_ok());
        for (name, bad) in [
            ("unpadded", unpadded.as_str()),
            ("non-canonical padding bits", non_canonical.as_str()),
            ("whitespace", &format!("{encoded}\n")),
            ("oversized", huge.as_str()),
            ("not base64", "not base64!"),
        ] {
            assert!(diversified(&[], &root, bad).is_err(), "{name}");
        }
    }
}
