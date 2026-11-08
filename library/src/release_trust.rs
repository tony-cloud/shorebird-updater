//! Release root of trust (hardening contract v2, stage P4;
//! `docs/HARDENING_CONTRACTS.md` §10 in the workspace).
//!
//! A hardened engine compiles one version of the operator's offline release
//! root: the exact canonical payload bytes of a `release-root` document
//! (GN `shorebird_release_root`) and a floor on the delegations version
//! (GN `shorebird_release_min_delegations_version`). The bundled build
//! manifest carries a `release-trust` bundle:
//!
//! * `root_chain`: root versions, oldest first. Entries at or below the
//!   compiled version are skipped; each later one must be the next version
//!   and be signed by thresholds of both the previous and its own keys.
//! * `delegations`: signed by a threshold of the final root, naming the keys
//!   of each signing role and every revoked key.
//!
//! Every envelope is `{"payload": base64(bytes), "signatures": [...]}` and a
//! signature covers `<domain><hex SHA-256 of the payload bytes>` with one
//! domain per document type. Expiry and key validity windows are enforced by
//! the signing tools, never here: a startup must not depend on the device
//! clock. Revocation and rotation reach a device through the compiled
//! delegations floor of a newer native release.
use crate::integrity::IntegrityFailure;
use crate::security_inputs::is_sha256_id;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const ROOT_SCHEMA: &str = "open-shorebird.release-root";
pub const DELEGATIONS_SCHEMA: &str = "open-shorebird.release-delegations";
pub const TRUST_SCHEMA: &str = "open-shorebird.release-trust";
pub const CONTRACT_VERSION: u32 = 2;
pub const ROOT_SIGNATURE_DOMAIN: &str = "open-shorebird.release-root-signature.v2:";
pub const DELEGATIONS_SIGNATURE_DOMAIN: &str = "open-shorebird.release-delegations-signature.v2:";
const MAX_ROOT_CHAIN: usize = 16;
const MAX_KEYS: usize = 32;
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024;

/// The signing roles a delegations document names. A key belongs to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    BuildManifest,
    ArtifactCatalog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeSignature {
    key_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootDocument {
    schema: String,
    contract_version: u32,
    version: u64,
    threshold: usize,
    keys: Vec<KeyEntry>,
    #[allow(dead_code)]
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegatedKey {
    key_id: String,
    public_key: String,
    #[allow(dead_code)]
    not_before: String,
    #[allow(dead_code)]
    not_after: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roles {
    #[serde(rename = "build-manifest")]
    build_manifest: Vec<DelegatedKey>,
    #[serde(rename = "artifact-catalog")]
    artifact_catalog: Vec<DelegatedKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationsDocument {
    schema: String,
    contract_version: u32,
    version: u64,
    root_version: u64,
    #[allow(dead_code)]
    issued_at: String,
    #[allow(dead_code)]
    expires_at: String,
    roles: Roles,
    revoked_key_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundle {
    schema: String,
    contract_version: u32,
    root_chain: Vec<Envelope>,
    delegations: Envelope,
}

/// A public key whose ID was recomputed from its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    id: String,
    raw: Vec<u8>,
}

struct Root {
    version: u64,
    threshold: usize,
    keys: Vec<Key>,
}

/// The outcome of [`verify_bundle`]: the delegations in force, authorized by
/// the compiled root through the bundle's root chain.
#[derive(Debug)]
pub struct VerifiedTrust {
    pub root_version: u64,
    pub delegations_version: u64,
    /// SHA-256 of the delegations payload bytes; the build manifest binds it.
    pub delegations_sha256: [u8; 32],
    root_key_ids: Vec<String>,
    build_manifest: Vec<Key>,
    artifact_catalog: Vec<Key>,
    revoked_key_ids: Vec<String>,
}

fn malformed(why: &str) -> IntegrityFailure {
    IntegrityFailure::TrustMalformed(why.to_string())
}

/// `sha256:` over a raw 32-byte Ed25519 public key.
pub fn key_id(raw: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(raw)))
}

/// Standard padded base64, canonical encodings only.
fn decode_b64(value: &str, what: &str) -> Result<Vec<u8>, IntegrityFailure> {
    let engine = base64::engine::general_purpose::STANDARD;
    let raw = engine.decode(value).map_err(|_| malformed(what))?;
    if engine.encode(&raw) != value {
        return Err(malformed(what));
    }
    Ok(raw)
}

fn parse_keys<'a>(
    entries: impl Iterator<Item = (&'a str, &'a str)>,
    what: &str,
) -> Result<Vec<Key>, IntegrityFailure> {
    let mut keys: Vec<Key> = Vec::new();
    for (id, public) in entries {
        let raw = decode_b64(public, what)?;
        if raw.len() != 32 || !is_sha256_id(id) || key_id(&raw) != id {
            return Err(malformed(what));
        }
        if keys.iter().any(|k| k.id == id) {
            return Err(malformed(what));
        }
        keys.push(Key {
            id: id.to_string(),
            raw,
        });
    }
    if keys.len() > MAX_KEYS {
        return Err(malformed(what));
    }
    Ok(keys)
}

fn parse_root(payload: &[u8]) -> Result<Root, IntegrityFailure> {
    let document: RootDocument =
        serde_json::from_slice(payload).map_err(|_| malformed("release root"))?;
    if document.schema != ROOT_SCHEMA || document.contract_version != CONTRACT_VERSION {
        return Err(malformed("release root schema"));
    }
    let keys = parse_keys(
        document
            .keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.public_key.as_str())),
        "release root keys",
    )?;
    if document.version == 0
        || keys.is_empty()
        || document.threshold == 0
        || document.threshold > keys.len()
    {
        return Err(malformed("release root threshold"));
    }
    Ok(Root {
        version: document.version,
        threshold: document.threshold,
        keys,
    })
}

/// `(key ID, signature)` pairs of an envelope.
type Signatures = Vec<(String, Vec<u8>)>;

/// (payload bytes, signatures) after shape checks.
fn open(envelope: &Envelope, what: &str) -> Result<(Vec<u8>, Signatures), IntegrityFailure> {
    let payload = decode_b64(&envelope.payload, what)?;
    if envelope.signatures.is_empty() {
        return Err(malformed(what));
    }
    let mut signatures: Signatures = Vec::new();
    for entry in &envelope.signatures {
        let signature = decode_b64(&entry.signature, what)?;
        if signature.len() != 64
            || !is_sha256_id(&entry.key_id)
            || signatures.iter().any(|(id, _)| id == &entry.key_id)
        {
            return Err(malformed(what));
        }
        signatures.push((entry.key_id.clone(), signature));
    }
    Ok((payload, signatures))
}

fn message(domain: &str, payload: &[u8]) -> Vec<u8> {
    format!("{domain}{}", hex::encode(Sha256::digest(payload))).into_bytes()
}

/// Distinct authorized keys whose signature verifies. Signatures by other
/// keys are ignored, so a rotation document can carry old and new keys.
fn count_valid(
    domain: &str,
    payload: &[u8],
    signatures: &[(String, Vec<u8>)],
    keys: &[Key],
) -> usize {
    let message = message(domain, payload);
    signatures
        .iter()
        .filter(|(id, signature)| {
            keys.iter().find(|k| &k.id == id).is_some_and(|key| {
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key.raw)
                    .verify(&message, signature)
                    .is_ok()
            })
        })
        .count()
}

/// Verifies `bundle` against the compiled root payload and delegations floor.
pub fn verify_bundle(
    pinned_root: &[u8],
    min_delegations_version: u64,
    bundle: &[u8],
) -> Result<VerifiedTrust, IntegrityFailure> {
    let mut root = parse_root(pinned_root).map_err(|_| malformed("compiled release root"))?;
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(malformed("release trust size"));
    }
    let bundle: TrustBundle =
        serde_json::from_slice(bundle).map_err(|_| malformed("release trust"))?;
    if bundle.schema != TRUST_SCHEMA || bundle.contract_version != CONTRACT_VERSION {
        return Err(malformed("release trust schema"));
    }
    if bundle.root_chain.len() > MAX_ROOT_CHAIN {
        return Err(malformed("root chain length"));
    }
    for envelope in &bundle.root_chain {
        let (payload, signatures) = open(envelope, "root chain")?;
        let next = parse_root(&payload)?;
        if next.version <= root.version {
            continue;
        }
        if next.version != root.version + 1 {
            return Err(IntegrityFailure::TrustUnverified("root chain gap"));
        }
        if count_valid(ROOT_SIGNATURE_DOMAIN, &payload, &signatures, &root.keys) < root.threshold
            || count_valid(ROOT_SIGNATURE_DOMAIN, &payload, &signatures, &next.keys)
                < next.threshold
        {
            return Err(IntegrityFailure::TrustUnverified("root rotation"));
        }
        root = next;
    }

    let (payload, signatures) = open(&bundle.delegations, "delegations")?;
    let delegations: DelegationsDocument =
        serde_json::from_slice(&payload).map_err(|_| malformed("delegations"))?;
    if delegations.schema != DELEGATIONS_SCHEMA
        || delegations.contract_version != CONTRACT_VERSION
        || delegations.version == 0
    {
        return Err(malformed("delegations schema"));
    }
    if delegations.root_version != root.version {
        return Err(IntegrityFailure::TrustUnverified(
            "delegations root version",
        ));
    }
    if count_valid(
        DELEGATIONS_SIGNATURE_DOMAIN,
        &payload,
        &signatures,
        &root.keys,
    ) < root.threshold
    {
        return Err(IntegrityFailure::TrustUnverified("delegations signature"));
    }
    if delegations.version < min_delegations_version {
        return Err(IntegrityFailure::TrustRollback);
    }

    let role_keys = |entries: &[DelegatedKey]| {
        parse_keys(
            entries
                .iter()
                .map(|k| (k.key_id.as_str(), k.public_key.as_str())),
            "delegated keys",
        )
    };
    let build_manifest = role_keys(&delegations.roles.build_manifest)?;
    let artifact_catalog = role_keys(&delegations.roles.artifact_catalog)?;
    // Role separation: no key in two roles, no root key in a role, no
    // revoked key delegated. The signing tools refuse to produce such a
    // document; a device refuses to rely on one.
    let root_key_ids: Vec<String> = root.keys.iter().map(|k| k.id.clone()).collect();
    for key in build_manifest.iter().chain(&artifact_catalog) {
        if root_key_ids.contains(&key.id) || delegations.revoked_key_ids.contains(&key.id) {
            return Err(malformed("role separation"));
        }
    }
    if build_manifest
        .iter()
        .any(|k| artifact_catalog.iter().any(|o| o.id == k.id))
    {
        return Err(malformed("role separation"));
    }
    if !delegations
        .revoked_key_ids
        .iter()
        .all(|id| is_sha256_id(id))
    {
        return Err(malformed("revoked key IDs"));
    }
    Ok(VerifiedTrust {
        root_version: root.version,
        delegations_version: delegations.version,
        delegations_sha256: Sha256::digest(&payload).into(),
        root_key_ids,
        build_manifest,
        artifact_catalog,
        revoked_key_ids: delegations.revoked_key_ids,
    })
}

impl VerifiedTrust {
    /// The raw public key `key_id` may use for `role`, or the typed reason
    /// it may not: revoked, delegated for another role (or a root key), or
    /// not delegated at all.
    pub fn role_key(&self, role: Role, key_id: &str) -> Result<&[u8], IntegrityFailure> {
        if self.revoked_key_ids.iter().any(|id| id == key_id) {
            return Err(IntegrityFailure::SignerRevoked);
        }
        let (own, other) = match role {
            Role::BuildManifest => (&self.build_manifest, &self.artifact_catalog),
            Role::ArtifactCatalog => (&self.artifact_catalog, &self.build_manifest),
        };
        if let Some(key) = own.iter().find(|k| k.id == key_id) {
            return Ok(&key.raw);
        }
        if other.iter().any(|k| k.id == key_id) || self.root_key_ids.iter().any(|id| id == key_id) {
            return Err(IntegrityFailure::SignerRole);
        }
        Err(IntegrityFailure::UntrustedSigner)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub const ROOT_SEED: [u8; 32] = [1; 32];
    pub const NEXT_ROOT_SEED: [u8; 32] = [2; 32];
    pub const MANIFEST_SEED: [u8; 32] = [7; 32];
    pub const NEXT_MANIFEST_SEED: [u8; 32] = [8; 32];
    pub const CATALOG_SEED: [u8; 32] = [3; 32];
    pub const STRANGER_SEED: [u8; 32] = [9; 32];

    pub fn public(seed: &[u8; 32]) -> Vec<u8> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec()
    }

    pub fn id(seed: &[u8; 32]) -> String {
        key_id(&public(seed))
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn key_json(seed: &[u8; 32]) -> String {
        format!(
            "{{\"key_id\":\"{}\",\"public_key\":\"{}\"}}",
            id(seed),
            b64(&public(seed))
        )
    }

    fn delegated_json(seed: &[u8; 32]) -> String {
        format!(
            "{{\"key_id\":\"{}\",\"not_after\":\"2036-11-01T00:00:00Z\",\
             \"not_before\":\"2026-11-01T00:00:00Z\",\"public_key\":\"{}\"}}",
            id(seed),
            b64(&public(seed))
        )
    }

    /// Canonical root payload (sorted keys, as the Python tool writes it).
    pub fn root_payload(version: u64, threshold: usize, seeds: &[[u8; 32]]) -> String {
        let keys: Vec<String> = seeds.iter().map(key_json).collect();
        format!(
            "{{\"contract_version\":2,\"expires_at\":\"2036-11-09T00:00:00Z\",\"keys\":[{}],\
             \"schema\":\"{ROOT_SCHEMA}\",\"threshold\":{threshold},\"version\":{version}}}",
            keys.join(",")
        )
    }

    pub fn delegations_payload(
        version: u64,
        root_version: u64,
        manifest: &[[u8; 32]],
        catalog: &[[u8; 32]],
        revoked: &[String],
    ) -> String {
        let list = |seeds: &[[u8; 32]]| {
            seeds
                .iter()
                .map(delegated_json)
                .collect::<Vec<_>>()
                .join(",")
        };
        let revoked: Vec<String> = revoked.iter().map(|id| format!("\"{id}\"")).collect();
        format!(
            "{{\"contract_version\":2,\"expires_at\":\"2036-11-01T00:00:00Z\",\
             \"issued_at\":\"2026-11-01T00:00:00Z\",\"revoked_key_ids\":[{}],\
             \"roles\":{{\"artifact-catalog\":[{}],\"build-manifest\":[{}]}},\
             \"root_version\":{root_version},\"schema\":\"{DELEGATIONS_SCHEMA}\",\"version\":{version}}}",
            revoked.join(","),
            list(catalog),
            list(manifest)
        )
    }

    pub fn envelope(domain: &str, payload: &str, signers: &[[u8; 32]]) -> String {
        let signatures: Vec<String> = signers
            .iter()
            .map(|seed| {
                let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
                format!(
                    "{{\"key_id\":\"{}\",\"signature\":\"{}\"}}",
                    id(seed),
                    b64(pair.sign(&message(domain, payload.as_bytes())).as_ref())
                )
            })
            .collect();
        format!(
            "{{\"payload\":\"{}\",\"signatures\":[{}]}}",
            b64(payload.as_bytes()),
            signatures.join(",")
        )
    }

    pub fn trust_bundle(root_chain: &[String], delegations: &str) -> String {
        format!(
            "{{\"contract_version\":2,\"delegations\":{delegations},\"root_chain\":[{}],\
             \"schema\":\"{TRUST_SCHEMA}\"}}",
            root_chain.join(",")
        )
    }

    /// The default test trust: root v1 ([1;32]) delegating the manifest key
    /// [7;32] and the catalog key [3;32].
    pub fn default_root() -> String {
        root_payload(1, 1, &[ROOT_SEED])
    }

    pub fn default_delegations() -> String {
        delegations_payload(1, 1, &[MANIFEST_SEED], &[CATALOG_SEED], &[])
    }

    pub fn default_bundle() -> String {
        trust_bundle(
            &[envelope(
                ROOT_SIGNATURE_DOMAIN,
                &default_root(),
                &[ROOT_SEED],
            )],
            &envelope(
                DELEGATIONS_SIGNATURE_DOMAIN,
                &default_delegations(),
                &[ROOT_SEED],
            ),
        )
    }

    fn verify(bundle: &str) -> Result<VerifiedTrust, IntegrityFailure> {
        verify_bundle(default_root().as_bytes(), 1, bundle.as_bytes())
    }

    #[test]
    fn verifies_a_bundle_under_the_compiled_root() {
        let trust = verify(&default_bundle()).unwrap();
        assert_eq!(trust.root_version, 1);
        assert_eq!(trust.delegations_version, 1);
        assert_eq!(
            trust.delegations_sha256,
            <[u8; 32]>::from(Sha256::digest(default_delegations().as_bytes()))
        );
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&MANIFEST_SEED)),
            Ok(public(&MANIFEST_SEED).as_slice())
        );
        assert_eq!(
            trust.role_key(Role::ArtifactCatalog, &id(&CATALOG_SEED)),
            Ok(public(&CATALOG_SEED).as_slice())
        );
    }

    #[test]
    fn signer_role_confusion_and_unknown_keys_are_refused() {
        let trust = verify(&default_bundle()).unwrap();
        // A catalog key, or the root key itself, never signs a manifest.
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&CATALOG_SEED)),
            Err(IntegrityFailure::SignerRole)
        );
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&ROOT_SEED)),
            Err(IntegrityFailure::SignerRole)
        );
        assert_eq!(
            trust.role_key(Role::ArtifactCatalog, &id(&MANIFEST_SEED)),
            Err(IntegrityFailure::SignerRole)
        );
        // A key the delegations never name (wrong key ID).
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&STRANGER_SEED)),
            Err(IntegrityFailure::UntrustedSigner)
        );
    }

    #[test]
    fn revoked_and_rotated_out_keys_are_refused() {
        // Version 2 rotates the manifest key and revokes the old one.
        let rotated = delegations_payload(
            2,
            1,
            &[NEXT_MANIFEST_SEED],
            &[CATALOG_SEED],
            &[id(&MANIFEST_SEED)],
        );
        let bundle = trust_bundle(
            &[],
            &envelope(DELEGATIONS_SIGNATURE_DOMAIN, &rotated, &[ROOT_SEED]),
        );
        let trust = verify_bundle(default_root().as_bytes(), 2, bundle.as_bytes()).unwrap();
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&MANIFEST_SEED)),
            Err(IntegrityFailure::SignerRevoked)
        );
        assert!(trust
            .role_key(Role::BuildManifest, &id(&NEXT_MANIFEST_SEED))
            .is_ok());
        // Rotated out without a revocation: simply no longer delegated.
        let dropped = delegations_payload(2, 1, &[NEXT_MANIFEST_SEED], &[CATALOG_SEED], &[]);
        let bundle = trust_bundle(
            &[],
            &envelope(DELEGATIONS_SIGNATURE_DOMAIN, &dropped, &[ROOT_SEED]),
        );
        let trust = verify_bundle(default_root().as_bytes(), 2, bundle.as_bytes()).unwrap();
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&MANIFEST_SEED)),
            Err(IntegrityFailure::UntrustedSigner)
        );
        // Replaying the old delegations (which still list the old key) is a
        // rollback once the engine compiles the version 2 floor.
        assert_eq!(
            verify_bundle(default_root().as_bytes(), 2, default_bundle().as_bytes()).unwrap_err(),
            IntegrityFailure::TrustRollback
        );
    }

    #[test]
    fn delegations_must_be_signed_by_the_root() {
        for signers in [vec![MANIFEST_SEED], vec![STRANGER_SEED], vec![CATALOG_SEED]] {
            let bundle = trust_bundle(
                &[],
                &envelope(
                    DELEGATIONS_SIGNATURE_DOMAIN,
                    &default_delegations(),
                    &signers,
                ),
            );
            assert_eq!(
                verify(&bundle).unwrap_err(),
                IntegrityFailure::TrustUnverified("delegations signature")
            );
        }
        // A root signature (other domain) over the same bytes is not a
        // delegations signature.
        let bundle = trust_bundle(
            &[],
            &envelope(ROOT_SIGNATURE_DOMAIN, &default_delegations(), &[ROOT_SEED]),
        );
        assert_eq!(
            verify(&bundle).unwrap_err(),
            IntegrityFailure::TrustUnverified("delegations signature")
        );
        // A changed payload under the original signature.
        let original = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &default_delegations(),
            &[ROOT_SEED],
        );
        let forged = default_delegations().replace(&id(&MANIFEST_SEED), &id(&STRANGER_SEED));
        let swapped = original.replace(
            &b64(default_delegations().as_bytes()),
            &b64(forged.as_bytes()),
        );
        assert!(verify(&trust_bundle(&[], &swapped)).is_err());
    }

    #[test]
    fn root_rotation_requires_both_thresholds() {
        let next = root_payload(2, 1, &[NEXT_ROOT_SEED]);
        let delegations = delegations_payload(1, 2, &[MANIFEST_SEED], &[], &[]);
        let signed_delegations = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &delegations,
            &[NEXT_ROOT_SEED],
        );
        // Cross-signed by the old and the new root: accepted.
        let chain = envelope(ROOT_SIGNATURE_DOMAIN, &next, &[ROOT_SEED, NEXT_ROOT_SEED]);
        let trust = verify(&trust_bundle(
            &[
                envelope(ROOT_SIGNATURE_DOMAIN, &default_root(), &[ROOT_SEED]),
                chain,
            ],
            &signed_delegations,
        ))
        .unwrap();
        assert_eq!(trust.root_version, 2);
        // The new root key is now the root, so it can never be a role key.
        assert_eq!(
            trust.role_key(Role::BuildManifest, &id(&NEXT_ROOT_SEED)),
            Err(IntegrityFailure::SignerRole)
        );
        // Only the new key (an attacker's self-made root), or only the old.
        for signers in [[NEXT_ROOT_SEED], [ROOT_SEED]] {
            let chain = envelope(ROOT_SIGNATURE_DOMAIN, &next, &signers);
            assert_eq!(
                verify(&trust_bundle(&[chain], &signed_delegations)).unwrap_err(),
                IntegrityFailure::TrustUnverified("root rotation")
            );
        }
        // Skipping a version.
        let v3 = root_payload(3, 1, &[NEXT_ROOT_SEED]);
        let chain = envelope(ROOT_SIGNATURE_DOMAIN, &v3, &[ROOT_SEED, NEXT_ROOT_SEED]);
        assert_eq!(
            verify(&trust_bundle(&[chain], &signed_delegations)).unwrap_err(),
            IntegrityFailure::TrustUnverified("root chain gap")
        );
        // Delegations signed by the old root after the chain moved on.
        let stale = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &default_delegations(),
            &[ROOT_SEED],
        );
        let chain = envelope(ROOT_SIGNATURE_DOMAIN, &next, &[ROOT_SEED, NEXT_ROOT_SEED]);
        assert_eq!(
            verify(&trust_bundle(&[chain], &stale)).unwrap_err(),
            IntegrityFailure::TrustUnverified("delegations root version")
        );
    }

    #[test]
    fn threshold_counts_distinct_valid_root_keys() {
        let root = root_payload(1, 2, &[ROOT_SEED, NEXT_ROOT_SEED]);
        let both = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &default_delegations(),
            &[ROOT_SEED, NEXT_ROOT_SEED],
        );
        assert!(verify_bundle(root.as_bytes(), 1, trust_bundle(&[], &both).as_bytes()).is_ok());
        let one = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &default_delegations(),
            &[ROOT_SEED, STRANGER_SEED],
        );
        assert_eq!(
            verify_bundle(root.as_bytes(), 1, trust_bundle(&[], &one).as_bytes()).unwrap_err(),
            IntegrityFailure::TrustUnverified("delegations signature")
        );
        // The same key twice is malformed, not two signatures.
        let twice = envelope(
            DELEGATIONS_SIGNATURE_DOMAIN,
            &default_delegations(),
            &[ROOT_SEED, ROOT_SEED],
        );
        assert!(matches!(
            verify_bundle(root.as_bytes(), 1, trust_bundle(&[], &twice).as_bytes()),
            Err(IntegrityFailure::TrustMalformed(_))
        ));
    }

    #[test]
    fn role_separation_is_enforced_on_device() {
        for delegations in [
            // One key in two roles.
            delegations_payload(1, 1, &[MANIFEST_SEED], &[MANIFEST_SEED], &[]),
            // The root key delegated as a role key.
            delegations_payload(1, 1, &[ROOT_SEED], &[], &[]),
            // A revoked key still delegated.
            delegations_payload(1, 1, &[MANIFEST_SEED], &[], &[id(&MANIFEST_SEED)]),
        ] {
            let bundle = trust_bundle(
                &[],
                &envelope(DELEGATIONS_SIGNATURE_DOMAIN, &delegations, &[ROOT_SEED]),
            );
            assert_eq!(
                verify(&bundle).unwrap_err(),
                IntegrityFailure::TrustMalformed("role separation".into()),
                "{delegations}"
            );
        }
    }

    #[test]
    fn malformed_documents_and_pins_are_refused() {
        let good = default_bundle();
        for bad in [
            String::new(),
            "{}".to_string(),
            good.replace(
                "\"contract_version\":2,\"delegations\"",
                "\"contract_version\":1,\"delegations\"",
            ),
            good.replace(
                "{\"contract_version\":2,\"delegations\"",
                "{\"x\":1,\"contract_version\":2,\"delegations\"",
            ),
            good.replace(
                "\"schema\":\"open-shorebird.release-trust\"",
                "\"schema\":\"other\"",
            ),
            // Duplicate field.
            good.replace(
                "{\"contract_version\":2,\"delegations\"",
                "{\"contract_version\":2,\"contract_version\":2,\"delegations\"",
            ),
            "x".repeat(MAX_BUNDLE_BYTES + 1),
        ] {
            assert!(
                matches!(verify(&bad), Err(IntegrityFailure::TrustMalformed(_))),
                "{bad}"
            );
        }
        // A bad compiled pin trusts nothing.
        for pin in [
            "",
            "{}",
            &default_root().replace("\"threshold\":1", "\"threshold\":2"),
        ] {
            assert_eq!(
                verify_bundle(pin.as_bytes(), 1, good.as_bytes()).unwrap_err(),
                IntegrityFailure::TrustMalformed("compiled release root".into())
            );
        }
        // Under another root, the bundle does not verify.
        let other = root_payload(1, 1, &[STRANGER_SEED]);
        assert_eq!(
            verify_bundle(other.as_bytes(), 1, good.as_bytes()).unwrap_err(),
            IntegrityFailure::TrustUnverified("delegations signature")
        );
    }

    /// The DEVELOPMENT-ONLY bundle `scripts/release_trust.py` produced
    /// (`scripts/testdata/release-trust/release-trust.DEVELOPMENT-ONLY.json`,
    /// compacted) verifies here under its pinned root: the Python and Rust
    /// implementations agree on envelopes, domains and key IDs.
    pub const PYTHON_ROOT_PIN: &str = "eyJjb250cmFjdF92ZXJzaW9uIjoyLCJleHBpcmVzX2F0IjoiMjAzNi0xMS0wOVQwMDowMDowMFoiLCJrZXlzIjpbeyJrZXlfaWQiOiJzaGEyNTY6MzQ3NTBmOThiZDU5ZmNmYzk0NmRhNDVhYWFiZTkzM2JlMTU0YTRiNTA5NGUxYzRhYmY0Mjg2NjUwNWYzYzk3ZSIsInB1YmxpY19rZXkiOiJpb2pqM1hRSjhaWDlVdHN0UExwZGNzcG5DYjhkbEJJYjgzU0lBYlFQYjF3PSJ9XSwic2NoZW1hIjoib3Blbi1zaG9yZWJpcmQucmVsZWFzZS1yb290IiwidGhyZXNob2xkIjoxLCJ2ZXJzaW9uIjoxfQ==";

    #[test]
    fn python_reference_bundle_verifies() {
        let pin = base64::engine::general_purpose::STANDARD
            .decode(PYTHON_ROOT_PIN)
            .unwrap();
        assert_eq!(String::from_utf8(pin.clone()).unwrap(), default_root());
        let trust = verify_bundle(&pin, 1, PYTHON_BUNDLE.as_bytes()).unwrap();
        assert!(trust
            .role_key(Role::BuildManifest, &id(&MANIFEST_SEED))
            .is_ok());
        assert_eq!(
            hex::encode(trust.delegations_sha256),
            PYTHON_DELEGATIONS_SHA256
        );
    }

    pub const PYTHON_DELEGATIONS_SHA256: &str =
        "79a604ff91d68aadcbd12c4fa4a3e42c5dce2b4d9ce71a1ef22dc3977cb994df";
    pub const PYTHON_BUNDLE: &str = include_str!("../testdata/release-trust.DEVELOPMENT-ONLY.json");
}
