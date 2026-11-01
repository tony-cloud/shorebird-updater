# Protocol 2 updater integration

This is an opt-in updater consumer foundation. Existing engine initializers,
response shapes, providers and v1 release behavior remain v1. No engine or CLI
currently calls the new initializer, so this change does not establish runnable
v2 applications on any platform.

`selection_v2.rs` implements the frozen workspace
`docs/VARIANT_SELECTION_PROTOCOL.md` contract. The committed test fixture is an
exact copy of workspace `testdata/variant_selection_v2.json` so this repository's
unit tests also run independently. The synthetic fixture proves protocol
encoding, signatures and decisions; it contains no executable application.

## Host producer requirements

An updated engine must call `shorebird_init_selection_v2`, with existing
`AppParameters`, native diff `FileCallbacks`, compiled YAML, engine options,
compiled release-scope JSON, and a separate set of `release_baseline_callbacks`.

The strict JSON scope has exactly `app_id`, `release_version`, `platform`,
`arch`, `base_artifact_hash`, required nullable `host_abi_hash`, and
`runtime_profile`. App/release/platform/architecture must match the installed
host. The public key and strict artifact/required response verification policies
remain compiled YAML settings. Identity and both callback sets become immutable
for repeated initialization. A v2 initialization failure cannot downgrade to a
v1 initializer in the same process.

The release baseline callbacks must open the bundled ORIGINAL bytecode baseline
for the selected interpreter profile. This is independent of the existing
native snapshot-region callbacks. Before publishing configuration the updater
measures that stream against the compiled hash; v2 interpreter diff application
subsequently reopens that same original baseline. Every open supplies a fresh
read/seek stream and callbacks must remain valid for the process lifetime.
The CLI/engine must bundle the baseline for body and structural profiles as well
as full replacement, and supply it before updater initialization. A server
response cannot replace the compiled scope or baseline callback.

The engine then uses the existing prepare/begin/abort source-token APIs, and
copies `shorebird_boot_selection_context_json(token)` before executing selected
interpreter code or releasing its key. The returned owned UTF-8 string is
`{version:2,selection:<verified descriptor>,selection_digest:<digest>}`; free it
with `shorebird_free_string`. BASE/v1/error returns NULL. Context belongs to the
immutable process source, even when another check changes the next-boot grant.
The legacy path getter refuses v2; a producer must use prepared source tokens.

The engine must independently verify the interpreter envelope's authenticated
key ID, flavor, license, expiry, original baseline, runtime and host ABI against
this verified context. Existing key-refusal deferral must retain content and the
journal for a later cold retry. No callback or artifact-validation step may
relax the envelope's own expiry. Begin must succeed for the same prepared token
before execution; a stale unbegun source becomes BASE. These engine changes and
selection-aware interpreter key policy are still required.

Native AOT v2 initialization is explicitly refused until a selection-aware
native key adapter is implemented. The existing native v1 callback never
receives or releases keys for a v2 grant. A future additive provider must receive
verified descriptor/digest plus authenticated transport key ID/AAD directly from
the verified grant, before both install and boot reconstruction. It must run
without config/selection/journal locks. Registration, context ownership and
remote provisioning authentication require their own integration/tests.

## Authority and recovery

V2 requests explicitly advertise protocol 2. Signed responses pass strict
schema/size, exact original-byte RSA signature, outstanding nonce and immutable
installation, outer equality, descriptor digest, artifact signature, delivery
and transport binding checks before epoch comparison. All integer protocol
values remain canonical decimal strings backed by u64 comparisons.

Authorization is journaled under `selections-v2/<scope hash>.json`, outside
`patches/`. It stores epoch/digest, exact signed payload/signature and an accepted
wall-time floor. Replacement writes a unique sibling, flushes/fsyncs, renames,
and syncs the parent directory on Unix before exposing a new target. Acceptance
writes are serialized, including competing journal instances. Network check
entry points also use the updater operation lock. No key callback runs under a
journal lock.

The journal survives content cleanup, failures and BASE fallback. Boot validates
its signature/scope/high-water fields again and chooses only its exact target
when the lease and installed signed bytes permit it. Missing/corrupt journals,
missing content, expired/future grants and quarantined content choose BASE. A
fresh valid online check can restore corrupt/missing authority. Pointers are
reconstructed from the journal, never from v1 per-patch authentication or a
last-good content number. Content reference retention protects pending, running
and boot references; other content can be evicted and redownloaded. The accepted
wall-time floor is not protected against full storage rollback and cannot prove
elapsed offline time against clock rollback.

## Evidence and remaining gates

Unit tests cover every frozen canonical byte sequence/digest and all 16 signed
vectors, strict null/duplicate/unknown/UTF-8/numeric constraints, signed payload
schema, bounded v2 HTTP requests/responses, concurrent epoch acceptance,
journal restart/cleanup/tampering, cached lower-number reselection, explicit
BASE, quarantined content and immutable prepared context. Initialization tests
reject a mismatched original baseline and v2-to-v1 fallback.

Still required: engine/CLI producers; interpreter key/envelope integration;
native v2 provider and materialization; a public Dart variant/epoch/status
surface; platform-specific protected clock/durability decisions; injected
power-loss/fsync failure coverage; and actual repeated free/pro/enterprise
application execution, offline/key recovery and persistent user-data evidence
on each platform/architecture. Unit-level synthetic cache construction is not
that runtime acceptance sequence.
