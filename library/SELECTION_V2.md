# Protocol 2 updater integration

This is an opt-in updater consumer foundation. Existing engine initializers,
response shapes, providers and v1 release behavior remain v1. Engines must
explicitly adopt the initializer and verified context; updater implementation
alone does not establish runnable v2 applications on any platform.

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

Native AOT v2 requires `shorebird_set_patch_decryption_key_provider_v2` before
initialization, mutually exclusive with the legacy provider. The callback is
`bool(key_id, aad, verified_selection_context_json, key_out, capacity, written)`.
All C strings are borrowed for the call only. Return exactly 32 bytes and set
written, or return false. Short keys and authentication failures remain typed
retryable key failures; key and plaintext buffers are wiped by their existing
owners. No fallback to a v1 provider exists for a v2 release.

For native AOT the initializer ignores the interpreter baseline callbacks and
measures the original native AOT stream through the existing platform resolver,
including the exact library in Android's installed APK. Native v2 requires a
supported sealed FD route on Linux/Android or verified memory on Windows, and a
nonzero image budget. Other native platform/capability combinations fail closed.
The authenticated delivery/ciphertext, current usable grant and exact complete
delivery identity are checked before passing selection JSON to the provider at
both install and cold reconstruction. Lease refusal is typed and cannot
quarantine an artifact; a grant expiring after download retains the staged
candidate for a higher-epoch renewal. Signed same-epoch refreshes may rotate
transport nonce/key/ciphertext: a mismatching cached transport is discarded and
redownloaded without condemning the immutable artifact. Proven reconstructed
artifact failures remain quarantined. The application's authenticated key
service must independently authorize the account/installation and grant: public
selection JSON and installation IDs are not credentials.

The existing nonblocking updater operation guard continues to serialize native
materialization. No config, process-selection, journal-authority or provider
registry mutex spans an application key callback. Reentrant update refuses with
UpdateInProgress; an unselected reentrant prepare freezes BASE; an already begun
source/its context stays pinned. Installation/status reads and begin/prepare are
covered by callback reentry tests. No provider callback is invoked by those
status/identity getters.

## Read-only installation and selection status

The additive Dart-stable C functions `shorebird_installation_id` and
`shorebird_selection_status_json` return owned UTF-8 strings, freed with
`shorebird_free_status_string`. ID reads never create/reset identity. Status
reads do not rewrite pointers, quarantine content, prune storage or reset state.
Status is NULL for v1 or unavailable state. New Dart probes both getter and
free symbols before allocation; older engines fall back to existing patch APIs.
Existing symbols, result struct layouts and success codes remain unchanged.

Dart exposes `readInstallationId()` and `readSelectionStatus()`. The status
model has `current`, `accepted`, `nextBoot`, and `restartRequired`. Epochs are
BigInt; patch numbers remain content identities. The atomic JSON form is:

```json
{
  "version": 2,
  "current": {"epoch":"11","digest":"<sha256>","variant_id":"pro","license_type":"pro","patch_number":"2"},
  "accepted": {"epoch":"12","digest":"<sha256>","variant_id":"pro","license_type":"pro","patch_number":"2","target_kind":"patch"},
  "next_boot": {"variant_id":"pro","license_type":"pro","patch_number":"2","reason":"ready"},
  "restart_required": true
}
```

No authorization is epoch `"0"` and null digest. Bundled BASE is null patch
number with effective free variant/license. Accepted identity remains distinct
from effective BASE after expiry, missing content/key or quarantine. Next reason
is ready, selected_base, expired, not_yet_valid, content_unavailable, quarantined,
or no_authorization; ready content still requires successful cold key lookup.
Current identity is process-pinned, including BASE fallback authorization.
Greater accepted epoch/different digest requests restart even for identical
content. Dart `checkForUpdate` uses this atomic status when available and keeps
its previous patch-number comparison on old engines/v1.

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
reject a mismatched original baseline and v2-to-v1 fallback. Native-specific
tests cover provider exclusivity, short/wrong keys, callback reentry, native
capability gating, delivery rotation and expiry-before-reconstruction recovery.
Status tests cover read-only identity/corrupt-state handling, assignment races,
precise 64-bit epochs and same-content higher-epoch restart. Portable anonymous
memory reconstruction on the test host is not native image execution.

Platform support still requires matched engine/CLI producers and interpreter
key/envelope integration, platform-specific protected clock/durability decisions,
injected
power-loss/fsync failure coverage; and actual repeated free/pro/enterprise
application execution, offline/key recovery and persistent user-data evidence
on each platform/architecture. Unit-level synthetic cache construction is not
that runtime acceptance sequence.
