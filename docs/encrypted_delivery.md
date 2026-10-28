# Encrypted native patch delivery

The open updater can consume the server's `per_device_aes_gcm` transport. This
is independent of the iOS interpreter envelope: native binary diffs, and iOS
interpreter envelopes if desired, may both be carried inside this transport.

## Application integration

Before any Flutter engine initializes the updater, register a native callback:

```c
bool resolve_patch_key(const char* key_id, const char* authenticated_aad,
                       uint8_t* output, size_t capacity, size_t* written);

bool configured =
    shorebird_set_patch_decryption_key_provider(resolve_patch_key);
```

The callback returns exactly 32 key bytes and sets `*written = 32`, or returns
false. It runs on an updater worker and must remain valid for the process
lifetime. It must be thread-safe, bound its own work, and not reenter updater
operations. Arguments are borrowed UTF-8, NUL-terminated strings and are valid
only for that call. Do not retain the output buffer. Registration returns false
after initialization; disabling or replacing a provider then is rejected.

The custom engine exposes this function through its Apple `FlutterDartProject.h`,
Windows `flutter_windows.h`, Linux `flutter_linux.h`, and Android's packaged
`shorebird_patch_encryption.h`. Android applications must register from native
bootstrap after loading `libflutter.so` and before creating a Flutter engine.
On older engines the symbol is absent: applications using dynamic lookup must
fail their encryption setup explicitly instead of silently opting out.

A registered provider requires a compiled public signing key, strict boot
verification, and required signed patch responses. The updater advertises
`accept_encrypted_patch` only with that provider. A plaintext offer is rejected
once encryption is enabled. No new field is added to the stable Dart FFI structs.

## Real key provisioning is application-owned

The callback obtains a **per-patch, per-install derived key**, from app-owned
secure storage or an independently authenticated entitlement/key service. The
server's `PATCH_DELIVERY_AES_SECRET` must never enter an app bundle, YAML asset,
Dart define, or callback result. An install UUID or its SHA-256 hash is a routing
identifier, not authentication and not a secret.

For the existing server format, the authorized backend computes
`HMAC-SHA256(master_secret, UTF8("key") || 0x00 || UTF8(aad))`. The callback's
AAD is the exact signed and locally validated `open-aot-patch-delivery-v2`
context. A provisioning backend must authorize the caller's app, entitlement,
release, patch, and install binding before returning that derived key. Merely
accepting an arbitrary caller-supplied AAD or device ID is not secure provisioning.
There is deliberately no unauthenticated key-distribution endpoint here.

The transport key and the iOS interpreter's inner AES key are separate keys with
separate purposes. Existing iOS `setShorebirdAotPatchKeyProvider` registration does
not register this transport provider.

## Verification and storage boundaries

The pinned RSA response signature covers every encryption metadata field, the
patch number/final hash, download URL, request nonce and release context. Before
key lookup the updater validates the v2 AAD schema, application, patch number and
hash, platform, architecture, and hashed install ID. It verifies the ciphertext
SHA-256, authenticates AES-256-GCM using the supplied AAD, and checks the recovered
compressed transport's SHA-256. Ordinary patch inflation and final artifact
signature/hash checks then run unchanged; signed identity persists for boot.

The existing single-tag format permits at most 128 MiB of compressed plaintext
(plus its 16-byte GCM tag). Decryption uses one bounded buffer. It never writes
plaintext compressed transport to a temporary file; downloaded/resumable bytes
stay encrypted. Key input and plaintext buffers are wiped when released. Native
installed executable artifacts remain plaintext in the application's private
storage so the platform loader can execute them. This is transport/download-cache
confidentiality, not a claim that running native code is unrecoverable or that
native executable cache files are encrypted at rest.

If key provisioning is temporarily unavailable or a supplied key cannot
authenticate the unchanged ciphertext, no patch is promoted. The download stays
available for a later key-resolution attempt, even when its signed URL grant
rotates: resume identity includes the stable URL origin/path and authenticated
ciphertext hash, while HTTP requests always use the fresh complete grant URL. Invalid ciphertext hashes, context,
or signatures are rejected. Legacy applications without a provider retain their
existing unencrypted-delivery behavior; they cannot use a server that requires
encrypted delivery until an actual provider is installed.

## Evidence

`library/test_fixtures/server_encrypted_native_v2.json` contains test-only data
created by the real Go HTTP patch-check/signing/encryption path. Its plaintext
transport was produced by the public Rust patch tool from two compiled Mach-O
libraries whose function returns 1 and 2. Rust verifies the Go response, decrypts
the transport and reconstructs the exact target binary. Other tests reject every
modified signed encryption field, wrong keys, ciphertext mutation, and app/device/
patch context mismatch. A full updater test exercises unavailable key, retry,
installation and strict boot verification without downloading a second copy.

Unencrypted legacy delivery retains exact-URL resume identity. Refreshing a
signed plaintext download grant can therefore restart a partial download. The
final executable hash alone does not identify its compressed diff bytes, so the
updater does not strip query parameters for plaintext offers. This conservative
availability limitation avoids combining different compressed transports.
