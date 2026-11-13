# TSRA PKCS#11 module

A standalone **PKCS#11 (Cryptoki) v3.1** module for the TSRA. It links the
native C API (`tsra.h`, generated from `api/native`) the same way
`plugins/ossl_prov` does.

## Status: digests, AES and EC keys, ciphers, ECDSA, key unwrap, host objects

Unimplemented PKCS#11 entry points return `CKR_FUNCTION_NOT_SUPPORTED` (after
`C_Initialize`; before it every entry point other than `C_Initialize` and the
function-list / interface queries reports `CKR_CRYPTOKI_NOT_INITIALIZED`, as
the spec requires). Implemented so far:

- **Library / slots / sessions** — `C_Initialize`, `C_GetInfo`, slot/token/
  mechanism enumeration (real TSRA partitions become slots), sessions and the
  login state machine. The "PKCS 11" interface comes in versions 3.1 (the
  default), 3.0 and 2.40 (`C_GetInterfaceList`, `C_GetInterface`), and
  `C_GetFunctionList` returns the 2.40 table.
  `C_GetMechanismList` reports only the eighteen mechanisms below, and
  `C_GetTokenInfo` the real session counts (at most 256 sessions).
- **`C_Login`**: runs the TSRA provisioning ceremony and opens one device
  session for the token. Provisioning is done lazily: login opens a device
  session and provisions the partition only if the device reports it is not
  yet provisioned (provisioning is one-shot per power cycle; a session is the
  repeatable per-login primitive). Login state is per token, so every PKCS#11
  session of the slot shares that one device session. It closes at
  `C_Logout`, when the slot's last session closes, and at `C_Finalize`. The
  token has one user; see User role and PIN.
- **Host objects** — `C_CreateObject` / `C_DestroyObject` / `C_GetAttributeValue`
  / `C_SetAttributeValue` / `C_GetObjectSize` / `C_FindObjects*` against the
  host object store: in memory, or token objects in files with
  `TSRA_PKCS11_PERSIST` (see Configuration). Every template is checked
  against one attribute type table before anything is stored or matched: a
  `CK_BBOOL`, `CK_ULONG` or `CK_DATE` value of the wrong size or content is
  `CKR_ATTRIBUTE_VALUE_INVALID`, and no value is read at a wrong length. A
  template takes at most 64 attributes (`CKR_ARGUMENTS_BAD`, also for
  `C_GetAttributeValue`) and 1 MiB of values (`CKR_ATTRIBUTE_VALUE_INVALID`).
  The file store keeps a token object in a record of at most 256 KiB,
  attribute values and masked key body included; a larger one is
  `CKR_DEVICE_MEMORY`. `C_CreateObject` needs `CKA_CLASS`
  (`CKR_TEMPLATE_INCOMPLETE`) naming a data object, a certificate or a key
  (any other class is `CKR_ATTRIBUTE_VALUE_INVALID`), creates no secret or
  private key (see Deviations), and refuses the attributes only the token
  sets (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`,
  `CKA_KEY_GEN_MECHANISM`, `CKA_UNIQUE_ID`, and `CKA_TRUSTED` TRUE, which is
  the Security Officer's: `CKR_ATTRIBUTE_READ_ONLY`).
  `CKA_VALUE` of a sensitive key answers `CKR_ATTRIBUTE_SENSITIVE`.
  `C_SetAttributeValue` changes only the attributes PKCS#11 marks modifiable
  for the object's class (label, ID, dates, usage flags), and applies a
  template all-or-nothing; on keys `CKA_SENSITIVE` can only become TRUE and
  `CKA_EXTRACTABLE` only FALSE, and an EC key's usage flags stay as generated
  (see Deviations). `C_DestroyObject` needs a read/write session
  for a token object (`CKR_SESSION_READ_ONLY`) and refuses an object with
  `CKA_DESTROYABLE` FALSE (`CKR_ACTION_PROHIBITED`).
  `C_GetObjectSize` reports the bytes of the attribute values plus the masked
  key body. `C_CopyObject` is not implemented.
  A session object is destroyed when the session that created it closes, a
  private one also at `C_Logout`; token objects outlive both (see Key storage
  and key lifetime).
- **`C_Digest*` (SHA-1/256/384/512)** — host-side digests (one-shot and
  multi-part); every other digest mechanism returns `CKR_MECHANISM_INVALID`.
- **`C_GenerateKey` (`CKM_AES_KEY_GEN`, `CKM_AES_XTS_KEY_GEN`)** — generates a
  key on the device and stores its **masked blob** (the TSRA key's only
  durable form) as the object's key body. The device has three disjoint AES key
  kinds, so the template picks one, and the key records it as
  `CKA_ALLOWED_MECHANISMS`:

  | Mechanism and template | Key | `CKA_KEY_TYPE` | `CKA_VALUE_LEN` |
  |---|---|---|---|
  | `CKM_AES_KEY_GEN` | AES for `CKM_AES_CBC` / `_CBC_PAD` | `CKK_AES` | 16, 24, 32 |
  | `CKM_AES_KEY_GEN` + `CKA_ALLOWED_MECHANISMS = { CKM_AES_GCM }` | AES-GCM | `CKK_AES` | 32 |
  | `CKM_AES_XTS_KEY_GEN` | AES-XTS | `CKK_AES_XTS` | 64 |

  PKCS#11 has no GCM key-generation mechanism, hence the allowed-mechanism
  list; a list mixing families (GCM with CBC) is refused. A caller's narrower
  list (`{ CKM_AES_CBC }`) is kept and enforced. Generated keys are always
  sensitive, unextractable and local — a template asking otherwise is rejected
  (note: OpenSC `pkcs11-tool --keygen` needs its `--sensitive` flag for this
  reason). A key is private (`CKA_PRIVATE` TRUE, visible only while logged in)
  unless the template sets `CKA_PRIVATE` to FALSE.
- **`C_Encrypt` / `C_Decrypt` one-shot (`CKM_AES_CBC`, `CKM_AES_CBC_PAD`,
  `CKM_AES_GCM`, `CKM_AES_XTS`)** — each `C_EncryptInit`/`C_DecryptInit`
  unmasks the stored blob into a fresh device key that lives exactly as long
  as the operation; a key serves only its own family. Input and
  output may be the same buffer; the binding stages the input whenever the two
  ranges overlap, because the native API cannot hold a read and a write slice
  over the same bytes.
  - GCM takes `CK_GCM_PARAMS` with a 12-byte IV and a 128-bit tag only (the
    device supports no other sizes) and optional AAD. The tag is appended to
    the ciphertext. A failed tag check currently reports
    `CKR_FUNCTION_FAILED`: the SDK delivers it as a generic device-command
    failure that the module cannot tell apart from a device fault.
  - XTS takes the 16-byte tweak (little-endian sector number, below 2^64 - 1:
    see Deviations) and encrypts the whole message as one data unit, which
    the device caps at 8 KiB: a message must be a non-zero multiple of 16
    bytes up to 8192.

- **Multi-part `C_EncryptUpdate` / `C_EncryptFinal` and `C_DecryptUpdate` /
  `C_DecryptFinal` (the same four mechanisms)**: the one-shot lifetime rules
  apply, and one operation cannot mix one-shot and multi-part calls
  (`CKR_OPERATION_ACTIVE`). The result always equals the one-shot result.
  - CBC and CBC-PAD run through the SDK's stream context. It holds back the
    last full block until the final call, even without padding, so an
    update's output trails its input by up to one block (the spec allows
    that). A sizing probe on an update reports an upper bound, because the
    SDK's own sizing call would already consume the data.
  - GCM and XTS buffer the parts and run the one-shot operation at the final
    call. The device has no incremental GCM or XTS, the SDK's GCM decrypt
    needs the tag before the data, and a PKCS#11 XTS operation is one data
    unit. So their updates return no output, a GCM decrypt releases no
    plaintext before the tag is checked, and the one-shot size limits apply to
    the sum of the parts.
  - The OpenSSL provider works around the same SDK constraints
    (`plugins/ossl_prov/src/tsra_ossl_cipher.c`).

- **`C_GenerateKeyPair` (`CKM_EC_KEY_PAIR_GEN`)**: generates a P-256, P-384
  or P-521 key pair on the device, named by the public template's
  `CKA_EC_PARAMS` as a named-curve OID; any other curve returns
  `CKR_CURVE_NOT_SUPPORTED`; `C_GetMechanismInfo` says so with `CKF_EC_F_P`,
  `CKF_EC_OID` and `CKF_EC_UNCOMPRESS` on every EC mechanism. The private key
  signs or derives, never both (see Deviations). `CKA_EC_POINT` is the
  uncompressed point in a DER OCTET STRING. The private key is private,
  sensitive, unextractable and local; the public key is not private unless
  the template says so, and is readable while logged out. Both objects keep the pair's masked blob as their key body: the
  SDK verifies only with a device key, and only unmasking the pair gives one.
- **`C_Sign*` / `C_Verify*` (`CKM_ECDSA`, `CKM_ECDSA_SHA1`, `_SHA256`,
  `_SHA384`, `_SHA512`)**: each init unmasks the pair into device keys that
  live as long as the operation, like the cipher operations. A signature is
  r || s, 64, 96 or 132 bytes. The hashing mechanisms work one-shot and
  multi-part (through the SDK's stream); `CKM_ECDSA` signs a hash the caller
  made, one-shot only (`C_SignUpdate` and `C_SignFinal` return
  `CKR_FUNCTION_NOT_SUPPORTED`), and takes 20, 32, 48 or 64 bytes (see
  Deviations). A signature of the wrong length returns
  `CKR_SIGNATURE_LEN_RANGE`, a wrong one `CKR_SIGNATURE_INVALID`. A key's
  `CKA_ALLOWED_MECHANISMS`, if it has one, is enforced.
- **`C_GenerateKeyPair` (`CKM_RSA_PKCS_KEY_PAIR_GEN`)**: returns a public and
  a private object for the partition's RSA unwrapping key, the only RSA key
  the device has (see Deviations). The template must ask for exactly that
  key: `CKA_MODULUS_BITS` 2048 and `CKA_WRAP` TRUE in the public template,
  `CKA_UNWRAP` TRUE in the private one, no other usage TRUE, and, if given,
  the exponent 65537. Anything else returns `CKR_TEMPLATE_INCONSISTENT` (no
  `CKA_MODULUS_BITS`: `CKR_TEMPLATE_INCOMPLETE`). Both objects carry the
  modulus, the exponent, `CKA_ID` (the SHA-1 of the modulus) and
  `CKA_ALLOWED_MECHANISMS = { CKM_RSA_AES_KEY_WRAP }`; the private one is
  sensitive and unextractable.
- **`C_UnwrapKey` (`CKM_RSA_AES_KEY_WRAP`)**: the only way a key from outside
  enters the token. The blob is the RSA-OAEP encryption of an AES
  key-encryption key under the unwrapping key, then the target key wrapped
  under that key with RFC 5649. `CK_RSA_PKCS_OAEP_PARAMS` must name SHA-256,
  SHA-384 or SHA-512 with MGF1 of the same hash, `CKZ_DATA_SPECIFIED` and no
  label (the SDK passes none to the device); `ulAESKeyBits` is 128, 192 or
  256. The target is an AES, AES-GCM or AES-XTS key, picked by the template
  as at generation (`CKA_CLASS` and `CKA_KEY_TYPE` are required); its length
  comes from the blob, so `CKA_VALUE_LEN` may be left out. A blob of the
  wrong length returns `CKR_WRAPPED_KEY_LEN_RANGE`; every other bad blob
  (tampered, wrong key-encryption key, wrong OAEP hash) returns one
  `CKR_WRAPPED_KEY_INVALID`, so the error tells nothing about where the
  unwrap failed, and no object is created. The unwrapping key needs
  `CKA_UNWRAP` (`CKR_KEY_FUNCTION_NOT_PERMITTED`). An unwrapped key is
  sensitive and unextractable like a generated one, but not local
  (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` FALSE,
  `CKA_KEY_GEN_MECHANISM` unavailable). An XTS key whose two halves are equal
  unwraps but is refused at use (`CKR_FUNCTION_FAILED`), as FIPS 140-3
  requires. Private (EC, RSA) key targets are not implemented yet.
- **`C_WrapKey`** returns `CKR_FUNCTION_NOT_SUPPORTED`: no key ever leaves
  the device.

  The other key-backed mechanisms (RSA operations, derive) are not
  implemented yet.
- **Ending an operation**: `C_DigestInit`, `C_EncryptInit`,
  `C_DecryptInit`, `C_SignInit` and `C_VerifyInit` with a NULL mechanism end
  the session's active operation of their kind (and return `CKR_OK` when
  there is none), and `C_SessionCancel` ends the operations its flags name.

## Deviations from PKCS#11

- **One user, no PIN management.** There is no Security Officer, and
  `C_InitToken`, `C_InitPIN` and `C_SetPIN` are not supported. A wrong PIN
  returns `CKR_FUNCTION_FAILED`, not `CKR_PIN_INCORRECT`. See User role and
  PIN.
- **No random-number generator.** The device offers the host none, so the
  token does not set `CKF_RNG`, and `C_GenerateRandom` and `C_SeedRandom`
  return `CKR_RANDOM_NO_RNG`.
- **An AES-GCM key is a key kind of its own.** The device keeps CBC, GCM and
  XTS keys apart, so a key serves only its own family (table above). A GCM key
  is requested with `CKA_ALLOWED_MECHANISMS = { CKM_AES_GCM }` at generation;
  with OpenSC: `pkcs11-tool --keygen --key-type aes:32 --sensitive
  --allowed-mechanisms AES-GCM`. A key generated without that list is a CBC
  key, and `CKM_AES_GCM` on it returns `CKR_KEY_FUNCTION_NOT_PERMITTED`. In
  PKCS#11 an AES key without the attribute serves every AES mechanism.
- **GCM IV uniqueness is the caller's duty.** The caller supplies the 12-byte
  IV in `CK_GCM_PARAMS`, and neither the module nor the device checks that an
  IV is never reused with the same key. The message-based API, in which a
  token can generate the IVs, is not implemented.
- **No plaintext key import.** Keys enter the token only by generation and by
  unwrap; the device holds them only masked. `C_CreateObject` with
  a secret, private or public key that carries key material (`CKA_VALUE`,
  `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1`, `CKA_PRIME_2`, `CKA_EXPONENT_1`,
  `CKA_EXPONENT_2`, `CKA_COEFFICIENT`) returns `CKR_TEMPLATE_INCONSISTENT`, and
  a secret or private key without it `CKR_TEMPLATE_INCOMPLETE`. Tools that
  import plaintext keys, such as OpenSC `pkcs11-tool --write-object --type
  secrkey` or `privkey`, get this error.
- **An EC private key signs or derives, not both.** The device makes a
  signing key or a deriving key. A private-key template with both `CKA_SIGN`
  and `CKA_DERIVE` TRUE, or neither, returns `CKR_TEMPLATE_INCONSISTENT`, and
  the debug trace (`TSRA_PKCS11_DEBUG=1`) names the rule. Ask for one:
  `pkcs11-tool --keypairgen --key-type EC:prime256v1 --usage-sign` (or
  `--usage-derive`). Tools that ask for both by default, such as
  `pkcs11-tool` without a `--usage-*` option, get this error. The usage
  stays as generated: `CKA_SIGN`, `CKA_VERIFY` and `CKA_DERIVE` of an EC key
  are read-only (`CKR_ATTRIBUTE_READ_ONLY`), where PKCS#11 lets them change,
  because the device key keeps the usage it was made with.
- **No per-operation login.** The token has no context-specific login
  (`CKU_CONTEXT_SPECIFIC`) that would enforce `CKA_ALWAYS_AUTHENTICATE`, so a
  private-key template with it TRUE returns `CKR_ATTRIBUTE_VALUE_INVALID`.
- **Raw ECDSA takes 20, 32, 48 or 64 bytes.** The SDK infers the hash from
  the input length, so `CKM_ECDSA` input of any other length (SHA-224's 28
  bytes among them) returns `CKR_DATA_LEN_RANGE`. The module neither pads nor
  truncates; the device truncates a hash longer than the curve order, as
  PKCS#11 describes.
- **Verification needs a login and a generated key.** The SDK verifies only
  through a device key, so `C_VerifyInit` needs the login's device session
  (`CKR_USER_NOT_LOGGED_IN`) even with a public key, and a public key made
  with `C_CreateObject` cannot verify (`CKR_KEY_HANDLE_INVALID`).
- **No attribute arrays.** `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE` and
  `CKA_DERIVE_TEMPLATE` return `CKR_ATTRIBUTE_TYPE_INVALID` in every template.
- **The one RSA key pair is the partition's unwrapping key.** The device
  generates no general RSA keys. `C_GenerateKeyPair` with
  `CKM_RSA_PKCS_KEY_PAIR_GEN` returns the partition's one fixed RSA-2048
  unwrapping key: the same key on every call and for every application, so
  repeated calls make further objects for the same key (with the same
  `CKA_ID`), and destroying the objects does not destroy the device key. The
  objects hold no key body; `C_UnwrapKey` fetches the device key each time and
  refuses an object whose modulus is not the partition's
  (`CKR_UNWRAPPING_KEY_HANDLE_INVALID`).
- **An XTS key is unwrapped from the SDK's container.** The device keeps the
  two halves of an XTS key as two keys, and the SDK unwraps them from a
  format of its own: a 16-byte header (the bytes `TSRA-XTS`, then version 1,
  the lengths of the two blobs and two zero bytes, each a little-endian
  16-bit value), then one `CKM_RSA_AES_KEY_WRAP` blob for each 32-byte half. A
  single blob of the 64-byte key returns `CKR_WRAPPED_KEY_LEN_RANGE`.
- **XTS tweaks are 64-bit.** The tweak, read as a little-endian 128-bit
  integer, must be below 2^64 - 1: its upper 8 bytes zero and its lower 8 not
  all 0xFF, so the device can advance it past the data unit. Any other tweak
  returns `CKR_MECHANISM_PARAM_INVALID`, where PKCS#11 allows any 16 bytes.

## Key storage and key lifetime

The TSRA device keeps no keys. When it generates or unwraps a key, it returns
the key encrypted under a masking key that never leaves the device: the masked
blob.
The masked blob is the key's only durable form. The module stores it as the
key body of the PKCS#11 object, in memory or, with `TSRA_PKCS11_PERSIST=1`, in
the file store.

For every operation the module sends the masked blob to the device, which
unmasks it into a temporary device key. The module deletes that device key
when the operation ends, whatever the outcome. No device key outlives an
operation.

Which masking key encrypts the masked blob is chosen when the key is
generated. The device offers two: the masking key of the current device
session, which is gone when that device session closes, and the masking key
of the partition, which lasts as long as the partition's provisioning. The
module always uses the partition masking key, for token and session objects
alike: it passes `TSRA_KEY_PROP_ID_SESSION` as false. The module opens one
device session per login and closes it at `C_Logout`, when the slot's last
PKCS#11 session closes, at `C_CloseAllSessions` and at `C_Finalize`. With the
device-session masking key every key would become unusable at each of those
points, whatever its PKCS#11 lifetime.

The partition's RSA unwrapping key is the exception: the device keeps it for
good, so its objects hold no masked blob, and `C_UnwrapKey` asks the device
for the key at every call.

PKCS#11 object lifetime is therefore managed by the module alone, as the
specification describes it:

| Object | Destroyed when |
|---|---|
| session object | the PKCS#11 session that created it closes (`C_CloseSession`, `C_CloseAllSessions`, `C_Finalize`) |
| private session object | also at `C_Logout`, whichever session of the slot calls it |
| token object | `C_DestroyObject`, and with the memory store `C_Finalize` |

What a token key survives:

- `C_Logout` and `C_Login`, the close of the slot's last session, and
  `C_CloseAllSessions`: yes. `C_Finalize` and `C_Initialize` in the same
  process: yes, with the file store.
- Another process on the same device: not shown yet. The emulator
  provisions every process from scratch, so a key from another process does
  not unmask there (`CKR_KEY_HANDLE_INVALID`). Hardware checklist item H-d.
- A power cycle or a partition reset: no, not until the module replays the
  partition's backup masking key at re-provisioning. Hardware checklist item
  H-e.

## Layering

| Layer | Files | Responsibility |
|---|---|---|
| C ABI | `tsra_pkcs11_dispatch.c` | the 2.40, 3.0 and 3.1 function lists and the "PKCS 11" interfaces over them; `C_LoginUser` |
| Framework | `tsra_pkcs11_module.c`, `tsra_pkcs11_slot.c`, `tsra_pkcs11_session.c`, `tsra_pkcs11_mech.c` | init, slots, sessions, login, operation state machine; the mechanism table is a device-free unit of its own |
| Host crypto | `tsra_pkcs11_digest.c` | self-contained SHA-1/256/384/512 (PKCS#11 digests must work in public sessions; the SDK digest needs a login) |
| Object store | `tsra_pkcs11_objstore.h`, `tsra_pkcs11_objstore_mem.c` | host-side objects behind a vtable seam; the in-memory backend |
| File store | `tsra_pkcs11_objstore_file.c`, `tsra_pkcs11_store_record.c`, `tsra_pkcs11_store_io.c` | the persistent backend for token objects (session objects stay in memory): one record file per object, the record codec, and the crash-safe, owner-only filesystem primitives with a cross-process lock |
| Object policy | `tsra_pkcs11_attr_types.c`, `tsra_pkcs11_attr_policy.c` | the attribute type table and template ceilings every template entry point uses; what `C_CreateObject` may create and which attributes `C_SetAttributeValue` may change, per class; device-free units of their own |
| Key operations | `tsra_pkcs11_crypt.c`, `tsra_pkcs11_sign.c`, `tsra_pkcs11_template.c`, `tsra_pkcs11_ec_template.c` | key-backed entry points: operation state and the masked-blob store/unmask flow (CK_RV only); the keygen template validation, key-family choice, cipher and sign mechanism policy, and the EC templates and encodings are device-free units of their own |
| Key import | `tsra_pkcs11_unwrap.c`, `tsra_pkcs11_unwrap_params.c` | `C_UnwrapKey` and the unwrapping key pair behind `C_GenerateKeyPair`; the mechanism parameters, the unwrap and key pair templates and the public key decoding are a device-free unit of their own |
| Configuration | `tsra_pkcs11_config.c` | the configuration file and environment, the PIN rules and the owner backup key file; a device-free unit of its own |
| HSM binding | `tsra_pkcs11_hsm.c`, `tsra_pkcs11_key.c`, `tsra_pkcs11_status.c` | the only code that calls `tsra_*` and maps `tsra_status` to `CK_RV` |
| Not implemented | `tsra_pkcs11_stubs.c` (generated) | everything else → `CKR_FUNCTION_NOT_SUPPORTED` |

The object store is the emulation layer PKCS#11 requires and the device does not
provide (no persistent, attribute-templated, searchable key store). It is fronted
by the `tsra_pkcs11_objstore` vtable, so the in-memory and the file backend
serve the same callers.

## Build

```sh
# Against the simulator over the DDI socket transport (no physical device):
cargo build -p tsra_pkcs11
# -> target/debug/tsra_pkcs11.so
# Start the simulator and point the module at it before loading it:
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234 &
export TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:1234"
# Explicit provisioning inputs for this local simulator:
export TSRA_PKCS11_ID=01010101010101010101010101010101
export TSRA_PKCS11_OBK_PATH="$(mktemp)"
head -c 48 /dev/urandom > "$TSRA_PKCS11_OBK_PATH"

# Standalone (no device linked) framework smoke build:
gcc -shared -fPIC -Iinclude/pkcs11-v3.1 src/*.c -o tsra_pkcs11.so -lpthread
```

`build.rs` drives CMake, which imports `tsra_api_native` via Corrosion and
generates `tsra.h` with cbindgen.

The same module and SDK build supports hardware and the simulator. Neither
transport supplies built-in provisioning inputs.

`include/pkcs11-v3.1/` holds the OASIS PKCS #11 v3.1 headers, vendored
unmodified under their own copyright; see the `NOTICE` file there. The
copyright check skips those three files by name.

## Configuration

The module reads its settings at `C_Initialize` and again at every
`C_Login`: from the file `TSRA_PKCS11_CONF` names, if set, and from the
environment, which wins over the file key by key. The file has one
`key = value` per line; a line starting with `#` is a comment.
`tsra_pkcs11.conf.sample` next to this README shows every key.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| `persist` | `TSRA_PKCS11_PERSIST` | `0` | `1` keeps token objects in files under `store_dir`; `0` keeps them in memory until the process ends. |
| `store_dir` | `TSRA_PKCS11_STORE_DIR` | `/var/lib/tsra/pkcs11` | The file store, one subdirectory per slot. |
| `obk_path` | `TSRA_PKCS11_OBK_PATH` | none | The 48-byte owner backup key file. Every `C_Login` reads it; only a login that provisions the partition hands it to the device. The OpenSSL provider's `tsra-obk-path` file fits. |
| `debug` | `TSRA_PKCS11_DEBUG` | `0` | `1` traces to stderr. |

Credentials are never read from the file, only from the environment, as 32
hex characters (16 bytes) each:

- `TSRA_PKCS11_ID`: the partition ID.
- `TSRA_PKCS11_PIN`: a default PIN, as the 16-byte credential PIN (a typed
  PIN zero-padded). With it the token reports
  `CKF_PROTECTED_AUTHENTICATION_PATH`, and a `C_Login` without a PIN uses it.

No build has a built-in partition ID or owner backup key. Hardware and simulator
connections both need explicit configuration in every process: without `TSRA_PKCS11_ID`
or `obk_path`, `C_Initialize` returns `CKR_GENERAL_ERROR` with a debug line.
`C_Initialize` only takes the key file's name; the key is in memory only
during a `C_Login`. Every `C_Login` reads the file before it opens the device session,
also on a provisioned partition, and returns `CKR_FUNCTION_FAILED` with a
debug line when it is missing, a symbolic link or not exactly 48 bytes.

A bad setting fails closed instead of falling back to a default: an unknown
key (a credential included), a line without `=`, a boolean other than `1`,
`0`, `true` or `false` (any case), a credential that is not 32 hex
characters, a missing or empty file, and a path that is not absolute,
contains `..` or is longer than 4095 bytes make `C_Initialize` return
`CKR_GENERAL_ERROR`. `TSRA_PKCS11_DEBUG=1` prints the reason, with the line
for the file. Every path, `TSRA_PKCS11_CONF` included, must be absolute and
may carry a `file:` prefix. The configuration file and the owner backup key
file must be regular files, not symbolic links.

The module creates a missing store directory with mode 0700 (its parent must
exist) and refuses an existing one that is not a directory the calling user
owns with mode 0700, so `C_Initialize` fails.

## User role and PIN

This is the agreed user-role and PIN behaviour. The module logs in with the
device's V1 session, whose credential is a 16-byte partition ID plus a
16-byte PIN, so the token has exactly one user.

- `C_Login` as `CKU_USER` is the only login; `C_LoginUser` is the same call
  and ignores the username. `CKU_SO` returns `CKR_USER_TYPE_INVALID`.
  `C_InitToken`, `C_InitPIN` and `C_SetPIN` return
  `CKR_FUNCTION_NOT_SUPPORTED`: the device session has no Security Officer
  and no PIN change.
- A PIN has 4 to 16 bytes. It becomes the credential PIN zero-padded to 16
  bytes, unhashed, so the OpenSSL provider can present the same credential
  as raw bytes to the same partition. A PIN of another length returns `CKR_PIN_LEN_RANGE`, a PIN with
  a NUL byte `CKR_PIN_INVALID`. An empty PIN returns `CKR_PIN_LEN_RANGE`
  unless a default PIN is configured.
- A wrong PIN returns `CKR_FUNCTION_FAILED`, because the SDK reports a
  rejected credential as a generic failure (SDK issue #53). It becomes
  `CKR_PIN_INCORRECT` when the SDK names that status.
- The token reports `CKF_TOKEN_INITIALIZED` and `CKF_USER_PIN_INITIALIZED`
  from the start: there is no initialisation step, the first login does it.

**Trust boundary.** The first `C_Login` after power-on provisions the
partition with the configured partition ID, that login's PIN and the owner
backup key. Every later login, from any process, must present the same
credential until the next power cycle. So whoever opens the device node
first after power-on chooses the credential: restrict the device node to the
service account that runs the applications using this module.

## Testing

`tests/run_validation.sh` builds the module and drives it with OpenSC
`pkcs11-tool` (interactive smoke). Pure host logic has device-free unit tests
that link the translation unit directly: `tests/digest_kat_test.c` (NIST
vectors), the object-store harnesses, and `tests/aes_template_test.c` (the
complete CK_RV matrix of the keygen template validation and defaults, the
key-family choice and cipher mechanism policy, CK_GCM_PARAMS decoding, the
GCM/XTS output-length plan and the status maps; built with UBSan, so the
misaligned templates and parameter blocks it feeds the decoders are real
checks), `tests/attr_types_test.c` (the attribute type table and ceilings:
every `CK_BBOOL` and `CK_ULONG` attribute at the lengths callers get wrong),
`tests/attr_policy_test.c` (every `C_CreateObject` and `C_SetAttributeValue`
verdict, per object class), `tests/ec_template_test.c` (the EC key-pair
template verdicts, the curve and point encodings, the raw ECDSA lengths and
the sign mechanism table), `tests/mech_table_test.c` (the mechanism table
against the dispatch arms, in both directions), `tests/unwrap_params_test.c`
(the `CKM_RSA_AES_KEY_WRAP` parameters, the unwrap and key pair templates, the
blob lengths and the public key decoding), `tests/config_test.c` (the
environment configuration, the PIN rules and the owner backup key, built as a
hardware build) and `tests/config_file_test.c` (the configuration file
parser). `integration-tests/cpp/` is the functional suite
(GoogleTest, same shape as the OpenSSL provider's): it `dlopen`s the built
module and drives the real Cryptoki ABI: keygen including the GCM/XTS key
families, one-shot CBC, GCM and XTS round trips, EC key pairs on every curve
and ECDSA with every mechanism, each signature verified by the host oracle,
the two-call sizing discipline, the operation state machine and init
precedence, an init path for every advertised mechanism, attribute changes
and object sizes, the object policy and attribute typing, key survival
across every event that ends the device session, the unwrapping key pair and
`C_UnwrapKey`, known-answer tests on keys unwrapped from published vectors
(NIST CAVP AES-CBC and AES-XTS; the Project Wycheproof AES-CBC-PKCS#7,
AES-GCM and AES key wrap sets, invalid vectors included), what `C_Logout`
does to session objects, the configuration at `C_Initialize`, the interface
list, and the login rules (each
login case in a process of its own, because the first login of a process
provisions the emulated partition with its PIN). So it needs the emulator or
hardware build (see the CMakeLists.txt header for
the build/run recipe; `TSRA_PKCS11_MODULE` points it at a module,
`TSRA_PKCS11_TEST_PIN` overrides the test PIN). `tests/pkcs11test/` is
the conformance gate: it builds Google's PKCS#11 conformance program at a
pinned revision and requires every test on its include-list to pass, on the
memory store and again on a file store seeded with objects, which is how spec
behaviour is kept from regressing as pieces land (the list grows with them;
see the README there). `tests/pkcs11-check/` is a second, independent
conformance gate of the same kind: pkcs11-check, pinned with every dependency
by hash, against its own include-list (see the README there). The functional
suite also links the host's OpenSSL as an oracle (`utils/host_crypto.hpp`:
HMAC, HKDF, AES-CBC, AES key wrap, ECDSA verification, ECDH, RSA signatures and
OAEP, and the `CKM_RSA_AES_KEY_WRAP` blob builder), checked against published
vectors by `host_crypto_tests.cpp`; `integration-tests/cpp/vectors/` holds
known answers that `tools/gen_vectors.py` takes from the NIST and BoringSSL
vectors in `crates/crypto/src/testvectors/`. Wycheproof is not in the
repository: the functional suite's CMake build fetches it at a pinned commit
with a hash check and `tools/gen_wycheproof.py` converts the sets it uses in
the build directory (`FETCHCONTENT_SOURCE_DIR_WYCHEPROOF` points it at a local
copy). The CI
workflow (`.github/workflows/pkcs11.yml`) runs all of these on pushes/PRs to
the staging branch: the unit harnesses under UBSan and under ASan
(`tests/build_units.sh`), the functional suite on the memory store, on the
file store (`TSRA_PKCS11_PERSIST=1`) and against an ASan build of the module,
60 s of libFuzzer over the template decoders (`tests/template_fuzz.c`), and
the per-PR part of the pkcs11-check gate. `.github/workflows/pkcs11-nightly.yml`
adds the rest: the functional suite under ASan and UBSan on both stores, the
full pkcs11-check run against its baseline, the unfiltered pkcs11test run
against `tests/pkcs11test/offlist.md`, pkcs11-tool thread and import-refusal
smokes, and OpenSSL 3.5 with pkcs11-provider in front of the module
(`tests/nightly/`).
`tests/HARDWARE.md` lists what only a device can show, and how to run the same
suites on one.
