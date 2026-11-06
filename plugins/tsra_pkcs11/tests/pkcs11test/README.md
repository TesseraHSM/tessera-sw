# Conformance gate: Google pkcs11test

[pkcs11test](https://github.com/google/pkcs11test) (Apache-2.0) is Google's
PKCS#11 conformance program: 330 GoogleTest cases that `dlopen` any Cryptoki
module and check its behaviour against the spec — return-value precedence,
operation lifetimes, two-call sizing, template rules, token and session
semantics. It is the external oracle for this module, independent of our own
unit and functional tests, and it runs as a CI gate on pushes to and pull
requests into the staging branch.

## How the gate works

`run.sh <module.so> [work-dir]`

1. clones pkcs11test at the pinned revision (`PKCS11TEST_REV` in the script)
   into the work directory, or reuses a previous clone there,
2. resets that checkout, applies the two fixture patches (below) and builds
   the tool from clean — its makefile has no header dependencies, so an
   incremental build after a header change is silently stale,
3. runs it against the module with `-s 0 -u <pin> -X` and
   `--gtest_filter=<every name in include-list.txt>`,
4. fails unless **every listed test passed, ran, and actually asserted
   something**,
5. seeds a file object store with `seed_store.c` (a public and a private
   token data object and a token AES key, in a directory the module creates)
   and runs the same list again with `TSRA_PKCS11_PERSIST=1`, under the same
   conditions. Each process starts with an empty memory store, so only this
   run makes the object searches and listings meet objects the test did not
   create itself.

That third condition is not pedantry. GoogleTest exits 0 when a filter matches
nothing, so a test renamed upstream would silently stop being checked; and
pkcs11test's own skip mechanism does not mark a case skipped for GoogleTest —
the test body returns early and the case still prints `[ OK ]` and counts as
passed. A module that lost a whole mechanism would then keep a green gate,
because every test of that mechanism would "pass" by skipping. So the script
also compares the tests that ran against the list, and fails if a listed test
appears in pkcs11test's skip report.

The gate is an **include-list, not an exclude-list**: only the tests named in
`include-list.txt` must pass. Gating on the whole run would be red until the
module is complete — pkcs11test's `SKIP_IF_UNIMPLEMENTED` guard sits at
`C_*Init`, and our unimplemented mechanisms fail earlier, in fixture set-up
(key generation for DES/RSA/EC, the streaming stubs), so they show up as
failures. Gating on the listed names keeps every behaviour that once passed
from regressing while the list grows piece by piece.

**Policy:** when a piece lands, run `offlist.sh` (below), add every newly
green name to `include-list.txt`, raise `FLOOR` in `run.sh` to the new count,
and mention the additions in the commit message. `run.sh` fails when the list
names fewer tests than `FLOOR`, so a name cannot drop off silently; never
remove one without saying why. A test pkcs11test skips belongs off the list
until the feature lands, because it would assert nothing.

Flags: `-X` disables the Security Officer tests (this token has no SO
credential — the TSRA DDI has none); `-I` (token initialisation) is not
needed because `C_Login` provisions the partition lazily.

The gate drives the **emulator** module (`cargo build --features emu`), not
the standalone no-device build: every interesting conformance behaviour is
key-backed and needs a device behind the login.

## The fixture patches

Each patch encodes one policy and stays a few one-line changes. To regenerate
one against a newer revision, make the same substitutions in a clean checkout
and `git diff`.

### Login profile (`hsm-profile-login.patch`)

Four fixture base classes and five tests change their session class:

| file | class or test | from | to |
|---|---|---|---|
| `pkcs11test.h` | `SecretKeyTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `sign.cc` | `SignTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `hmac.cc` | `HmacTest` | `ReadOnlySessionTest` | `ROUserSessionTest` |
| `keypair.cc` | `KeyPairTest` | `ReadWriteSessionTest` | `RWUserSessionTest` |
| `object.cc` | `SetLatchingAttribute` | `ReadWriteSessionTest` | `RWUserSessionTest` |
| `tookan.cc` | `TookanAttackA3`, `A4`, `A5a`, `A5b` | `ReadWriteSessionTest` | `RWUserSessionTest` |

i.e. the cipher, signature, MAC and key-pair fixtures, and the tests that
generate a secret key in a read/write session, log in as the user before
generating their keys. The five tests therefore run under the name
`RWUserSessionTest.<test>`.

Why: pkcs11test's fixtures encode the soft-token model, where key generation
and use work in a public session. On this token every key operation runs in an
authenticated device session (`CKF_LOGIN_REQUIRED`), which the spec permits:
`CKR_USER_NOT_LOGGED_IN` is a listed return of `C_GenerateKey`,
`C_EncryptInit` and friends. Without the patch every key-backed fixture fails
in set-up before reaching the behaviour under test; with it the same tests run
unchanged against the logged-in profile. Public-object and digest tests need no
login and are untouched. Auto-opening a device session for public sessions was
considered and rejected — it would defeat the login.

### AES secret keys (`aes-fixture.patch`)

pkcs11test's `SecretKey` helper generates a 3DES key unless its caller names
a mechanism. The patch makes the default an AES-256 key (`CKM_AES_KEY_GEN`,
`CKA_VALUE_LEN` 32), the one secret-key type this token generates, so the
latch and Tookan tests built on the helper test this token's keys. Callers
that name a mechanism, such as the DES cipher cases, are unchanged.

## What the gate covers today (148 of 330)

Digests (SHA-1/256/384/512, one-shot and multi-part, sizing, the operation
state machine), the library/slot/session/login surface, public data objects
(including the `C_SetAttributeValue` argument and read-only checks and the
`C_CreateObject` template checks), the key-attribute latches and the readback
refusal of a sensitive key (`SetLatchingAttribute`, `TookanAttackA3`,
`TookanAttackA5a`), BER decoding, the AES-CBC cipher tests (one-shot round trip, sizing, wrong key,
IV validation, argument errors; multi-part argument errors, the final-call
length rules and the one-shot/multi-part mode rule) and the operation-lifetime
rules on the cipher and digest entry points, and the answers of the
random-number functions on a token without a generator (`CKR_RANDOM_NO_RNG`).

A full run reports 174 passing, but 26 of those are deliberately **not** on
the list, because they assert nothing: 23 that pkcs11test skips (the MD5
digest parameter, token initialisation, the SO logins suppressed by `-X`,
`C_GetOperationState`, the dual-function digest+encrypt), the two AES-ECB IV
cases, whose bodies return immediately for a mechanism that has no IV, and
`GenerateRandomNone`, which has nothing to check without a generator. They
come onto the list when the feature behind them lands.

Not yet covered, by bucket: `EncryptDecryptParts`, which expects one block out
of every one-block `C_EncryptUpdate`, while the SDK's CBC stream holds back the
last full block until the final call (the spec allows that; the case joins the
list once the SDK releases unpadded blocks at once), mechanisms this module
does not implement
(DES/3DES/AES-ECB, RSA, EC, sign/verify, HMAC, key pairs, wrap/unwrap),
entry points that are stubs (`C_CopyObject`, `C_DigestKey`), key import
through `C_CreateObject` with `CKA_VALUE`, which the token refuses, keys that
are not sensitive (`TookanAttackA4` and `A5b` ask for one, and the device holds
keys only masked), and a few tests
whose expectations assume a soft token or predate v3.0. For example
`EncryptDecryptInitInvalid` wants `CKR_KEY_TYPE_INCONSISTENT` for
`CKM_RSA_PKCS` on an AES key, where this token, which does not offer RSA,
answers `CKR_MECHANISM_INVALID`, and an error for a NULL mechanism, which
v3.0 made the way to end an operation.

A wrong PIN can be checked on the emulator: the first login in a process
provisions the credential, and a later login with another PIN fails. It fails
with `CKR_FUNCTION_FAILED`, because the SDK reports a rejected credential as a
generic failure, so `UserLoginWrongPIN` (which wants `CKR_PIN_INCORRECT`)
stays off the list until the SDK names that status.

No listed test uses a key after its device session ended; key survival
within a process is covered by the GoogleTest suite (`key_survival.*`). The
seeded key of the second run is only found and listed, never used: on the
emulator every process provisions its partition afresh, so a key from another
process does not unmask there (`CKR_KEY_HANDLE_INVALID`).

## Running it locally

```sh
cargo build -p tsra_pkcs11 --features emu
plugins/tsra_pkcs11/tests/pkcs11test/run.sh target/debug/tsra_pkcs11.so
```

`tests/run_validation.sh` runs it too, when the emulator module is present.

For the full picture rather than the gate, `offlist.sh` takes the same
arguments: it runs the gate, then the tool without a filter, and rewrites
`offlist.md` with every test that is not on the list, sorted into a bucket
that says why. It fails when an off-list test passes and asserts something
(that test belongs on the list) or when a name matches no bucket rule (add
one to `offlist.sh`).

```sh
plugins/tsra_pkcs11/tests/pkcs11test/offlist.sh target/debug/tsra_pkcs11.so
```
