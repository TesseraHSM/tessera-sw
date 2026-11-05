# Hardware checklist

Every module test runs against the mock device. Some behaviour is decided by
the firmware and cannot be shown on the mock: credential checks, retry limits,
provisioning races, capacities, power-cycle survival, firmware crypto paths.
This file lists those items with the result expected on hardware, so a run on
a device is a run, not a design session.

## Running the suites on hardware

The test binaries are the same as in CI. Everything the run needs comes from
the environment:

| Variable | Meaning |
|---|---|
| `TSRA_PKCS11_HW=1` | The module drives a real device. Cases named `*_hw` run; mock-only cases skip. |
| `TSRA_PKCS11_MODULE` | Path of the hardware-backed `tsra_pkcs11.so`. |
| `TSRA_PKCS11_TEST_PIN` | The user PIN of the partition (default: the simulator's `1234`). |
| `TSRA_PKCS11_ID` | The partition ID, 32 hex characters. A hardware build has no built-in one and does not initialise without it. |
| `TSRA_PKCS11_OBK_PATH` | The 48-byte owner backup key file (or `obk_path` in the file `TSRA_PKCS11_CONF` names). A hardware build does not initialise without it, and every login reads it. |
| `TSRA_PKCS11_PERSIST=1`, `TSRA_PKCS11_STORE_DIR` | The file object store, in a directory that does not exist yet. |

```sh
export TSRA_PKCS11_HW=1 TSRA_PKCS11_MODULE=/path/to/tsra_pkcs11.so TSRA_PKCS11_TEST_PIN=...
ctest --test-dir <gtest-build-dir> --output-on-failure --output-junit gtest-mem.xml
TSRA_PKCS11_PERSIST=1 TSRA_PKCS11_STORE_DIR="$PWD/store" \
    ctest --test-dir <gtest-build-dir> --output-on-failure --output-junit gtest-file.xml
plugins/tsra_pkcs11/tests/pkcs11test/run.sh "$TSRA_PKCS11_MODULE" "$PWD/pkcs11test"
plugins/tsra_pkcs11/tests/pkcs11-check/run.sh "$TSRA_PKCS11_MODULE" "$PWD/pkcs11-check"
```

The GoogleTest results land in the JUnit files, the pkcs11test log in
`<work-dir>/run.log`, the pkcs11-check reports in `<work-dir>/run/out`. Any
difference from the mock result is a finding, not a reason to change an
include-list.

In the GoogleTest suite a hardware-only case is named `*_hw` and starts with
`HW_ONLY("why")`; it is skipped with that reason unless `TSRA_PKCS11_HW=1`. A
case that pins a mock-only model starts with `MOCK_ONLY("why")` and is skipped
on hardware (`integration-tests/cpp/utils/module.hpp`).

## Checklist

Record the firmware version and the platform before anything else, for every
run. Each item says what to do, what to expect, which cases cover it today,
and the result of the last hardware run.

### H-a Firmware, platform and key survival

- Run: generate AES keys, encrypt with CBC, GCM and XTS, `C_Logout`,
  `C_Login`, encrypt again. The same with an EC key pair, signing.
- Expect: the same ciphertexts after the login, and EC signatures that
  verify under the public point read before it. Firmware older than the key
  generation enablement fails at key generation.
- Cases: `key_survival.*`, `key_survival_persist.after_finalize_initialize`,
  `logout.public_session_object_survives_logout`,
  `aes_cbc.logout_tears_down_the_active_operation`, `ec_survival.*`,
  `ec_survival_persist.*`.
- Result: not run yet.

### H-b Provisioning through C_Login on a fresh partition

- Run: the first `C_Login` on a partition nobody has provisioned; then the
  same without `TSRA_PKCS11_ID`, without an owner backup key, and with a key
  file of 47 bytes.
- Expect: `CKR_OK`. The caller endorsement the module builds at run time (a
  fresh P-384 key from host libcrypto) passes the device's PKA check; the
  simulator checks it in software only. Without the partition ID or the
  owner backup key, `C_Initialize` fails with `CKR_GENERAL_ERROR` and a debug
  line. With the short key file, `C_Login` fails with `CKR_FUNCTION_FAILED`
  and a debug line, on a fresh partition (which stays unprovisioned) and on
  a provisioned one.
- Cases: `config_test` (unit, the hardware build's configuration),
  `login.every_login_reads_the_owner_backup_key` (mock only).
- Result: not run yet.

### H-c Provisioning race

- Run: two processes perform the first `C_Login` at the same time. Then kill
  a process between the BK3 initialisation and the credential setup.
- Expect: one process wins; the other gets "BK3 already initialised" (-41)
  and a clean `CK_RV` from `C_Login`. After the kill, record whether every
  later `C_Login` fails until a power cycle.
- Result: not run yet.

### H-d Second process on a provisioned partition

- Run: a second process logs in with the same PIN, another PIN and an empty
  PIN, and uses a token key the first process created.
- Expect: the same PIN logs in; another PIN fails with `CKR_FUNCTION_FAILED`
  (not `CKR_PIN_INCORRECT` until the SDK names the status); an empty PIN
  fails with `CKR_PIN_LEN_RANGE` unless `TSRA_PKCS11_PIN` sets a default; the
  token key works in the second process. The mock cannot show the last part:
  it provisions every process afresh.
- Cases: `persist.a_second_process_sees_the_token_object` (the object, not
  the key), `login.*`.
- Result: not run yet.

### H-e Power cycle and NSSR

- Run: create token keys, power-cycle the device (and separately reset it
  with NSSR), log in, use the keys.
- Expect: fails today, with the keys unusable (-26), until the module
  replays the backup masking key and the owner backup key at
  re-provisioning. With both replayed and the same endorsement key the keys
  come back; with a fresh endorsement key they do not.
- Result: not run yet.

### H-f First login wins

- Run: after power-on, log in from an arbitrary local process with an
  arbitrary PIN; try wrong PINs repeatedly; check the device node's
  permissions; after a reset, log in with any PIN once the backup keys are
  replayed.
- Expect: the first `C_Login` sets the credential, so the device node's
  permissions are the trust boundary. Record whether the device limits failed
  attempts (the simulator does not), and whether the first login after a
  reset takes over the old keys with any PIN.
- Result: not run yet.

### H-g Partition after the last file descriptor closes

- Run: provision, close every handle to the device, open it again, log in.
- Expect: unknown; record whether the partition stays provisioned.
- Result: not run yet.

### H-h Capacity across processes

- Run: start processes that log in and hold their session until `C_Login`
  refuses; end one; log in again. Fill the key table the same way.
- Expect: a clean `CK_RV` at the limit and a successful login after one
  holder ends. No fixed number: firmware and mock differ.
- Result: not run yet.

### H-i Killed processes

- Run: create token keys, `kill -9` the process, repeat.
- Expect: record whether device key entries stay until a partition reset.
- Result: not run yet.

### H-j Fork

- Run: fork a child from a process with an open device session; use the
  session in the parent afterwards.
- Expect: the parent's device session is unharmed; the child starts fresh.
- Result: not run yet.

### H-k Firmware crypto paths

- Run: an over-long ECDSA digest on the PKA, the XTS key container, GCM keys
  unwrapped over MBOR, a 16-byte XTS tweak against an 8-byte little-endian
  sector number, an XTS key with equal halves.
- Expect: the same results as on the mock and the host references: the
  known-answer cases give the published answers, every invalid Wycheproof
  vector is refused, and the XTS key with equal halves unwraps but does not
  encrypt.
- Cases: `ec_sign.every_curve_and_hash_signs_what_the_host_verifies` (a
  64-byte hash on P-256 and P-384 is the over-long digest), `unwrap_kat.*`,
  `unwrap.*`.
- Result: not run yet.

### H-l RSA decryption timing

- Run: time RSA decryption of valid and invalid PKCS#1 v1.5 and OAEP
  ciphertexts (Bleichenbacher, Manger), and `C_UnwrapKey` with blobs that fail
  in the OAEP block and in the key wrap. Optional before general availability.
- Expect: no timing difference an attacker can use.
- Result: not run yet.

### H-m External tools

- Run: pkcs11-check against an externally provisioned token; pkcs11-provider
  TLS with a token EC key; `p11perftest -n`.
- Expect: the same verdicts as on the mock.
- Result: not run yet.

### H-n The partition's unwrapping key

- Run: `C_GenerateKeyPair` for the unwrapping key right after power-on, after
  a partition reset, in two processes, and after a power cycle; unwrap with a
  token pair created before each event.
- Expect: the same modulus every time and in every process: the HSP keeps the
  key and re-imports it after a partition erase. While it is still staging
  the key the device answers "pending key generation"; the SDK retries with a
  backoff of about 12 s in all, then the call fails with
  `CKR_FUNCTION_FAILED`. Record how long the first call takes. A token pair
  from before the event still unwraps.
- Cases: `unwrapping_pair.*`, `unwrapping_pair_persist.token_pair_survives_finalize_initialize`;
  `unwrapping_pair_persist.another_partitions_pair_is_refused_at_unwrap` is
  mock-only (every mock process has a partition of its own).
- Result: not run yet.
