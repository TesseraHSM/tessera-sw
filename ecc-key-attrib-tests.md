# ECC Key-Generation Attribute Tests

Date: 2026-11-11. Branch: `user/rajeshgali/ecc-key-attrib`.
Merge resolution verified: 2026-11-12.

## Scope

Add or strengthen tests in [api/tests/src/algo/ecc/key_prop_tests.rs](api/tests/src/algo/ecc/key_prop_tests.rs), one test at a time. After each implementation, run only that test against both runtime-selected session APIs and record the result before implementing the next test. Production API and firmware source code must remain unchanged. Preserve unrelated existing tests and user edits.

`PASS` means the named test ran and its assertions passed. `FAIL` means it ran and an assertion failed; record the actual result without fixing production code. `NOT RUN` is not a pass. Matrix entries within a test are described in the coverage column; test-runner counts refer to test functions, not matrix entries.

Both configurations use the socket simulator, not hardware:

- API `1_0`: legacy MBOR session.
- API `1_1`: SessionEx/TBOR session.

## Test Table

| # | Test | Change and Coverage | Expected Result | API 1.0 | API 1.1 |
| --- | --- | --- | --- | --- | --- |
| 1 | Private flag cases below | One independently named test per flag, usage, and curve (P-256/P-384/P-521). Each proves an otherwise identical control succeeds first. | Flag unset: success. Only that flag set: `InvalidKeyProps`. | See individual results | See individual results |
| 2 | Public flag cases below | One independently named test per flag, usage, and curve (P-256/P-384/P-521). Each proves an otherwise identical control succeeds first. | Flag unset: success. Only that flag set: `InvalidKeyProps`. | See individual results | See individual results |
| 3 | `test_ecc_pub_props_missing_curve_with_bits_fails` | Add: build public properties with bits but no curve, then call key generation with a valid private template; P-256/P-384/P-521, 3 cases. | Builder succeeds; key generation returns exactly `InvalidKeyProps`. | PASS | PASS |
| 4 | `test_ecc_key_pair_valid_derive_succeeds` | Strengthen: replace the misleading derive-only negative with an actual DERIVE/DERIVE success check; P-256/P-384/P-521, 3 cases. Existing incompatible-pair negatives remain. | Generation succeeds; returned keys have DERIVE, no SIGN/VERIFY, and matching sizes/curves. | PASS | PASS |
| 5 | `test_ecc_pub_props_bits_normalized_to_curve` | Strengthen: replace the weak public-bits mismatch assertion with exact success/metadata checks; 3 curves and both usages, 6 cases. | Current behavior: success and returned bits match the curve, not the inconsistent public bit request. This is normalization, not rejection. | PASS (behavior only) | PASS (behavior only) |
| 6 | `test_ecc_key_pair_session_mismatch_fails` | Add: private session/public persistent and the reverse; 2 cases. | Exactly `InvalidKeyProps`. | PASS | PASS |
| 7 | `test_ecc_key_pair_explicit_scope_mismatch_fails` | Add: all unequal ordered pairs of Session, Ephemeral, Local, and SecurityDomain scopes; 12 cases. No security-domain provisioning is needed for invalid pairs. | Observed `InvalidKeyProps`; legacy error precedence needs confirmation. No command-dispatch assertion. | PASS (precedence unconfirmed) | PASS |
| 8 | `test_ecc_key_pair_equivalent_scopes` | Add: equivalent explicit/implicit Session and Local scopes on either or both halves; contradictory legacy session flags are normalized by the builder; 6 cases. | API 1.0: exactly `UnsupportedApiRevision`. API 1.1: success with the expected session flags. | PASS | PASS |
| 9 | `test_ecc_key_labels_preserved` | Add: empty, short nonempty, maximum-minus-one, and maximum-length private labels; 3 curves and both usages, 24 cases. | Success; private label bytes and both key sizes are preserved. The API maximum remains unconfirmed. | PASS (boundary unconfirmed) | PASS (boundary unconfirmed) |
| 10 | `test_ecc_key_label_too_long_fails` | Add: maximum-plus-one private label for signing and derivation; 2 cases. | Current behavior: API 1.0 returns exactly `InternalError`; API 1.1 returns exactly `InvalidKeyProps`. The legacy error mapping is not fixed here. | PASS (behavior only) | PASS (behavior only) |

## Independent Flag Tests

Each flag/usage family has three independently named tests: `p256`, `p384`, and `p521`. For example, `test_ecc_priv_sign_wrap_fails::p384` checks only P-384. A local macro defines the same three tests for each family without a runtime curve loop. Convert one family at a time and run each of its three tests separately on both API revisions before converting the next family.

Each test generates a session key pair for its selected curve with its selected flag explicitly false, verifies both returned curves and bit lengths, deletes the control keys, then repeats the same property construction with only that flag true. A failed control fails the test; it cannot be counted as a successful negative case. Signing uses private SIGN/public VERIFY; derivation uses DERIVE on both halves. Curve-specific results must be recorded separately; prior P-256-only passes are not results for the replacement tests.

The private WRAP and VERIFY restrictions also follow the property-class applicability in [api/native/doc/chapter_05_key_props.md](api/native/doc/chapter_05_key_props.md). ECC encryption/decryption/wrapping usages are outside the ECC signing/derivation contract; these assertions do not derive their expected result from a backend's observed output. Error-location claims are not made: the tests check the public API result, not command-dispatch counts.

Each result column identifies the curve and API revision. All cases require control success followed by exactly `InvalidKeyProps` when only the selected flag is set.

| Test Family | Selected Flag | P256 1.0 | P256 1.1 | P384 1.0 | P384 1.1 | P521 1.0 | P521 1.1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `test_ecc_priv_sign_wrap_fails` | Private WRAP, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_derive_wrap_fails` | Private WRAP, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_sign_encrypt_fails` | Private ENCRYPT, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_derive_encrypt_fails` | Private ENCRYPT, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_sign_decrypt_fails` | Private DECRYPT, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_derive_decrypt_fails` | Private DECRYPT, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_sign_unwrap_fails` | Private UNWRAP, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_derive_unwrap_fails` | Private UNWRAP, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_sign_verify_fails` | Private VERIFY, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_priv_derive_verify_fails` | Private VERIFY, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_verify_wrap_fails` | Public WRAP, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_derive_wrap_fails` | Public WRAP, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_verify_encrypt_fails` | Public ENCRYPT, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_derive_encrypt_fails` | Public ENCRYPT, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_verify_decrypt_fails` | Public DECRYPT, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_derive_decrypt_fails` | Public DECRYPT, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_verify_unwrap_fails` | Public UNWRAP, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_derive_unwrap_fails` | Public UNWRAP, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_verify_sign_fails` | Public SIGN, signing pair | PASS | PASS | PASS | PASS | PASS | PASS |
| `test_ecc_pub_derive_sign_fails` | Public SIGN, derivation pair | PASS | PASS | PASS | PASS | PASS | PASS |

Three-curve result: 20 flag/usage families generate 60 independently named tests. Each was run separately on API 1.0 and 1.1: 120 isolated executions, 120 PASS, 0 FAIL. Each command selected exactly one test. Each execution checked successful control generation with the selected curve and bit length, then `InvalidKeyProps` with only the selected flag enabled. The macro is retained; no production or firmware behavior was changed.

Historical P-256-only result: 20 tests on API 1.0 and 1.1, for 40 isolated executions, all PASS. The curve-specific table above supersedes those results for the new three-curve tests. No production or firmware behavior is changed.

## Reproduction

For flag tests, replace `TEST_NAME` with a family name from the table and `CURVE` with `p256`, `p384`, or `p521`. The anchored filter must select exactly one test; a zero-test selection is not a pass. For the other test-table entries, omit `::CURVE`.

```bash
cargo xtask nextest --transport sock --api-rev 1_0 --package tsra_api_tests --filterset 'test(/^algo::ecc::key_prop_tests::TEST_NAME::CURVE$/)'
cargo xtask nextest --transport sock --api-rev 1_1 --package tsra_api_tests --filterset 'test(/^algo::ecc::key_prop_tests::TEST_NAME::CURVE$/)'
```

## Historical Execution Log

The following list records the original ten-function execution, before the flag-test correction. It is not validation of the replacement tests or proof of requirements compliance. The individual flag table above records the replacement results. The current tree uses runtime transport/API selection, not the removed `emu` and `session-ex-tests` feature switches.

1. Private forbidden flags: PASS on API 1.0 and 1.1. Each command selected exactly one test; all 10 combinations returned `InvalidKeyProps`.
2. Public forbidden flags: PASS on API 1.0 and 1.1. Each command selected exactly one test; all 10 combinations returned `InvalidKeyProps` while valid public usage remained set.
3. Missing public curve with explicit bits: PASS on API 1.0 and 1.1. Each command selected exactly one test; all three templates built successfully and generation returned `InvalidKeyProps`.
4. Valid derive-only pairs: PASS on API 1.0 and 1.1. Each command selected exactly one test; all three curves generated DERIVE/DERIVE pairs with the expected sizes and no signing/verification capability.
5. Public bit-length normalization: PASS on API 1.0 and 1.1. Each command selected exactly one test; all six inconsistent public-size requests succeeded and returned the curve's actual size. No strict rejection policy was added.
6. Session-flag mismatch: PASS on API 1.0 and 1.1. Each command selected exactly one test; both private/public lifetime mismatch directions returned `InvalidKeyProps`.
7. Explicit scope mismatch: PASS on API 1.0 and 1.1. Each command selected exactly one test; all 12 unequal ordered scope pairs returned `InvalidKeyProps`.
8. Equivalent explicit/implicit scopes: PASS on API 1.0 and 1.1. Each command selected exactly one test; all six legacy cases returned `UnsupportedApiRevision`, while all six SessionEx cases generated keys with the expected normalized session flags.
9. Label preservation: PASS on API 1.0 and 1.1. Each command selected exactly one test; all 24 label/curve/usage combinations generated keys with the requested private label and expected key sizes.
10. Oversized labels: PASS on API 1.0 and 1.1. Each command selected exactly one test; signing and derivation both returned `InternalError` on legacy and `InvalidKeyProps` on SessionEx. The difference remains unchanged.

Historical result before the flag-test correction: 10 test functions executed individually on each API revision, for 20 isolated test executions: 20 PASS, 0 FAIL. The old flag-matrix results are superseded by the independent control/negative tests above; they are not results for the replacement tests. This is behavioral testing, not measured branch coverage.

## Merge Resolution Verification

All nine conflict regions in the ECC property-test file were reconciled. The approved macro and matched positive controls remain. The two older P-256-only flag matrices restored by the stash were removed because the 60 curve-specific cases supersede them. Other property, generation, and unwrap tests were preserved, including the more accurate `test_ecc_pub_props_verify_and_derive_fail` name from the stashed edits.

The duplicate oversized-label definition was reconciled into one test. Scope and label tests use runtime `api_rev_at_least(1, 1)` selection, not the removed `session-ex-tests` feature. Existing size/label expectations were not changed or promoted into requirements.

| Check | Result |
| --- | --- |
| Macro flag inventory | All 20 flag/usage families retained, with independent `p256`, `p384`, and `p521` tests: 60 cases. |
| Companion additions | Missing public curve with bits, derive-only success, public-bit normalization, session mismatch, explicit-scope mismatch, equivalent scopes, label preservation, and label overflow all retained. |
| Previously broken label test | Compiled and passed individually on API 1.0 and 1.1. |
| Complete Rust ECC property suite plus generation checks, API 1.0 | 126 selected tests, 126 PASS, 0 FAIL. |
| Same selection, API 1.1 | 126 selected tests, 126 PASS, 0 FAIL. |
| Editor diagnostics | No errors in either Rust ECC test file. |
| Test-package formatting | PASS. |
| Repository CI Clippy (`--all-targets -- -D warnings`) | PASS. |

The 126-test selection includes all 104 tests in the Rust ECC property module, 16 existing key-generation rejection tests, three curve-specific generation success tests, and three ECDH success tests. Tests outside this selection were not run. These are fresh post-resolution results, separate from the earlier individually executed curve tests.

```bash
cargo xtask nextest --transport sock --api-rev 1_0 --package tsra_api_tests --filterset 'test(algo::ecc::key_prop_tests::) | test(algo::ecc::key_tests::test_ecc_keygen_) | test(key_pair_generation) | test(algo::ecc::ecdh_tests::test_ecdh_success_)'
cargo xtask nextest --transport sock --api-rev 1_1 --package tsra_api_tests --filterset 'test(algo::ecc::key_prop_tests::) | test(algo::ecc::key_tests::test_ecc_keygen_) | test(key_pair_generation) | test(algo::ecc::ecdh_tests::test_ecdh_success_)'
```

No production or firmware files were edited. Only the resolved property-test file's staged content is refreshed; pre-existing staged changes in the other ECC test file and unrelated untracked documents are preserved. No commit was created.

## Remaining Requirement Questions

- Public bits/curve inconsistency is currently normalized rather than rejected. A green normalization test does not establish strict public-template consistency validation; its requirement remains unresolved. It was not changed by the flag-test correction.
- An oversized label currently maps to `InternalError` through the legacy MBOR conversion, rather than the TBOR `InvalidKeyProps` result. That expectation is characterization, not an established requirement, and was not changed by the flag-test correction.
- The native property documentation says labels are shorter than 128 bytes, while the existing label test accepts the 128-byte wire capacity. The Rust API boundary must be confirmed before correcting that test.
- The legacy error precedence for an explicitly scoped but inconsistent key pair is not established by the documented scope contract. A final `InvalidKeyProps` result alone also does not prove rejection before a device command.

## Final Checks

- Formatting after three-curve correction: PASS (`cargo +nightly fmt --package tsra_api_tests -- --check`).
- Repository CI Clippy after three-curve correction: PASS (`cargo xtask precheck --clippy`, including `--all-targets -- -D warnings`).
- Whitespace after three-curve correction: PASS (`git diff --check`).
- Production/firmware source unchanged after three-curve correction: VERIFIED. Only the ECC Rust test file and this report were edited; the pre-existing untracked test-gate inventory is untouched.