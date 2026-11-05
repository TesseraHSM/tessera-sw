<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaSign (Opcode 0x27)

**Handler:** `fw/core/lib/src/ddi/tbor/mldsa_sign.rs`
**Session:** InSession

## Description

Signs a 64-byte message representative `μ` with a caller-held **masked**
ML-DSA secret key from [`MlDsaGenerateKey`](./mldsa_generate_key.md).  The
device unmasks the key on use and signs, hedged or deterministically as
`hedge` selects.

There is intentionally no `key_kind` request field. The masked blob is
self-describing: its authenticated key kind tells firmware which ML-DSA
parameter set the seed belongs to.

Like [`EccSign`](./ecc_sign.md), which signs a digest rather than a
message, `MlDsaSign` signs `μ` rather than the message `M`:

```text
tr = SHAKE256(pk, 64)
μ  = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64)
```

`μ` is what pure ML-DSA (FIPS 204 §5.2) signs for `M` under the context
string `ctx` (0..=255 bytes; empty is the FIPS 204 default), so a signature
over it is a pure ML-DSA signature over `M` and `ctx`, verifiable by any
FIPS 204 implementation.  The caller computes `μ`, binding its context
string: on the host, or on the device with [`Hash`](./hash.md) (SHAKE256,
64-byte output), once over the public key for `tr` and then over
`tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M`.

`hedge` selects how the signature is randomized.  Its values and meanings
follow PKCS#11's `CK_HEDGE_TYPE`:

| `hedge` | PKCS#11 | Signature |
|---|---|---|
| `0` — preferred | `CKH_HEDGE_PREFERRED` | Hedged or deterministic, as the device chooses.  The device signs hedged. |
| `1` — required | `CKH_HEDGE_REQUIRED` | Hedged: FIPS 204's default variant, with fresh randomness `rnd` from the device's TRNG, so the same `μ` yields a different, equally valid signature each time. |
| `2` — deterministic | `CKH_DETERMINISTIC_REQUIRED` | Deterministic: FIPS 204's variant with `rnd = {0}^32`, so the same key and `μ` always yield the same signature. |

Both variants verify the same way, so `MlDsaVerify` has no `hedge`.
Hedged signing also resists fault and side-channel attacks that exploit
signing the same input repeatedly; prefer it unless signatures must be
reproducible.  Other values are rejected.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_key` | `buffer` (up to 5160 B) | The complete masked blob returned by `MlDsaGenerateKey`; unmasked on-device.  The 32-byte `xi` seed followed by the expanded secret key, plus the 232 B envelope: 2824 / 4296 / 5160 B for ML-DSA-44 / 65 / 87. |
| — | `mu` | `buffer` (64 B) | The message representative `μ` to sign. |
| — | `hedge` | `u8` | `0` = hedge preferred; `1` = hedge required; `2` = deterministic required. |

### Data section

Carries the masked key, then `μ`.

Worst-case frame (ML-DSA-87 key): data `5160 + 64 = 5224` B; staged
`132 + 5224 = 5356` B and encoded `8 + 4*4 + 5224 = 5248` B — both inside
the 8192-byte transport buffer.  `hedge` travels in its TOC entry, so it
costs the data section nothing.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `signature` | `buffer` (up to 4627 B) | ML-DSA signature bytes (maximum for ML-DSA-87). |

### Data section

Carries the signature.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | `hedge` other than `0`, `1` or `2` |
| `InvalidKeyType` | The masked blob is not an ML-DSA key |
| `InvalidPermissions` | The key may not sign |
| `TborInvalidFixedLength` | `mu` is not 64 bytes |
| `DdiDecodeFailed` | Malformed request body |

The parameter set is recovered from the masked key's authenticated key
kind, so it is not carried on the wire.

## See also

- Generate the signing key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Verify a signature: [`mldsa_verify.md`](./mldsa_verify.md)
- Compute `μ` on the device: [`hash.md`](./hash.md)
- Sign a digest with ECC: [`ecc_sign.md`](./ecc_sign.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_sign.rs`
