<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaSign (Opcode 0x27)

**Handler:** `fw/core/lib/src/ddi/tbor/mldsa_sign.rs`
**Session:** InSession

## Description

Signs a host-supplied message, or an external `μ`, with a caller-held
**masked** ML-DSA secret key from
[`MlDsaGenerateKey`](./mldsa_generate_key.md).  The device unmasks the key
on use and signs; signing is hedged, so the same input yields a different,
equally valid signature each time.

There is intentionally no `key_kind` request field. The masked blob is
self-describing: its authenticated key kind tells firmware which ML-DSA
parameter set the seed belongs to.

`ctx` is the FIPS 204 context string of `ML-DSA.Sign(sk, M, ctx)`
(§5.2).  It is domain-separation input bound into the signature, so a
signature produced under one `ctx` never verifies under another.  It is
0..=255 bytes — a hard FIPS 204 limit, because the signed message
representative encodes `|ctx|` in a single byte.  An empty `ctx` is the
FIPS 204 default and reproduces the pre-context behaviour.

`msg_type` selects what `message` is:

| `msg_type` | `message` | `ctx` |
|---|---|---|
| `0` — pure | The message `M` (FIPS 204 §5.2). | 0..=255 B |
| `3` — external `μ` | The 64-byte message representative `μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64)`, where `tr = SHAKE256(pk, 64)`, computed by the caller and signed as is. | Must be empty: `μ` already binds it. |

A signature over `μ` is a pure signature over `M` and `ctx`: it verifies
with `msg_type` `0`, and a pure signature verifies with `msg_type` `3`.
`μ` can be computed on the device with [`Hash`](./hash.md) (SHAKE256, 64-byte
output): once over the public key for `tr`, then over
`tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M`.  Values `1` and `2` are reserved
(pre-hash ML-DSA) and rejected, as are all others.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_key` | `buffer` (164 B) | The masked ML-DSA seed; unmasked on-device.  Seed-only wire: 32-byte `xi` seed + 132 B envelope. |
| — | `msg_type` | `u8` | `0` = `message` is the message; `3` = `message` is an external `μ`. |
| — | `message` | `buffer` (up to 586 B) | Message bytes to sign, or the 64-byte `μ`. |
| — | `ctx` | `buffer` (0..=255 B) | FIPS 204 context string.  Empty is the default; must be empty with `μ`. |

### Data section

Carries the masked key, the message, then the context string.

The 586 B message cap is inherited from [`MlDsaVerify`](./mldsa_verify.md)
— sign and verify are inverse operations, so a message that can be signed
must also be verifiable.  `MlDsaSign` on its own would allow
`8192 - 132 - 164 - 255 = 7641` B.

Worst-case frame: data `164 + 586 + 255 = 1005` B; staged `132 + 1005 =
1137` B and encoded `8 + 5*4 + 1005 = 1033` B — both well inside the
8192-byte transport buffer.

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
| `InvalidArg` | `msg_type` other than `0` or `3`; with `3`, a `message` that is not 64 bytes or a non-empty `ctx` |
| `InvalidPermissions` | The key may not sign |
| `DdiDecodeFailed` | Malformed request body (e.g. `message` exceeds 586 B) |

The parameter set is recovered from the masked key's authenticated key
kind, so it is not carried on the wire.

## See also

- Generate the signing key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Verify a signature: [`mldsa_verify.md`](./mldsa_verify.md)
- Compute `μ` on the device: [`hash.md`](./hash.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_sign.rs`
