<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaSign (Opcode 0x27) — schema-only

**Handler:** _Not implemented yet (wire schema only)_
**Session:** InSession

## Description

Signs a host-supplied message with a caller-held **masked** ML-DSA secret
key from [`MlDsaGenerateKey`](./mldsa_generate_key.md).  The device will
unmask the key on use; this types-only phase defines no cryptography and
no firmware command handler.

There is intentionally no `key_kind` request field. The masked blob is
self-describing: its authenticated key kind tells firmware which ML-DSA
parameter set the seed belongs to.

`ctx` is the FIPS 204 context string of `ML-DSA.Sign(sk, M, ctx)`
(§5.2).  It is domain-separation input bound into the signature, so a
signature produced under one `ctx` never verifies under another.  It is
0..=255 bytes — a hard FIPS 204 limit, because the signed message
representative encodes `|ctx|` in a single byte.  An empty `ctx` is the
FIPS 204 default and reproduces the pre-context behaviour.

Available to **both Crypto-Officer and Crypto-User** sessions once a
handler is added.  In this snapshot the command is schema-only and is not
registered with firmware dispatch.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_key` | `buffer` (164 B) | The masked ML-DSA seed; unmasked on-device by the future handler.  Seed-only wire: 32-byte `xi` seed + 132 B envelope. |
| — | `message` | `buffer` (up to 586 B) | Message bytes to sign. |
| — | `ctx` | `buffer` (0..=255 B) | FIPS 204 context string.  Empty is the default. |

### Data section

Carries the masked key, the message, then the context string.

The 586 B message cap is inherited from [`MlDsaVerify`](./mldsa_verify.md)
— sign and verify are inverse operations, so a message that can be signed
must also be verifiable.  `MlDsaSign` on its own would allow
`8192 - 132 - 164 - 255 = 7641` B.

Worst-case frame: data `164 + 586 + 255 = 1005` B; staged `132 + 1005 =
1137` B and encoded `4 + 4*4 + 1005 = 1025` B — both well inside the
8192-byte transport buffer.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `signature` | `buffer` (up to 4627 B) | ML-DSA signature bytes (maximum for ML-DSA-87). |

### Data section

Carries the signature.

## Errors

Handler errors are not defined yet because this command is schema-only.
The parameter set is recovered from the masked key's authenticated key
kind, so it is not carried on the wire.

## See also

- Generate the signing key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Verify a signature: [`mldsa_verify.md`](./mldsa_verify.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_sign.rs`
