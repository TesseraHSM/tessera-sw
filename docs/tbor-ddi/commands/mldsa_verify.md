<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaVerify (Opcode 0x28)

The parameter set is **not** carried on the wire.  It is recovered from the length of `pub_key`, which is unique per parameter set (ML-DSA-44 = 1312 B, ML-DSA-65 = 1952 B, ML-DSA-87 = 2592 B).  Carrying it explicitly would create a second source of truth that firmware must cross-check against the key, and would let a caller pair a parameter set with a mismatched key.

**Handler:** `fw/core/lib/src/ddi/tbor/mldsa_verify.rs`
**Session:** InSession

## Description

Verifies an ML-DSA signature over a 64-byte message representative `μ`
under a host-supplied public key.
The response carries no payload: a successful response *is* the affirmative
verification result.  An invalid signature is reported as the
`MlDsaVerifyFailed` (`0x0870010D`) error status, mirroring `EccVerifyFailed`.
Returning a boolean instead would let a caller that forgets to inspect it
treat any signature as valid.

As [`MlDsaSign`](./mldsa_sign.md) signs `μ` rather than a message,
verification takes `μ` too: a pure ML-DSA signature over the message `M`
under the context string `ctx` (FIPS 204 §5.3) verifies over
`μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64)`, with
`tr = SHAKE256(pk, 64)`, whichever FIPS 204 implementation made it.  The
caller computes `μ`, on the host or on the device with [`Hash`](./hash.md).

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `pub_key` | `buffer` (up to 2592 B) | ML-DSA public key bytes. |
| — | `mu` | `buffer` (64 B) | The message representative `μ` the signature covers. |
| — | `signature` | `buffer` (up to 4627 B) | ML-DSA signature bytes. |

### Data section

Carries the public key, `μ`, and signature in that order.

Worst-case frame (ML-DSA-87): data `2592 + 64 + 4627 = 7283` B; staged
`132 + 7283 = 7415` B and encoded `8 + 4*4 + 7283 = 7307` B — both inside
the 8192-byte transport buffer.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
### Data section

_Empty._

## Errors

| Error | Cause |
|---|---|
| `MlDsaVerifyFailed` | The signature does not verify |
| `InvalidArg` | A public key whose length matches no parameter set; a signature of the wrong length for it |
| `TborInvalidFixedLength` | `mu` is not 64 bytes |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Generate a key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Sign a `μ`: [`mldsa_sign.md`](./mldsa_sign.md)
- Compute `μ` on the device: [`hash.md`](./hash.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_verify.rs`
