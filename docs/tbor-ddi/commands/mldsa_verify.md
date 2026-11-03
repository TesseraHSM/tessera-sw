<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaVerify (Opcode 0x28)

The parameter set is **not** carried on the wire.  It is recovered from the length of `pub_key`, which is unique per parameter set (ML-DSA-44 = 1312 B, ML-DSA-65 = 1952 B, ML-DSA-87 = 2592 B).  Carrying it explicitly would create a second source of truth that firmware must cross-check against the key, and would let a caller pair a parameter set with a mismatched key.

**Handler:** `fw/core/lib/src/ddi/tbor/mldsa_verify.rs`
**Session:** InSession

## Description

Verifies an ML-DSA signature over a host-supplied message, or an external
`μ`, and public key.
The response carries no payload: a successful response *is* the affirmative
verification result.  An invalid signature is reported as the
`MlDsaVerifyFailed` (`0x0870010D`) error status, mirroring `EccVerifyFailed`.
Returning a boolean instead would let a caller that forgets to inspect it
treat any signature as valid.

`ctx` is the FIPS 204 context string of `ML-DSA.Verify(pk, M, sigma,
ctx)` (§5.3) and must match the `ctx` used at signing time: it is bound
into the signature, so verification under a different context fails.  It
is 0..=255 bytes — a hard FIPS 204 limit, because the signed message
representative encodes `|ctx|` in a single byte.  An empty `ctx` is the
FIPS 204 default.

`msg_type` selects what `message` is, as for
[`MlDsaSign`](./mldsa_sign.md): `0` for the message `M`, or `3` for the
64-byte external `μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M, 64)` with
an empty `ctx`.  A pure signature over `M` and `ctx` verifies over its
`μ`, and vice versa.  Values `1` and `2` are reserved (pre-hash ML-DSA)
and rejected, as are all others.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `pub_key` | `buffer` (up to 2592 B) | ML-DSA public key bytes. |
| — | `msg_type` | `u8` | `0` = `message` is the message; `3` = `message` is an external `μ`. |
| — | `message` | `buffer` (up to 586 B) | Message bytes that were signed, or the 64-byte `μ`. |
| — | `ctx` | `buffer` (0..=255 B) | FIPS 204 context string; must match the one used at signing time, and be empty with `μ`. |
| — | `signature` | `buffer` (up to 4627 B) | ML-DSA signature bytes. |

### Data section

Carries the public key, message, context string, and signature in that
order.

The message cap is **586 B**.  `MlDsaVerify` is the largest PQC frame —
it carries an ML-DSA-87 public key (2592 B), context string (255 B) and
signature (4627 B) alongside the message — and the binding limit is the
host encoder's staging budget, not TBOR's 8191-byte `MAX_DATA_SIZE`.  The
encoder stages the data section at offset 132 (`header(4) + 32 TOC
entries * 4`) inside an 8192-byte transport buffer (`REQ_BUF_LEN`):

```text
  transport buffer  =  8192
  stage offset      =  -132
  pub_key           = -2592
  signature         = -4627
  ctx               =  -255
  message budget    =   586
```

`MlDsaSign` uses the same cap: sign and verify are inverse operations
over pure ML-DSA, so any message that can be signed must also be
verifiable.

The cap is dictated entirely by `MlDsaVerify`.  If `MlDsaVerify` is ever
removed as a command, raising it is a deliberate one-constant change to
`MLDSA_MESSAGE_MAX_LEN` — sign alone would allow
`8192 - 132 - 164 - 255 = 7641` B.

Worst-case frame: data `2592 + 586 + 255 + 4627 = 8060` B; staged
`132 + 8060 = 8192` B (exactly the transport buffer) and encoded
`8 + 6*4 + 8060 = 8092` B (inside both the 8192-byte buffer and the
8191-byte `MAX_DATA_SIZE` data limit).  `msg_type` travels in its TOC
entry, so it costs the data section nothing.

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
| `InvalidArg` | A public key whose length matches no parameter set; a signature of the wrong length for it; `msg_type` other than `0` or `3`; with `3`, a `message` that is not 64 bytes or a non-empty `ctx` |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Generate a key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Sign a message: [`mldsa_sign.md`](./mldsa_sign.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_verify.rs`
