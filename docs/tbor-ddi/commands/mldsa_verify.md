<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaVerify (Opcode 0x28) — schema-only

The parameter set is **not** carried on the wire.  It is recovered from the length of `pub_key`, which is unique per parameter set (ML-DSA-44 = 1312 B, ML-DSA-65 = 1952 B, ML-DSA-87 = 2592 B).  Carrying it explicitly would create a second source of truth that firmware must cross-check against the key, and would let a caller pair a parameter set with a mismatched key.

**Handler:** _Not implemented yet (wire schema only)_
**Session:** InSession

## Description

Verifies an ML-DSA signature over a host-supplied message and public key.
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

This snapshot defines only the wire schema; no firmware handler or PQC
implementation is registered.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `pub_key` | `buffer` (up to 2592 B) | ML-DSA public key bytes. |
| — | `message` | `buffer` (up to 586 B) | Message bytes that were signed. |
| — | `ctx` | `buffer` (0..=255 B) | FIPS 204 context string; must match the one used at signing time. |
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
`4 + 6*4 + 8060 = 8088` B (inside both the 8192-byte buffer and the
8191-byte `MAX_DATA_SIZE` data limit).

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
### Data section

_Empty._

## Errors

Handler errors are not defined yet because this command is schema-only.
Expected future errors include a public key whose length matches no
supported parameter set, malformed public
keys/signatures, and malformed request bodies.

## See also

- Generate a key: [`mldsa_generate_key.md`](./mldsa_generate_key.md)
- Sign a message: [`mldsa_sign.md`](./mldsa_sign.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_verify.rs`
