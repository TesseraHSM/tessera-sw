<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemEncapsulate (Opcode 0x2A)

The parameter set is **not** carried on the wire.  It is recovered from the length of `pub_key`, which is unique per parameter set (ML-KEM-512 = 800 B, ML-KEM-768 = 1184 B, ML-KEM-1024 = 1568 B).  Carrying it explicitly would create a second source of truth that firmware must cross-check against the key, and would let a caller pair a parameter set with a mismatched key.

**Handler:** `fw/core/lib/src/ddi/tbor/mlkem_encapsulate.rs`
**Session:** InSession

## Description

Encapsulates to a host-supplied ML-KEM public key and returns both the
ciphertext and the derived shared secret as a **masked** blob under the
requested scope's masking key.  The shared secret plaintext is 32 bytes
for all ML-KEM parameter sets; the TBOR response carries only the masked
envelope.

An active session is required. The requested scope determines the masking
key for the returned shared secret.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the returned shared secret. |
| 20 | `pub_key` | `buffer` (up to 1568 B) | ML-KEM public / encapsulation key bytes. |

### Data section

Carries the public key.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `ciphertext` | `buffer` (up to 1568 B) | ML-KEM ciphertext bytes. |
| 16 | (padding) | `padding` (0..=3 B) | Places `masked_shared_secret` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 20 | `masked_shared_secret` | `buffer` (264 B) | The 32-byte shared secret, masked under the requested scope's masking key. |

### Data section

Carries the ciphertext followed by the masked shared secret.  The masked
shared-secret length is `32 + 232 = 264` bytes.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an active session |
| `InvalidArg` | The public-key length matches no supported parameter set |
| `UnsupportedKeyScope` | The requested scope has no available masking key |
| `TborNonCanonicalLayout` | `pub_key` is not the first data field immediately after the request TOC |

Malformed keys, request bodies, and backend encapsulation or masking
failures are reported through their corresponding error statuses.

## See also

- Decapsulate a ciphertext: [`mlkem_decapsulate.md`](./mlkem_decapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_encapsulate.rs`
