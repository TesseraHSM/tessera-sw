<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemEncapsulate (Opcode 0x2A) — schema-only

The parameter set is **not** carried on the wire.  It is recovered from the length of `pub_key`, which is unique per parameter set (ML-KEM-512 = 800 B, ML-KEM-768 = 1184 B, ML-KEM-1024 = 1568 B).  Carrying it explicitly would create a second source of truth that firmware must cross-check against the key, and would let a caller pair a parameter set with a mismatched key.

**Handler:** _Not implemented yet (wire schema only)_
**Session:** InSession

## Description

Encapsulates to a host-supplied ML-KEM public key and returns both the
ciphertext and the derived shared secret as a **masked** blob under the
requested scope's masking key.  The shared secret plaintext is 32 bytes
for all ML-KEM parameter sets; the TBOR response carries only the masked
envelope.

This snapshot defines only the wire schema; no firmware handler or PQC
implementation is registered.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the returned shared secret. |
| — | `pub_key` | `buffer` (up to 1568 B) | ML-KEM public / encapsulation key bytes. |

### Data section

Carries the public key.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `ciphertext` | `buffer` (up to 1568 B) | ML-KEM ciphertext bytes. |
| — | `masked_shared_secret` | `buffer` (164 B) | The 32-byte shared secret, masked under the requested scope's masking key. |

### Data section

Carries the ciphertext followed by the masked shared secret.  The masked
shared-secret length is `32 + 132 = 164` bytes.

## Errors

Handler errors are not defined yet because this command is schema-only.
Expected future errors include a public key whose length matches no
supported parameter set, malformed public
keys, unsupported key scope, and malformed request bodies.

## See also

- Decapsulate a ciphertext: [`mlkem_decapsulate.md`](./mlkem_decapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_encapsulate.rs`
