<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# VerifyKey (Opcode 0x32)

**Handler:** `fw/core/lib/src/ddi/tbor/verify_key.rs`
**Session:** InSession

## Description

Authenticates a caller-held **masked** key of any kind without using it.
Hosts call it when a masked key is unmasked, so a tampered blob or a
session-scoped blob from another session is rejected at that point rather
than on the first operation that uses the key.

The device resolves the masking key for the blob's scope (a `Session`-scope
blob resolves to the calling session's key) and unmasks the key **in place**
in the request buffer. This verifies the AEAD tag, which covers both the
cleartext metadata (carried as AAD) and the encrypted key material, and then
validates the metadata. No key usage attribute is required. The recovered
plaintext key is scrubbed from the request buffer during IO teardown. The
command persists nothing and returns no payload.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | `masked_key` | `buffer` (≤ 5160 B) | The masked key; unmasked in place. |

### Data section

Carries the masked key, including expanded ML-DSA-87 material (the largest
generated envelope), ML-DSA-65 and ML-KEM-1024 envelopes.

## Response

Empty acknowledgement (a single `none` TOC entry).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `AesGcmDecryptTagDoesNotMatch` | The masked key fails authentication (tampered, or wrong scope / session) |
| `MaskedKeyDecodeFailed` | The masked key is malformed |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Recover a key pair's public key (also authenticates): [`get_public_key.md`](./get_public_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/verify_key.rs`
