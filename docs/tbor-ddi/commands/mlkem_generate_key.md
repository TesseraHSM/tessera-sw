<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemGenerateKey (Opcode 0x29)

**Handler:** `fw/core/lib/src/ddi/tbor/mlkem_generate_key.rs`
**Session:** InSession

## Description

Generates a fresh ML-KEM keypair for the requested PQC key kind and
returns the decapsulation key as a **masked** blob under the requested
scope's masking key, plus the public encapsulation key.

The decapsulation key is **not** persisted on-device: the caller holds
the masked blob and passes it back to
[`MlKemDecapsulate`](./mlkem_decapsulate.md) (unmask-on-use).  This is
the TBOR analogue of MBOR `MlkemGenerateKey`, but keyed by a masked blob
instead of a vault `private_key_id`.

`key_kind` is byte-identical to the PQC subset of `HsmVaultKeyKind` and
selects the ML-KEM parameter set.

The accepted key kinds are the three seed kinds `55`/`56`/`57`
(ML-KEM-512/-768/-1024). The masked payload contains the 64-byte `(d, z)`
seed pair followed by the expanded decapsulation key, authenticated
together. Decapsulation uses the expanded key directly; the seeds permit
public-key regeneration.

An active session is required. The requested scope determines the masking
key; there is no out-of-session development-key path.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the decapsulation key. |
| 20 | `key_kind` | `u8` (inline) | PQC key kind, seed-only: `55` = ML-KEM-512 seed, `56` = ML-KEM-768 seed, `57` = ML-KEM-1024 seed. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_key` | `buffer` (up to 3464 B) | The seed pair and expanded decapsulation key, masked (AEAD-GCM-256) under the scope's masking key. |
| 20 | `pub_key` | `buffer` (up to 1568 B) | The ML-KEM public / encapsulation key bytes. |

### Data section

Carries the masked decapsulation key followed by the public key. Masked
lengths are 1928 / 2696 / 3464 bytes for ML-KEM-512 / -768 / -1024:
`64 + expanded_decapsulation_key_len + 232`, where the envelope overhead
is header 8 + IV 16 + AAD 192 + tag 16.

The largest response carries `3464 + 1568 = 5032` data bytes and fits
inside the 8192-byte transport buffer with its header, TOC, and padding.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an active session |
| `InvalidArg` | `key_kind` is not one of the three supported seed kinds |
| `UnsupportedKeyScope` | The requested scope has no available masking key |

Malformed request bodies and backend key-generation or masking failures
are reported through their corresponding error statuses.

## See also

- Decapsulate with the generated key: [`mlkem_decapsulate.md`](./mlkem_decapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_generate_key.rs`
