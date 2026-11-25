<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaGenerateKey (Opcode 0x26)

**Handler:** `fw/core/lib/src/ddi/tbor/mldsa_generate_key.rs`
**Session:** InSession

## Description

Generates a fresh ML-DSA keypair for the requested PQC key kind and
returns the secret key as a **masked** blob under the requested scope's
masking key, plus the ML-DSA public key.

The secret key is **not** persisted on-device: the caller holds the
masked blob and passes it back to [`MlDsaSign`](./mldsa_sign.md)
(unmask-on-use).  This is the TBOR analogue of the MBOR
`MldsaGenerateKey` command, but keyed by a masked blob instead of a vault
`private_key_id`.

`key_kind` is byte-identical to the PQC subset of `HsmVaultKeyKind` and
selects the ML-DSA parameter set.

The accepted key kinds are the three seed kinds `46`/`47`/`48`
(ML-DSA-44/-65/-87). The masked payload contains the 32-byte `xi` seed
followed by the expanded secret key, authenticated together. Keeping the
expanded key avoids regenerating it for every signature; retaining the
seed permits public-key regeneration.

Available to **both Crypto-Officer and Crypto-User** active sessions.
The requested scope determines the masking key; there is no
out-of-session development-key path.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the secret key. |
| 20 | `key_kind` | `u8` (inline) | PQC key kind, seed-only: `46` = ML-DSA-44 seed, `47` = ML-DSA-65 seed, `48` = ML-DSA-87 seed. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_key` | `buffer` (up to 5160 B) | The seed and expanded ML-DSA secret key, masked (AEAD-GCM-256) under the scope's masking key. |
| 20 | `pub_key` | `buffer` (up to 2592 B) | The ML-DSA public key bytes. |

### Data section

Carries the masked private key followed by the public key. Masked lengths
are 2824 / 4296 / 5160 bytes for ML-DSA-44 / -65 / -87:
`32 + expanded_secret_key_len + 232`, where the envelope overhead is
header 8 + IV 16 + AAD 192 + tag 16.

The largest response carries `5160 + 2592 = 7752` data bytes and fits
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

- Sign with the generated key: [`mldsa_sign.md`](./mldsa_sign.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_generate_key.rs`
