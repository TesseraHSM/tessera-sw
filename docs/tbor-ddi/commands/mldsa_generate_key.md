<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlDsaGenerateKey (Opcode 0x26) — schema-only

**Handler:** _Not implemented yet (wire schema only)_
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

The TBOR wire is **seed-only**: the only accepted kinds are the three
seed kinds `46`/`47`/`48` (ML-DSA-44/-65/-87), each carrying the compact
32-byte ML-DSA `xi` seed that is re-expanded on every use.  The expanded
kinds `MlDsa44Private = 47` … `MlDsa87Private = 49` still exist in
`HsmVaultKeyKind` and remain supported by the vault; they are simply not
offered on the wire yet.  Adding them later is additive to the wire enum,
but also requires raising the `masked_key` cap from 164 B to 5028 B (an
expanded ML-DSA-87 secret key is 4896 B).

Available to **both Crypto-Officer and Crypto-User** sessions once a
handler is added.  In this snapshot the command is schema-only and is not
registered with firmware dispatch.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the secret key. |
| — | `key_kind` | `u8` (inline) | PQC key kind, seed-only: `46` = ML-DSA-44 seed, `47` = ML-DSA-65 seed, `48` = ML-DSA-87 seed. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (164 B) | The ML-DSA seed, masked (AEAD-GCM-256) under the scope's masking key. |
| — | `pub_key` | `buffer` (up to 2592 B) | The ML-DSA public key bytes. |

### Data section

Carries the masked private key followed by the public key.  The wire is
seed-only, so the masked blob is always `32 + 132 = 164` bytes: the
32-byte `xi` seed plus masked-envelope overhead (header 8 + IV 12 +
AAD 96 + tag 16).  If expanded key kinds are added later the blob grows
to `4896 + 132 = 5028` bytes for ML-DSA-87.

Worst-case frame: request `4 + 3*4 = 16` B (no data section); response
`8 + 2*4 + (164 + 2592) = 2772` B — both well inside the 8192-byte
transport buffer.

## Errors

Handler errors are not defined yet because this command is schema-only.
Expected future errors include unsupported `key_kind`, unsupported key
scope, session lookup failures, and malformed request bodies.

## See also

- Sign with the generated key: [`mldsa_sign.md`](./mldsa_sign.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mldsa_generate_key.rs`
