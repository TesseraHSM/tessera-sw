<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemGenerateKey (Opcode 0x29) — schema-only

**Handler:** _Not implemented yet (wire schema only)_
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

The TBOR wire is **seed-only**: the only accepted kinds are the three
seed kinds `55`/`56`/`57` (ML-KEM-512/-768/-1024), each carrying the
compact 64-byte `(d ‖ z)` seed material that is re-expanded on every use.
The expanded kinds `MlKem512Private = 56` … `MlKem1024Private = 58` still
exist in `HsmVaultKeyKind` and remain supported by the vault; they are
simply not offered on the wire yet.  Adding them later is additive to the
wire enum, but also requires raising the `masked_key` cap from 196 B to
3300 B (an expanded ML-KEM-1024 decapsulation key is 3168 B).

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the decapsulation key. |
| — | `key_kind` | `u8` (inline) | PQC key kind, seed-only: `55` = ML-KEM-512 seed, `56` = ML-KEM-768 seed, `57` = ML-KEM-1024 seed. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (196 B) | The ML-KEM `(d ‖ z)` seed material, masked (AEAD-GCM-256) under the scope's masking key. |
| — | `pub_key` | `buffer` (up to 1568 B) | The ML-KEM public / encapsulation key bytes. |

### Data section

Carries the masked decapsulation key followed by the public key.  The
wire is seed-only, so the masked blob is always `64 + 132 = 196` bytes:
the 64-byte `(d ‖ z)` seed material plus masked-envelope overhead
(header 8 + IV 12 + AAD 96 + tag 16).  If expanded key kinds are added
later the blob grows to `3168 + 132 = 3300` bytes for ML-KEM-1024.

Worst-case frame: request `4 + 3*4 = 16` B (no data section); response
`8 + 2*4 + (196 + 1568) = 1780` B — both well inside the 8192-byte
transport buffer.

## Errors

Handler errors are not defined yet because this command is schema-only.
Expected future errors include unsupported `key_kind`, unsupported key
scope, session lookup failures, and malformed request bodies.

## See also

- Decapsulate with the generated key: [`mlkem_decapsulate.md`](./mlkem_decapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_generate_key.rs`
