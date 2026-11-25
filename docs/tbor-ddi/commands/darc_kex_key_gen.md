<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcKexKeyGen (Opcode 0x20)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_kex_key_gen.rs`
**Session:** InSession

## Description

Generates a new DARC key-exchange key and returns the **masked** private
key together with the public key.  The request's `kem` selects the HPKE
KEM of the key-exchange key:

| `kem` | KEM | Private key (masked) | `masked_key` | `pub_key` |
|---|---|---|---|---|
| `0` | DHKEM(P-384, HKDF-SHA384) | 48-B scalar | 280 B | 96 B raw `x ‖ y` |
| `1` | ML-KEM-1024 | 64-B seed (`d ‖ z`) | 296 B | 1568 B encapsulation key |
| `2` | MLKEM1024-P384 (hybrid) | 32-B seed | 264 B | 1665 B (`ek ‖ SEC1 P-384`) |

Each KEM is recorded under its own masked-key kind (`DarcKex`,
`DarcKexMlKem1024`, `DarcKexMlKem1024P384`); the kind selects the KEM when
the key is later used by [`DarcTmkImport`](darc_tmk_import.md) or attested
by [`KeyReport`](key_report.md).

This is the HPKE **recipient** key for DARC TMK imports. Outgoing DARC
transfers use HPKE Base and authenticate with a source PID-signed
operation report, not a source KEX identity.

The private key is **not** stored on the device.  It is masked
(AEAD-GCM-256) under the masking key associated with the requested
`scope` and the masked blob is returned to the caller, which re-imports
it (unmask-on-use) when the key is later needed.  Because nothing is
persisted, the command records no rollback on the undo log.

The request carries the requested key `scope` (lifecycle / visibility
domain) as its 1-byte `KeyScope` discriminant — a wire mirror of the
firmware `HsmKeyScope`.  Scope → masking key:

- `Ephemeral` → the partition `PartitionEphemeralMaskingKey`.
- `Local` → the partition `PartitionLocalMaskingKey`.
- `SecurityDomain` → `SdMasking`, once the security domain is initialized.

Both masking keys are provisioned by `PartFinal`, so the partition must
be in the `Initialized` lifecycle state. The `Session` scope
and unsupported scopes are rejected with
`UnsupportedKeyScope`.  The masked key's metadata records the
key-exchange key as `derive`-only, `local`, `private`, and
never-extractable, plus the requested scope, under the distinct
DARC key-exchange kind (kept separate from the security-domain `SdSealing`
kind so the two are never interchangeable in later commands).

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 12-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Field | Type | Description |
|---|---|---|
| `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| `scope` | `uint8` (inline) | Requested key scope: `2` = Ephemeral, `3` = Local, `4` = SecurityDomain (requires initialized SD). Unsupported scopes return `UnsupportedKeyScope`. |
| `kem` | `uint8` (inline) | `TransferKemId`: `0` = P-384, `1` = ML-KEM-1024, `2` = MLKEM1024-P384. Other values return `InvalidArg`. |

### Data section

_Empty — all fields are carried inline within their TOC entries._

## Response

Wire layout: 12-byte header, followed by the TOC entries, then the data
section carrying the masked key and public key.

### TOC entries

| Field | Type | Description |
|---|---|---|
| (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary. |
| `masked_key` | `buffer` (264..=296 B) | Masked private P-384 scalar or ML-KEM seed; not stored on-device. |
| `pub_key` | `buffer` (96..=1665 B) | P-384: raw device-order coordinates (96 B), not SEC1. ML-KEM-1024: 1568 B. Hybrid: 1568-B PQ key followed by the 97-B SEC1 P-384 point. |

### Data section

Carries `masked_key` followed by `pub_key`; lengths depend on `kem` (see above).

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first), or `kem` is unknown (checked after `scope`) |
| `UnsupportedKeyScope` | Unsupported scope, or the requested security-domain masking key has not been provisioned |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_kex_key_gen.rs`
- Companion command: [`SdSealingKeyGen`](sd_sealing_key_gen.md)
