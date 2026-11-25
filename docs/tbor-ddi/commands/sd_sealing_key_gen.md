<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdSealingKeyGen (Opcode 0x09)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_sealing_key_gen.rs`
**Session:** InSession

## Description

Generates a new security-domain sealing key and returns the **masked**
private key together with the public key.  The sealing key is the HPKE
recipient key for SD transfer; its KEM is chosen by the request `kem`:

| `kem` | KEM | Masked secret | `masked_key` | `pub_key` | Key kind |
|---|---|---|---|---|---|
| 0 | DHKEM(P-384, HKDF-SHA384) | 48 B scalar | 280 B | 96 B `x ‖ y` | `SdSealing` (41) |
| 1 | ML-KEM-1024 (HPKE-13) | 64 B seed `d ‖ z` | 296 B | 1568 B encapsulation key | `SdSealingMlKem1024` (65) |
| 2 | MLKEM1024-P384 (HPKE-10) | 32 B seed | 264 B | 1665 B `ek_PQ ‖ SEC1(ek_T)` | `SdSealingMlKem1024P384` (66) |

Other `kem` values return `InvalidArg`. PQ keys are expanded from their seed
on use, and their key report attests the public key as an AKP `COSE_Key`.

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
- `SecurityDomain` uses the `SdMasking` key provisioned by SD creation or
	restoration.

`PartFinal` provisions the Ephemeral and Local masking keys, and the
partition must be in the `Initialized` lifecycle state. SecurityDomain
additionally requires a provisioned SD masking key; otherwise it returns
`UnsupportedKeyScope`. Session and other unsupported scopes return the
same error. The masked key's metadata records the
sealing key as `derive`-only, `local`, `private`, and never-extractable,
plus the requested scope.

An SD-scoped sealing key cannot bootstrap SD creation or restoration on
the partition: those commands require an uninitialized SD, while using
the key requires the SD masking key to be available already. Use Local
or Ephemeral scope for the partition's bootstrap sealing key.

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 12-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `0` = Unspecified, `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain, `5` = Internal. Supports Ephemeral, Local, and SecurityDomain when its masking key is provisioned. Other scopes return `UnsupportedKeyScope`. |
| 20 | `kem` | `uint8` (inline) | `0` = P-384, `1` = ML-KEM-1024, `2` = MLKEM1024-P384. |

### Data section

_Empty — all three fields are carried inline within their TOC entries._

## Response

Wire layout: 12-byte header, followed by the TOC entries, then the data
section carrying the masked key and public key.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_key` | `buffer` (264 / 280 / 296 B) | P-384 scalar or PQ seed in `header(8)`, `iv(16)`, metadata AAD(192), padded secret, tag(16). Not stored on-device. |
| 20 | `pub_key` | `buffer` (96 / 1568 / 1665 B) | P-384 raw coordinates in device byte order, or the ML-KEM-1024 / hybrid HPKE public key. The hybrid's ECC share is an uncompressed SEC1 point. |

### Data section

Carries the `masked_key` followed by the `pub_key`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first), or `kem` is unknown |
| `UnsupportedKeyScope` | The scope is unsupported, or its masking key has not been provisioned |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_sealing_key_gen.rs`
