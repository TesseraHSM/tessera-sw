<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PartInitWithObk (Opcode 0x30)

**Handler:** Implemented (`fw/core/lib/src/ddi/tbor/part_init_with_obk.rs`).
**Session:** InSession (Crypto Officer)

## Description

Provisions an `Enabled` partition from the **owner backup key** (OBK) and
returns the current `local_mk` backup.  It is the TBOR counterpart of the v1
`EstablishCredential` provisioning step, for deployments where UEFI seals
the masked owner backup key (MOBK, the output of MBOR `InitBk3`) with the TPM:
the host opens a session **first**, then provisions, instead of provisioning
over MBOR and opening a session afterwards.

The command fuses the roles of [`PartInit`](./part_init.md) and
[`PartFinal`](./part_final.md) for the OBK trust model, which has no CSR /
certificate round trip.  The partition owner's trust is a POTA endorsement of
the partition identity, as in v1: a signature over
`SHA-384(0x04 ‖ PID public key)` by the POTA key the host presents.  The two
flows are mutually exclusive on a partition: either provisions it, once, from
`Enabled`.

The caller supplies the MOBK wrapped in an AEAD envelope under the session
`param_key`, the POTA public key and signature, and an optional prior
`local_mk` backup.  The firmware returns the current `local_mk` backup, which
the host persists and replays as `prev_local_mk_backup` after a reset (the OBK
analogue of the v1 BMK).  BK3 never leaves the command: it exists only in
scoped scratch that IO teardown scrubs.

The command is **Uno only** in practice: the MOBK is minted by the MBOR
`InitBk3` command, which a Duo does not have.

## Handler steps

1. **Gate:** CO-only `Active` session; partition state must be `Enabled` with
   neither the v1 credential nor `MK` set (`PartitionAlreadyProvisioned`
   otherwise).  The dispatcher additionally requires the CO PSK to have been
   rotated, and the handler requires the session to authenticate with the
   **current** CO PSK (`SessionAuthFailure` for a session opened before the
   rotation).  The partition credential lock is held for the whole command.
2. **Open the MOBK:** AEAD-open `mobk_envelope` in place under the session
   `param_key`; its 32-byte AAD must equal
   `"part-init-obk-v1" ‖ session_id (2 B LE) ‖ 14 × 0x00`
   (`AeadEnvelopeAuthFailed` otherwise).
3. **POTA:** verify `pota_sig` over `SHA-384(0x04 ‖ PID public key)` with
   `pota_pub_key` (`EccVerifyFailed` otherwise).
4. **BK3:** unmask the MOBK under the partition's `BK_BOOT` (the AES-CBC-256 +
   HMAC-SHA-384 envelope `InitBk3` produced) to the 48-byte BK3.
5. **PartLocalMK:** derive
   `PartLocalBMK = KBKDF(BK3, "TSRA-PartInitWithObk-PartLocalBMK-v1",
   MFGR_SEED[svn] ‖ DEV_OWNER_SEED[owner] ‖ pota_pub_key)`, so a backup only
   restores under the same BK3, device lineage **and** POTA; generate a fresh
   32 B `PartLocalMK` (no prior backup) or restore it by unmasking
   `prev_local_mk_backup` (the anti-rollback and re-mask rules are
   `PartFinal`'s), and re-mask it under the current `{svn, owner}`.
6. **EphemeralMK:** sample a fresh 32 B random masking key.
7. **Commit:** vault `PartLocalMK` (Local scope) and `EphemeralMK` (Ephemeral
   scope) recording their ids, and advance the lifecycle `Enabled →
   Initialized` in one await-free guards-first block; every mutation records
   its undo inverse first.
8. **Respond:** return the 264 B `local_mk_backup`.

A rejected command changes nothing: all crypto runs before any mutation.

## Request

Wire layout: 8-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | `mobk_envelope` | `buffer` (max 584 B) | AEAD-GCM envelope (AES-256-GCM, 40 B framing + 32 B AAD) wrapping the MOBK (at most 512 B) under the session `param_key`. |
| 16 | `pota_pub_key` | `buffer` (exactly 96 B) | POTA public key, raw P-384 `x ‖ y`, each coordinate in the device byte order. |
| 20 | `pota_sig` | `buffer` (exactly 96 B) | POTA endorsement signature, raw P-384 `r ‖ s`, each component in the device byte order. |
| 24 | `prev_local_mk_backup` | `buffer` (max 264 B) | Optional previously-returned `local_mk` backup to restore. An **empty** field means absent; when present it is exactly 264 B. |

Crypto operands travel in the device byte order (little-endian on Uno; see
"Crypto operand byte order" in the [README](../README.md)).  The AAD session id
is little-endian on every device.

### Data section

Carries the four buffers back to back, in TOC order.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `local_mk_backup` | `buffer` (exactly 264 B) | Current `local_mk` backup envelope (`CurrPartLocalMKBackup`). |

### Data section

Carries the 264-byte `local_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | Decode-time length-bound violation: `mobk_envelope` > 584 B, `pota_pub_key` or `pota_sig` not exactly 96 B, or `prev_local_mk_backup` > 264 B |
| `DefaultPskMustRotate` | The CO PSK is still the public default (dispatcher gate) |
| `InvalidPermissions` | The session is not a Crypto Officer session |
| `SessionNotFound` | The session is not `Active` |
| `SessionAuthFailure` | The session was opened under a PSK that has since been rotated |
| `PartitionAlreadyProvisioned` | The partition is not `Enabled`, or was already provisioned (v1 or v2), or a racing provisioning won the commit |
| `AeadEnvelopeAuthFailed` | `mobk_envelope` failed its AEAD tag, or its AAD does not bind this command and session |
| `InvalidArg` | The `mobk_envelope` AAD or plaintext has the wrong shape, or a present `prev_local_mk_backup` is not exactly 264 B |
| `EccVerifyFailed` | `pota_sig` does not verify over the partition identity under `pota_pub_key` |
| `MaskedKeyDecodeFailed` | The MOBK is malformed or was not masked by this partition's `BK_BOOT` (a failed HMAC included) |
| `AesGcmDecryptTagDoesNotMatch` | `prev_local_mk_backup` fails its AEAD tag: tampered, or minted under another BK3, device lineage or POTA |
| `PartFinalBackupSvnRollback` | `prev_local_mk_backup` was minted under a newer SVN than this firmware's |
| `DdiDecodeFailed` | Malformed request body |

## Limits on an OBK-provisioned partition

The partition reaches `Initialized` with the Local and Ephemeral masking keys,
so the key-generation and key-use commands under those scopes work.  An OBK
partition has **no PTA key, UPS or policy hash**, so the commands that need
them are not supported on it: `KeyReport`, the on-demand slot-2 PID
certificate, and the security-domain (`Sd*`) commands.  They report the missing
provisioning state rather than a dedicated error.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/part_init_with_obk.rs`
- Same-shape provisioning for the policy / PTA trust model:
  [`part_init.md`](./part_init.md), [`part_final.md`](./part_final.md)
- Session bootstrap and the default-PSK gate: [README](../README.md)
