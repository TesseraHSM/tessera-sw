<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcTmkExport (Opcode 0x24)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_tmk_export.rs`
**Session:** InSession

## Description

Seals a locally-masked DARC **Transfer Masking Key (TMK)** to a remote
**target** so the target can import it with [`DarcTmkImport`](darc_tmk_import.md),
producing a 145-byte `sealed_tmk` byte-compatible with what `DarcTmkImport`
consumes.  It is the **source-side** mirror of `DarcTmkImport`: where
import opens a `sealed_tmk` and re-masks it under the SDMK, export unmasks
a local `masked_tmk` and HPKE-Auth-seals it to the target.

The target is authenticated by a certificate chain anchored to the policy
`DATAPubKey` — the export-side mirror of the `POTAPubKey`-anchored sender
chain `DarcTmkImport` verifies (the two anchors are distinct: export
verifies the target against DATA, import verifies the sender against POTA).

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the SDMK the input TMK
   is masked under is provisioned by SD setup).
2. Verify `SHA-384(policy)` equals the partition's bound `policy_hash`,
   then validate `target_cert_chain` (read out of band) anchored to the
   policy `DATAPubKey`, recovering the terminal certificate's public key
   as the HPKE receiver key `RcvrPub`.
3. Unmask `masked_sender_key` → `SndrPriv` (its masked-key kind must be
   `DarcKex`) and derive `SndrPub`.
4. Unmask `masked_tmk` → the 32-byte TMK (its masked-key kind must be
   `DarcTmk` and the plaintext exactly 32 bytes).
5. HPKE-Auth-seal the TMK to `RcvrPub` (sender-auth `SndrPriv`) → the
   145-byte `sealed_tmk`. IO teardown scrubs `SndrPriv` and the TMK.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.

This command is **Crypto-Officer-only**: a Crypto-User session is rejected
with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, the TOC entries, then the data section
carrying the fixed-length buffers and the packed cert-descriptor list.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_sender_key` | `buffer` (180 B) | The source's masked DARC key-exchange key (from `DarcKexKeyGen`); unmasked on-device to `SndrPriv`. Must be a `DarcKex`-kind masked key. |
| — | `masked_tmk` | `buffer` (164 B) | The locally-masked TMK envelope (from `DarcTmkGen`/`DarcTmkImport`); unmasked on-device to the 32-byte TMK. Must be a `DarcTmk`-kind masked key. |
| — | `policy` | `buffer` (584 B) | The unified `PartPolicy` whose `DATAPubKey` anchors `target_cert_chain`; its SHA-384 digest must equal the bound `policy_hash`. |
| — | `target_cert_chain` | `buffer` (`CertDescriptor[1..=2]`, 3 B each) | Packed `(index, length)` descriptors for the DATA-anchored target certificate chain; the DER bytes are carried **out of band** as SGL Data Blocks. |

### Data section

Carries the 180-byte `masked_sender_key`, 164-byte `masked_tmk`, 584-byte
`policy`, and the packed cert-descriptor list.  The certificate DER bytes
referenced by the descriptors travel out of band.

## Response

Wire layout: 8-byte header, the TOC entry, then the data section carrying
the sealed TMK.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `sealed_tmk` | `buffer` (145 B) | The HPKE-Auth seal of the 32-byte TMK: `enc(SEC1 97) ‖ ct(TMK 32 + GCM tag 16)`. Byte-for-byte what `DarcTmkImport` consumes. |

### Data section

Carries the 145-byte `sealed_tmk`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, the security domain is not initialized, the policy hash mismatches, the policy carries no `DATAPubKey` anchor, the cert chain is missing/not DATA-anchored, or the unmasked TMK is not 32 bytes |
| `UnsupportedKeyScope` | The security-domain masking key (SDMK) is not provisioned yet |
| `UnsupportedKeyType` | `masked_sender_key` is not a `DarcKex` masked key, or `masked_tmk` is not a `DarcTmk` masked key |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_tmk_export.rs`
- Companion command: [`DarcTmkImport`](darc_tmk_import.md) (the target-side import of `sealed_tmk`)
- Source of the local TMK: [`DarcTmkGen`](darc_tmk_gen.md)
- Source key: [`DarcKexKeyGen`](darc_kex_key_gen.md)
- Template command: [`SdCreateRemoteBackup`](sd_create_remote_backup.md)
