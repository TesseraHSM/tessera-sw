<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestorePeerBackup (Opcode 0x0F)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_restore_peer_backup.rs`
**Session:** Active Crypto Officer

Restores an SD from a same-policy peer's Base envelope and mandatory
`SdBackup` operation report. The initialized partition's bound policy must
match the request and permit peer cloning.

Source evidence identifies the **PID operation signer**, not a sender
sealing key. Manufacturer and partition-owner chains are required; the
partition-owner chain must anchor to the SD policy's POTA. The optional
owner chain must agree on the PID leaf if supplied.

Firmware verifies the signature, report kind, source PID ID, actual
recipient ID, whole-envelope digest, and bound SD policy hash **before
HPKE decapsulation** with the unmasked recipient private key. No BKS3 is
published on validation failure.

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `masked_sealing_key` | 280 B, aligned to 4 B | Actual recipient key |
| `policy` | 1-384 B | Bound SD policy permitting peer cloning |
| `src_evidence` | Three chain descriptor lists and report descriptor | POTA-authorized source PID and `SdBackup` report |
| `pok_peer_backup` | 322 B | Canonical Base envelope |
| `prev_sd_mk_backup` | 264 B | Previous SDMK backup |

The evidence group expands to four TOC entries. Referenced DER certificates
and operation reports travel out of band.

## Response

| Field | Shape | Meaning |
|---|---|---|
| `pok_local_backup` | 280 B, aligned to 4 B | Refreshed local BKS3 backup |
| `sd_mk_backup` | 264 B, aligned to 4 B | Refreshed SDMK backup |

See [transfer format](key_report.md#p-384-transfer-envelope-binding).
Local derivation, masking, ownership, SVN checks, and provisioning undo are
unchanged. Restore is one-shot: `SdAlreadyInitialized` rejects an existing
SD. Disabled cloning returns `SdPeerCloningNotAllowed`. Malformed sizes
and invalid reports, policies, keys, evidence, or sessions are rejected.
