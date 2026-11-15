<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestoreRemoteBackup (Opcode 0x0C)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_restore_remote_backup.rs`
**Session:** Active Crypto Officer

Restores an SD from its Base envelope and mandatory `SdBackup` operation
report. The initialized partition's bound policy must match the request.
The actual unmasked receiver key must match the envelope's recipient.
Signature, report kind, source PID ID, recipient ID, whole-envelope digest,
and **target SD policy hash** are checked before HPKE decapsulation.

**SATA sender authorization is removed.** `sender_pid_pub_key` is the raw
96-byte big-endian P-384 `X || Y` of the operation signer.

When `require_trusted_sa_key` is set, source PID identity chains must be
SAPOTA-authorized and match that supplied PID key. Manufacturer and
partition-owner chains are required; the owner chain is optional but must
agree if supplied. Otherwise source certificate chains can be empty and
are ignored, but the operation report is **still mandatory**. This mode
checks signature integrity and transfer bindings, **not trusted SA identity**.
The SA's local policy may differ from the SD; its operation report must
nevertheless bind the transferred SD policy.

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `masked_sealing_key` | 264 / 280 / 296 B, aligned to 4 B | Actual recipient key |
| `policy` | 1-384 B | Bound SD policy |
| `sender_pid_pub_key` | 96 B | Report signer `X || Y`, big-endian |
| `sender_evidence` | Three chain descriptor lists and report descriptor | Required `SdBackup` report; optional/required SAPOTA PID chains as above |
| `src_remote_backup` | 322 / 1793 / 1890 B | Canonical Base envelope |
| `prev_sd_mk_backup` | 264 B | Previous SDMK backup |

The evidence group expands to four TOC entries. Certificates and the source
operation report are fetched out of band.

## Response

| Field | Shape | Meaning |
|---|---|---|
| `pok_local_backup` | 280 B, aligned to 4 B | Refreshed local BKS3 backup |
| `sd_mk_backup` | 264 B, aligned to 4 B | Refreshed SDMK backup |

See [transfer format](key_report.md#transfer-envelope-binding).
Local derivation, masking, SVN checks, and provisioning undo behavior are
unchanged. Restore is one-shot; an initialized SD returns
`SdAlreadyInitialized`. Validation failures do not provision the SD or
consume a successful restore. Legacy Auth envelopes are not supported.
