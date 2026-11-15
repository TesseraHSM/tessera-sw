<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreatePeerBackup (Opcode 0x0E)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_create_peer_backup.rs`
**Session:** Active Crypto Officer

Recovers BKS3 from a local backup and transfers it to a same-policy peer.
The initialized partition's bound policy must match the request and allow
peer cloning. The destination's POTA-authorized `PublicKey` report must
prove an HSM-generated SD sealing key and carry that same policy hash.
Manufacturer and partition-owner chains are required; the owner chain is
optional, but all supplied chains must identify the same report-signing PID.

No sender sealing key is supplied. Firmware emits a fresh HPKE Base
envelope and signs the bound `SdBackup` report with its actual PID.
The command is stateless and does not require an already-provisioned SD
when the local backup's masking key is available.

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `policy` | 1-384 B | Bound SD policy permitting peer cloning |
| `dst_evidence` | Three chain descriptor lists and report descriptor | POTA-authorized destination `PublicKey` evidence |
| `pok_local_backup` | 280 B, aligned to 4 B | Local BKS3 backup |

Evidence certificates and reports travel out of band. The evidence group
expands to four TOC entries.

Out-of-band item 0 is the report output: reserve at least 5120 B
(`SD_BACKUP_REPORT_MAX_LEN`). Evidence input descriptors therefore index
from 1. `report_len` gives the bytes written; firmware writes the report
only on success.

## Response

| Field | Shape | Meaning |
|---|---|---|
| `pok_peer_backup` | 322 / 1793 / 1890 B, aligned to 4 B | Canonical Base envelope |
| `report_len` | `U16` (inline) | Bytes of the PID-signed `SdBackup` report (ES384 or ML-DSA-87, per policy PTA algorithm) written to out-of-band item 0 |

Keep both outputs together. The report binds the source PID, recipient,
complete envelope, and SD policy. See [transfer format](key_report.md#transfer-envelope-binding).
Local backup authentication, ownership, SVN checks, and masking are unchanged.

Disabled cloning returns `SdPeerCloningNotAllowed`; malformed sizes fail
decoding. Invalid policy, destination attestation, provenance, local backup,
lifecycle, session, and permission errors are propagated.
