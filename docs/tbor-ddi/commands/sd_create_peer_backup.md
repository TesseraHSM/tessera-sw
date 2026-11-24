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

No sender sealing key is supplied. Firmware emits a fresh P-384 HPKE Base
envelope and signs that complete `SdBackup` envelope with its actual PID.
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

## Response

| Field | Shape | Meaning |
|---|---|---|
| `pok_peer_backup` | 431 B | Complete PID-signed Base envelope |

There is no detached report. The direct signature binds the source PID, recipient,
complete envelope, and SD policy. See [transfer format](key_report.md#p-384-transfer-envelope-binding).
Local backup authentication, ownership, SVN checks, and masking are unchanged.

Disabled cloning returns `SdPeerCloningNotAllowed`; malformed sizes fail
decoding. Invalid policy, destination attestation, provenance, local backup,
lifecycle, session, and permission errors are propagated.
