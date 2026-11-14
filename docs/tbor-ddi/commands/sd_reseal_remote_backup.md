<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdResealRemoteBackup (Opcode 0x0B)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_reseal_remote_backup.rs`
**Session:** Active Crypto Officer

An initialized sealing authority validates and opens a source Base envelope
with its actual recipient private key, then reseals BKS3 to a new recipient.
It does not provision or mutate its SD.

The source evidence contains **PID identity chains and the source `SdBackup`
operation report**, not an attestation of a sender sealing key. Its PID must
be POTA-authorized by the request's client SD policy. The destination remains
POTA-authorized `PublicKey` evidence proving an HSM-generated SD sealing key
with the same client SD policy hash. Manufacturer and partition-owner chains
are required; the optional owner chain must agree on the PID leaf.

The SA's bound local policy may differ from the transferred SD policy.
Both input bindings and the outgoing report use the **request's SD policy
hash**, never the SA-local hash. Firmware signs the fresh outgoing report
with its actual SA PID.

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `masked_sealing_key` | 280 B, aligned to 4 B | Actual source-envelope recipient key |
| `policy` | 1-384 B | Client SD policy |
| `src_evidence` | Three chain descriptor lists and report descriptor | POTA-authorized source PID and `SdBackup` report |
| `dest_evidence` | Three chain descriptor lists and report descriptor | POTA-authorized destination `PublicKey` evidence |
| `src_remote_backup` | 322 B | Canonical source Base envelope |

Each evidence group expands to four TOC entries; referenced DER certificates
and reports travel out of band.

## Response

| Field | Shape | Meaning |
|---|---|---|
| `dst_remote_backup` | 322 B | Fresh canonical Base envelope |
| `report` | 1..896 B | SA-PID-signed `SdBackup` report |

See [transfer format](key_report.md#p-384-transfer-envelope-binding).
The source signature, report kind, PID ID, recipient ID, envelope digest,
and client policy are verified **before HPKE decapsulation**. A different
source key's `PublicKey` report cannot authorize a transfer. Failures do not
publish BKS3 or a successful output envelope.

Malformed sizes fail decoding. Invalid source/destination evidence, policy,
recipient, envelope, report, masked key, lifecycle, session, and permission
errors are propagated.
