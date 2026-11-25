<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreateRemoteBackup (Opcode 0x0A)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_create_remote_backup.rs`
**Session:** Active Crypto Officer

Creates the SD on its policy-designated backing partition. The request
policy must match the partition's bound policy and backing PID/public key.
The command generates BKS3 and SDMK, provisions the SD, and is one-shot:
an already-initialized SD returns `SdAlreadyInitialized`. Persistent changes
and a failed completion are covered by the existing undo mechanism.

The recipient is always authorized by a SATA-anchored certificate chain.
When `require_trusted_sa_key` is set, additional SAPOTA-anchored `PublicKey`
evidence must attest that same recipient. Otherwise recipient evidence can
be empty. The optional owner chain, if supplied, must share the PID leaf
with the required manufacturer and partition-owner chains.

There is no sender sealing-key input. The SATA chain leaf is the default
P-384 recipient. For an ML-KEM-1024 or MLKEM1024-P384 recipient, supply
`receiver_key_report`: its `PublicKey` report re-signed by the chain leaf.
Firmware verifies that signature and seals to the attested KEM key; trusted-SA
evidence must attest the same recipient. HPKE **Base** encrypts BKS3, then
the actual PID directly signs the complete envelope using ES384 or ML-DSA-87,
selected by policy. The signature binds the source, recipient, ciphertext,
and transferred SD policy. See [transfer format](key_report.md#transfer-envelope-binding).

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `receiver_cert_chain` | Certificate descriptors, at most 24 B | SATA-authorized recipient |
| `receiver_key_report` | Zero or one report descriptor | Optional leaf-signed `PublicKey` report naming a PQ recipient key |
| `receiver_evidence` | Manufacturer/owner/partition-owner descriptors and report descriptor | Optional recipient `PublicKey` attestation; required for trusted-SA policy |
| `policy` | 1-384 B | Bound SD policy |

Evidence groups expand to four TOC entries. DER certificates and evidence
reports are fetched out of band using their descriptors.

Out-of-band item 0 is the complete signed-backup output: reserve at least 6531 B
(`SD_BACKUP_REPORT_MAX_LEN`). Evidence input descriptors therefore index
from 1. `report_len` gives the bytes written; firmware writes the report
only on success.

## Response

| Field | Shape | Meaning |
|---|---|---|
| `pok_local_backup` | 280 B, aligned to 4 B | Unchanged local BKS3 backup |
| `sd_mk_backup` | 264 B, aligned to 4 B | Unchanged local SDMK backup |
| `report_len` | `U16` inline | Length of the single complete PID-signed backup in OOB item 0; 431 / 1902 / 1999 / 4963 / 6434 / 6531 B |

Persist the signed backup with the SDMK backup; there is no detached report.
Legacy 161-byte Auth envelopes are not accepted by migrated transfer
commands. Local masking, derivation, ownership, SVN, and recovery formats
are unchanged.

Malformed sizes fail decoding; invalid lifecycle, policy, recipient,
or required attestation fails before provisioning. Certificate validation,
session, and permission errors are propagated.
