<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestoreRemoteBackup (Opcode 0x0C)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_restore_remote_backup.rs`
**Session:** Active Crypto Officer

Restores an SD from one PID-signed `SdBackup` Base envelope.
The initialized partition's bound policy must match the request.
The actual unmasked receiver key must match the envelope's recipient.
Direct signature, transfer kind, source PID thumbprint, recipient thumbprint,
and **target SD policy hash** are checked before HPKE decapsulation.

**SATA does not authorize the sender.** `sender_pid_pub_key` is the
DER SubjectPublicKeyInfo of the operation signer. The field is
length-delimited and accepts canonical uncompressed P-384 SPKI (120 bytes,
`id-ecPublicKey` with `secp384r1`) or ML-DSA-87 SPKI (2614 bytes).
Bare public keys, unsupported algorithms, noncanonical encodings, and
trailing data are rejected. The complete public key is needed for signature
verification; its SHA-384 SPKI thumbprint must match the signed
`source_pid_spki_thumbprint`.

When `require_trusted_sa_key` is set, source PID identity chains must be
SAPOTA-authorized and match that supplied PID key. Manufacturer and
partition-owner chains are required; the owner chain is optional but must
agree if supplied. Otherwise source certificate chains can be empty and
are ignored, but the embedded signature is **still mandatory**. This mode
checks signature integrity and transfer bindings, **not trusted SA identity**.
The SA's local policy may differ from the SD; its signed envelope must
nevertheless bind the transferred SD policy.

## BKS3 compromise and restore authorization

A leaked plaintext BKS3 can enable restoration in signature-only mode when
the caller also has the matching `prev_sd_mk_backup`, an active CO session,
a usable recipient sealing key, and an eligible partition with the bound
policy and compatible manufacturer/owner seed lineage. The caller can seal
that BKS3 to the recipient and sign the envelope with a caller-selected key;
the matching SDMK backup still authenticates. BKS3 alone does not reveal SDMK
off-device or bypass the session, policy, key, lineage, or one-shot checks.

Set `require_trusted_sa_key` when restoration must require a
SAPOTA-authorized source PID. Knowing BKS3 does not forge that PID's
signature. This is not replay prevention: a previously valid signed
transfer can still be accepted when all restore checks pass.

## Request fields, in wire order

| Field | Shape | Meaning |
|---|---|---|
| `session_id` | Inline session ID | Active CO session |
| `masked_sealing_key` | 264 / 280 / 296 B, aligned to 4 B | Actual recipient key |
| `policy` | 1-384 B | Bound SD policy |
| `sender_pid_pub_key` | DER SPKI, 120 or 2614 B | Signer: canonical P-384 or ML-DSA-87 SPKI |
| `sender_evidence` | Three chain descriptor lists | Optional/required SAPOTA PID chains as above |
| `src_remote_backup` | 3 B report descriptor | OOB complete signed artifact; 431 / 1902 / 1999 / 4963 / 6434 / 6531 B |
| `prev_sd_mk_backup` | 264 B | Previous SDMK backup |

The identity group expands to three TOC entries. Certificates are fetched
out of band; the signature is inside `src_remote_backup`.

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
