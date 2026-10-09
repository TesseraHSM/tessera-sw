<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcTmkImport (Opcode 0x21)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_tmk_import.rs`
**Session:** InSession

## Description

Imports a DARC **Transfer Masking Key (TMK)** that was HPKE-sealed
off-device to a DARC key-exchange key (see
[`DarcKexKeyGen`](darc_kex_key_gen.md)) and re-masks it locally under the
partition **security-domain masking key (SDMK)** so the caller can persist
and later re-import it.

It is `SdRestoreRemoteBackup`'s **open front-end** narrowed to a single
POTA-anchored certificate chain: the 32-byte TMK is recovered by
HPKE-Auth-opening `sealed_tmk` with the receiver's masked DARC
key-exchange private key (`RcvrPriv`, recovered by unmasking
`masked_kex_key`), authenticated by the sender public key recovered from
the terminal (leaf) certificate of `remote_cert_chain`.

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the SDMK the output is
   masked under is provisioned by SD setup).
2. Verify `SHA-384(policy)` equals the partition's bound `policy_hash`,
   then validate `remote_cert_chain` (read out of band) anchored to the
   policy `POTAPubKey`, recovering the terminal certificate's public key
   as the HPKE sender key.
3. Unmask `masked_kex_key` → `RcvrPriv` (its masked-key kind must be
   `DarcKex`) and derive `RcvrPub`.
4. HPKE-Auth-open `sealed_tmk` (`sk_r = RcvrPriv`, sender-auth `SndrPub`)
   → the 32-byte TMK.
5. Re-mask the TMK (AEAD-GCM-256) under the SDMK and return the masked
   envelope.  `RcvrPriv` and the TMK are zeroized on every exit path.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.  The masked output's metadata
records the TMK as `derive`-only, `local`, `private`, and
never-extractable, under the distinct `DarcTmk` key kind, scoped
`SecurityDomain`.

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, the TOC entries, then the data section
carrying the fixed-length buffers and the packed cert-descriptor list.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_kex_key` | `buffer` (180 B) | The receiver's masked DARC key-exchange key (from `DarcKexKeyGen`); unmasked on-device to `RcvrPriv`. Must be a `DarcKex`-kind masked key. |
| — | `policy` | `buffer` (584 B) | The unified `PartPolicy` whose `POTAPubKey` anchors `remote_cert_chain`; its SHA-384 digest must equal the bound `policy_hash`. |
| — | `sealed_tmk` | `buffer` (145 B) | The HPKE-Auth seal of the 32-byte TMK: `enc(SEC1 97) ‖ ct(TMK 32 + GCM tag 16)`. |
| — | `remote_cert_chain` | `buffer` (`CertDescriptor[1..=2]`, 3 B each) | Packed `(index, length)` descriptors for the POTA-anchored sender certificate chain; the DER bytes are carried **out of band** as SGL Data Blocks. |

### Data section

Carries the 180-byte `masked_kex_key`, 584-byte `policy`, 145-byte
`sealed_tmk`, and the packed cert-descriptor list.  The certificate DER
bytes referenced by the descriptors travel out of band.

## Response

Wire layout: 8-byte header, the TOC entry, then the data section carrying
the masked TMK.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_tmk` | `buffer` (164 B) | The imported TMK, masked (AEAD-GCM-256) under the SDMK: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`. Recorded under the `DarcTmk` key kind. |

### Data section

Carries the 164-byte `masked_tmk`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, the security domain is not initialized, the policy hash mismatches, the cert chain is missing/not POTA-anchored, or the opened TMK is not 32 bytes |
| `UnsupportedKeyScope` | The security-domain masking key (SDMK) is not provisioned yet |
| `UnsupportedKeyType` | `masked_kex_key` is not a `DarcKex` masked key |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_tmk_import.rs`
- Companion command: [`DarcKexKeyGen`](darc_kex_key_gen.md)
- Template command: [`SdRestoreRemoteBackup`](sd_restore_remote_backup.md)
