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

The required `Darc` operation report authenticates the exact encrypted
envelope, source PID, and recipient. Its signer is authorized by a
POTA-anchored certificate chain. Only after report verification does
HPKE Base recover the TMK with the receiver's masked DARC key-exchange
private key (`RcvrPriv`, recovered by unmasking `masked_kex_key`).

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the SDMK the output is
   masked under is provisioned by SD setup).
2. Verify `SHA-384(policy)` equals the partition's bound `policy_hash`,
   then validate `remote_cert_chain` (read out of band) anchored to the
   policy `pota_spki_thumbprint`, recovering the terminal certificate's public key
   as the authorized PID report-signing key. The normal three-certificate
   path is POTA root, PTA intermediate, and PTA-issued PID leaf. The
   source partition's certificate slot 2 supplies the PID leaf, not the
   entire chain.
3. Unmask `masked_kex_key` → `RcvrPriv` (its masked-key kind must be
   `DarcKex`) and derive `RcvrPub`.
4. Verify the ES384 report signature, `Darc` kind, signer-derived source
   ID, actual recipient-derived ID, report/header agreement, and digest
   of the complete encrypted envelope. A `PublicKey` or `SdBackup`
   report cannot substitute for `Darc`.
5. HPKE Base open the envelope, using the full canonical header as both
   HPKE `info` and AEAD AAD. Plaintext is not published on failure.
6. Re-mask the TMK (AEAD-GCM-256) under the SDMK and return the masked
   envelope. IO teardown scrubs `RcvrPriv` and the TMK.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.  The masked output's metadata
records the TMK as `derive`-only, `local`, `private`, and
never-extractable, under the distinct `DarcTmk` key kind, scoped
`SecurityDomain`.

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

See [`KeyReport`](key_report.md#p-384-transfer-envelope-binding) for the
canonical envelope and report formats. The import policy is the target
partition's bound policy; DARC reports contain no policy hash. Reports
do not by themselves provide replay protection or certificate freshness.

## Request

Wire layout: 8-byte header, the TOC entries, then the data section
carrying the policy document, fixed-length key buffers and the packed cert-descriptor list.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_kex_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_kex_key` | `buffer` (280 B) | The receiver's masked `DarcKex` private key from `DarcKexKeyGen`. |
| 20 | `policy` | `buffer` (1-384 B) | The unified `PartPolicy` whose `pota_spki_thumbprint` anchors `remote_cert_chain`; its SHA-384 digest must equal the bound `policy_hash`. |
| 24 | `sealed_tmk` | `buffer` (258 B) | Canonical DARC header (113 B), encapsulation (97 B), ciphertext (32 B), GCM tag (16 B). |
| 28 | `report` | `buffer` (1..=896 B) | Required PID-signed v2 `Darc` operation report accompanying `sealed_tmk`. |
| 32 | `remote_cert_chain` | `buffer` (`CertDescriptor[1..=3]`, 3 B each) | POTA-anchored source PID chain, root first; DER bytes travel **out of band**. |

### Data section

Carries the 280-byte `masked_kex_key`, variable-length CBOR `policy`, 258-byte
`sealed_tmk`, `report`, and the packed cert-descriptor list. The certificate DER
bytes referenced by the descriptors travel out of band.

## Response

Wire layout: 8-byte header, the TOC entry, then the data section carrying
the masked TMK.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | (padding) | `padding` (0..=3 B) | Places `masked_tmk` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 12 | `masked_tmk` | `buffer` (264 B) | The imported TMK, masked under the SDMK and recorded under the `DarcTmk` key kind. |

### Data section

Carries the 264-byte `masked_tmk`; the local masking format is unchanged.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | Invalid partition/SD state or policy, non-POTA-anchored source chain, malformed or mismatched envelope/report, wrong report kind/signer/recipient/digest, or invalid TMK length |
| `UnsupportedKeyScope` | The security-domain masking key (SDMK) is not provisioned yet |
| `UnsupportedKeyType` | `masked_kex_key` is not a `DarcKex` masked key |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_tmk_import.rs`
- Companion command: [`DarcKexKeyGen`](darc_kex_key_gen.md)
- Export producer: [`DarcTmkExport`](darc_tmk_export.md)
- Signed report and envelope: [`KeyReport`](key_report.md)
