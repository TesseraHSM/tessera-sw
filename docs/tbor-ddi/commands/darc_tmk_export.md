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
producing one 367-byte signed `sealed_tmk`. Export uses P-384 HPKE Base
with HKDF-SHA384 and AES-256-GCM; the source PID signs the complete binary
envelope directly in COSE_Sign1 using ES384. No source KEX key is needed.

The target is authenticated by a certificate chain anchored to the policy
`data_spki_thumbprint`. Import separately authenticates the source PID using a
`pota_spki_thumbprint`-anchored chain. DATA authorizes the recipient; POTA authorizes
the report signer.

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the SDMK the input TMK
   is masked under is provisioned by SD setup).
2. Verify `SHA-384(policy)` equals the partition's bound `policy_hash`,
   then validate `target_cert_chain` (read out of band) anchored to the
   policy `data_spki_thumbprint`, recovering the terminal certificate's public key
   as the HPKE receiver key `RcvrPub`.
3. Unmask `masked_tmk` to the 32-byte TMK (its masked-key kind must be
   `DarcTmk` and the plaintext exactly 32 bytes).
4. Build the canonical DARC header with source PID and recipient key IDs,
   as SHA-384 of canonical DER SPKI, and HPKE Base seal to `RcvrPub`,
   using the entire header as `info`, with empty AEAD AAD.
5. Sign the complete encrypted envelope with the partition PID and return
   the single COSE_Sign1 artifact. IO teardown scrubs the plaintext TMK.

The signed envelope format is specified in
[`KeyReport`](key_report.md#p-384-transfer-envelope-binding).
The signature authenticates this operation; a generic public-key report
cannot replace it. The signed artifact does not itself provide replay protection.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.

This command is **Crypto-Officer-only**: a Crypto-User session is rejected
with `InvalidPermissions`.

## Request

Wire layout: 12-byte header, the TOC entries, then the data section
carrying the policy document, fixed-length key buffers and the packed cert-descriptor list.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | (padding) | `padding` (0..=3 B) | Aligns `masked_tmk` to a 4-byte boundary. |
| 20 | `masked_tmk` | `buffer` (264 B) | The locally-masked `DarcTmk` from `DarcTmkGen` or `DarcTmkImport`. |
| 24 | `policy` | `buffer` (1-384 B) | Unified `PartPolicy`; its SHA-384 digest must equal the bound `policy_hash`. |
| 28 | `target_cert_chain` | `buffer` (`CertDescriptor[1..=2]`, 3 B each) | DATA-anchored recipient chain, root first; DER bytes travel **out of band**. |

### Data section

Carries the 264-byte `masked_tmk`, variable-length CBOR `policy`, and the packed
cert-descriptor list. The certificate DER bytes
referenced by the descriptors travel out of band.

## Response

The response follows the [paired TOC footprint](../README.md#paired-toc-footprint);
unused metadata slots are `None`.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `sealed_tmk` | `buffer` (367 B) | One PID-signed COSE_Sign1 containing the header (113 B), encapsulation (97 B), ciphertext (32 B), and GCM tag (16 B). |

### Data section

Carries only `sealed_tmk`; no detached report is returned.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, the security domain is not initialized, the policy hash mismatches, the policy carries no `data_spki_thumbprint` anchor, the cert chain is missing/not DATA-anchored, or the unmasked TMK is not 32 bytes |
| `UnsupportedKeyScope` | The security-domain masking key (SDMK) is not provisioned yet |
| `UnsupportedKeyType` | `masked_tmk` is not a `DarcTmk` masked key |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_tmk_export.rs`
- Companion command: [`DarcTmkImport`](darc_tmk_import.md) (the target-side import of `sealed_tmk`)
- Source of the local TMK: [`DarcTmkGen`](darc_tmk_gen.md)
- Recipient key: [`DarcKexKeyGen`](darc_kex_key_gen.md)
- Signed report and envelope: [`KeyReport`](key_report.md)
