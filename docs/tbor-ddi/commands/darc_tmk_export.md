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
producing one signed `sealed_tmk`. Export supports P-384, ML-KEM-1024 and
MLKEM1024-P384 HPKE Base suites with AES-256-GCM. The source PID signs the
complete binary envelope directly in COSE_Sign1 using the policy-selected
ES384 or ML-DSA-87 algorithm. No source KEX key is needed.

The recipient is authenticated like a security-domain backup receiver:
the target **PID** chain is anchored to the policy `data_spki_thumbprint`,
and the target supplies a [`KeyReport`](key_report.md) signed by that PID
attesting its device-generated DARC key-exchange key (signed flag
`is_darc_kex`, bit 11). The attested key becomes the HPKE recipient and
selects the KEM. Import separately authenticates the source PID using a
`pota_spki_thumbprint`-anchored chain. DATA authorizes the recipient;
POTA authorizes the report signer.

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the SDMK the input TMK
   is masked under is provisioned by SD setup).
2. Verify `SHA-384(policy)` equals the partition's bound `policy_hash`,
   then validate `target_cert_chain` (read out of band) anchored to the
   policy `data_spki_thumbprint`, recovering the target PID leaf key
   (P-384 or ML-DSA-87).
3. Verify `target_key_report` (read out of band) with the target PID key:
   it must attest an authenticated, generated, not-imported DARC
   key-exchange key (`is_darc_kex`). Its public key becomes `RcvrPub`.
4. Unmask `masked_tmk` to the 32-byte TMK (its masked-key kind must be
   `DarcTmk` and the plaintext exactly 32 bytes).
5. Build the canonical DARC header with the canonical PID SPKI thumbprint
   and recipient identifier (canonical SPKI for P-384, domain-separated
   raw-key hash for PQ recipients), and HPKE Base seal to `RcvrPub`,
   using the entire header as `info`, with empty AEAD AAD.
6. Sign the complete encrypted envelope with the partition PID, write
   the single COSE_Sign1 artifact to OOB item 0, and return its length.
   IO teardown scrubs the plaintext TMK.

The signed envelope format is specified in
[`KeyReport`](key_report.md#transfer-envelope-binding).
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
| 28 | `target_cert_chain` | `buffer` (`CertDescriptor[1..=3]`, 3 B each) | DATA-anchored target PID chain, root first; DER bytes travel **out of band**. |
| 32 | `target_key_report` | `buffer` (3 B report descriptor) | OOB target PID-signed proof of its generated DARC recipient key. |

### Data section

Carries the 264-byte `masked_tmk`, variable-length CBOR `policy`, the packed
cert-descriptor list and the report descriptor. The certificate DER bytes
and the target key report travel out of band.

## Response

The response follows the [paired TOC footprint](../README.md#paired-toc-footprint);
unused metadata slots are `None`.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `report_len` | `U16` (inline) | Length of the complete PID-signed artifact in OOB output item 0. |

### Data section

No inline envelope is returned. Reserve 6467 bytes for OOB output item 0;
input certificates and key proof must use other items. Actual signed lengths
are 367 / 1838 / 1935 B with ES384 and 4899 / 6370 / 6467 B with ML-DSA-87,
in P-384 / ML-KEM-1024 / hybrid order. No detached report is returned.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, the security domain is not initialized, the policy hash mismatches, the policy carries no `data_spki_thumbprint` anchor, the cert chain is missing/not DATA-anchored, the target key report is invalid or does not attest a generated DARC key-exchange key, or the unmasked TMK is not 32 bytes |
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
