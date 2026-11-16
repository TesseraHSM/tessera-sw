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
producing a `sealed_tmk` envelope and a separate, required `Darc`
operation report. Export uses HPKE Base with AES-256-GCM and the
recipient's KEM: DHKEM(P-384) with HKDF-SHA384, or ML-KEM-1024 /
MLKEM1024-P384 with SHAKE256. The source PID signs the report with ES384
or ML-DSA-87. No source KEX key is needed.

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
5. Build the canonical DARC header with source PID and recipient key IDs,
   and HPKE Base seal to `RcvrPub`, using the entire header as both
   HPKE `info` and AEAD AAD.
6. Sign a v3 `Darc` report with the partition PID, binding the source PID
   key ID, recipient key ID, and digest of the complete encrypted envelope.
   Return the envelope in the response and the report through out-of-band
   item 0. IO teardown scrubs the plaintext TMK.

The envelope and report formats are specified in
[`KeyReport`](key_report.md#transfer-envelope-binding).
The report authenticates this operation; a generic public-key report
cannot replace it. Replay protection is not provided by the report itself.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.

This command is **Crypto-Officer-only**: a Crypto-User session is rejected
with `InvalidPermissions`.

## Request

Wire layout: 8-byte header, the TOC entries, then the data section
carrying the policy document, fixed-length key buffers and the packed cert-descriptor list.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | (padding) | `padding` (0..=3 B) | Aligns `masked_tmk` to a 4-byte boundary. |
| 16 | `masked_tmk` | `buffer` (264 B) | The locally-masked `DarcTmk` from `DarcTmkGen` or `DarcTmkImport`. |
| 20 | `policy` | `buffer` (1-384 B) | Unified `PartPolicy`; its SHA-384 digest must equal the bound `policy_hash`. |
| 24 | `target_cert_chain` | `buffer` (`CertDescriptor[1..=3]`, 3 B each) | DATA-anchored target PID chain (normally DATA → PTA → PID), root first; DER bytes travel **out of band**. |
| 28 | `target_key_report` | `buffer` (`ReportDescriptor`, 3 B) | Out-of-band `KeyReport` signed by the target PID over its DARC key-exchange key. |

### Data section

Carries the 264-byte `masked_tmk`, variable-length CBOR `policy`, the packed
cert-descriptor list and the report descriptor. The certificate DER bytes
and the target key report travel out of band.

## Response

Wire layout: 8-byte header, TOC entries, then the encrypted envelope.
The operation report is written to out-of-band item 0.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | (padding) | `padding` (0..=3 B) | Aligns `sealed_tmk` to a 4-byte boundary. |
| 12 | `sealed_tmk` | `buffer` (258..=1826 B) | Canonical header (113 B), encapsulation (97 B P-384, 1568 B ML-KEM-1024, 1665 B hybrid), ciphertext (32 B), GCM tag (16 B). |
| 16 | `report_len` | `uint16` (inline) | Length of the PID-signed v3 `Darc` COSE_Sign1 report (≤ 5120 B) written to out-of-band item 0. |

### Data section

Carries `sealed_tmk`. Persist and transport it together with the out-of-band report.

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
