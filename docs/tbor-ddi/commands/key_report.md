<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# KeyReport (Opcode 0x10)

**Handler:** `fw/core/lib/src/ddi/tbor/key_report.rs`
**Session:** InSession

## Description

Attests a **masked key** (as produced by
[`SdSealingKeyGen`](./sd_sealing_key_gen.md)).  The handler unmasks the
key, derives its public component **on-device**, and returns a
PID-signed COSE_Sign1 key-attestation report over it.  The
partition-identity (PID) signer follows the policy `pta_alg`, the same
signer as the partition's transfer reports; the request does not choose
it:

| Policy `pta_alg` | Signer | COSE `alg` | Verify against |
|---|---|---|---|
| ES384 | P-384 PID key | ES384 (-35) | ECC-bank PID leaf |
| ML-DSA-87 | ML-DSA-87 PID key | ML-DSA-87 (-50) | ML-DSA-bank PID leaf |

The payload is identical for both algorithms. Verifiers must check that
the protected-header `alg` matches the PID leaf they verify against.

Report building:

1. **Peek** the masked blob's cleartext metadata (AAD) to read the key
   `scope`, and resolve the scope's masking key (`Ephemeral` → the
   partition `PartitionEphemeralMaskingKey`, `Local` → the partition
   `PartitionLocalMaskingKey`).  Both masking keys are provisioned by
   `PartFinal`, so the partition must be in the `Initialized` lifecycle
   state. Other scopes require their corresponding masking key; Session
   scope uses the calling session's masking key.
2. **Unmask** the blob (AEAD-GCM-256), which verifies the authenticity
   tag and recovers the private key plus its validated metadata (key
   kind and attributes).
3. **Derive** the attested public key. ECC-private kinds, including the
   P-384 `SdSealing` key, re-derive the public point via `pub = priv · G`.
   ML-KEM-1024 and MLKEM1024-P384 `SdSealing` keys re-expand their seed and
   attest the encapsulation key as an AKP `COSE_Key` `{ 1: 7, 3: alg, -1: pub }`
   with private-use `alg` -65537 (ML-KEM-1024) or -65538 (MLKEM1024-P384).
   RSA-private and RSA-CRT kinds extract the public modulus and exponent.
   Symmetric and non-attestable internal kinds are rejected with
   `UnsupportedKeyType`.
4. **Sign** the COSE_Sign1 report with the policy algorithm's PID key (ES384, or
   pure ML-DSA-87 with required hedging and an empty context over the
   Sig_structure) over the derived key, the caller-supplied
   `report_data`, the session app id, and the partition VM launch id.
5. **Return** the report through out-of-band item 0.

Because nothing is persisted, the command records no rollback on the undo
log.  The masked blob's `svn` / `owner_seed_id` are **not** enforced
against the current partition lineage: the report reflects the key
as-masked (the AEAD tag still guarantees integrity / authenticity).

This command is available to **both Crypto-Officer and Crypto-User** sessions.
The session must be active, the partition must be finalized, and the calling
role's default PSK must have been rotated. Key-scope and masked-key
authentication checks apply equally to both roles.

The session must have authenticated with the **current TBOR PSK**. Its
handshake records the role, AppId and PSK digest; a legacy MBOR session
or a session established before that credential changed cannot attest.
The report uses the captured AppId, never an identity read from a newer PSK.

CU requests additionally require a session-bound `auth_envelope`, verified
before unmasking. CO requests may carry an empty authentication buffer;
the SDK authenticates requests for both roles.

SD sealing reports set signed flag **bit 10** only for an authenticated,
HSM-generated `SdSealing` key. Peer backup, peer restore and reseal require
this provenance together with Generated set and Imported clear. Ordinary
ECC/RSA reports remain available but are not SD-sealing evidence.

DARC key-exchange reports likewise set signed flag **bit 11**
(`is_darc_kex`) only for an authenticated, HSM-generated DARC KEX key
(P-384, ML-KEM-1024 or MLKEM1024-P384). [`DarcTmkExport`](darc_tmk_export.md)
requires it, with Generated set and Imported clear.

## Request

Wire layout: 12-byte header, followed by the TOC entries, then the data
section carrying the masked key and report data.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | CO or CU session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 20 | `masked_key` | `buffer` (≤ 3168 B) | The masked-key envelope to attest: `header(8) ‖ iv(16) ‖ aad(192) ‖ pt(N) ‖ tag(16)`. |
| 24 | `report_data` | `buffer` (128 B) | Caller-supplied data bound into the report payload (typically a freshness nonce or a challenge digest). |
| 28 | `auth_envelope` | `buffer` (≤ 160 B) | 120-byte AES-GCM envelope under the session `param_key`; required for CU. CO may send an empty buffer. |

### Data section

Carries the variable-length `masked_key` followed by the 128-byte
`report_data`, followed by `auth_envelope`.

The authentication envelope uses the existing AEAD framing:
`header(8) ‖ iv(16) ‖ aad(32) ‖ ciphertext(48) ‖ tag(16)`.
Its AAD is `"key-report-v3" ‖ session_id_le(2) ‖ zero(17)`.
Its plaintext is `SHA-384(masked_key ‖ report_data)`. This binds the exact
key, report data, command and session without exposing the
session key.
The new authentication TOC entry must be encoded even for an empty CO buffer.

## Response

Wire layout: 12-byte header followed by one inline TOC entry.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `report_len` | `U16` (inline) | Number of report bytes written to out-of-band item 0. |

### Out-of-band output

| Index | Direction | Size | Contents |
|---|---|---|---|
| 0 | Out | ≥ report length (8192 B always suffices) | The tagged COSE_Sign1 key-attestation report (CBOR tag 18, opening byte `0xD2`), signed by the PID key of the policy `pta_alg`. The embedded COSE_Key holds the derived public key (big-endian coordinates for ECC). |

Report size grows with the attested public key and PID signature.
Reserve 8192 bytes to cover all supported combinations.

## Errors

| Error | Cause |
|---|---|
| `DefaultPskMustRotate` | The calling role's PSK is still the public default |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidPermissions` | The session was not established under the TBOR role's credential |
| `SessionAuthFailure` | The session's authenticated PSK is no longer current |
| `AeadEnvelopeAuthFailed` | Missing, malformed, tampered or wrong-session CU request authentication |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first), or `report_data` is the wrong length |
| `InsufficientBuffer` | Out-of-band item 0 is missing or shorter than the report |
| `UnsupportedKeyScope` | The masked key's scope (`Session`, `SecurityDomain`, or other) has no masking key yet |
| `AesGcmDecryptTagDoesNotMatch` | The masked key failed authentication (tampered or wrong masking key) |
| `UnsupportedKeyType` | The attested key kind cannot be attested (symmetric or a non-attestable internal kind) |
| `DdiDecodeFailed` | Malformed request body |

## Public-key report schema

Report version 2 supports a signed `report_kind` discriminator. Existing
`KeyReport` commands continue to emit public-key reports without that
discriminator. Public-key v1/v2 encoding and ES384 signatures are unchanged.
Protected headers contain `{1: -35, 3: "application/cbor"}` for ES384 or
`{1: -50, 3: "application/cbor"}` for ML-DSA-87.

For public-key reports without a discriminator, v1 omits the policy hash
and v2 requires it. With an explicit `PublicKey` discriminator, v2 permits
the policy hash to be absent. A public-key report cannot substitute for a
directly signed transfer envelope.

The signed payload is a definite-length CBOR map with these integer keys:

| Map key | Field | Required kinds |
|---|---|---|
| 0 | `version` (1 or 2) | All |
| 1 | Fixed-width encoded public key | `PublicKey` |
| 2 | Encoded public-key length | `PublicKey` |
| 3 | Key capability/provenance flags | `PublicKey` |
| 4 | Application UUID | `PublicKey` |
| 5 | Caller-supplied report data | `PublicKey` |
| 6 | VM launch ID | `PublicKey` |
| 7 | SHA-384 policy hash | `PublicKey` v2, as above |
| 8 | Optional `report_kind`: `PublicKey` (0) | `PublicKey` v2 |

Unknown, duplicate, missing, wrong-kind, or incorrectly sized fields are
rejected. Binary transfer payloads are not public-key report maps.

Only exporting command handlers may construct and sign `Darc` or `SdBackup`
envelopes after validating the secret and recipient on-device.
A generic key report containing caller-supplied envelope bytes
or a digest does not prove export provenance. Signature verification also
does not replace signer authorization, recipient/envelope binding checks,
or replay policy.

### Transfer-envelope binding

The DARC and SD export, reseal, and import/restore commands use this
envelope with HPKE Base and a direct PID signature. SD and DARC select the KEM
from their respective recipient key.

| KEM | Suite (KEM / KDF / AEAD) | Recipient identifier | Public key / `enc` |
|---|---|---|---|
| DHKEM(P-384, HKDF-SHA384) | `0x0011` / `0x0002` / `0x0002` | SHA-384 of canonical DER SPKI | 97 B SEC1 |
| ML-KEM-1024 (HPKE-13) | `0x0042` / `0x0011` (SHAKE256) / `0x0002` | SHA-384(`TSRA-MLKEM1024-KEY-v1` followed by raw key) | 1568 B |
| MLKEM1024-P384 (HPKE-10) | `0x0051` / `0x0011` (SHAKE256) / `0x0002` | SHA-384(`TSRA-MLKEM1024-P384-KEY-v1` followed by raw key) | 1665 B, PQ key followed by SEC1 point |

The SD/DARC signer is the actual partition PID, using ES384 or ML-DSA-87
according to the policy PTA algorithm.

The single artifact is tagged `COSE_Sign1(payload=envelope)`, where
`envelope = header || enc || ciphertext || tag`. The protected header is
exactly `{1: -35}` (ES384) or `{1: -50}` (ML-DSA-87), with an empty
unprotected map. ES384 signatures are 96-byte big-endian `r` followed by `s`;
ML-DSA-87 signatures are 4627 bytes.
The binary payload has no CBOR content-type claim, duplicate claims map,
or envelope hash. All integer fields below
are unsigned; suite IDs use network byte order.

COSE signature domains use standard
[`external_aad` (RFC 9052 Sections 4.3-4.4)](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4):

| Kind | Exact COSE `external_aad` bytes |
|---|---|
| `Darc` | ASCII `TSRA-Darc-v1` followed by 20 zero bytes (32 bytes total) |
| `SdBackup` | ASCII `TSRA-SdBackup-v1` followed by 16 zero bytes (32 bytes total) |
| `PublicKey` v1/v2 | Empty byte string, unchanged |

Signers and verifiers select the domain from the validated kind; callers
cannot override it. The signature covers the CBOR-encoded
`["Signature1", protected_header, external_aad, envelope]`. External AAD
is not serialized in COSE_Sign1. Empty, unpadded, or wrong-kind transfer
domains are not accepted.
The 32-byte label size is a TSRA profile choice, not a COSE requirement.
This is separate from HPKE AAD, which remains empty.

| Offset | Header field | Length |
|---|---|---|
| 0 | ASCII `TSRA-XFER` | 9 |
| 9 | Envelope version (1) | 1 |
| 10 | Operation kind: `Darc` (1) or `SdBackup` (2) | 1 |
| 11 | KEM ID | 2 |
| 13 | KDF ID | 2 |
| 15 | AES-256-GCM ID (`0x0002`) | 2 |
| 17 | `source_pid_spki_thumbprint` | 48 |
| 65 | `recipient_spki_thumbprint` | 48 |
| 113 | Transferred SD policy hash, `SdBackup` only | 48 |

For both `Darc` and `SdBackup`, the fields at offsets 17 and 65 are
`source_pid_spki_thumbprint` and `recipient_spki_thumbprint`, respectively.
The source is `SHA-384(canonical_DER_SPKI(PID_public_key))`, using the same
canonical SPKI representation as policy trust-anchor thumbprints. A P-384
recipient uses that same construction. For PQ recipients, the field named
`recipient_spki_thumbprint` carries the algorithm-domain identifier in the
table above. The recipient is the HPKE encryption key, not its PID.

The SEC1 public key and encapsulation are exactly 97 bytes:
`0x04 || X_be[48] || Y_be[48]`.
Canonical SPKI encodes `id-ecPublicKey` and `secp384r1` with that uncompressed
point (120 bytes total); canonical ML-DSA-87 SPKI is 2614 bytes. Header fields identify source or recipient
roles; a matching thumbprint alone does not grant authorization.

HPKE uses **Base** mode with the selected suite above. The complete canonical
header is passed verbatim as HPKE `info`, with empty AEAD AAD. DARC encrypts
exactly 32 bytes of TMK; SD encrypts exactly 48 bytes of BKS3. Their headers
are 113 and 161 bytes respectively, and their complete encrypted envelopes
are 258 and 322 bytes respectively for P-384, including the 16-byte GCM tag.
PQ SD inner envelopes are 1793 or 1890 bytes.

| DARC recipient KEM | Inner envelope | Complete ES384 artifact | Complete ML-DSA-87 artifact |
|---|---:|---:|---:|
| P-384 | 258 B | 367 B | 4899 B |
| ML-KEM-1024 | 1729 B | 1838 B | 6370 B |
| MLKEM1024-P384 | 1826 B | 1935 B | 6467 B |

| SD recipient KEM | Inner envelope | Complete ES384 artifact | Complete ML-DSA-87 artifact |
|---|---:|---:|---:|
| P-384 | 322 B | 431 B | 4963 B |
| ML-KEM-1024 | 1793 B | 1902 B | 6434 B |
| MLKEM1024-P384 | 1890 B | 1999 B | 6531 B |

DARC export and SD creation/reseal write the complete artifact to OOB output item 0 and
return its `report_len`. Import/restore/reseal source inputs use a report
descriptor referencing that same complete artifact. There is no inline
second envelope or detached report.
Unknown versions/kinds/suites, malformed SEC1 encodings, missing fields,
wrong secret/ciphertext sizes, and trailing bytes are rejected.

Exporting commands construct the complete payload internally and authorize
the recipient before sealing; the seal helper additionally checks its SPKI
thumbprint. No separate transfer report is produced or accepted.

Before opening, the receiver must authorize the reporting PID using the
operation's trust contract. The binding helper verifies the PID signature and the required
transfer kind, derives the source/recipient thumbprints from the actual keys,
and requires equality with the signed header. For SD, the signed policy
hash must equal the requested transferred SD policy. A sealing authority's
local policy may differ from that policy.
This does not bypass cloning permissions, trusted-SA evidence requirements,
rollback checks, or freshness rules. Plaintext is published only after both
signature verification and HPKE authentication succeed. The unreleased
transfer format has no old claims-map, detached-report, or Auth fallback.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/key_report.rs`
- Report format: `fw/core/crypto/key-report/`
- Masked-key producer: [SdSealingKeyGen](./sd_sealing_key_gen.md)
