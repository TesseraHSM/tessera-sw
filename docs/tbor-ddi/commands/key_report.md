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
PID-signed COSE_Sign1 key-attestation report over it.  The report is
signed by the partition-identity (PID) key — the same signer as the
`PartInit` PTA report — so a relying party can verify it against the
partition's slot-0 certificate chain.

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
   RSA-private and RSA-CRT kinds extract the public modulus and exponent.
   Symmetric and non-attestable internal kinds are rejected with
   `UnsupportedKeyType`.
4. **Sign** the COSE_Sign1 report (ES384 / ECDSA-P384) with the PID key
   over the derived key, the caller-supplied `report_data`, the session
   app id, and the partition VM launch id.

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
Its AAD is `"key-report-v1" ‖ session_id_le(2) ‖ zero(17)`.
Its plaintext is `SHA-384(masked_key ‖ report_data)`. This binds the exact
key, report data, command and session without exposing the session key.
The new authentication TOC entry must be encoded even for an empty CO buffer.

## Response

Wire layout: 12-byte header, followed by the TOC entry, then the data
section carrying the report.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `report` | `buffer` (≤ 1024 B) | The tagged COSE_Sign1 key-attestation report (CBOR tag 18, opening byte `0xD2`), signed by the PID key. The embedded COSE_Key holds the derived public key (big-endian coordinates for ECC). |

### Data section

Carries the variable-length COSE_Sign1 `report`.

## Errors

| Error | Cause |
|---|---|
| `DefaultPskMustRotate` | The calling role's PSK is still the public default |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidPermissions` | The session was not established under the TBOR role's credential |
| `SessionAuthFailure` | The session's authenticated PSK is no longer current |
| `AeadEnvelopeAuthFailed` | Missing, malformed, tampered or wrong-session CU request authentication |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first), or `report_data` is the wrong length |
| `UnsupportedKeyScope` | The masked key's scope (`Session`, `SecurityDomain`, or other) has no masking key yet |
| `AesGcmDecryptTagDoesNotMatch` | The masked key failed authentication (tampered or wrong masking key) |
| `UnsupportedKeyType` | The attested key kind cannot be attested (symmetric or a non-attestable internal kind) |
| `DdiDecodeFailed` | Malformed request body |

## Public-key report schema

Report version 2 supports a signed `report_kind` discriminator. Existing
`KeyReport` commands continue to emit public-key reports without that
discriminator. Public-key v1/v2 encoding, the protected header
`{1: -35, 3: "application/cbor"}`, and ES384 signatures are unchanged.

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

### P-384 transfer-envelope binding

The DARC and SD export, reseal, and import/restore commands use this
envelope with HPKE Base and a direct PID signature.
Only P-384 is supported; there are no PQ or hybrid selectors.

The single artifact is tagged `COSE_Sign1(payload=envelope)`, where
`envelope = header || enc || ciphertext || tag`. The protected header is
exactly `{1: -35}` (ES384), the unprotected map is empty, and the 96-byte
signature is `r || s` in big-endian order.
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
is not serialized in COSE_Sign1, so signed artifacts remain 367 and
431 bytes. Empty, unpadded, or wrong-kind transfer domains are not accepted.
The 32-byte label size is a TSRA profile choice, not a COSE requirement.
This is separate from HPKE AAD, which remains empty.

| Offset | Header field | Length |
|---|---|---|
| 0 | ASCII `TSRA-XFER` | 9 |
| 9 | Envelope version (1) | 1 |
| 10 | Operation kind: `Darc` (1) or `SdBackup` (2) | 1 |
| 11 | DHKEM(P-384, HKDF-SHA384) ID (`0x0011`) | 2 |
| 13 | HKDF-SHA384 ID (`0x0002`) | 2 |
| 15 | AES-256-GCM ID (`0x0002`) | 2 |
| 17 | `source_pid_spki_thumbprint` | 48 |
| 65 | `recipient_spki_thumbprint` | 48 |
| 113 | Transferred SD policy hash, `SdBackup` only | 48 |

For both `Darc` and `SdBackup`, the fields at offsets 17 and 65 are
`source_pid_spki_thumbprint` and `recipient_spki_thumbprint`, respectively.
Each is `SHA-384(canonical_DER_SPKI(public_key))`, using the same canonical
SPKI representation as policy trust-anchor thumbprints. The source is the
PID signing key; the recipient is the HPKE encryption key, not its PID.

The SEC1 public key and encapsulation are exactly 97 bytes:
`0x04 || X_be[48] || Y_be[48]`.
Canonical SPKI encodes `id-ecPublicKey` and `secp384r1` with that uncompressed
point (120 bytes total). Header fields identify source or recipient
roles; a matching thumbprint alone does not grant authorization.

HPKE uses **Base** mode with the fixed suite above. The complete canonical
header is passed verbatim as HPKE `info`, with empty AEAD AAD. DARC encrypts
exactly 32 bytes of TMK; SD encrypts exactly 48 bytes of BKS3. Their headers
are 113 and 161 bytes respectively, and their complete encrypted envelopes
are 258 and 322 bytes respectively, including the 16-byte GCM tag. The
complete signed artifacts are 367 bytes for DARC and 431 bytes for SD.
Unknown versions/kinds/suites, malformed SEC1 encodings, missing fields,
wrong secret/ciphertext sizes, and trailing bytes are rejected.

Exporting commands construct the complete payload internally and authorize
the recipient before sealing; the seal helper additionally checks its SPKI
thumbprint. No separate transfer report is produced or accepted.

Before opening, the receiver must authorize the reporting PID using the
operation's trust contract. The binding helper verifies ES384 and the required
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
