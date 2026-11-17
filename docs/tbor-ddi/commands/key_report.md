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

Wire layout: 8-byte header, followed by the TOC entries, then the data
section carrying the masked key and report data.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | CO or CU session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_key` | `buffer` (≤ 3168 B) | The masked-key envelope to attest: `header(8) ‖ iv(16) ‖ aad(192) ‖ pt(N) ‖ tag(16)`. |
| 20 | `report_data` | `buffer` (128 B) | Caller-supplied data bound into the report payload (typically a freshness nonce or a challenge digest). |
| 24 | `auth_envelope` | `buffer` (≤ 160 B) | 120-byte AES-GCM envelope under the session `param_key`; required for CU. CO may send an empty buffer. |

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

Wire layout: 8-byte header, followed by the TOC entry, then the data
section carrying the report.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `report` | `buffer` (≤ 1024 B) | The tagged COSE_Sign1 key-attestation report (CBOR tag 18, opening byte `0xD2`), signed by the PID key. The embedded COSE_Key holds the derived public key (big-endian coordinates for ECC). |

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

## Discriminated report schema

Report version 2 supports a signed `report_kind` discriminator. Existing
`KeyReport` commands continue to emit public-key reports without that
discriminator. Operation reports use version 2 with an explicit kind;
there is no report-version bump. The COSE_Sign1 wrapper and ES384 signature
format are unchanged.

For public-key reports without a discriminator, v1 omits the policy hash
and v2 requires it. With an explicit `PublicKey` discriminator, v2 permits
the policy hash to be absent. Operation reports require their discriminator
and exact kind-specific fields; a public-key report cannot substitute for one.

The signed payload is a definite-length CBOR map with these integer keys:

| Map key | Field | Required kinds |
|---|---|---|
| 0 | `version` (2) | All |
| 1 | Fixed-width encoded public key | `PublicKey` |
| 2 | Encoded public-key length | `PublicKey` |
| 3 | Key capability/provenance flags | `PublicKey` |
| 4 | Application UUID | `PublicKey` |
| 5 | Caller-supplied report data | `PublicKey` |
| 6 | VM launch ID | `PublicKey` |
| 7 | SHA-384 policy hash | Required for `SdBackup`; optional for `PublicKey` |
| 8 | `report_kind`: `PublicKey` (0), `Darc` (1), `SdBackup` (2) | All |
| 9 | SHA-384 source PID key ID | `Darc`, `SdBackup` |
| 10 | SHA-384 recipient key ID | `Darc`, `SdBackup` |
| 11 | SHA-384 transfer-envelope hash | `Darc`, `SdBackup` |

Unknown, duplicate, missing, wrong-kind, or incorrectly sized fields are
rejected. Operation reports carry no public-key fields or caller report data.
The `SdBackup` policy hash identifies the transferred SD policy, including
when the sealing authority's local policy differs from it.

Only exporting command handlers may construct `Darc` or `SdBackup` claims
after validating the secret and recipient and computing the envelope hash
on-device. A generic key report containing caller-supplied envelope bytes
or a digest does not prove export provenance. Signature verification also
does not replace signer authorization, recipient/envelope binding checks,
or replay policy.

### P-384 transfer-envelope binding

The DARC and SD export, reseal, and import/restore commands use this
envelope with HPKE Base and PID-signed operation reports.
Only P-384 is supported; there are no PQ or hybrid selectors.

The envelope is `header || enc || ciphertext || tag`. The report is a separate
COSE_Sign1 value, excluded from the envelope hash. All integer fields below
are unsigned; suite IDs use network byte order.

| Offset | Header field | Length |
|---|---|---|
| 0 | ASCII `TSRA-XFER` | 9 |
| 9 | Envelope version (1) | 1 |
| 10 | Operation kind: `Darc` (1) or `SdBackup` (2) | 1 |
| 11 | DHKEM(P-384, HKDF-SHA384) ID (`0x0011`) | 2 |
| 13 | HKDF-SHA384 ID (`0x0002`) | 2 |
| 15 | AES-256-GCM ID (`0x0002`) | 2 |
| 17 | Source PID key ID | 48 |
| 65 | Recipient key ID | 48 |
| 113 | Transferred SD policy hash, `SdBackup` only | 48 |

Both identifiers are
`SHA-384(ASCII("TSRA-P384-KEY-v1") || SEC1_public_key)`.
The SEC1 public key and encapsulation are exactly 97 bytes:
`0x04 || X_be[48] || Y_be[48]`.
The curve-specific domain identifies the key algorithm; the header/report
field identifies its source-PID or recipient role.

HPKE uses **Base** mode with the fixed suite above. The complete canonical
header is passed verbatim as both HPKE `info` and AEAD AAD. DARC encrypts
exactly 32 bytes of TMK; SD encrypts exactly 48 bytes of BKS3. Their headers
are 113 and 161 bytes respectively, and their complete encrypted envelopes
are 258 and 322 bytes respectively, including the 16-byte GCM tag.
Unknown versions/kinds/suites, malformed SEC1 encodings, missing fields,
wrong secret/ciphertext sizes, and trailing bytes are rejected.

The signed envelope hash is
`SHA-384(ASCII("TSRA-XFER-HASH-v1") || header || enc || ciphertext || tag)`.
Exporting commands must derive this digest and all report claims internally.
They must authorize the recipient before sealing; the seal helper additionally
checks the recipient key ID. A public-key report is never an operation report.

Before opening, the receiver must authorize the reporting PID using the
operation's trust contract. The binding helper verifies ES384 and the required
report kind, derives the source/recipient identifiers from the actual keys,
requires report/header agreement, and recomputes the envelope hash.
For SD, the report and header must always agree on the policy hash. A caller
may additionally require equality with an expected policy (for example peer
cloning); remote-SA flows may authenticate a different source policy.
This does not bypass cloning permissions, trusted-SA evidence requirements,
rollback checks, or freshness rules. Plaintext is published only after both
report verification and HPKE authentication succeed.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/key_report.rs`
- Report format: `fw/core/crypto/key-report/`
- Masked-key producer: [SdSealingKeyGen](./sd_sealing_key_gen.md)
