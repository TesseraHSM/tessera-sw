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

Wire layout: 4-byte header, followed by the TOC entries, then the data
section carrying the masked key and report data.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO or CU session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `masked_key` | `buffer` (≤ 3168 B) | The masked-key envelope to attest: `header(8) ‖ iv(16) ‖ aad(192) ‖ pt(N) ‖ tag(16)`. |
| — | `report_data` | `buffer` (128 B) | Caller-supplied data bound into the report payload (typically a freshness nonce or a challenge digest). |
| — | `auth_envelope` | `buffer` (≤ 160 B) | 120-byte AES-GCM envelope under the session `param_key`; required for CU. CO may send an empty buffer. |

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

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/key_report.rs`
- Report format: `fw/core/crypto/key-report/`
- Masked-key producer: [SdSealingKeyGen](./sd_sealing_key_gen.md)
