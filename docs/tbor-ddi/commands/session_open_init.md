<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionOpenInit (Opcode 0x03)

**Handler:** `fw/core/lib/src/ddi/tbor/session_open_init.rs`
**Session:** NoSession

## Description

Phase 1 of session establishment. The host supplies a fresh ephemeral public
key, PSK identifier (`0` = Crypto Officer, `1` = Crypto User), encrypted
session type (`0`), and cryptographic suite. Both roles use AES-256-GCM
protected session traffic, including Finish while the slot is Pending.

The selected API revision is carried only in the common 12-byte TBOR header,
not duplicated in the Init body. Firmware validates its support, reserves a
Pending slot, and returns a fresh KEM output and a PID-key signature over the
revision-bound transcript. The host verifies the PID certificate chain against
an independently provisioned root SPKI thumbprint before trusting that signature.

### Suite registry

| `suite_id` | KEM | `pk_init` | `enc` | Authentication |
|---|---|---|---|---|
| `0x01` | Ephemeral ECDH P-384 | 97-byte uncompressed SEC1 point | 97-byte device ephemeral SEC1 point | ECDSA P-384 with PID key |
| `0x02` | ML-KEM-1024 | 1568-byte encapsulation key | 1568-byte ciphertext | ML-DSA-87 with PID key |

All suites use HKDF-SHA-384, HMAC-SHA-384 Finish confirmation, and
AES-256-GCM transport. The selected suite and API revision remain pinned for
the session lifetime. Suite `0x02` provides post-quantum key agreement and
ML-DSA-87 transcript authentication, requiring the
ML-DSA bank (`1`) and ML-DSA-87 keys throughout the validated PID-to-root path.
Its root must be pinned independently; there is no fallback to the ECC bank.

## Request

The 12-byte header is followed by five TOC entries. Variable-length data begins
at byte 32.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `reopen_id` | `uint16` (inline) | `65535` for fresh open; otherwise existing stale slot. |
| 16 | `psk_id` | `uint8` (inline) | `0` = Crypto Officer; `1` = Crypto User. |
| 20 | `session_type` | `uint8` (inline) | `0` = Encrypted; all other values are rejected. |
| 24 | `suite_id` | `uint8` (inline) | `0x01` or `0x02`; other identifiers are unsupported. |
| 28 | `pk_init` | `buffer` (ref) | Data-relative offset 0; length 97 or 1568 according to the suite. |

## Response

The header echoes the request's API revision. Five TOC slots preserve the
request footprint; variable-length data begins at byte 32.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Reserved Pending slot: CO 0, CU 1..=7. |
| 16 | `enc` | `buffer` (ref) | Data-relative offset 0; length 97 or 1568 according to the suite. |
| 20 | `sig` | `buffer` (ref) | Data-relative offset `len(enc)`; 96-byte raw ECDSA signature for `0x01`, empty for `0x02`. |
| 24 | Reserved | `none` | Paired TOC placeholder. |
| 28 | Reserved | `none` | Paired TOC placeholder. |

For suite `0x02`, the host must supply OOB output item `0` with exactly
4627 bytes. Firmware writes the raw ML-DSA-87 signature there; the in-band
response remains below 4 KiB. The public signature is not encrypted, but
the host must verify it against its locally reconstructed transcript.

## Transcript and key binding

```text
M1 = "TSRA-SESSION-v1"
     || BE16(api_major) || BE16(api_minor)
     || suite_id || psk_id || session_type
     || pk_pid
     || BE16(len(pk_init)) || pk_init
     || BE16(len(enc)) || enc
T1 = SHA-384(M1)
sig = ECDSA-P384.SignDigest(sk_pid, T1)                  # suite 0x01
sig = ML-DSA-87.Sign(sk_pid, T1, context="")             # suite 0x02, pure mode
```

`pk_pid` is a 97-byte SEC1 P-384 point for suite `0x01`, or a
2592-byte raw ML-DSA-87 public key for `0x02`. ML-DSA signing is hedged;
it signs `T1` as its message, not as an external message representative.

For reopen only, append `"TSRA-REOPEN-v1:" || BE16(reopen_id)` to `M1`
before hashing. Fresh-open transcripts are unchanged. Reopen uses the same
establishment pipeline, authenticates the current role PSK, and reserves the
same migrated slot. Active and fresh Pending targets are rejected. An abandoned
recovery Pending may be replaced; fresh opens cannot evict it. Recovery lineage
is authenticated by Finish using the saved envelope and retained fingerprint.

The revision integers come from the header but are encoded big-endian in the
transcript, unlike their little-endian wire representation. The host verifies
using its original local revision, suite, role, type, and ephemeral public key.
`T1` also enters handshake-secret derivation, so changing either revision
component invalidates authentication and changes the session keys.

This binds the selected context; capability discovery is not authenticated
version negotiation and does not guarantee highest-version selection.

The Pending state contains the selected revision, handshake secret, transcript
hash, role/AppId/PSK-digest binding, type, suite, and directional transport
secrets. Finish requires this same revision and a still-current credential.
The [session design](../session-design.md) specifies the complete trust checks,
transcript, key derivation, transport, and storage layouts.

## Errors

| Error | Cause |
|---|---|
| `UnsupportedRevision` | Header revision is unsupported by this platform. |
| `InvalidPskId` | `psk_id` is neither 0 nor 1. |
| `InvalidSessionType` | `session_type` is not 0. |
| `UnsupportedSessionSuite` | Suite is not implemented. |
| `InvalidArg` | Malformed ephemeral public key, incorrect length, non-canonical ML-KEM encapsulation key, or missing/wrong-length ML-DSA signature OOB output. |
| `EccPointValidationFailed` | Invalid P-384 point. |
| `PartitionNotEnabled` | Partition is not enabled. |
| `PartitionNotProvisioned` | Identity key is unavailable. |
| `VaultSessionLimitReached` | No eligible Pending slot. |

## See also

- [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- [SessionOpenFinish](./session_open_finish.md)
