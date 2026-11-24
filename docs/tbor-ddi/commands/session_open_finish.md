<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionOpenFinish (Opcode 0x04)

**Handler:** `fw/core/lib/src/ddi/tbor/session_open_finish.rs`
**Session:** InSession (Pending)

## Description

Phase 2 confirms the revision-bound Init transcript and promotes its Pending
slot to Active. The entire request and response are AES-256-GCM protected using
the Pending transport keys on both Uno and Duo.

The common header must use the exact API major/minor selected in Init.
Firmware recovers the revision, suite, type, transcript, and credential binding
from Pending state rather than accepting replacements in the Finish body.

The host sends `mac_fin = HMAC-SHA-384(fin_key, T1)` and a 32-byte seed in
an AEAD envelope under the fresh `param_key`. For a fresh open, the seed is
new and firmware generates an independent random masking key. Reopen instead
sends the original seed and saved masking-key envelope to restore the original
masking key after validating its slot lineage. Firmware verifies the confirmation
and current credential, wraps the masking key for the response, and commits
Active state.

## Request

The 12-byte header is followed by four TOC entries. Data begins at byte 28.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Pending slot allocated by Init. |
| 16 | `mac_fin` | `buffer` (ref) | 48-byte confirmation at data-relative offset 0. |
| 20 | `seed_envelope` | `buffer` (ref) | 72-byte envelope at data-relative offset 48. |
| 24 | `bmk_session` | `buffer` (ref) | Empty for fresh open; saved envelope for recovery, up to 512 bytes. |

## Response

The header echoes the request revision. Four TOC slots preserve the request
footprint; data begins at byte 28.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `bmk_session` | `buffer` (ref) | 264-byte wrapped masking key at data-relative offset 0. |
| 16 | Reserved | `none` | Paired TOC placeholder. |
| 20 | Reserved | `none` | Paired TOC placeholder. |
| 24 | Reserved | `none` | Paired TOC placeholder. |

## Key schedule and storage

```text
IKM = Z || PSK
PRK = HKDF-Extract("TSRA-SESSION-v1", IKM)
hs  = HKDF-Expand(PRK, "tsra-session-hs-v1" || T1, 48)
ExpandLabel(label, n) = HKDF-Expand(hs, ASCII(label) || BE16(n), n)

fin_key   = ExpandLabel("tsra-session-host-fin-v1", 48)
param_key = ExpandLabel("tsra-session-param-v1", 32)
h2m       = ExpandLabel("tsra-session-xport-h2m-v1", 36)
m2h       = ExpandLabel("tsra-session-xport-m2h-v1", 36)
```

Each transport secret is `AES key(32) || nonce salt(4)`. The masking key is
random device-generated material, not derived from host-known `hs`.

The 243-byte Pending blob is replaced by the 216-byte Active blob:

```text
internal_format_tag(8) || LE16(api_major) || LE16(api_minor)
|| param_key(32) || masking_key(32) || auth_binding(68)
|| h2m(36) || m2h(36)
```

The opaque internal tag is not the selected DDI revision. Revision checks
continue for all subsequent session commands. Transport keys and sender
counters carry over through promotion; they must not restart.

## Seed and masking-key envelopes

The seed envelope uses AES-256-GCM under `param_key` with empty AAD:

```text
"AEAD"(4) || alg(1) || reserved(1) || BE16(0)
|| IV_slot(16) || seed_ciphertext(32) || tag(16)
```

`IV_slot` is the 12-byte GCM nonce followed by `00 00 00 01`.

`bmk_session` wraps only the independent 32-byte masking key under
`BK_SESSION`, using the partition's 80-byte boot-key material and the seed
with SP800-108 HMAC-SHA-384 counter KDF, label `SESSION_BK`, and 32-byte output.
Its 192-byte authenticated metadata identifies the masking key, attributes,
SVN, owner seed, and `SESSION_BMK` label:

```text
"AEAD"(4) || alg(1) || reserved(1) || BE16(192)
|| IV_slot(16) || metadata(192) || masking_key_ciphertext(32) || tag(16)
```

Neither the handshake secret nor parameter/transport keys are included in
`bmk_session`. On reopen, the host reuses its securely retained original seed
and supplies the saved envelope inside the fresh protected Finish. Firmware
unwraps and validates the masking key, its metadata and a retained per-slot
128-bit SHA-384 fingerprint. It restores the original masking key rather than
generating a new one, but installs fresh parameter and transport keys.
The firmware-owned PSK-change-consumed bit survives recovery. A migration
clears it when it returns the PSKs to their defaults, so a session recovered
after a migration rotates its role PSK again.

## Errors

| Error | Cause |
|---|---|
| `UnsupportedRevision` | Unsupported header revision or mismatch with Pending state. |
| `InvalidArg` | Invalid field lengths or session identifier. |
| `SessionNotPending` | Slot is not Pending. |
| `SessionAuthFailure` | Confirmation, seed authentication, or credential validation failed. |
| `PartitionNotProvisioned` | Required partition material is unavailable. |

For fresh open, authentication failure tears down the slot after its protected error response,
so transport keys remain available long enough to authenticate that response.
A late Finish for an evicted/reused slot fails under its different handshake
and transport keys; this is not a general command replay cache.
Failed reopen instead restores `NeedsRenegotiation` after completion, preserving
the original recovery identity and rotation allowance state for retry.

## See also

- [Complete session design](../session-design.md)
- [SessionOpenInit](./session_open_init.md)
- [SessionClose](./session_close.md)
