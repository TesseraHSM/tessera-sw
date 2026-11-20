<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EccVerify (Opcode 0x33)

**Handler:** `fw/core/lib/src/ddi/tbor/ecc_verify.rs`  
**Session:** InSession

## Description

Verifies an ECDSA signature over a caller-supplied precomputed digest. The
caller supplies a masked ECC private-key envelope, not a public key. Firmware
authenticates and unmasks the envelope in place, resolves its masking scope,
recovers the curve from the authenticated private-key kind, derives the public
key on-device, and verifies the signature. The public key is neither accepted
from nor returned to the caller.

The key must have `sign` **or** `verify` usage. This permits generated signing
keys and imported signing keys without permitting derive-only keys. Supported
keys are P-256, P-384, and P-521; supported digests are SHA-256, SHA-384, and
SHA-512 for every curve. The digest is precomputed; firmware does not hash a
message. ECDSA applies the usual most-significant-bit truncation when the
digest is wider than the curve order, with no low-S restriction.

The command requires an active CO or CU session and uses the ordinary
default-PSK gate. There is no out-of-session bring-up path. The masked envelope
is authenticated and scope/session-bound; callers must not assume that an
envelope created on one platform can be used on another.

## Request

### Fields

| Field | Type | Description |
|---|---|---|
| `session_id` | `session_id` (inline) | Active CO/CU session; cross-checked against the SQE-carried session id. |
| `hash_algo` | `U8` | `1` = SHA-256, `2` = SHA-384, `3` = SHA-512. |
| `masked_key` | aligned `buffer` (264..=312 B) | Authenticated masked ECC private-key envelope from `EccGenerateKey` or `UnwrapKey`; mutable on firmware for in-place unmasking. |
| `input` | aligned `buffer` (96..=216 B) | Packed `r || s || digest_lane`; read-only on firmware. |

Firmware accepts only authenticated `Ecc256Private`, `Ecc384Private`, and
`Ecc521Private` key kinds. It checks the unmasked scalar's exact wire length,
the platform/curve/hash-dependent input size, and zero padding before calling
the PAL.

### Packed input

Let `C` be the coordinate lane width, `H` the selected digest length, and
`D = max(C, round_up(H, platform_coord_pad))`. The input is:

```text
r[C] || s[C] || digest[H] || zero_padding[D - H]
```

Coordinates and digest bytes use device byte order. Each signature component
is converted independently; the concatenated signature is never reversed as a
whole. The digest occupies the beginning of its lane: Uno callers reverse the
natural big-endian digest, while Duo callers retain its byte order. Framing
integers remain little-endian on all platforms.

| Platform | Operand order | Coordinate pad | P-521 `C` | P-521 signature input | P-521 verify input |
|---|---|---:|---:|---:|---:|
| Uno / std Uno | Little-endian | 4 B | 68 B | 136 B | 204 B |
| std Duo | Big-endian | 8 B | 72 B | 144 B | 216 B |

For P-521, the meaningful 66-byte coordinate begins at the start of each lane,
followed by zero padding, including on Duo. Duo uses the same 72-byte lanes
for `EccGenerateKey`, `EccSign`, and `EccVerify`.

## Response

Success has an empty typed response body. There is no boolean result: an
invalid signature is returned as `EccVerifyFailed` (`0x08700024`).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | Session is missing or inactive. |
| `DefaultPskMustRotate` | The calling role's default PSK has not been rotated. |
| `InvalidArg` | Unsupported hash, incorrect packed/scalar length, or nonzero operand padding. |
| `InvalidKeyType` | Authenticated key kind is not an ECC private key. |
| `InvalidPermissions` | The key has neither `sign` nor `verify` usage. |
| `EccVerifyFailed` | Signature is invalid, including out-of-range `r` or `s`. |
| Existing unmask/scope error | Envelope authentication fails or its masking scope is unavailable. |
| Existing PAL/operational error | Public-key derivation, hardware, allocation, or transport operation fails. |

The authenticated private scalar and derived public key remain on-device.
Private bytes are scrubbed by existing IO teardown; the command persists no
state and creates no undo-log entry.

## See also

- Generate an ECC key: [`ecc_generate_key.md`](./ecc_generate_key.md)
- Sign a precomputed digest: [`ecc_sign.md`](./ecc_sign.md)
- Import an ECC private key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/ecc_verify.rs`
