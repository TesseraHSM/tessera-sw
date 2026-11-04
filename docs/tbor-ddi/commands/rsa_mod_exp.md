<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# RsaModExp (Opcode 0x1A)

**Handler:** `fw/core/lib/src/ddi/tbor/rsa_mod_exp.rs`
**Session:** InSession

## Description

Performs the RSA private-key primitive `x = y^d mod n` using a
caller-held **masked** RSA private key (imported via
[`UnwrapKey`](./unwrap_key.md) with the RSA / RSA-CRT key class).

The device unmasks the key **in place** in the request buffer (recovering
its modulus size and CRT form from the blob's key kind), checks the usage
attribute the requested operation needs, computes the modular
exponentiation, and returns the result.  The recovered plaintext key is
scrubbed from the request buffer during IO teardown.  This is the raw primitive
underlying RSA decrypt / sign — the host applies and removes any padding.
This is the TBOR analogue of MBOR `RsaModExp`, keyed by a masked blob
instead of a vault id.

There is no TBOR RSA key generation; RSA keys enter the device only
through `UnwrapKey`.

Both the input `y` and the output `x` are in PKA-native **little-endian**
byte order; the device flips endianness internally if its primitive is
big-endian native (e.g. OpenSSL on the emulator).

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | `y` | `buffer` (256 / 384 / 512 B) | The input integer `y` in wire little-endian order, exactly the key's modulus length. |
| 16 | `masked_key` | `buffer` (260..=3168 B) | The masked RSA private key; unmasked in place.  Its kind recovers the modulus size and CRT form. |
| 20 | `op_type` | `u8` (inline) | The [`RsaOp`] selecting the required usage attribute: `1` = Decrypt (needs `decrypt`), `2` = Sign (needs `sign`). |

### Data section

Carries the input integer at offset 24, followed by the masked key. The integer
must start immediately after the TOC so the PAL can replace `y` with `x` in place
without moving the result or overlapping the key. Host and firmware schemas
must be updated together.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `x` | `buffer` (256 / 384 / 512 B) | The result `x = y^d mod n` in wire little-endian order, exactly the key's modulus length. |

### Data section

Carries the result integer at offset 24, replacing the request's `y`. The remaining
three paired TOC slots are `None`, and the unused allocation tail, including the
unmasked key, is scrubbed during IO teardown.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown `op_type`, `y` length ≠ the key's modulus length, or noncanonical `y` offset |
| `InvalidKeyType` | The masked blob is not an RSA private key |
| `InvalidPermissions` | The key lacks the usage the operation needs (`decrypt` for Decrypt, `sign` for Sign) |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked key is malformed or fails authentication (wrong scope / tampered) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Import an RSA key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/rsa_mod_exp.rs`
