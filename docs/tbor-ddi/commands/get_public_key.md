<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# GetPublicKey (Opcode 0x2F)

**Handler:** `fw/core/lib/src/ddi/tbor/get_public_key.rs`
**Session:** InSession

## Description

Returns the public key of a caller-held **masked** RSA, RSA-CRT, or ECC
private key (from [`EccGenerateKey`](./ecc_generate_key.md) or imported via
[`UnwrapKey`](./unwrap_key.md)). Hosts that hold only the masked blob use
it to rebuild the public half of a key pair.

The device unmasks the key **in place** in the request buffer (which
verifies the AEAD tag under the blob's scope), derives the public key, and
returns it in the same wire format as `UnwrapKey`'s `pub_key`. No key usage
attribute is required. The recovered plaintext key is scrubbed from the
request buffer during IO teardown. The command persists nothing.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 12 | `masked_key` | `buffer` (≤ 3168 B) | The masked private key; unmasked in place. |

### Data section

Carries the masked key.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pub_key` | `buffer` (≤ 520 B) | RSA: `n_le ‖ e_le` (modulus bytes + 4). ECC: `x ‖ y`, each little-endian and padded to the curve wire coordinate length. |

### Data section

Carries the wire-format public key.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidKeyType` | The masked blob is not an RSA, RSA-CRT, or ECC private key |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked key is malformed or fails authentication (wrong scope / tampered) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Generate an ECC key: [`ecc_generate_key.md`](./ecc_generate_key.md)
- Import a key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/get_public_key.rs`
