<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# RsaModExp (Opcode 0x1A)

**Handler:** `fw/core/lib/src/ddi/tbor/rsa_mod_exp.rs`
**Session:** InSession

## Description

Performs one raw RSA modular exponentiation using a caller-held **masked
RSA private key** imported with `UnwrapKey` as RSA or RSA-CRT. This command
does not accept a raw public key. The device authenticates and unmasks the
private-key envelope, checks the selected usage, and for public operations
derives the actual `n || e` from that private key using the PAL.

| `op_type` | Operation | Primitive | Required key usage |
|---:|---|---|---|
| 1 | Decrypt | `x = y^d mod n` | `decrypt` |
| 2 | Sign | `x = y^d mod n` | `sign` |
| 3 | Encrypt | `x = y^e mod n` | `encrypt` |
| 4 | Verify | `x = y^e mod n` | `verify` |

Encrypt returns a raw RSA result, not a padded OAEP/PKCS#1 encryption service.
Verify returns the recovered encoded block; it does not validate PSS or
PKCS#1 padding, compare a digest, or return a signature-valid boolean. The
host is responsible for adding/removing encryption padding and validating
signature blocks.

All operands are exactly the RSA modulus length (256, 384, or 512 bytes) and
are in **device byte order**: little-endian on Uno/std Uno and big-endian on
std Duo. Public operations accept `0 <= y < n`; private Decrypt/Sign preserve
the existing `1 < y < n - 1` restriction.

Available to both Crypto-Officer and Crypto-User sessions. Existing session
gating, default-PSK rotation requirements, SQE/body session cross-checking,
and secure-session transport are unchanged. The unmasked private-key bytes
remain in the request buffer and are scrubbed by IO teardown.

## Request

The request has five TOC entries. Offsets below identify the TOC entries,
not the variable data they describe.

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `y` | `buffer` (256 / 384 / 512 B) | The input integer `y` in device byte order, exactly the key's modulus length. |
| 20 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 24 | `masked_key` | `buffer` (264..=3168 B) | The masked RSA private key; unmasked in place. Its kind recovers the modulus size and CRT form. |
| 28 | `op_type` | `u8` (inline) | Selector 1..=4 as specified above; other values are `InvalidArg`. |

### Data section and canonical placement

The data section begins at byte offset 32. `y` starts at offset 32, and
`masked_key` begins immediately after `y`, rounded up to a 4-byte boundary.
Since valid modulus lengths are multiples of four, there is no intervening
padding for a valid request. The `op_type` and session id are inline in their
TOC entries and do not occupy data-section bytes. Firmware rejects a request
whose `y` does not start at offset 32.

## Response

The response has five TOC entries: `x` refers to the request's `y` storage,
and the remaining paired TOC slots are `None`. The result replaces `y` at
data offset 32 and has exactly the modulus length:

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `x` | `buffer` (256 / 384 / 512 B) | The result in device byte order: `y^d mod n` for Decrypt/Sign or `y^e mod n` for Encrypt/Verify. |

### Data section

Carries the result integer at offset 32, replacing the request's `y`. The remaining
four paired TOC slots are `None`, and the unused allocation tail, including the
unmasked key, is scrubbed during IO teardown.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | The session id does not refer to an active session. |
| `InvalidArg` | Unknown selector; wrong operand length; public `y >= n`; or the PAL rejects a private representative outside `1 < y < n - 1`. |
| `InvalidKeyType` | The authenticated masked blob is not an RSA private key. |
| `InvalidPermissions` | The key lacks the exact usage required by the selector. |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The envelope is malformed, tampered, or authenticated under a different key/session. |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler). |
| `TborNonCanonicalLayout` | `y` does not start the data section. |
| `InternalError` | A PAL reports success but writes/returns a non-modulus-sized result. |
| `DdiDecodeFailed` | The request body is malformed. |

## See also

- Import an RSA key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/rsa_mod_exp.rs`
