<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# RsaEncryptDecrypt (Opcode 0x34)

**Handler:** `fw/core/lib/src/ddi/tbor/rsa_encrypt_decrypt.rs`  
**Session:** InSession

## Description

Encrypts or decrypts a single RSA block using an authenticated, caller-held
masked RSA private key. The key is imported with `UnwrapKey`; encryption
authenticates and unmasks the private key on-device, then extracts its public
modulus and exponent on-device. Decryption uses the authenticated private key
directly. The command accepts RSA-2048, RSA-3072, and RSA-4096 keys, both CRT
and non-CRT.

This command is distinct from raw [`RsaModExp`](./rsa_mod_exp.md). Padding is
mandatory, and only RSAES-OAEP and RSAES-PKCS1-v1_5 encryption are supported.
There is no raw mode, RSA signature operation, PSS, public-key input, chunking,
or OOB transfer. This command does not add a public SDK or native FFI API.

It is available to active Crypto-Officer and Crypto-User sessions. The default
PSK rotation gate, session-id cross-check, masked-key authentication, ownership,
scope, and platform binding apply as for other in-session masked-key commands.
The key must have the exact `encrypt` permission for encryption or `decrypt`
permission for decryption; signing-only keys are not accepted. The key is not
persisted or mutated.

OAEP uses the selected hash for both OAEP and MGF1. SHA-256, SHA-384, or
SHA-512 is required. The label is an opaque byte string up to 256 bytes.
PKCS#1 v1.5 requires an absent hash and an empty label. Unsupported, missing,
or inapplicable selectors are rejected; there are no defaults.

## Request

The request uses inline buffers:

| Field | Type | Constraints |
|---|---|---|
| `session_id` | `SessionId` | Active CO or CU session; cross-checked against the SQE |
| `op` | `u8` | `1` = Encrypt, `2` = Decrypt |
| `padding` | `u8` | `1` = OAEP, `2` = PKCS#1 v1.5 |
| `hash_algo` | optional `u8` | OAEP only: `1` = SHA-256, `2` = SHA-384, `3` = SHA-512 |
| `label` | buffer | 0..=256 bytes; must be empty for PKCS#1 v1.5 |
| `input` | aligned buffer | Plaintext or one ciphertext block, at most 512 bytes |
| `masked_key` | aligned mutable buffer | Existing RSA masked-envelope bounds, 264..=3168 bytes |

The maximum encoded request, including framing, TOC, alignment, and the
optional-hash representation, fits in the existing 4096-byte transport frame.
No frame-size increase or OOB buffer is required.

## Lengths

Encryption accepts plaintext from empty through the applicable maximum.
Ciphertext is exactly one modulus wide. Decryption rejects ciphertext shorter
or longer than the modulus; it does not left-pad or split input.

| Key size | Ciphertext | PKCS#1 v1.5 plaintext max | OAEP/SHA-256 | OAEP/SHA-384 | OAEP/SHA-512 |
|---:|---:|---:|---:|---:|---:|
| RSA-2048 | 256 B | 245 B | 190 B | 158 B | 126 B |
| RSA-3072 | 384 B | 373 B | 318 B | 286 B | 254 B |
| RSA-4096 | 512 B | 501 B | 446 B | 414 B | 382 B |

The response contains a modulus-sized ciphertext after encryption. Successful
decryption returns exactly the recovered plaintext bytes, including a valid
zero-length plaintext; unused output scratch is not included.

## Byte order

Ciphertext uses device operand order: little-endian on Uno/std Uno and
big-endian on std Duo. Plaintext and OAEP labels are opaque byte strings,
preserved exactly and never reversed. Framing integers remain little-endian.
Masked key blobs are authenticated and platform/session/scope-bound; do not
assume a blob is portable across platforms.

## Errors and decryption limits

Invalid selectors, inconsistent hash/label parameters, oversized plaintext,
and ciphertext lengths other than one modulus block return `InvalidArg`.
Wrong key classes return `InvalidKeyType`, missing direction permissions return
`InvalidPermissions`, and authentication, session, and scope failures retain
their established error results. Invalid ciphertext representatives, padding,
or OAEP labels return the single cryptographic failure `RsaDecryptFailed`.
Operational, allocation, hardware, and malformed-key errors are not broadly
converted to padding failures. No partial plaintext is returned on failure.

OAEP is the preferred decryption mode. PKCS#1 v1.5 decryption has explicit
padding failure and therefore retains padding-oracle considerations even
though failures use one status and require an authenticated active session.
Do not treat this interface as eliminating those risks. Padding checks are
backend implementations and this contract makes no constant-time claim.

## See also

- Import a masked RSA key: [`UnwrapKey`](./unwrap_key.md)
- Raw RSA primitive: [`RsaModExp`](./rsa_mod_exp.md)
- Wire schema: `fw/core/ddi/tbor/types/src/rsa_encrypt_decrypt.rs`
