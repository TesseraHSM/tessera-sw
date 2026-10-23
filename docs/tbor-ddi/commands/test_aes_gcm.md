<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# TestAesGcm (Opcode 0xF0, test-only)

**Handler:** `fw/core/lib/src/ddi/tbor/test_aes_gcm.rs`
**Session:** NoSession
**Feature:** `tbor-test-cmds` (firmware); never ship in a production image

## Description

AES-256-GCM encrypts or decrypts host-supplied `data` under a **raw**
32-byte key carried in the request, through the platform's GCM on the
regular HSM command path (the PAL `HsmAes::gcm_encrypt_in_place` /
`gcm_decrypt_in_place` methods, the same path firmware key masking takes).
On Uno that is the CP1 AES engine with software GHASH; the std platform
uses its software AES. It exists to validate and measure the platform GCM
end to end, without key provisioning or a session. Nothing is persisted.

The command is an encryption oracle under host-chosen keys, so the
firmware dispatches it only when built with the `tbor-test-cmds` cargo
feature. Without the feature the opcode is unknown and falls through to
the platform dispatch hook (`UnsupportedCmd`).

The IV is 96 bits. `aad` (up to 256 bytes) and `data` (up to 2048 bytes)
may each be empty and need not be block-aligned.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `op` | `uint8` (inline) | Direction (`AesOp` discriminant): `1` = Encrypt, `2` = Decrypt. |
| 8 | `key` | `buffer` (32 B) | The raw AES-256 key. |
| 12 | `iv` | `buffer` (12 B) | The 96-bit GCM IV. |
| 16 | `aad` | `buffer` (≤ 256 B) | Additional authenticated data (may be empty). |
| 20 | `data` | `buffer` (≤ 2048 B) | Plaintext (encrypt) or ciphertext (decrypt); may be empty. |
| 24 | `tag` | `buffer` (16 B) | The expected tag (decrypt); ignored on encrypt. |

### Data section

Carries the key, IV, AAD, data and tag.

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `data` | `buffer` (≤ 2048 B) | The transformed text (same length as the request `data`). |
| 12 | `tag` | `buffer` (16 B) | The computed tag (encrypt) or the verified tag (decrypt). |

### Data section

Carries the transformed text followed by the 16-byte tag.

## Errors

| Error | Cause |
|---|---|
| `InvalidArg` | Unknown `op` |
| `AesGcmDecryptTagDoesNotMatch` | Decrypt: the tag failed to verify (wrong key, IV, AAD, ciphertext or tag) |
| `UnsupportedCmd` | Firmware built without `tbor-test-cmds` |
| `DdiDecodeFailed` | Malformed request body (wrong fixed length, or `aad` / `data` over the maximum) |

Platform engines may also return their own errors (on Uno, BCP driver
errors such as a failed engine command).

On Uno the BCP processes only whole blocks: the padded AAD and the
16-byte-aligned part of `data`. The PAL encrypts a final partial block and
corrects the tag in software, so any `aad` and `data` length is accepted.

## See also

- [`AesEncryptDecrypt`](./aes_encrypt_decrypt.md) — AES-CBC under a masked key
