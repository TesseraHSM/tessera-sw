<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemDecapsulate (Opcode 0x2B)

**Handler:** `fw/core/lib/src/ddi/tbor/mlkem_decapsulate.rs`
**Session:** InSession

## Description

Decapsulates an ML-KEM ciphertext using a caller-held **masked**
decapsulation key from [`MlKemGenerateKey`](./mlkem_generate_key.md) and
returns the shared secret as a **masked** blob under the requested scope's
masking key.  This is the TBOR unmask-on-use analogue of the MBOR
operation.

There is intentionally no `key_kind` request field. The masked blob is
self-describing: its authenticated key kind tells firmware which ML-KEM
parameter set the key belongs to.

An active session is required. Firmware resolves the input key's masking
scope from its authenticated metadata and the output masking scope from
the request. The unmasked payload contains the seed pair followed by the
expanded decapsulation key; decapsulation uses the expanded key directly.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 16 | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the returned shared secret. |
| 20 | (padding) | `padding` (0..=3 B) | Places `masked_key` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 24 | `masked_key` | `buffer` (up to 3464 B) | The complete masked seed-pair and expanded-key blob returned by `MlKemGenerateKey`; unmasked on-device. |
| 28 | `ciphertext` | `buffer` (up to 1568 B) | ML-KEM ciphertext bytes. |

### Data section

Carries the masked decapsulation key followed by the ciphertext.

The largest request carries `3464 + 1568 = 5032` data bytes and fits
inside the 8192-byte transport buffer with its header, TOC, and padding.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | (padding) | `padding` (0..=3 B) | Places `masked_shared_secret` on a 4-byte boundary from the start of the message. See [Alignment padding](../README.md#alignment-padding). |
| 16 | `masked_shared_secret` | `buffer` (264 B) | The 32-byte shared secret, masked under the requested scope's masking key. |

### Data section

Carries the masked shared secret.  The masked shared-secret length is
`32 + 232 = 264` bytes.

## Errors

An unknown or inactive session, unavailable masking scope, malformed or
unauthentic masked key, unsupported key kind, missing derive permission,
incorrect key/ciphertext length, or malformed request is rejected.

For a valid key and correctly sized ciphertext, ML-KEM uses implicit
rejection: an invalid ciphertext produces a derived rejection secret,
not a signature-style verification error. Backend and output-masking
failures are still reported.

## See also

- Generate a decapsulation key: [`mlkem_generate_key.md`](./mlkem_generate_key.md)
- Encapsulate to a public key: [`mlkem_encapsulate.md`](./mlkem_encapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_decapsulate.rs`
