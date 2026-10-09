<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# MlKemDecapsulate (Opcode 0x2B) — schema-only

**Handler:** _Not implemented yet (wire schema only)_
**Session:** InSession

## Description

Decapsulates an ML-KEM ciphertext using a caller-held **masked**
decapsulation key from [`MlKemGenerateKey`](./mlkem_generate_key.md) and
returns the shared secret as a **masked** blob under the requested scope's
masking key.  This is the TBOR unmask-on-use analogue of the MBOR
operation.

There is intentionally no `key_kind` request field. The masked blob is
self-describing: its authenticated key kind tells firmware which ML-KEM
parameter set the seed belongs to.

This snapshot defines only the wire schema; no firmware handler or PQC
implementation is registered.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the returned shared secret. |
| — | `masked_key` | `buffer` (196 B) | The masked ML-KEM `(d ‖ z)` seed material; unmasked on-device by the future handler.  Seed-only wire: 64-byte seed + 132 B envelope. |
| — | `ciphertext` | `buffer` (up to 1568 B) | ML-KEM ciphertext bytes. |

### Data section

Carries the masked decapsulation key followed by the ciphertext.

Worst-case frame: data `196 + 1568 = 1764` B; staged `132 + 1764 = 1896`
B and encoded `4 + 4*4 + 1764 = 1784` B — both well inside the 8192-byte
transport buffer.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_shared_secret` | `buffer` (164 B) | The 32-byte shared secret, masked under the requested scope's masking key. |

### Data section

Carries the masked shared secret.  The masked shared-secret length is
`32 + 132 = 164` bytes.

## Errors

Handler errors are not defined yet because this command is schema-only.
The parameter set is recovered from the masked key's authenticated key
kind, so it is not carried on the wire.

## See also

- Generate a decapsulation key: [`mlkem_generate_key.md`](./mlkem_generate_key.md)
- Encapsulate to a public key: [`mlkem_encapsulate.md`](./mlkem_encapsulate.md)
- Wire schema: `fw/core/ddi/tbor/types/src/mlkem_decapsulate.rs`
