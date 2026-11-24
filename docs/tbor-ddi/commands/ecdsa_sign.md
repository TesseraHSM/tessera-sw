<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EcdsaSign (Opcode 0x37)

**Handler:** `fw/core/lib/src/ddi/tbor/ecdsa_sign.rs`  
**Session:** InSession

## Description

Signs a raw message using an authenticated, caller-held masked ECC private
key. Unlike [`EccSign`](./ecc_sign.md), which accepts a pre-computed digest,
`EcdsaSign` hashes the message internally. It supports P-256, P-384, and
P-521 with SHA-256, SHA-384, or SHA-512 in every curve/hash combination.

The key's authenticated metadata selects the curve. The key must have the
`sign` usage attribute. Session- and application-scoped masked keys are
accepted when valid for the active session. The device generates the ECDSA
nonce internally; the request has no nonce field or nonce mode.

## Request

| Field | Type | Description |
|---|---|---|
| `session_id` | `u16` | Active session bound to the request and its SQE. |
| `masked_key` | aligned bytes, 264..=312 B | Authenticated masked ECC private-key envelope. The curve is recovered from its authenticated key kind. |
| `hash_algo` | `u8` | Required selector: SHA-256, SHA-384, or SHA-512. Other selectors are rejected. |
| `message_index` | `u8` | Index of the message's input OOB SGL descriptor. Must be zero for an empty message. |
| `message_len` | `u16` | Raw message length, 0..=8192 bytes inclusive. |

For nonempty input, the host OOB descriptor page supplies the root SGL
descriptor at `message_index`. A Data Block descriptor length must equal
`message_len`. On Uno, a Segment or Last Segment descriptor length describes
the list itself; GDMA gathers exactly `message_len` payload bytes. Uno submits
the captured root unchanged to GDMA and uses scoped DMA scratch sized to the
message. std Uno and std Duo stream Data Blocks in 1024-byte chunks.

Empty input requires `message_index = 0`; the device hashes the empty byte
string without reading a descriptor. The host must keep the OOB buffers
accessible and unchanged until the command completes. Capturing the root
does not make the message bytes an atomic snapshot. OOB data does not gain
confidentiality or integrity from session sealing.

## Response

| Field | Type | Description |
|---|---|---|
| `signature` | bytes, at most 144 B | Raw `r ‖ s`; each component begins at its lane start in device operand order, with zero padding after the value. P-256/P-384 use 32/48-byte lanes; P-521 uses 68-byte lanes on Uno/std Uno and 72-byte lanes on std Duo. No DER wrapper is used. |

The returned signature has exactly two component lanes for the recovered
curve. The unused bytes at the end of P-521 lanes are zero.

## Errors

Malformed fields, unsupported hashes, oversized messages, or invalid
empty-message indices are rejected as argument/decode errors. Invalid
descriptors, descriptor length mismatches, hashing failures, and crypto
failures return their corresponding operational errors. Session,
masked-key authentication, key-kind, and permission failures preserve
their specific statuses. No signature is returned after a failure.

## See also

- [`EccSign`](./ecc_sign.md) — signs a caller-supplied pre-computed digest.
- [`EcdsaVerify`](./ecdsa_verify.md) — verifies a raw OOB message.
- Wire schema: `fw/core/ddi/tbor/types/src/ecdsa_sign.rs`
