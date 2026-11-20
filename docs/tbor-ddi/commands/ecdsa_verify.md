<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EcdsaVerify (Opcode 0x38)

**Handler:** `fw/core/lib/src/ddi/tbor/ecdsa_verify.rs`  
**Session:** InSession

## Description

Verifies a raw message using an authenticated, caller-held masked ECC
private key. The device derives the public point from that key on-device;
the request cannot supply or override public coordinates. Unlike
[`EccVerify`](./ecc_verify.md), which accepts a pre-computed digest,
`EcdsaVerify` hashes the OOB message internally. It supports P-256, P-384,
and P-521 with SHA-256, SHA-384, or SHA-512 in every curve/hash combination.

The authenticated key metadata selects the curve. The key must have either
the `sign` or `verify` usage attribute; derive-only keys are not accepted.
Session- and application-scoped masked keys are accepted when valid for
the active session.

## Request

| Field | Type | Description |
|---|---|---|
| `session_id` | `u16` | Active session bound to the request and its SQE. |
| `masked_key` | aligned bytes, 264..=312 B | Authenticated masked ECC private-key envelope. The curve is recovered from its authenticated key kind. |
| `hash_algo` | `u8` | Required selector: SHA-256, SHA-384, or SHA-512. Other selectors are rejected. |
| `message_index` | `u8` | Index of the message's input OOB SGL descriptor. Must be zero for an empty message. |
| `message_len` | `u16` | Raw message length, 0..=8192 bytes inclusive. |
| `signature` | bytes, at most 144 B | Raw padded `r ‖ s`, in device operand order and with the exact curve-specific length. |

OOB descriptor handling and host buffer lifetime requirements are the same
as for [`EcdsaSign`](./ecdsa_sign.md#request). Empty input requires
`message_index = 0`; the device hashes the empty byte string without reading
a descriptor.

Each signature component begins at the start of its own lane, followed by
zero padding. P-256/P-384 use 32/48-byte lanes; P-521 uses 68-byte lanes
on Uno/std Uno and 72-byte lanes on std Duo. The signature must have
exactly two lanes and all padding bytes must be zero. DER signatures,
truncated components, and signatures encoded with a different lane size
are rejected.

## Response

Success has no body fields. A well-formed signature that does not verify
returns `EccVerifyFailed`; malformed signature shape or padding returns an
argument error.

## Errors

Unsupported hashes, oversized messages, invalid empty-message indices,
wrong signature lengths, and nonzero lane padding are rejected as
argument/decode errors. Invalid descriptors, descriptor length
mismatches, hashing failures, and crypto failures return their
corresponding operational errors. Session, masked-key authentication,
key-kind, and permission failures preserve their specific statuses.

## See also

- [`EccVerify`](./ecc_verify.md) — verifies a caller-supplied pre-computed digest.
- [`EcdsaSign`](./ecdsa_sign.md) — signs a raw OOB message.
- Wire schema: `fw/core/ddi/tbor/types/src/ecdsa_verify.rs`
