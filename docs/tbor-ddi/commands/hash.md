<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Hash (Opcode 0x1B)

**Handler:** `fw/core/lib/src/ddi/tbor/hash.rs`
**Session:** InSession

## Description

Computes a cryptographic hash (SHA-1 / 256 / 384 / 512), or SHAKE128 /
SHAKE256 output of a requested length, of a host-supplied message and
returns it.  A pure hashing utility — it carries no key, no scope, and
touches no partition state.  This is the TBOR analogue of MBOR `ShaDigest`.

SHA-1 is available for legacy compatibility, not collision-resistant uses
such as digital signatures. Firmware without SHA-1 support rejects selector
`0` with `InvalidArg`.

The SHAKE extendable-output functions (FIPS 202) produce `out_len` bytes,
which the request must carry; the fixed-length digests must omit it.
Selectors `4`–`6` are reserved for SHA3-256 / 384 / 512.

The handler consumes the message into a streaming hash context before
reclaiming the same allocation for a compact response. Finalization writes
the digest into its final response slot, without an encoded-response
allocation or payload copy-back. The digest is emitted in natural
(big-endian) byte order.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `algo` | `u8` (inline) | Digest algorithm ([`HashAlgo`]): `0` = SHA-1, `1` = SHA-256, `2` = SHA-384, `3` = SHA-512, `7` = SHAKE128, `8` = SHAKE256. |
| — | `out_len` | `u16` (inline, optional) | SHAKE output length, 1 to 256 bytes; required for SHAKE, absent (`none`) for the fixed-length digests. |
| — | `msg` | `buffer` (≤ 2048 B) | The message to hash. |

### Data section

Carries the message bytes.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `digest` | `buffer` (≤ 256 B) | The natural (big-endian) digest, exactly the algorithm's length (20 / 32 / 48 / 64 B), or `out_len` bytes of SHAKE output. |

### Data section

Carries the digest or SHAKE output.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown `algo`; SHAKE without `out_len` or with `out_len` 0 or above 256; `out_len` with a fixed-length digest |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body (e.g. `msg` exceeds 2048 B) |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/hash.rs`
