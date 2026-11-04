<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcKeyWrap (Opcode 0x25)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_key_wrap.rs`
**Session:** InSession

## Description

Exports a **local EC private key** by AES-KWP wrapping it under a DARC
**Transfer Masking Key (TMK)**, producing a `wrapped_key` byte-for-byte
compatible with what [`DarcKeyUnwrap`](darc_key_unwrap.md) consumes. It is
the source-side mirror of `DarcKeyUnwrap`.

The exported key is:

1. encoded as an **EC2 `COSE_Key`** (private form: `kty`, `kid`, `alg`, a
   non-empty `key_ops`, `crv`, and the big-endian `x`/`y`/`d` field
   elements — see the COSE Key Definition Format profile);
2. **AES-KWP** (RFC 5649) wrapped under the DARC TMK;
3. where the TMK is supplied as the masked envelope produced by
   [`DarcTmkGen`](darc_tmk_gen.md) / [`DarcTmkImport`](darc_tmk_import.md).

Only EC private keys on **P-256 / P-384 / P-521** are supported.

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the TMK is masked under
   the SDMK).
2. Route `masked_tmk` to its masking key via its cleartext metadata,
   unmask it (its masked-key kind must be `DarcTmk`), and recover the
   32-byte TMK.
3. Route `masked_key` to its masking key, unmask it (its masked-key kind
   must be one of `Ecc{256,384,521}Private`), and recover the vault
   scalar.
4. Convert the vault scalar to the big-endian COSE `d`, re-derive the
   public key `(x, y)`, and encode the EC2 private `COSE_Key`: its
   `key_ops` derived from the key's own vault attributes, its `alg` from
   the curve (P-256 → ESP256 (-9), P-384 → ESP384 (-51), P-521 → ESP512
   (-52)), and its `kid` set to the key's masked-key label.
5. AES-KWP-wrap the `COSE_Key` plaintext with the TMK → `wrapped_key`.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log. The recovered TMK, the vault
scalar, the big-endian `d`, and the `COSE_Key` plaintext are scrubbed
during IO teardown.

This command is **Crypto-Officer-only**: a Crypto-User session is rejected
with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, the TOC entries, then the data section
carrying the fixed-length `masked_tmk` and the variable-length
`masked_key`.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `masked_tmk` | `buffer` (164 B) | The masked TMK envelope from `DarcTmkGen`/`DarcTmkImport`. Must be a `DarcTmk`-kind masked key. |
| — | `masked_key` | `buffer` (≤ 200 B) | The local masked EC private key to export. Must be an `Ecc{256,384,521}Private`-kind masked key. |

### Data section

Carries the 164-byte `masked_tmk` followed by the variable-length
`masked_key`.

## Response

Wire layout: 8-byte header, the TOC entries, then the data section
carrying the wrapped key.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `wrapped_key` | `buffer` (≤ 512 B) | The AES-KWP-wrapped EC2 `COSE_Key`. Byte-for-byte what `DarcKeyUnwrap` consumes. |

### Data section

Carries the variable-length `wrapped_key`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, or the security domain is not initialized |
| `UnsupportedKeyType` | `masked_tmk` is not a `DarcTmk` masked key, or `masked_key` is not an `Ecc{256,384,521}Private` masked key |
| `AesEncryptFailed` | AES-KWP wrap of the `COSE_Key` plaintext failed |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_key_wrap.rs`
- COSE codec: `fw/core/crypto/cose-key/src/ec2.rs`
- Companion command: [`DarcKeyUnwrap`](darc_key_unwrap.md)
- TMK source: [`DarcTmkGen`](darc_tmk_gen.md), [`DarcTmkImport`](darc_tmk_import.md)
