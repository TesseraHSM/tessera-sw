<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcKeyUnwrap (Opcode 0x22)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_key_unwrap.rs`
**Session:** InSession

## Description

Imports an externally-generated **EC private key** and returns it re-masked
under a caller-chosen partition scope.  The key is delivered:

1. encoded as an **EC2 `COSE_Key`** (private form: `kty`, `kid`, `alg`, a
   non-empty `key_ops`, `crv`, and the big-endian `x`/`y`/`d` field
   elements — see the COSE Key Definition Format profile);
2. **AES-KWP** (RFC 5649) wrapped under a DARC **Transfer Masking Key
   (TMK)**;
3. where the TMK is supplied as the masked envelope produced by
   [`DarcTmkImport`](darc_tmk_import.md).

Only EC private keys on **P-256 / P-384 / P-521** are supported.

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition whose security domain is initialized (the TMK is masked under
   the SDMK, and the output masking keys are provisioned by partition
   setup).  The requested output `scope` is restricted to `Ephemeral` /
   `Local`.
2. Route `masked_tmk` to its masking key via its cleartext metadata,
   unmask it (its masked-key kind must be `DarcTmk`), and recover the
   32-byte TMK.
3. AES-KWP-unwrap `wrapped_key` with the TMK → the `COSE_Key` plaintext.
4. Decode the EC2 private `COSE_Key`, rejecting the deprecated polymorphic
   ECDSA `alg` identifiers and any out-of-profile encoding.
5. Convert `d` to the vault representation, re-derive the public key, and
   enforce the COSE private/public consistency (`d·G == (x, y)`).
6. Intersect the requested `key_usage` with the COSE `key_ops`
   (`sign`/`verify` → the signing-key group; `derive` → the ECDH group;
   exactly one group must remain, else `InvalidPermissions`), mask the
   recovered private key (AEAD-GCM-256) under the requested scope's masking
   key, and return the masked key plus its wire public key.

The command **persists nothing** (no vault write, no lifecycle advance),
so it records no rollback on the undo log.  The recovered TMK, the
`COSE_Key` plaintext, and the vault scalar are zeroized on every exit
path.

This command is **Crypto-Officer-only**: a Crypto-User session is rejected
with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, the TOC entries, then the data section
carrying the fixed-length `masked_tmk` and the variable-length
`wrapped_key`.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (`KeyScope`) | Output scope masking the recovered key. Restricted to `Ephemeral` (`0b010`) / `Local` (`0b011`). |
| — | `key_usage` | `u64` (`KeyUsage` bitfield) | Requested key-usage permissions; intersected on-device with the `COSE_Key`'s `key_ops`. |
| — | `masked_tmk` | `buffer` (164 B) | The masked TMK envelope from `DarcTmkImport`. Must be a `DarcTmk`-kind masked key. |
| — | `wrapped_key` | `buffer` (≤ 512 B) | The AES-KWP-wrapped EC2 `COSE_Key`. |

### Data section

Carries the 164-byte `masked_tmk` followed by the variable-length
`wrapped_key`.

## Response

Wire layout: 8-byte header, the TOC entries, then the data section
carrying the masked key and the public key.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `key_kind` | `u8` | The recovered key's vault-kind discriminant (`Ecc{256,384,521}Private`). |
| — | `masked_key` | `buffer` (≤ 200 B) | The recovered EC private key, masked (AEAD-GCM-256) under the scope's masking key: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(vault scalar) ‖ tag(16)`. |
| — | `pub_key` | `buffer` (≤ 136 B) | The recovered key's wire public key (`x ‖ y`, wire little-endian, P-521 padded). |

### Data section

Carries the variable-length `masked_key` and `pub_key`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User, or the requested `key_usage` intersected with the COSE `key_ops` is empty/ambiguous |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, the security domain is not initialized, the `COSE_Key` is malformed/out-of-profile, or its public point does not match `d` |
| `UnsupportedKeyScope` | The requested output scope is not `Ephemeral`/`Local`, or its masking key is not provisioned yet |
| `UnsupportedKeyType` | `masked_tmk` is not a `DarcTmk` masked key |
| `AesUnwrapFailed` | AES-KWP unwrap of `wrapped_key` failed the AIV / padding check |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_key_unwrap.rs`
- COSE codec: `fw/core/crypto/cose-key/src/ec2.rs`
- Companion command: [`DarcTmkImport`](darc_tmk_import.md)
- Template command: [`UnwrapKey`](unwrap_key.md)
