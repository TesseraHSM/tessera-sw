<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# DarcTmkGen (Opcode 0x23)

**Handler:** `fw/core/lib/src/ddi/tbor/darc_tmk_gen.rs`
**Session:** InSession

## Description

Originates a fresh DARC **Transfer Masking Key (TMK)** — a random
256-bit symmetric secret — and returns it **masked** under the partition
**security-domain masking key (SDMK)** so the caller can persist and
later re-import it.

It is the **source-side counterpart** of
[`DarcTmkImport`](darc_tmk_import.md): where import recovers a TMK that
was HPKE-sealed off-device and re-masks it, this command *mints* the TMK
locally. Both mask through the same helper, so the emitted 164-byte
envelope is byte-identical — a created TMK and an imported TMK are
interchangeable in later commands (e.g. `DarcTmkExport`).

Handler flow:

1. Decode; gate to a Crypto-Officer, `Active` session on an
   `Initialized` partition whose security domain is initialized (the SDMK
   the output is masked under is provisioned by SD setup).
2. Draw a fresh 32-byte TMK from the RNG.
3. Mask the TMK (AEAD-GCM-256) under the SDMK and return the masked
   envelope. The raw TMK is zeroized on every exit path.

The TMK is always security-domain-scoped, so the request carries no scope
selector. The command **persists nothing** (no vault write, no lifecycle
advance), so it records no rollback on the undo log. The masked output's
metadata records the TMK as `derive`-only, `local`, `private`, and
never-extractable, under the distinct `DarcTmk` key kind, scoped
`SecurityDomain`.

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, followed by the TOC entry, then the (empty)
data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |

### Data section

_Empty — the session id is carried inline within its TOC entry._

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section carrying the masked TMK.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_tmk` | `buffer` (164 B) | The minted TMK, masked (AEAD-GCM-256) under the SDMK: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`. Recorded under the `DarcTmk` key kind. Byte-identical envelope to `DarcTmkImport`'s output. |

### Data section

Carries the 164-byte `masked_tmk`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized`, or the security domain is not initialized |
| `UnsupportedKeyScope` | The security-domain masking key (SDMK) is not provisioned yet |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/darc_tmk_gen.rs`
- Companion command: [`DarcTmkImport`](darc_tmk_import.md)
