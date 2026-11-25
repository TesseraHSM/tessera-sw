<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionClose (Opcode 0x05)

**Handler:** `fw/core/lib/src/ddi/tbor/session_close.rs`
**Session:** InSession

## Description

Tears down an Active or Pending session slot, releasing the slot's
session vault blob and any session-scoped keys.  Slot 0 (the Crypto
Officer slot) may be closed and later reopened via a fresh
`SessionOpenInit` with `psk_id = 0`.

Active and Pending TBOR sessions require protected close. An explicit plaintext
close is allowed only for `NeedsRenegotiation`, without reopening merely to
discard it. Uno uses `NoSession` control with a valid SQE session ID; Duo uses
the plaintext TBOR channel. Both still check supported header revision and
SQE/body ID agreement, but do not consult missing negotiated-revision or
transport-key material. State is rechecked under the lifecycle lock, so a stale
plaintext close cannot tear down a newly Active session in a reused slot.
Destruction remains deferred until successful completion. MBOR is unchanged.

## Request

Wire layout: 12-byte header, followed by the TOC entry, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 12 | `session_id` | `session_id` (inline) | Slot to destroy. |

### Data section

_Empty — `session_id` is carried inline within its TOC entry._

## Response

(empty body)

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `InvalidPermissions` | Plaintext close targets an Active or Pending slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/session_close.rs`
- Session lifecycle: [`session_open_init.md`](./session_open_init.md),
  [`session_open_finish.md`](./session_open_finish.md)
