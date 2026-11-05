<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionReopenFinish (Opcode 0x31)

**Handler:** `fw/core/lib/src/ddi/tbor/session_reopen_finish.rs`
**Session:** InSession (session id carried; not subject to the default-PSK gate)

## Description

Phase 2 of the session **reopen** handshake started by
[`SessionReopenInit`](./session_reopen_init.md).  It shares its
implementation with [`SessionOpenFinish`](./session_open_finish.md):
the `mac_fin` and `seed_envelope` are built identically.  The
differences are:

- `seed_envelope` must carry the session's **original** 32-byte
  `seed` (the one sealed in its `SessionOpenFinish`), and
- the request additionally carries the session's most recent
  `bmk_session`.

Instead of generating a fresh `masking_key`, the HSM re-derives
`BK_SESSION` from `seed` and unmasks `bmk_session`, requiring the
`MaskingKey` kind, label `SESSION_BMK`, the current owner-seed id, and
an SVN no newer than the current one.  Keys masked under the session
before the reset therefore remain usable.  Transport keys
(`param_key`, MAC keys) are freshly derived from the new handshake.
On success the slot becomes `Active` under the same `session_id` and
a fresh `bmk_session` is returned; the host should keep it for any
later reopen.

## Request

| Field | Type | Description |
|---|---|---|
| `session_id` | `session_id` (inline) | Reopen-Pending slot. |
| `mac_fin` | `buffer` (48 B) | Phase-2 confirmation MAC (same as `SessionOpenFinish`). |
| `seed_envelope` | `buffer` (72 B) | The original `seed` sealed under the new `param_key`. |
| `bmk_session` | `buffer` (≤ 512 B) | The session's last `bmk_session`. |

## Response

| Field | Type | Description |
|---|---|---|
| `bmk_session` | `buffer` (≤ 512 B) | Refreshed wrapped masking-key blob. |

## Errors

| Error | Cause |
|---|---|
| `InvalidArg` | Malformed fields, or the Pending state was started by `SessionOpenInit` |
| `SessionNotPending` | Slot is not Pending |
| `SessionAuthFailure` | `mac_fin`, `seed_envelope`, or `bmk_session` failed authentication |

Any failure after the handshake kind check reverts the slot to
`NeedsRenegotiation`, so the host may retry from `SessionReopenInit`.
Conversely, `SessionOpenFinish` on a reopen-Pending slot fails with
`InvalidArg` and leaves the slot untouched.

## See also

- Wire schema: `fw/core/ddi/tbor/types/src/session_reopen_finish.rs`
- Phase 1: [`session_reopen_init.md`](./session_reopen_init.md)
