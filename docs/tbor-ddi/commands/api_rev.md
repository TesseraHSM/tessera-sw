<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# ApiRev (Opcode 0x01)

**Handler:** `fw/core/lib/src/ddi/tbor/api_rev.rs`
**Session:** NoSession

## Description

Returns the inclusive range of SDK API revisions (`major.minor`) the
device supports.  The host uses it to select the API revision for the
session it opens next.

The range is a per-platform constant supplied by the firmware PAL
(`HsmPal::API_REV_MIN` / `HsmPal::API_REV_MAX`):

| Platform | Minimum | Maximum |
|---|---|---|
| Uno | 1.0 | 1.1 |
| Duo | 2.0 | 2.0 |

## Request

(empty body)

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `min_major` | `uint16` (inline) | Major number of the lowest supported API revision. |
| 12 | `min_minor` | `uint16` (inline) | Minor number of the lowest supported API revision. |
| 16 | `max_major` | `uint16` (inline) | Major number of the highest supported API revision. |
| 20 | `max_minor` | `uint16` (inline) | Minor number of the highest supported API revision. |

### Data section

_Empty — all fields are carried inline within their TOC entries._

## Errors

| Error | Cause |
|---|---|
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/api_rev.rs`
