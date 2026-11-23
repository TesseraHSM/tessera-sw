# Tabular Binary Object Representation (TBOR) Specification

## Version

0.6 (API-revision-defined framing; no separate encoding version)

## Table of Contents

- [Overview](#overview)
  - [Purpose](#purpose)
  - [Scope](#scope)
  - [Terminology](#terminology)
  - [Byte Ordering](#byte-ordering)
- [Request Format](#request-format)
  - [Header Fields](#header-fields)
  - [Field Details](#field-details)
- [Response Format](#response-format)
  - [Header Fields](#header-fields-1)
  - [Field Details](#field-details-1)
  - [Well-Known Status Codes](#well-known-status-codes)
- [TOC Entry Format](#toc-entry-format)
  - [Entry Types](#entry-types)
  - [Encoding: Inline None](#encoding-inline-none)
  - [Encoding: Inline 8-bit](#encoding-inline-8-bit)
  - [Encoding: Inline 16-bit](#encoding-inline-16-bit)
  - [Encoding: Offset/Length](#encoding-offsetlength)
  - [Data Alignment](#data-alignment)
- [Protocol Rules](#protocol-rules)
- [Schema Features](#schema-features)
  - [Optional Fields](#optional-fields)
  - [Alignment Padding](#alignment-padding)
  - [Typed Slices](#typed-slices)
  - [Fixed-Size Arrays](#fixed-size-arrays)
  - [Length Constraints](#length-constraints)
  - [Field Groups](#field-groups)
  - [Dispatch Traits](#dispatch-traits)
- [Security Considerations](#security-considerations)
- [Worked Examples](#worked-examples)
  - [Example 1 — Simple Request](#example-1--simple-request)
  - [Example 2 — Simple Response](#example-2--simple-response)
  - [Example 3 — Request with Optional Field](#example-3--request-with-optional-field)
- [Revision History](#revision-history)

---

## Overview

### Purpose

This document defines the binary request/response protocol used for communication between host software and device hardware. The protocol provides a compact, structured wire format that enables the host to issue commands (requests) to the device and receive structured results (responses). It is designed for low-overhead, deterministic communication in environments where bandwidth and latency are constrained.

### Scope

This specification covers:

- The wire format for request and response messages.
- The framing structure, including the fixed header and Table of Contents (TOC) mechanism.
- The encoding rules for TOC entries and the variable-length data section.
- The `none` entry type for representing absent optional fields.
- The `padding` entry type for aligning field data within the variable-length data section.
- Protocol-level rules for versioning, ordering, error handling, and timeouts.

This specification does **not** cover:

- The transport layer (e.g., SPI, I2C, USB, shared memory). The protocol is transport-agnostic and assumes a reliable, ordered byte-stream or message-based transport.
- The application-layer opcode catalog. Opcodes and their semantics are defined by the application layer built on top of this protocol.
- Session management beyond the `session_id` TOC entry type.

### Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### Byte Ordering

All multi-byte integer fields in the header and TOC structures are encoded in **little-endian** byte order. All reserved fields MUST be set to zero by senders and MUST be ignored by receivers.

> **Note:** Inline 16-bit values within TOC entries are an exception — see [Encoding: Inline 16-bit](#encoding-inline-16-bit) for details.

---

## Request Format

A request is sent by the host to the device to initiate an operation. It consists of a **fixed 12-byte header** followed by 1–32 [TOC entries](#toc-entry-format) and an optional variable-length data section. The TOC entries describe the parameters of the operation; each entry either inlines a small value directly or provides an offset and length into the variable-length data section that follows the TOC.

For each command, the request and successful response MUST reserve the same
number of TOC slots: the larger of their schema entry counts, with at least
one slot. Unused trailing slots MUST contain `none`. Thus both data sections
begin at `12 + 4 * toc_count`; replacing metadata does not relocate payloads.
Firmware validates reserved trailing slots. Generic error responses may use
one `none` entry because they carry no command payload.

The API revision defines both the encoding and command semantics, without a
separate encoding-version byte. An incompatible encoding change requires an API
revision change. Earlier development layouts are not supported.

**Message size bounds:**

| Component             | Minimum  | Maximum  |
|-----------------------|----------|----------|
| Header                | 12 bytes | 12 bytes |
| TOC entries (1–32)    | 4 bytes  | 128 bytes|
| Variable-length data  | 0 bytes  | 8191 bytes |
| **Total**             | **16 bytes** | **8331 bytes** |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           API Major           |           API Minor           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Rsv |TOC Count|     Opcode    |          Reserved (zero)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Reserved (zero)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 1                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 2                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 32                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Variable-Length Data ...                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Offset | Size    | Field       | Description                                      |
|--------|---------|-------------|--------------------------------------------------|
| 0      | 2 bytes | API Major   | Selected API major revision, little-endian. |
| 2      | 2 bytes | API Minor   | Selected API minor revision, little-endian. |
| 4      | 3 bits  | Reserved    | High three bits; MUST be zero. |
| 4      | 5 bits  | TOC Count   | Low five bits; count minus 1 (`0x00` = 1 entry, `0x1F` = 32 entries). |
| 5      | 1 byte  | Opcode      | Operation code identifying the request type. |
| 6      | 2 bytes | Reserved    | MUST be zero; ignored by receivers. |
| 8      | 4 bytes | Reserved    | MUST be zero; ignored by receivers. |

### Field Details

#### API Revision (Bytes 0–3)

Two unsigned 16-bit integers identify the API major and minor revision.
Firmware MUST reject unsupported revisions before executing the command.
The host retains its locally selected revision and MUST reject responses
whose header differs from the request, including error responses.

#### Reserved / TOC Count (Byte 4)

```
Bit layout of byte 4:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|  Rsvd (3) |   TOC Count (5)   |
+---+---+---+---+---+---+---+---+
```

- **Bits 7–5 (Reserved):** MUST be `0`. Reserved for future use.
- **Bits 4–0 (TOC Count):** Encoded as **count minus 1** (unsigned). A value of `0x00` means 1 TOC entry; `0x1F` means 32 TOC entries. Every request MUST contain at least one TOC entry. Each TOC entry describes a parameter or data section of the request payload. See [TOC Entry Format](#toc-entry-format) for the structure of individual entries.

#### Opcode (Byte 5)

Identifies the operation to be performed. Opcode values are defined by the
application layer; there is no special version-negotiation opcode.

---

## Response Format

A response is sent by the device back to the host after processing a request. Every request MUST produce exactly one response. The response consists of a **fixed 12-byte header** followed by 1–32 [TOC entries](#toc-entry-format) and an optional variable-length data section. The TOC entries describe the output data returned by the operation.

**Message size bounds:**

| Component             | Minimum   | Maximum   |
|-----------------------|-----------|-----------|
| Header                | 12 bytes  | 12 bytes  |
| TOC entries (1–32)    | 4 bytes   | 128 bytes |
| Variable-length data  | 0 bytes   | 8191 bytes |
| **Total**             | **16 bytes** | **8331 bytes** |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           API Major           |           API Minor           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Rsv |TOC Count|     Flags     |          Reserved (zero)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Status Code                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 1                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 2                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 32                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Variable-Length Data ...                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Offset | Size    | Field       | Description                                      |
|--------|---------|-------------|--------------------------------------------------|
| 0      | 2 bytes | API Major   | Little-endian; MUST match the request. |
| 2      | 2 bytes | API Minor   | Little-endian; MUST match the request. |
| 4      | 3 bits  | Reserved    | High three bits; MUST be zero. |
| 4      | 5 bits  | TOC Count   | Low five bits; number of TOC entries minus 1. |
| 5      | 1 byte  | Flags       | Bit flags (see [Flags](#flags-byte-5) below). |
| 6      | 2 bytes | Reserved    | MUST be zero; ignored by receivers. |
| 8      | 4 bytes | Status Code | Little-endian status; see [Well-Known Status Codes](#well-known-status-codes). |

### Field Details

#### API Revision (Bytes 0–3)

The response API major and minor MUST match the corresponding request, even
in error responses reporting an unsupported revision. The host checks these
values after authenticating and decrypting encrypted responses.

#### Flags (Byte 5)

```
Bit layout of byte 5:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|        Reserved (7)       | F |
+---+---+---+---+---+---+---+---+
```

| Bit | Name          | Description                                                  |
|-----|---------------|--------------------------------------------------------------|
| 0   | FIPS_APPROVED | Set to `1` if the operation was performed using only FIPS 140-2/140-3 approved cryptographic algorithms and modules. Set to `0` otherwise. This flag is informational and MUST NOT be used as the sole mechanism for enforcing compliance policy (see [Security Considerations](#security-considerations)). |
| 1–7 | Reserved      | MUST be `0`. Reserved for future use.                        |

#### Reserved (Bytes 6–7)

Reserved for future protocol extensions. Senders MUST set both bytes to zero.
Receivers MUST ignore their values.

#### Reserved / TOC Count (Byte 4)

```
Bit layout of byte 4:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|  Rsvd (3) |   TOC Count (5)   |
+---+---+---+---+---+---+---+---+
```

- **Bits 7–5 (Reserved):** MUST be `0`. Reserved for future use.
- **Bits 4–0 (TOC Count):** Encoded as **count minus 1** (unsigned). A value of `0x00` means 1 TOC entry; `0x1F` means 32 TOC entries. Every response MUST contain at least one TOC entry.

#### Status Code (Bytes 8–11)

A 4-byte little-endian unsigned integer indicating the result of the requested operation. A value of `0x00000000` indicates success. Non-zero values indicate an error or an informational condition. See [Well-Known Status Codes](#well-known-status-codes) for protocol-level codes; additional codes are defined by the application layer.

### Well-Known Status Codes

The following status codes are defined at the protocol level. Application-layer status codes SHOULD use values `0x00010000` and above to avoid collisions with future protocol-level codes.

| Code           | Name                 | Description                                                                 |
|----------------|----------------------|-----------------------------------------------------------------------------|
| `0x00000000`   | Success              | The operation completed successfully.                                        |
| `0x0870002A`   | Unsupported Revision | The selected API revision is unsupported or differs from the session's bound revision. |
| `0x00000002`   | Invalid Opcode       | The opcode is not recognized by the receiver.                                |
| `0x00000003`   | Malformed Request    | The request could not be parsed (e.g., invalid TOC structure, offset/length out of bounds). |
| `0x00000004`   | Internal Error       | The device encountered an unspecified internal error while processing the request. |
| `0x00000005`   | Session Not Found    | The `session_id` in the request does not correspond to an active session.    |
| `0x00000006`   | Key Not Found        | The `key_id` in the request does not correspond to a known key.              |
| `0x00000007`   | Permission Denied    | The operation is not permitted in the current context.                        |
| `0x0000FFFF`   | *(Reserved)*         | Upper bound of the protocol-level status code range.                         |

---

## TOC Entry Format

The Table of Contents (TOC) is the central mechanism for passing structured parameters in requests and returning structured results in responses. Each TOC entry is a **4-byte (32-bit)** structure that is self-describing: the first 6 bits identify the entry type, and the remaining 26 bits carry a type-specific encoding.

This design achieves two goals:

1. **Compactness.** Small values (8-bit or 16-bit integers, session IDs, key IDs) are inlined directly in the TOC entry, requiring no additional space in the variable-length data section.
2. **Flexibility.** Larger or variable-length values (buffers, sealed keys, 32/64-bit integers) are stored in the variable-length data section and referenced by offset and length from the TOC entry.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|               Type-Specific Encoding              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Fields

| Offset | Size    | Field                  | Description                                                        |
|--------|---------|------------------------|--------------------------------------------------------------------|
| 0      | 6 bits  | Entry Type             | Unsigned integer (0–63) identifying the type of this TOC entry.    |
| 0.6    | 26 bits | Type-Specific Encoding | Interpretation depends on the Entry Type. See type definitions below. |

### Entry Types

| Type Value | Name       | Encoding   | Description                        |
|------------|------------|------------|------------------------------------|
| 0          | session_id | [Inline 16](#encoding-inline-16-bit)  | Session identifier (2 bytes).      |
| 1          | key_id     | [Inline 16](#encoding-inline-16-bit)  | Key identifier (2 bytes).          |
| 2          | sealed_key | [Offset/Len](#encoding-offsetlength) | Sealed key blob in variable-length data. |
| 3          | uint8      | [Inline 8](#encoding-inline-8-bit)   | 8-bit unsigned integer.            |
| 4          | uint16     | [Inline 16](#encoding-inline-16-bit)  | 16-bit unsigned integer.           |
| 5          | uint32     | [Offset/Len](#encoding-offsetlength) | 32-bit unsigned integer (length MUST be 4). |
| 6          | uint64     | [Offset/Len](#encoding-offsetlength) | 64-bit unsigned integer (length MUST be 8). |
| 7          | buffer     | [Offset/Len](#encoding-offsetlength) | Variable-length byte buffer.       |
| 8          | none       | [Inline None](#encoding-inline-none) | Absent value. Used as a placeholder for optional fields that are not present in this message. |
| 9          | padding    | [Offset/Len](#encoding-offsetlength) | Alignment padding in the variable-length data section. Length is 0 to N−1 bytes where N is the desired alignment. Data bytes SHOULD be zero. Receivers MUST ignore the content of padding entries. |
| 10–63      | —          | —          | Reserved for future use. Receivers MUST ignore TOC entries with unrecognized Entry Type values (see [Protocol Rules](#protocol-rules), rule 6). |

### Encoding: Inline None

Used by: **none**.

Represents an absent or unset value. The entire 26-bit type-specific encoding region is reserved and MUST be zero. This entry type carries no value and does not reference the variable-length data section. It is used as a placeholder for optional fields that are not present in a message, allowing the TOC count to remain fixed regardless of which optional fields are populated.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|                  Reserved                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field      | Description                                |
|--------|---------|------------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier (`0x08` for none).         |
| 0.6    | 26 bits | Reserved   | MUST be `0`.                               |

### Encoding: Inline 8-bit

Used by: **uint8**.

The value is stored directly in the TOC entry. Bits 6–23 are reserved and MUST be zero.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|              Reserved             |     Value     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                |
|--------|---------|----------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier (`0x03` for uint8).      |
| 0.6    | 18 bits | Reserved | MUST be `0`.                               |
| 3      | 8 bits  | Value    | Unsigned 8-bit value.                      |

### Encoding: Inline 16-bit

Used by: **session_id**, **key_id**, **uint16**.

The value is stored directly in the TOC entry. Bits 6–15 are reserved and MUST be zero. The 16-bit value occupies bytes 2–3 of the TOC entry and is encoded in **big-endian** byte order.

> **Note:** This is the one exception to the protocol's little-endian convention. The inline 16-bit value is stored big-endian to preserve natural reading order when inspecting raw bytes.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|      Reserved     |             Value             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                |
|--------|---------|----------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier.                         |
| 0.6    | 10 bits | Reserved | MUST be `0`.                               |
| 2      | 16 bits | Value    | Unsigned 16-bit value (big-endian).        |

### Encoding: Offset/Length

Used by: **sealed_key**, **uint32**, **uint64**, **buffer**.

The data resides in the variable-length data section that follows all TOC entries. The TOC entry stores a 13-bit length and a 13-bit offset, both unsigned.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|          Length         |          Offset         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                                          |
|--------|---------|----------|----------------------------------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier.                                                   |
| 0.6    | 13 bits | Length   | Length in bytes of the data in the variable-length data section (0–8191). |
| 2.3    | 13 bits | Offset   | Byte offset from the start of the variable-length data section (0–8191). |

For fixed-size types the Length field MUST be set as follows. A receiver MUST reject a message where a fixed-size type has an incorrect length (status code `0x00000003`, Malformed Request):

| Type       | Required Length |
|------------|-----------------|
| uint32     | 4               |
| uint64     | 8               |
| sealed_key | Variable        |
| buffer     | Variable        |

A receiver MUST verify that `Offset + Length` does not exceed the actual size of the variable-length data section. If it does, the message MUST be rejected with status code `0x00000003` (Malformed Request).

### Data Alignment

Data in the variable-length data section is **not** required to be aligned to any particular boundary by default. Implementations that operate on architectures requiring aligned memory access MUST perform appropriate byte-level reads (e.g., `memcpy` into an aligned buffer) rather than assuming natural alignment of referenced data.

To support aligned access, a sender MAY insert a `padding` TOC entry (Entry Type `9`) immediately before a data-bearing TOC entry. The padding entry references zero-filled bytes in the variable-length data section whose purpose is to advance the data offset so that the subsequent entry's data begins at a multiple of N bytes from the **start of the message** (byte 0 of the header), where N is the desired alignment. The padding length is between 0 and N−1 bytes. A receiver MUST ignore the content of padding entries.

Alignment is measured from the start of the message, not the start of the variable-length data section: the data section starts at `12 + 4 × TOC Count`, which is 8-byte aligned when the TOC Count is odd. An aligned field therefore starts at `12 + 4 × TOC Count + Offset ≡ 0 (mod N)`.

The message itself carries no alignment guarantee. A field aligned to N bytes within the message is aligned to N bytes in memory only if the buffer holding the message starts at an address aligned to at least N bytes. A receiver that relies on in-memory alignment SHOULD place incoming messages at such an address.

Multiple TOC entries MAY reference overlapping regions of the variable-length data section, though this is NOT RECOMMENDED and the behavior is application-defined.

---

## Protocol Rules

The following rules govern the behavior of all conforming implementations.

### 1. Request-Response Semantics

Every request MUST receive exactly one response. A sender that does not receive a response within the configured timeout period (see rule 5) SHOULD treat the request as failed. The recovery strategy (retry, session teardown, or device reset) is application-defined, but implementations SHOULD document their chosen behavior. A receiver MUST NOT send more than one response per request.

### 2. Ordering and Pipelining

Multiple requests MAY be issued concurrently without waiting for prior responses (pipelining). Responses are **not** guaranteed to arrive in the order the corresponding requests were sent; a receiver MAY process requests in parallel and return responses in any order. Request-response correlation is performed using a command identifier carried by the external transport or framing protocol — this specification does not define a command ID field. Implementations MUST rely on the external protocol's command ID to match each response to its originating request.

### 3. API Revision Selection and Binding

The host selects an API revision using discovered capabilities and local policy.
There is no cryptographic version-negotiation handshake. Unsupported requests
receive `UnsupportedRevision` (`0x0870002A`), with the requested revision echoed
in the response header and a single `none` TOC entry.

Session establishment includes `BE16(api_major) || BE16(api_minor)` from the
Init header immediately after the `"TSRA-SESSION-v1"` transcript label. This
binds the selected revision into the PID signature and derived session keys;
Init carries no duplicate revision field in its body. Firmware persists the
revision in Pending and Active state and requires Finish and every subsequent
session command to match it. This authenticates the selected context, not a
claim that the host chose the highest revision the device supports.

### 4. Maximum TOC Entries

A message MUST contain between 1 and 32 TOC entries (inclusive). This constraint is enforced by the 5-bit TOC Count field, which encodes the count as `count minus 1` (range `0x00`–`0x1F`).

### 5. Timeouts

Implementations SHOULD enforce a configurable idle timeout to detect unresponsive peers. The RECOMMENDED default timeout is **5 seconds**. When a timeout fires, the sender SHOULD consider the outstanding request as failed and MAY initiate error recovery. Implementations MUST document their timeout behavior.

### 6. Unknown TOC Entry Types

A receiver MUST silently ignore TOC entries whose Entry Type value is not recognized. This ensures forward compatibility: a sender using a newer version of the application-layer TOC catalog can communicate with an older receiver, provided the older receiver can still process the entries it understands. The ignored entries' data regions (if any) in the variable-length section MAY be skipped without parsing.

### 7. Maximum Message Size

The maximum protocol size of either message is **8331 bytes** (12-byte header,
32 TOC slots, and 8191 data bytes). Production host transports impose a tighter
**8192-byte** capacity. Paired command schemas MUST fit that transport bound.
Typed request encoders reserve the known paired TOC footprint and write data
directly at its final offset, without staging behind a maximum-sized TOC.

### 8. Malformed Message Handling

A receiver that cannot parse a request (e.g., the TOC Count implies more TOC entries than the message contains, an Offset/Length pair references data beyond the message boundary, or a fixed-size type has an incorrect length) MUST respond with status code `0x00000003` (Malformed Request). The receiver MUST NOT partially process a malformed request.

### 9. Reserved Fields

All reserved fields and reserved bits MUST be set to zero by the sender. A receiver MUST ignore the values of reserved fields and MUST NOT reject a message solely because a reserved field is non-zero. This allows future protocol extensions to use these fields without breaking existing receivers.

---

## Schema Features

The following features describe conventions for structured message schemas built on top of the wire format. These are implemented by the `tsra_tbor_derive` macro but are not required by the protocol itself.

### Optional Fields

A schema field may be declared optional. When an optional field is absent from a message, its TOC slot contains a `none` entry (Entry Type `8`). The TOC count remains fixed regardless of which optional fields are present, allowing deterministic message layout.

### Alignment Padding

A schema field may request alignment to a power-of-two boundary, measured from the start of the message (see [Data Alignment](#data-alignment)). When alignment is specified, a `padding` TOC entry (Entry Type `9`) is inserted immediately before the field's TOC entry. The padding entry references zero-filled bytes that advance the data offset to the requested alignment boundary. Padding entries are always present (even with zero length) to maintain a fixed TOC count.

A receiver MUST reject a message in which a present aligned field does not start on its boundary, or in which the TOC entry before an aligned field is not a `padding` entry. Alignment is not supported inside field groups, because a group cannot know where the message starts.

Every masked key (the AEAD masked-key envelope) is declared with 4-byte alignment. The envelope's header and IV are 24 bytes and its metadata is 192 bytes, so a 4-aligned envelope puts both the metadata (the AES-GCM additional data) and the ciphertext on 4-byte boundaries. Firmware guarantees only that messages start on a 4-byte boundary, so 4 is the largest alignment that is also guaranteed in device memory. A response field that firmware writes in place over a request's masked key (for example the `MlDsaSign` signature) carries the same alignment so that both occupy the same offset.

Alignment is requested **explicitly** via a fixed power-of-two boundary annotation on the field. Typed-slice fields (see [Typed Slices](#typed-slices)) are **not** auto-aligned: their element type is required to be `Unaligned` (alignment 1), so the borrow is sound at any offset and no padding entry is inserted.

### Typed Slices

A variable-length `buffer` field may be declared as a typed slice `&[T]` (where `T` is a `#[repr(C)]` POD with no padding) instead of a raw `&[u8]`. The wire encoding is identical — raw little-endian bytes whose length is a multiple of `size_of::<T>()` — but the generated decoder borrows the bytes directly as `&[T]` (zero-copy) and the encoder accepts `&[T]`. `T` MUST be `Unaligned` (alignment 1) — use little-endian wire integer types (e.g. `tbor_int::U16`/`U32`/`U64`) rather than native `u16`/`u32`/`u64` — so the borrow is sound at any data-section offset with no alignment padding; a length that is not a whole number of elements yields an empty slice rather than a panic.

### Fixed-Size Arrays

A schema field declared as `[u8; N]` is encoded as a `buffer` TOC entry (Entry Type `7`) with a fixed length of exactly N bytes. The encoder and decoder validate that the buffer length matches N.

### Length Constraints

Variable-length buffer and sealed_key fields may specify minimum and maximum length constraints. The encoder validates constraints at write time and the decoder validates at parse time.

### Field Groups

Schema fields may be grouped into reusable field group types. A field group contributes its fields to the enclosing message's TOC layout without introducing any additional TOC entries of its own. Groups may be nested. An optional group (where the group type is wrapped in `Option`) emits `none` entries for all group field positions when absent.

### Dispatch Traits

Each request schema type exposes its opcode as an associated constant (`OPCODE`), enabling opcode-based dispatch without hardcoding opcode values in match arms.

---

## Security Considerations

The following security considerations apply to implementations of this protocol.

### FIPS_APPROVED Flag

The `FIPS_APPROVED` flag in the response header (bit 0 of the Flags byte) indicates whether the device used FIPS 140-2/140-3 approved cryptographic algorithms to process the request. This flag is **informational only**. Host software that requires FIPS compliance MUST independently verify the device's FIPS certification status through out-of-band means (e.g., hardware attestation, certificate chain validation) and MUST NOT rely solely on this flag for compliance decisions.

### Sealed Key Handling

The `sealed_key` TOC entry type carries opaque, device-sealed key material. Intermediaries and host software MUST treat sealed key blobs as opaque byte sequences and MUST NOT attempt to parse, modify, or interpret their contents. Sealed keys SHOULD be stored in secure, access-controlled memory when held by the host.

### Input Validation

Implementations MUST perform thorough bounds-checking on all incoming messages:

- Verify that `Offset + Length` for every Offset/Length TOC entry falls within the actual variable-length data section.
- Verify that the total message size is consistent with the TOC Count and the referenced data regions.
- Reject messages that fail validation with status code `0x00000003` (Malformed Request) and do not process them further.

Failure to validate inputs can lead to buffer over-reads or other memory safety vulnerabilities, which are especially critical in device driver contexts.

### Transport Security

This protocol does not define encryption or authentication at the wire level. If the transport channel is not physically secured (e.g., communication over a shared bus), implementations SHOULD layer appropriate transport security (encryption, message authentication) beneath this protocol.

---

## Worked Examples

The following examples demonstrate how requests and responses are encoded on the wire. All values are shown in hexadecimal. Byte offsets are zero-indexed from the start of the message.

### Example 1 — Simple Request

A request with API revision 1.1, opcode `0x0A`, containing two TOC entries:

1. A `session_id` (Entry Type 0, Inline 16-bit) with value `0x002B` (session 43).
2. A `buffer` (Entry Type 7, Offset/Length) containing 5 bytes of payload data: `48 65 6C 6C 6F` (ASCII "Hello").

#### Field Breakdown

| Byte Offset | Hex Value | Field             | Explanation                                                   |
|-------------|-----------|-------------------|---------------------------------------------------------------|
| 0–1         | `01 00`   | API Major         | Major revision 1. |
| 2–3         | `01 00`   | API Minor         | Minor revision 1. |
| 4           | `01`      | Rsv(3) + TOC Count(5) | Two TOC entries. |
| 5           | `0A`      | Opcode            | Application-defined opcode `0x0A`. |
| 6–7         | `00 00`   | Reserved          | Must be zero. |
| 8–11        | `00 00 00 00` | Reserved       | Must be zero. |
| 12–15       | `00 00 00 2B` | TOC Entry 1    | Session ID 43. |
| 16–19       | `1C 00 A0 00` | TOC Entry 2    | Buffer, length 5, offset 0. |
| 20–24       | `48 65 6C 6C 6F` | Variable data | The 5-byte buffer payload: "Hello". |

**Total message size:** 25 bytes.

#### Hex Dump

```
Offset  Bytes
 0000   01 00 01 00
 0004   01 0A 00 00
 0008   00 00 00 00
 000C   00 00 00 2B
 0010   1C 00 A0 00
 0014   48 65 6C 6C 6F
```

#### Decoding the TOC Entries

**TOC Entry 1** (`00 00 00 2B` as a 32-bit big-endian value = `0x0000002B`):
- Bits 31–26: `000000` = Entry Type 0 (`session_id`)
- Bits 25–16: `0000000000` = Reserved (all zeros)
- Bits 15–0: `0x002B` = Value 43 (big-endian inline 16-bit)

**TOC Entry 2** (`1C 00 A0 00` as a 32-bit big-endian value = `0x1C00A000`):
- Bits 31–26: `000111` = Entry Type 7 (`buffer`)
- Bits 25–13: `0000000000101` = Length 5
- Bits 12–0: `0000000000000` = Offset 0

### Example 2 — Simple Response

A response to the above request, indicating success with the FIPS_APPROVED
flag set, returning a `buffer` containing `4F 4B 21` (ASCII "OK!"). A trailing
`none` entry preserves the request's two-slot TOC footprint.

#### Field Breakdown

| Byte Offset | Hex Value      | Field                | Explanation                                                     |
|-------------|----------------|----------------------|-----------------------------------------------------------------|
| 0–1         | `01 00`        | API Major            | Matches the request. |
| 2–3         | `01 00`        | API Minor            | Matches the request. |
| 4           | `01`           | Rsv(3) + TOC Count(5) | Two entries, including the reserved slot. |
| 5           | `01`           | Flags                | Bit 0 (FIPS_APPROVED) = 1. |
| 6–7         | `00 00`        | Reserved             | Must be zero. |
| 8–11        | `00 00 00 00`  | Status Code          | `0x00000000` = Success. |
| 12–15       | `1C 00 60 00`  | TOC Entry 1          | Buffer, length 3, offset 0. |
| 16–19       | `20 00 00 00`  | TOC Entry 2          | Reserved `none` slot. |
| 20–22       | `4F 4B 21`     | Variable data        | The 3-byte buffer payload: "OK!". |

**Total message size:** 23 bytes.

#### Hex Dump

```
Offset  Bytes
 0000   01 00 01 00
 0004   01 01 00 00
 0008   00 00 00 00
 000C   1C 00 60 00
 0010   20 00 00 00
 0014   4F 4B 21
```

#### Decoding the TOC Entry

**TOC Entry 1** (`1C 00 60 00` as a 32-bit big-endian value = `0x1C006000`):
- Bits 31–26: `000111` = Entry Type 7 (`buffer`)
- Bits 25–13: `0000000000011` = Length 3
- Bits 12–0: `0000000000000` = Offset 0

### Example 3 — Request with Optional Field

A request with opcode `0x20`, a required `uint8` field (value 5), an absent optional `uint16` field, and a present optional `uint8` field (value 42).

**TOC layout:** 3 entries (required uint8, none, optional uint8).

| Offset | Bytes | Description |
|--------|-------|-------------|
| 0–3    | `01 00 01 00` | API revision 1.1 |
| 4–7    | `02 20 00 00` | Three entries, opcode 0x20, reserved |
| 8–11   | `00 00 00 00` | Reserved |
| 12–15  | `0C 00 00 05` | TOC[0]: uint8, value = 5 |
| 16–19  | `20 00 00 00` | TOC[1]: none (absent optional field) |
| 20–23  | `0C 00 00 2A` | TOC[2]: uint8, value = 42 |

Total message: 24 bytes, no variable-length data section.

---

## Revision History

| Version | Date       | Summary                                                                                       |
|---------|------------|-----------------------------------------------------------------------------------------------|
| 0.1     | —          | Initial draft. Defined core request/response framing, TOC structure, and basic entry types.    |
| 0.2     | —          | Added well-known status codes, security considerations, data alignment rules, and worked examples. Expanded protocol rules (pipelining, unknown TOC types, malformed message handling, maximum message size). Clarified endianness convention and FIPS_APPROVED flag semantics. |
| 0.3     | —          | Added Entry Type 8 (`none`) for optional fields. Added Entry Type 9 (`padding`) for data alignment. Added Schema Features section describing optional fields, alignment, fixed arrays, length constraints, field groups, and dispatch traits. |
| 0.4     | —          | Unreleased framing alignment under wire version 1: equal 8-byte headers, TOC count at byte 2 in both directions, and paired command TOC footprints with trailing `none` slots. |
| 0.5     | —          | Unreleased under wire version 1: field alignment is measured from the start of the message rather than the data section; receivers reject misaligned fields; masked keys are 4-byte aligned. |
| 0.6     | —          | Replaced the encoding version with 16-bit API major/minor in equal 12-byte headers; bound the selected revision into session establishment and pinned it for the session lifetime. |
