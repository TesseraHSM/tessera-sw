# Windows DDI encrypted TBOR transport

`DdiWinDev` supports the same native encrypted TBOR operations as `DdiNixDev`:
`check_secure_transport`, `exec_op_tbor_secure`, and `flush_session`.
`from_file` wraps a device handle opened with `FILE_FLAG_OVERLAPPED` without
reopening it or losing per-file session state.

**Driver prerequisite:** the secure Windows IOCTL below matches the Tiger
driver's `CP_ENCRYPT_DECRYPT` ABI, including the implementation on Martichoras
`ajisaxena/v2_tiger_impl` at `fad43ff536dd6fdbf00def46331073fab8ce799b`.
A matching kernel driver is required for hardware use. Probe support
before beginning an encrypted-session handshake. Unsupported drivers return a
Windows I/O error; the SDK never retries a sealed request through a plaintext
or legacy IOCTL.

Legacy MBOR, plaintext TBOR, fast-path, and DATA_XFER IOCTL layouts and function
codes are unchanged. Plaintext and encrypted OOB paths share the same descriptor
validation and explicit input/output direction flags.

## Device-model discovery

`DdiDev::discover()` identifies the PCI device associated with the existing
open handle, rather than inheriting the interface's legacy Uno default.
PCI vendor/device `1414:C003` identifies Uno; `1414:C008` identifies Duo.
The mapping is shared with the Linux backend.

On Windows, the existing device-info IOCTL (`0x400`) supplies the handle's
`MCR:bus:device:function` location. SetupAPI matches that location to one present
HSM device and reads its PCI hardware IDs. Missing, malformed, or ambiguous
identity information is an error. This uses the existing device-info ABI; no
new discovery IOCTL is required.

Uno discovery does not issue a secure IOCTL. Duo discovery verifies the secure
capability probe before returning, so unsupported drivers fail before the test
harness starts its session handshake. Probe failures are never reinterpreted
as Uno. On Linux, discovery reads PCI IDs from the sysfs PCI parent of the open
character device, with the same model mapping and capability policy.

## Secure Windows ABI (64-bit)

The combined normal/OOB interface uses device type `0x3f`, `METHOD_BUFFERED`, and
`FILE_READ_ACCESS | FILE_WRITE_ACCESS`. These are Windows function codes, not
Linux `_IOWR` numbers; the Linux command structures must not be sent on Windows.

| Function | Input | Input size | Output | Output size |
|---|---|---:|---|---:|
| `0x203` | generic input + transport + inline OOB table + reservations | 1680 | generic output + transport + reservations | 600 |

There is no separate encrypted `0x204` IOCTL. The existing Windows prefixes,
including hot-patch reservations, are preserved. The legacy plaintext `0x202`
DATA_XFER input retains its 4096-byte union; the secure interface does not use it.
`ioctl_data_size` contains the complete extended **input** size.

The 176-byte Windows `repr(C)` transport starts with the same fixed fields as
Linux, but includes an additional 128-byte Windows reservation:

| Offset | Field | Type |
|---:|---|---|
| 0 | operation | `u32`: 0 = capability probe, 1 = sealed TBOR, 2 = session flush |
| 4 | frame ID | `u32`, initially zero |
| 8 | key index | `u32`, zero |
| 12 | AAD length | `u32`, zero |
| 16 | authentication tag | 16 bytes |
| 32 | IV | 12 bytes |
| 44 | transport error | `u16` |
| 46 | reserved | `u16`, zero |
| 48 | reserved words | 32 `u32` values, zero |

The secure input layout is:

| Offset | Field | Size |
|---:|---|---:|
| 0 | generic Windows input | 344 |
| 344 | transport | 176 |
| 520 | OOB buffer count | 4 |
| 524 | reserved, zero | 4 |
| 528 | 64 inline OOB descriptors | 1024 |
| 1552 | 32 reserved `u32` values, zero | 128 |

The output contains the 296-byte generic prefix, transport at offset 296, and
32 reserved `u32` values at offset 472. Successful operations, including probe
and flush, require the full 600-byte output before the SDK reads the response
seal. Software rejection/cancellation may return only the 296-byte prefix:
its driver/firmware errors are preserved, but a prefix-only success is rejected.
Other completion lengths are rejected before interpreting any fields.

Probe and flush use `0x203` with null
DMA pointers and zero inline buffer lengths. Sealed requests carry a nonempty
ciphertext of at most 8192 bytes and reserve 8192 bytes for the sealed response.
The generic input uses TBOR opcode hint 2 and session-control flags 7 with the
caller-supplied session ID. Zero OOB buffers select command set 0; 1-64 OOB
buffers select command set 1. The driver translates this interface into native
Gen2 secure SQE/CQE metadata rather than a legacy firmware operation.

OOB data remains outside the inline transport encryption. A request may contain
1-64 OOB descriptors of 1-65536 bytes each. A descriptor's flag bit 0 means the
device writes the buffer; zero means the device reads it. Output pointers remain
writable and borrowed until the overlapped request completes.

All handles, events, request/response buffers, and OOB borrows remain live through
`GetOverlappedResult`, including immediate-success completions. Windows API
failures, driver IOCTL errors, firmware statuses, transport errors, and malformed
completion lengths are surfaced rather than converted to successful defaults.
Request/response contents and seals are not logged.

## Hardware-free validation

From a workspace that consumes this SDK and has a resolved lockfile, on Windows:

```text
cargo test --locked --package tsra_ddi_win --lib
cargo clippy --locked --package tsra_ddi_win --all-targets -- -D warnings
```

Tests inject completions to verify ciphertext/seal round trips, bounds,
direction flags, reserved fields, final-descriptor writes, prefix-only error
propagation, and malformed/short successful-output rejection.
Public transport entry points are also exercised against `NUL` to
confirm that unsupported-IOCTL errors are surfaced without fallback. These
tests do not establish Windows Gen2 hardware support.
