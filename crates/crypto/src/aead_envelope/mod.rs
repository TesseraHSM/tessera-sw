// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side AEAD envelopes — bit-identical wire format to the fw
//! [`aead-envelope`] crate, slice-based API.
//!
//! # Profiles
//!
//! AES-256-GCM ordinary envelopes (`0x03`) retain their original layout.
//! The masked-key profile (`0x04`, [`AeadAlg::AesGcm256Iv16`]) uses a
//! 16-byte IV slot, 32-byte AAD granularity, and payloads padded by the
//! caller to a multiple of 16 bytes.
//!
//! # Wire format
//!
//! ```text
//! ┌────────┬─────┬─────┬─────────────┬─────┬─────────────────┬─────────┬─────┐
//! │ "AEAD" │ alg │ rsv │ aad_len_be  │ IV  │       AAD       │  DATA   │ TAG │
//! └────────┴─────┴─────┴─────────────┴─────┴─────────────────┴─────────┴─────┘
//!    4B     1B    1B       2B        iv_len    aad_len       pt_len    16B
//! ```
//!
//! | Field        | Size       | Notes                                                |
//! |--------------|------------|------------------------------------------------------|
//! | `magic`      | 4 B        | [`FORMAT_TAG`] (`b"AEAD"`) — format + version 1.     |
//! | `alg`        | 1 B        | [`AeadAlg`] discriminant (`0x03` or `0x04`).        |
//! | `rsv`        | 1 B        | Reserved; MUST be `0`. Future versions may use.      |
//! | `aad_len_be` | 2 B        | u16 big-endian; profile-specific granularity.       |
//! | `iv`         | 12 or 16 B | First 12 bytes are the 96-bit GCM nonce.            |
//! | `aad`        | `aad_len`  | Application-supplied associated data.                |
//! | `data`       | `pt_len`   | Ciphertext after [`seal`], plaintext after [`open`]. |
//! | `tag`        | 16 B       | Standard NIST GCM tag.                               |
//!
//! Framing overhead is **36 bytes** for `0x03`, **40 bytes** for `0x04`.
//! The IV16 profile seals with suffix `00 00 00 01`; opening ignores
//! that suffix rather than authenticating it or using it as nonce bytes.
//!
//! # AAD-length invariant
//!
//! `aad_len` MUST be `0` or a multiple of `32` (both `0x03` and `0x04`). The constraint
//! comes from the fw side's hardware DMA layout; mirroring it here
//! guarantees envelopes produced by either side share an identical
//! wire layout.
//!
//! # Interop
//!
//! The fw crate's PAL produces standard NIST AES-GCM tags, so an
//! envelope sealed on the HSM can be opened by this crate with a
//! single [`open`] call, and vice versa.
//!
//! [`aead-envelope`]: ../../../../fw/core/crypto/aead-envelope

mod alg;
mod envelope;
mod format;
mod gcm;
mod ops;

#[cfg(test)]
mod tests;

pub use ops::AeadAlg;
pub use ops::AeadEnvelope;
pub use ops::FORMAT_TAG;
pub use ops::HEADER_LEN;
pub use ops::MAX_AAD_LEN;
pub use ops::inspect;
pub use ops::open;
pub use ops::seal;
