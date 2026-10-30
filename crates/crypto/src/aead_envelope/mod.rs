// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side AEAD envelopes — bit-identical wire format to the fw
//! [`aead-envelope`] crate, slice-based API.
//!
//! # Algorithm
//!
//! AES-256-GCM (`0x03`, [`AeadAlg::AesGcm256`]) uses a 16-byte IV
//! slot and 32-byte AAD granularity. Masked-key callers additionally
//! zero-pad their plaintext to a multiple of 16 bytes.
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
//! | `alg`        | 1 B        | [`AeadAlg`] discriminant (`0x03`).                  |
//! | `rsv`        | 1 B        | Reserved; MUST be `0`. Future versions may use.      |
//! | `aad_len_be` | 2 B        | u16 big-endian; `0` or a multiple of `32`.          |
//! | `iv`         | 16 B       | First 12 bytes are the 96-bit GCM nonce.            |
//! | `aad`        | `aad_len`  | Application-supplied associated data.                |
//! | `data`       | `pt_len`   | Ciphertext after [`seal`], plaintext after [`open`]. |
//! | `tag`        | 16 B       | Standard NIST GCM tag.                               |
//!
//! Framing overhead is **40 bytes**. Sealing stores suffix `00 00 00 01`; opening ignores
//! that suffix rather than authenticating it or using it as nonce bytes.
//!
//! # AAD-length invariant
//!
//! `aad_len` MUST be `0` or a multiple of `32`. The constraint
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
