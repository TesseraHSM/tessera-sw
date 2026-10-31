// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES cryptographic operation traits for the HSM PAL.
//!
//! AES support is split by mode so consumers can bound on only the
//! capabilities they use:
//!
//! | Trait | Module | Purpose |
//! |---|---|---|
//! | [`HsmAes`] | `base` | AES key generation + ECB / CBC |
//! | [`HsmAesGcm`] | `gcm` | AES-GCM authenticated encryption |
//! | [`HsmAesKw`] | `kw` | AES-KW (RFC 3394) / AES-KWP (RFC 5649) |
//! | [`HsmAesXts`] | `xts` | AES-XTS (currently disabled) |
//!
//! On Cortex-M7 hardware these delegate to a dedicated AES engine.
//! On the standard (host-native) PAL they use OpenSSL.
//!
//! ## Key representation
//!
//! DMA-facing AES operations take [`HsmDmaBuf`] inputs/outputs for any bytes
//! touched directly by the hardware engine (keys, IVs, payloads, tags,
//! tweaks). Random key-generation outputs remain plain `&mut [u8]` so
//! callers can write into either slices or DMA buffers via deref.
//!
//! ## In-place variants
//!
//! Methods suffixed `_in_place` operate on a single `&mut HsmDmaBuf` buffer,
//! reading input and writing output to the same memory. This avoids an
//! extra buffer allocation and is the natural model for hardware engines
//! that operate directly on DMA buffers.

mod base;
mod gcm;
mod kw;
mod xts;

pub use base::*;
pub use gcm::*;
pub use kw::*;
pub use xts::*;

use super::*;
