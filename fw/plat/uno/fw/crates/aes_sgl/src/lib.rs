// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware-independent logic of the Uno PAL's streamed AES modes.
//!
//! The PAL runs AES-GCM and AES-XTS host-to-host over raw SGLs, streaming
//! the data through a small DMA slot. The chunking, the GHASH, the XTS
//! tweak schedule and the GCM two-pass checkpoint defence live here, behind
//! the [`gcm::GcmSglIo`] trait, so that they run as host unit tests against
//! a mock stream; the PAL supplies the GDMA and AES-core implementation.

#![cfg_attr(not(test), no_std)]
#![allow(async_fn_in_trait)]

pub mod gcm;
pub mod ghash;
pub mod xts;

#[cfg(test)]
mod tests;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;
