// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the BCP (bulk crypto processor), the Marvell
//! CDMA engine at `0xA0C0_0000`.
//!
//! The FP cores used to drive this engine for host bulk AES-GCM/XTS; they
//! run PQC now, so CP1 drives it directly: it is the Uno PAL's AES-GCM.
//! The driver programs one 8-entry submission/completion queue pair and
//! DFL list 0 in GSRAM, and submits AES-256-GCM commands of up to two
//! 4 KiB chunks, three at a time; further callers wait for a command ID.
//! Each in-flight command owns the key-vault slot and DFL entry matching
//! its command ID.
//!
//! The engine has no interrupt routed to CP1, so completions are reaped by
//! [`BcpDriver::wake`], which the PAL calls from its poll loop. The engine
//! is brought up on first use rather than at boot.
//!
//! The engine only hashes and encrypts whole blocks: the AAD must be
//! padded to a 32-byte multiple and the text must be a 16-byte multiple.
//! Its tag therefore covers the padded AAD length; the caller corrects the
//! length block and any partial final block in software.
//!
//! # Example
//!
//! ```ignore
//! let bcp = static_init!(BcpDriver, BcpDriver::new());
//! let done = bcp.gcm(GcmRequest {
//!     op: GcmOp::Encrypt,
//!     key,
//!     iv: &iv,
//!     aad_len: 32,
//!     unpadded_aad_len: 20,
//!     tag: &[0; BCP_TAG_LEN],
//!     // [padded_AAD | text] -> [padded_AAD | ciphertext]
//!     data: GcmData::InPlace(buf),
//! }).await?;
//! ```

mod api;
mod error;
pub use api::*;
pub use error::*;
