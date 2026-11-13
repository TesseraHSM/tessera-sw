// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code shared by the std (host-native) Uno and Duo platforms.
//!
//! This crate holds the parts that don't depend on a platform's
//! `StdHsmPal` type: the emulated crypto/session drivers, the DMA buffer
//! pool, the tokio worker pool, and the process-wide trace hooks.
//!
//! PAL trait implementations can't live here (the orphan rule requires
//! them in the crate that defines `StdHsmPal`), so the platform crates
//! compile the shared implementation files in `../pal_src` and
//! `../lib_src` into themselves with `#[path]`. Only the IO wire format,
//! sessions and API revision range differ per platform.
//!
//! The `#[no_mangle]` trace hooks are defined only here, so both
//! platforms can be linked into one binary.

pub mod buf_pool;
pub mod drivers;
mod tracing;
pub mod worker;
