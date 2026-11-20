// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM core — generic application logic over a platform abstraction layer.
//!
//! This crate is a pure async library with no executor dependency.
//! The concrete PAL type and Embassy task wiring are provided by the
//! platform crate (e.g. `fw/plat/std/uno/lib`).

#![cfg_attr(not(feature = "std"), no_std)]

mod ddi;
mod error;
mod hsm;
mod io_duo;
mod io_uno;
mod op;
pub mod part_state;
mod session;

pub(crate) use error::*;
pub use hsm::Hsm;
pub use hsm::HsmIoPipeline;
pub use op::DuoOp;
pub use op::OP_FLUSH;
pub use op::OP_MBOR;
pub use op::OP_TBOR;
pub(crate) use op::*;
use tsra_fw_hsm_core_tracing::*;
use tsra_fw_hsm_pal_traits::*;
