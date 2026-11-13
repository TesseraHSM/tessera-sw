// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! StdHsm — host-native Duo HSM instance.
//!
//! Runs the HSM core logic natively on the host using channels for IO
//! transport and heap-allocated buffers.
//!
//! IO submission uses `async-channel` (bounded to `MAX_CONCURRENT_IOS` - 1)
//! for backpressure. Each IO carries a `tokio::sync::oneshot` reply channel
//! so completions are routed directly to the submitter — no ordering issues
//! with concurrent IOs.
//!
//! # Example
//!
//! ```ignore
//! // Default:
//! let hsm = StdHsm::new();
//! let c = hsm.io([0u32; DUO_SQE_DWORDS], 0, 0, 0).await?;
//! assert_eq!(c[0], expected_cmd_dword);
//!
//! // With caller's tokio runtime (from an async context):
//! let hsm = StdHsm::with_tokio(tokio::runtime::Handle::current());
//! hsm.shutdown_async().await;
//! ```
//!
//! The implementation is shared with the other std platform
//! (`fw/plat/std/common/lib_src`); only the PAL differs.

use tsra_fw_hsm_pal_std_duo as pal;

#[path = "../../../common/lib_src/std_hsm.rs"]
mod std_hsm;

pub use std_hsm::*;
