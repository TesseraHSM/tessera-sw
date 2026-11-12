// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std Duo PAL — host-native Duo HSM platform abstraction layer.
//!
//! Implements the HSM PAL traits ([`HsmPal`], [`HsmIoController`],
//! [`HsmGdmaController`]) for running HSM core logic natively on the
//! host without hardware or an emulator.
//!
//! # Architecture
//!
//! ```text
//! User (tokio)                    Embassy thread
//! ────────────                    ──────────────
//! HsmIoRequest ──► submit_rx ──► poll_io()
//!                                  alloc buffer slot
//!                                  wrap as StdHsmIo
//!                                  ▼
//!                                core recv_task / send_task
//!                                  ▼
//!                                complete_io()
//!                                  simulate delay (tokio worker)
//!                                  free buffer slot
//! HsmCqe      ◄─ reply_tx ◄── send response
//! ```
//!
//! ## Key components
//!
//! - [`StdHsmPal`] — implements PAL traits with channel-based IO
//!   transport and a tokio-backed worker pool for delay simulation.
//! - [`StdHsmIo`] — IO work item backed by a pool-allocated buffer
//!   slot. Implements [`HsmIo`] for the core's generic IO processing.
//! - [`BufferPool`](buf_pool::BufferPool) — pre-allocated 2KB + 8KB
//!   buffers with async bitmap allocation and waker-based backpressure.
//! - [`WorkerPool`](worker::WorkerPool) — dispatches delay tasks to
//!   tokio, wakes Embassy tasks on completion via cross-thread `Waker`.
//! - [`HsmIoRequest`] — request type for the submit channel.
//!
//! ## Thread model
//!
//! All PAL state (buffer pool, channels, wakers) lives on the Embassy
//! thread. The tokio runtime runs on separate threads and only
//! communicates via `Waker` (thread-safe). No mutexes are needed —
//! `Cell` and `RefCell` suffice for single-threaded Embassy access.
//!
//!
//! Everything except [`cmd`] (the IO wire format), `session` and the API
//! revision range is shared with the other std platform: the modules are
//! compiled from `fw/plat/std/common/pal_src` via `#[path]`, and the
//! drivers, buffer pool and worker pool come from `tsra_fw_hsm_std_common`.
//!
//! [`HsmPal`]: tsra_fw_hsm_pal_traits::HsmPal
//! [`HsmIoController`]: tsra_fw_hsm_pal_traits::HsmIoController
//! [`HsmGdmaController`]: tsra_fw_hsm_pal_traits::HsmGdmaController
//! [`HsmIo`]: tsra_fw_hsm_pal_traits::HsmIo

#[path = "../../../common/pal_src/aes.rs"]
mod aes;
#[path = "../../../common/pal_src/alloc.rs"]
mod alloc;
#[path = "../../../common/pal_src/bulk.rs"]
mod bulk;
#[path = "../../../common/pal_src/cert.rs"]
mod cert;
mod drivers;
#[path = "../../../common/pal_src/ecc.rs"]
mod ecc;
#[path = "../../../common/pal_src/gdma.rs"]
mod gdma;
#[path = "../../../common/pal_src/hash.rs"]
mod hash;
#[path = "../../../common/pal_src/hmac.rs"]
mod hmac;
#[path = "../../../common/pal_src/io.rs"]
mod io;
#[path = "../../../common/pal_src/kdf.rs"]
mod kdf;
#[path = "../../../common/pal_src/key_assurance.rs"]
mod key_assurance;
#[path = "../../../common/pal_src/key_masking.rs"]
mod key_masking;
#[path = "../../../common/pal_src/pal.rs"]
mod pal;
#[path = "../../../common/pal_src/part.rs"]
mod part;
#[path = "../../../common/pal_src/part_lock.rs"]
mod part_lock;
#[path = "../../../common/pal_src/pqc.rs"]
mod pqc;
#[path = "../../../common/pal_src/rng.rs"]
mod rng;
#[path = "../../../common/pal_src/rsa.rs"]
mod rsa;
#[path = "../../../common/pal_src/seed.rs"]
mod seed;
mod session;
mod transport;
#[path = "../../../common/pal_src/vault.rs"]
mod vault;

use tsra_fw_hsm_std_common::buf_pool;
use tsra_fw_hsm_std_common::worker;

/// Command-queue wire format of this platform: Duo's 32-dword SQE and
/// 16-dword CQE.
pub mod cmd {
    pub use tsra_fw_hsm_io::duo::DuoCqe as Cqe;
    pub use tsra_fw_hsm_io::duo::DuoCqeEntry as CqeEntry;
    pub use tsra_fw_hsm_io::duo::DuoRawCqe as RawCqe;
    pub use tsra_fw_hsm_io::duo::DuoRawSqe as RawSqe;
    pub use tsra_fw_hsm_io::duo::DuoSqeEntry as SqeEntry;
    pub use tsra_fw_hsm_io::duo::DUO_CQE_DWORDS as CQE_DWORDS;
    pub use tsra_fw_hsm_io::duo::DUO_SQE_DWORDS as SQE_DWORDS;
}

pub use alloc::StdScopedAlloc;

pub use io::HsmIoRequest;
pub use io::StdHsmIo;
pub use pal::StdHsmPal;
pub use part::HsmPartId;
pub use part::PartCommand;
pub use tsra_fw_hsm_bulk::RawBulkCqe;
pub use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_pal_traits::*;

/// Duo emulation: API revision 2.0, Duo IO protocol (secure sessions).
impl HsmPalFeatures for StdHsmPal {
    type IoProtocol = DuoIo;
    const API_REV_MIN: HsmApiRevision = HsmApiRevision::new(2, 0);
    const API_REV_MAX: HsmApiRevision = HsmApiRevision::new(2, 0);
}

/// Crypto operands are big-endian (exact-width P-521 coordinates).
impl HsmCryptoOrder for StdHsmPal {
    const BYTE_ORDER: HsmByteOrder = HsmByteOrder::Be;
}
