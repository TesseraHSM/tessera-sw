// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Async firmware driver for PQC offload to the fastpath cores.
//!
//! Post-quantum operations do not run on the HSM core.  They are
//! dispatched to the three FP Cortex-M7 cores, which own the ML-DSA /
//! ML-KEM implementations.  This driver is the HSM-side end of that link.
//!
//! Structurally this mirrors the UPKA driver: where UPKA manages sixteen
//! hardware PKA engines as a shared pool, this manages **three FP cores as
//! three PQC engines**.  Each engine executes one PQC command at a time
//! and the driver distributes work across whichever are free.
//!
//! Two API patterns, matching UPKA:
//! - **Convenience**: [`PqcDriver::mldsa_gen_key`] — acquire, run, release
//!   in one call.
//! - **Handle**: [`PqcDriver::acquire_any`] returns a [`PqcEngine`] to hold
//!   across several operations, released with [`PqcEngine::release`].
//!
//! Unlike UPKA there is no specific-engine acquisition: FP cores are
//! interchangeable, so callers never need to name one.
//!
//! # Transport
//!
//! Each engine has its own IPC message pair.  Descriptors 2–7 carry them,
//! two per core — FP0 on 2/3, FP1 on 4/5, FP2 on 6/7 — sitting below the
//! Admin↔HSM channels on descriptors 28–31.
//!
//! # Status: not yet submitting
//!
//! The FP firmware is currently a no-op image with no PQC responder, so
//! the submit path deliberately fails instead of calling into IPC.
//! Submitting would await a reply that never arrives and wedge the HSM
//! core's IO path on the very first PQC request.
//!
//! Everything up to that boundary is real and exercised: engine
//! acquisition, FIFO queueing when all three are busy, request encoding,
//! buffer validation, and release-on-drop.  What remains is the IPC
//! send/recv itself, the FP-side responder, and the choice of shared
//! memory window for operands — see the `request` module for why that
//! last one is not obvious.

mod api;
#[allow(unsafe_code)]
mod doorbell;
mod engine;
mod error;
#[allow(unsafe_code)]
mod mailbox;
mod pool;
mod request;
#[allow(unsafe_code)]
mod shared_status;

mod types;

pub use api::PqcDriver;
pub use engine::mldsa_pub_key_len;
pub use engine::mldsa_sig_len;
pub use engine::mlkem_ct_len;
pub use engine::mlkem_pub_key_len;
pub use engine::PqcEngine;
pub use engine::MLDSA_CTX_MAX;
pub use engine::MLDSA_MSG_MAX;
pub use engine::MLDSA_SEED_LEN;
pub use engine::MLKEM_SEED_LEN;
pub use error::PqcError;
pub use mailbox::map_normal as map_mailbox_normal;
pub use request::PqcOp;
pub use request::PqcRequest;
pub use request::PqcResponse;
pub use request::REQUEST_WORDS;
pub use request::RESPONSE_WORDS;
pub use shared_status::read_all as read_fp_status;
pub use shared_status::FpStatus;
pub use shared_status::FP_STATUS_MAGIC;
pub use types::EngineId;
pub use types::EngineState;
pub use types::ENGINES;
pub use types::FIRST_FP_DESC;
pub use types::FIRST_FP_IPC_PAIR;
pub use types::QUEUE_DEPTH;
