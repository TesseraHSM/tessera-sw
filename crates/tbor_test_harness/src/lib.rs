// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test infrastructure for the TBOR integration suite.
//!
//! - [`ctx`]           per-test fixture + canonical error-shape assertions
//! - [`session_guard`] RAII guard that closes a live session on drop
//! - [`fixture`]       backend bring-up and canonical PSK constants
//! - [`assertions`]    reusable error-shape predicates
//! - [`session`]       session-establishment + per-command crypto helpers
//! - [`api_rev`]       `ApiRev` request helper
//!
//! Anything declared `pub` here is reachable from consuming test
//! binaries as `tsra_ddi_tbor_test_harness::…`. Nothing in this
//! crate is part of the `tsra_ddi_tbor_types` public API.
//!
//! # Transports
//!
//! Consuming test binaries pick the transport at runtime:
//!
//! * `TSRA_TEST_ARGS=transport=sock` — the canonical configuration; drives the
//!   full suite over the socket transport against std-PAL firmware served
//!   by an in-process `ddi_sock_server` (or the server named by
//!   `sock=` in `TSRA_TEST_ARGS`).
//! * **Unset** (or `transport=ioctl`) — targets the platform device driver
//!   so the suite runs against real silicon. Tests that don't apply
//!   to the socket transport return early when it is selected (see
//!   `tsra_ddi::sock_selected`).

pub mod api_rev;
pub mod assertions;
pub mod ctx;
pub mod fixture;
pub mod pqc;
pub mod session;
pub mod session_guard;
pub mod x509_fixture;

// Re-export commonly-used schema items so test code doesn't have to
// import them from `tsra_ddi_tbor_types` directly when driving
// negative-path tests through raw `TborSessionOpen*Req` /
// `TborPskChangeReq` requests.
// Flat re-exports so test files write `use crate::TestCtx`
// instead of `crate::ctx::TestCtx`. Only items actually used
// from test files are re-exported here; helpers only reached through
// `TestCtx` methods stay behind their submodule.
pub use ctx::TestCtx;
pub use fixture::bootstrap_rotated_co;
pub use fixture::bootstrap_rotated_cu;
pub use fixture::CO_PSK_ID;
pub use fixture::CU_PSK_ID;
pub use fixture::ROTATED_CO_PSK;
pub use fixture::ROTATED_CU_PSK;
pub use session::build_mac_fin;
pub use session::build_part_init_mach_seed_aad;
pub use session::coord_sizes;
pub use session::encrypt_mach_seed_envelope;
pub use session::encrypt_psk_envelope;
pub use session::SessionHandshake;
pub use session::SessionOpenInitOptions;
pub use session_guard::SessionGuard;
pub use tsra_ddi_tbor_types::build_psk_change_aad;
pub use tsra_ddi_tbor_types::TborPskChangeReq;
