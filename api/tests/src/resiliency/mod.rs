// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! This module contains two categories of resiliency tests:
//!
//! 1. **Fault-injection tests** (`res-test` feature) — in the
//!    [`fault_injection`] sub-module. Each sub-module targets a
//!    specific API surface and uses the resiliency DDI device
//!    (`tsra_res_test_dev`) to inject transient faults, verifying
//!    that the retry-with-backoff machinery recovers correctly.
//!
//! 2. **Stress tests** — in the [`stress`] sub-module. Multi-threaded
//!    tests that trigger real NSSRs via [`HsmPartition::reset`] while
//!    worker threads perform key operations concurrently. These do
//!    **not** require the `res-test` feature. Under `session-ex-tests`
//!    they run against a TBOR partition with
//!    [`HsmPartition::enable_resiliency_ex`].

mod helpers;

// Fault injection targets the MBOR DDI surface only.
#[cfg(all(feature = "res-test", not(feature = "session-ex-tests")))]
mod fault_injection;

mod stress;
