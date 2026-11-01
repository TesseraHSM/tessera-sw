// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! **Stress tests** — in the [`stress`] sub-module. Multi-threaded
//! tests that trigger real NSSRs via [`HsmPartition::reset`] while
//! worker threads perform key operations concurrently. From API
//! revision 1.1 they run against a TBOR partition with
//! [`HsmPartition::enable_resiliency_ex`].
//!
//! The `fault_injection` sub-directory is dormant: it relied on the
//! removed `tsra_res_test_dev` fault-injection transport and is not built.

mod helpers;

mod stress;
