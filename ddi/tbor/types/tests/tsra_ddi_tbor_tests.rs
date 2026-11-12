// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `tsra_ddi_tbor_types`.
//!
//! The transport is selected at runtime; the same tests run across every
//! transport. Run with `TSRA_TEST_ARGS=transport=sock` (firmware behind an
//! in-process socket server, or the one named by `sock=` in `TSRA_TEST_ARGS`), or with
//! it unset or `transport=ioctl` (platform device driver, for on-silicon
//! test runs).

// Links the in-process socket server started before `main`.
use ddi_sock_server as _;

pub mod commands;
