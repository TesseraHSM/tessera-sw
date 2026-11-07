// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `tsra_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features sock` (firmware behind an in-process
//! socket server, or the one named by `TSRA_DDI_SOCK`), or with
//! **no** feature (native OS backend — `nix` on Linux / `win` on
//! Windows — for on-silicon test runs).

// Links the in-process socket server started before `main`.
#[cfg(feature = "sock")]
use ddi_sock_server as _;

pub mod commands;
