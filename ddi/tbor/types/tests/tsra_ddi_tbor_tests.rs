// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `tsra_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware),
//! `--features sock` (firmware behind a socket server), or with
//! **no** feature (native OS backend — `nix` on Linux / `win` on
//! Windows — for on-silicon test runs).

pub mod commands;
