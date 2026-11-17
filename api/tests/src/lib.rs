// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

// Links the in-process socket server started before `main`.
use ddi_sock_server as _;

mod algo;
mod ddi_sock_server_tests;
mod partition_tests;
mod resiliency;
mod session_tests;
mod utils;

mod darc;
mod partition_ex_tests;
mod sd;
mod session_ex_tests;

use tsra_api::*;
use tsra_api_tests_macro::*;
