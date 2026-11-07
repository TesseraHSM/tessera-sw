// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

mod algo;
#[cfg(feature = "sock")]
mod ddi_sock_server_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod partition_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod resiliency;
#[cfg(not(feature = "session-ex-tests"))]
mod session_tests;
mod utils;

#[cfg(feature = "session-ex-tests")]
mod darc;
#[cfg(feature = "session-ex-tests")]
mod partition_ex_tests;
#[cfg(feature = "session-ex-tests")]
mod sd;
#[cfg(feature = "session-ex-tests")]
mod session_ex_tests;

use tsra_api::*;
use tsra_api_tests_macro::*;
