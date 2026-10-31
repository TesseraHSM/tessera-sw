// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod cbc_tests;
mod cfb_tests;
mod ctr_tests;
mod ecb_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod gcm_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod key_prop_tests;
mod key_tests;
mod modes_common;
#[cfg(not(feature = "session-ex-tests"))]
mod nist_tests;
mod ofb_tests;

#[cfg(not(feature = "session-ex-tests"))]
mod xts_tests;

use super::*;

pub mod common;
