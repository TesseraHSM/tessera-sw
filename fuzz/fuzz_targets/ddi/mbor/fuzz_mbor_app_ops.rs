// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;
use libfuzzer_sys::fuzz_target;

use crate::common::*;

fuzz_target!(|ops: Vec<TestAppOps>| {
    fuzz_app_ops(ops);
});
