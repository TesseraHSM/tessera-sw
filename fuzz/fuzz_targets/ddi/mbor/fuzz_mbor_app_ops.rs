// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;
use libfuzzer_sys::fuzz_target;

use crate::common::*;

fuzz_target!(|ops: Vec<TestAppOps>| {
    fuzz_app_ops(ops);
});
