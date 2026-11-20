// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use crate::common::*;

// The minimum and maximum number of DDI requests to generate and execute in
// this fuzzing test.
const MIN_NUMBER_OF_REQS: usize = 1;
const MAX_NUMBER_OF_REQS: usize = 32;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Randomized seed for deterministically generating random DDI request
    /// command objects.
    rand_seed: u64,

    /// Whether to use valid DDI request headers that align with the DDI request
    /// types in the `reqs` vector, or to use completely random DDI request
    /// headers.
    use_valid_header: bool,
}

fuzz_target!(|input: FuzzInput| {
    // Derive a deterministic number of requests from the fuzz seed so that
    // corpus entries can be replayed without relying on the arbitrary input
    // value. This keeps the value within the allowed range.
    let number_of_reqs = (input.rand_seed as usize % (MAX_NUMBER_OF_REQS - MIN_NUMBER_OF_REQS + 1))
        + MIN_NUMBER_OF_REQS;

    // Generate a list of DDI request types to pass into `fuzz_cmd_reqs`:
    // Use `number_of_reqs` from the fuzz input to generate a new vector and
    // randomly select `TestDdiReqs` enum types.
    let reqs: Vec<TestDdiReqs> = generate_random_testddireqs_list(number_of_reqs, input.rand_seed);

    fuzz_cmd_reqs(reqs, input.rand_seed, input.use_valid_header);
});
