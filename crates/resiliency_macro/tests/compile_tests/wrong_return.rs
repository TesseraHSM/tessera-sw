// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::retry_with_backoff;

pub struct HsmError;
pub type HsmResult<T> = Result<T, HsmError>;

pub mod resiliency {
    pub const MAX_RETRIES: u32 = 3;
    pub fn backoff_base_ms() -> u64 {
        10
    }
    pub fn backoff_jitter_ms() -> u64 {
        1
    }

    pub fn is_io_abort_error<T>(_result: &crate::HsmResult<T>) -> bool {
        false
    }
}

#[retry_with_backoff(predicate = crate::resiliency::is_io_abort_error)]
fn wrong_return() -> Result<(), HsmError> {
    Ok(())
}

fn main() {}
