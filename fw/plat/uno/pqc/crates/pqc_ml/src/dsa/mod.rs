// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
pub mod keygen;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod rounding;
pub mod sampling;
pub mod sign;
pub mod verify;

// The reference transforms' twiddles; the ARM ones carry their own.
#[cfg(not(target_arch = "arm"))]
mod zetas;
