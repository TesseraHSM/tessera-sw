// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-independent configuration for ML-KEM operations.

#[cfg(all(test, target_os = "linux", ossl350))]
use super::MLKEM_M_LEN;

/// ML-KEM encapsulation and decapsulation engine.
///
/// The native backend draws fresh encapsulation entropy for each operation.
pub struct MlKemAlgo {
    #[cfg(all(test, target_os = "linux", ossl350))]
    pub(super) pinned_m: Option<[u8; MLKEM_M_LEN]>,
}

impl MlKemAlgo {
    /// Creates an ML-KEM engine.
    pub fn new() -> Self {
        Self {
            #[cfg(all(test, target_os = "linux", ossl350))]
            pinned_m: None,
        }
    }

    /// Pins encapsulation entropy for an exact-output known-answer test.
    #[cfg(all(test, target_os = "linux", ossl350))]
    pub(crate) fn with_message(m: [u8; MLKEM_M_LEN]) -> Self {
        Self { pinned_m: Some(m) }
    }
}

impl Default for MlKemAlgo {
    fn default() -> Self {
        Self::new()
    }
}
