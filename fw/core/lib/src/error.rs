// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_fw_hsm_core_tracing::*;
use tsra_fw_hsm_pal_traits::*;

/// Logs a failure and replaces it with a canonical [`HsmError`], which the
/// CQE maps to the host status.
pub(crate) trait ResultLogExt<T> {
    /// Logs the error and replaces it with `err`.
    fn log_as(self, tag: &str, err: HsmError) -> HsmResult<T>;
}

impl<T, E: core::fmt::Debug> ResultLogExt<T> for Result<T, E> {
    #[inline]
    fn log_as(self, _tag: &str, err: HsmError) -> HsmResult<T> {
        self.map_err(|_e| {
            error!(_tag, err, "{:?}", _e);
            err
        })
    }
}
