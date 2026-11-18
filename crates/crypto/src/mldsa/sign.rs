// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-independent configuration for ML-DSA signing and verification.

use super::*;

/// ML-DSA engine for pure signing under a FIPS 204 context, or an external `μ`.
///
/// Signing is hedged by default; the native backend draws fresh entropy for
/// every signature. An explicit deterministic request is honored or fails.
pub struct MlDsaAlgo {
    #[cfg(any(target_os = "windows", ossl350))]
    pub(super) ctx: Vec<u8>,
    pub(super) external_mu: bool,
    pub(super) deterministic: bool,
    #[cfg(all(test, target_os = "linux", ossl350))]
    pub(super) pinned_rnd: Option<[u8; MLDSA_RND_LEN]>,
}

impl MlDsaAlgo {
    /// Creates an engine with a FIPS 204 context of at most 255 bytes.
    ///
    /// Returns [`CryptoError::MlDsaInvalidContext`] for an oversized context.
    pub fn new(ctx: &[u8]) -> Result<Self, CryptoError> {
        if ctx.len() > MLDSA_CTX_MAX_LEN {
            return Err(CryptoError::MlDsaInvalidContext);
        }
        Ok(Self {
            #[cfg(any(target_os = "windows", ossl350))]
            ctx: ctx.to_vec(),
            external_mu: false,
            deterministic: false,
            #[cfg(all(test, target_os = "linux", ossl350))]
            pinned_rnd: None,
        })
    }

    /// Creates an engine whose input is the 64-byte FIPS 204 message
    /// representative `μ`, already binding the message and its context.
    pub fn external_mu() -> Self {
        Self {
            #[cfg(any(target_os = "windows", ossl350))]
            ctx: Vec::new(),
            external_mu: true,
            deterministic: false,
            #[cfg(all(test, target_os = "linux", ossl350))]
            pinned_rnd: None,
        }
    }

    /// Requires FIPS 204 deterministic signing (`rnd = {0}^32`).
    ///
    /// OpenSSL supports this variant. Windows CNG signing returns
    /// [`CryptoError::MlDsaDeterministicUnsupported`] without writing a
    /// signature. Verification and size queries are unaffected.
    pub fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self
    }

    #[cfg(all(test, target_os = "linux", ossl350))]
    pub(crate) fn with_randomness(
        ctx: &[u8],
        rnd: [u8; MLDSA_RND_LEN],
    ) -> Result<Self, CryptoError> {
        let mut algo = Self::new(ctx)?;
        algo.pinned_rnd = Some(rnd);
        Ok(algo)
    }

    #[cfg(all(test, target_os = "linux", ossl350))]
    pub(crate) fn external_mu_with_randomness(rnd: [u8; MLDSA_RND_LEN]) -> Self {
        Self {
            pinned_rnd: Some(rnd),
            ..Self::external_mu()
        }
    }

    pub(super) fn check_input(&self, data: &[u8]) -> Result<(), CryptoError> {
        if self.external_mu && data.len() != MLDSA_MU_LEN {
            return Err(CryptoError::MlDsaInvalidMu);
        }
        Ok(())
    }
}
