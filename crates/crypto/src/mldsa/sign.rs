// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA signing and verification operations.
//!
//! This module defines [`MlDsaAlgo`], which implements the crate's [`SignOp`]
//! and [`VerifyOp`] traits for ML-DSA and so is reachable through the
//! [`Signer`](crate::Signer) and [`Verifier`](crate::Verifier) wrappers.
//!
//! # Configuration lives in the engine
//!
//! FIPS 204 signing takes two parameters beyond the key and message: a context
//! string bound into the signature, and per-signature randomness. Neither fits
//! the [`SignOp::sign`] signature, so both are held by the engine — the same
//! shape [`EcdsaAlgo`](crate::EcdsaAlgo) uses to carry its hash algorithm.
#![allow(deprecated)]

use ml_dsa::EncodedSignature;
use ml_dsa::EncodedVerifyingKey;
use ml_dsa::ExpandedSigningKey;
use ml_dsa::ExpandedSigningKeyBytes;
use ml_dsa::MlDsa44;
use ml_dsa::MlDsa65;
use ml_dsa::MlDsa87;
use ml_dsa::MlDsaParams;
use ml_dsa::Signature;
use ml_dsa::VerifyingKey;
use ml_dsa::common::rand_core::TryCryptoRng;
use ml_dsa::common::rand_core::TryRng;

use super::*;

/// ML-DSA signature and verification engine.
///
/// The engine holds the FIPS 204 context string. One engine serves both
/// signing and verification, as [`EcdsaAlgo`](crate::EcdsaAlgo) does.
///
/// # Randomness
///
/// Signing randomness is drawn from the platform generator, freshly for every
/// signature, and is never a parameter — the same arrangement ECDSA's nonce
/// and RSA-PSS's salt already have in this crate. Signing is hedged, so a
/// given `(key, message, ctx)` yields a different, equally valid signature
/// each time.
pub struct MlDsaAlgo {
    /// FIPS 204 context string, bound into the signature.
    ctx: Vec<u8>,

    /// Randomness pinned by a known-answer test; see
    /// [`with_randomness`](Self::with_randomness). Production always draws.
    #[cfg(test)]
    pinned_rnd: Option<[u8; MLDSA_RND_LEN]>,
}

impl MlDsaAlgo {
    /// Creates an ML-DSA engine.
    ///
    /// # Arguments
    ///
    /// * `ctx` - FIPS 204 context string, at most [`MLDSA_CTX_MAX_LEN`] bytes
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaInvalidContext`] if `ctx` is too long.
    pub fn new(ctx: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            ctx: check_ctx(ctx)?,
            #[cfg(test)]
            pinned_rnd: None,
        })
    }

    /// Creates an engine that signs under fixed randomness.
    ///
    /// Test-only, and deliberately so. A published signature can only be
    /// reproduced by supplying the randomness that produced it, so the
    /// known-answer tests need this; no caller does. Pinning it in production
    /// could only make signing more predictable than the generator already
    /// guarantees, and there is nothing to gain by it — the PAL's generator is
    /// [`Rng`] itself.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaInvalidContext`] if `ctx` is too long.
    #[cfg(test)]
    pub(crate) fn with_randomness(
        ctx: &[u8],
        rnd: [u8; MLDSA_RND_LEN],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            ctx: check_ctx(ctx)?,
            pinned_rnd: Some(rnd),
        })
    }

    /// Draws the randomness for one signature.
    fn signing_rnd(&self) -> Result<[u8; MLDSA_RND_LEN], CryptoError> {
        #[cfg(test)]
        if let Some(rnd) = self.pinned_rnd {
            return Ok(rnd);
        }

        let mut rnd = [0u8; MLDSA_RND_LEN];
        Rng::rand_bytes(&mut rnd).map_err(|_| CryptoError::MlDsaSignError)?;
        Ok(rnd)
    }
}

impl SignOp for MlDsaAlgo {
    /// Expanded ML-DSA signing key.
    type Key = MlDsaPrivateKey;

    /// Produces a hedged ML-DSA signature over `data`.
    ///
    /// # Arguments
    ///
    /// * `key` - The signing key
    /// * `data` - The message to sign
    /// * `signature` - Optional output buffer. If `None`, only calculates the
    ///   required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written, or the required size if `signature` is
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CryptoError::MlDsaSignError`] - the key does not decode, or the
    ///   platform generator failed
    /// - [`CryptoError::MlDsaBufferTooSmall`] - the output buffer is too small
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        fn inner<P: MlDsaParams>(
            sec_key: &[u8],
            data: &[u8],
            ctx: &[u8],
            rnd: &[u8],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(sec_key)
                .map_err(|_| CryptoError::MlDsaSignError)?;
            let sk = ExpandedSigningKey::<P>::from_expanded(&enc);
            let mut rng = FixedRng { bytes: rnd };
            let sig = sk
                .sign_randomized(data, ctx, &mut rng)
                .map_err(|_| CryptoError::MlDsaSignError)?;
            let sig = sig.encode();
            signature
                .get_mut(..sig.len())
                .ok_or(CryptoError::MlDsaBufferTooSmall)?
                .copy_from_slice(&sig);
            Ok(sig.len())
        }

        let len = key.variant().sig_len();
        let Some(signature) = signature else {
            return Ok(len);
        };
        let rnd = self.signing_rnd()?;
        dispatch!(
            key.variant(),
            inner(key.as_bytes(), data, &self.ctx, &rnd, signature)
        )
    }
}

impl VerifyOp for MlDsaAlgo {
    /// Encoded ML-DSA verifying key.
    type Key = MlDsaPublicKey;

    /// Verifies an ML-DSA signature over `data`.
    ///
    /// # Arguments
    ///
    /// * `key` - The verifying key
    /// * `data` - The message that was signed
    /// * `signature` - The signature to check
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature authenticates `data` under `key`, `Ok(false)`
    /// otherwise. A signature that does not decode is a failed verification
    /// rather than an error: the question asked was whether these bytes
    /// authenticate the message, and they do not.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MlDsaVerifyError`] if `key` does not decode, so
    /// the question could not be answered at all.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        fn inner<P: MlDsaParams>(
            pub_key: &[u8],
            data: &[u8],
            ctx: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoError> {
            let enc = EncodedVerifyingKey::<P>::try_from(pub_key)
                .map_err(|_| CryptoError::MlDsaVerifyError)?;
            let vk = VerifyingKey::<P>::decode(&enc);

            let Ok(sig_enc) = EncodedSignature::<P>::try_from(signature) else {
                return Ok(false);
            };
            let Some(sig) = Signature::<P>::decode(&sig_enc) else {
                return Ok(false);
            };
            Ok(vk.verify_with_context(data, ctx, &sig))
        }

        dispatch!(
            key.variant(),
            inner(key.as_bytes(), data, &self.ctx, signature)
        )
    }
}

/// Validates and copies a FIPS 204 context string.
fn check_ctx(ctx: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ctx.len() > MLDSA_CTX_MAX_LEN {
        return Err(CryptoError::MlDsaInvalidContext);
    }
    Ok(ctx.to_vec())
}

/// Presents a fixed 32-byte block through the RNG interface `ml-dsa` expects.
///
/// `sign_randomized` asks for a generator, never for the bytes, so something
/// has to bridge the two. The alternative is `sign_internal`, which does take
/// `rnd` directly — but that is the *internal* interface, upstream notes that
/// normal code should not use it and intends to feature-gate it, and reaching
/// it means reproducing FIPS 204's `M'` framing here rather than letting the
/// crate do it.
///
/// [`signing_rnd`](MlDsaAlgo::signing_rnd) has already resolved where the block
/// came from — drawn, or pinned by a known-answer test — so this only has to
/// hand it over. It refuses a second draw: signing consumes exactly one
/// 32-byte value today, and if that ever changes this fails loudly instead of
/// silently repeating the same bytes.
struct FixedRng<'a> {
    bytes: &'a [u8],
}

/// Signalled when the algorithm asks for more randomness than was supplied.
#[derive(Debug)]
struct FixedRngExhausted;

impl core::fmt::Display for FixedRngExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ML-DSA requested more randomness than was supplied")
    }
}

impl core::error::Error for FixedRngExhausted {}

impl TryRng for FixedRng<'_> {
    type Error = FixedRngExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (head, rest) = self
            .bytes
            .split_at_checked(dst.len())
            .ok_or(FixedRngExhausted)?;
        dst.copy_from_slice(head);
        self.bytes = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng<'_> {}
