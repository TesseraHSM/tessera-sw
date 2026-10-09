// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std PQC driver — ML-DSA and ML-KEM via [`tsra_crypto`].
//!
//! Operates on the byte encodings the wire protocol carries: seeds and
//! expanded keys in, public keys, signatures and ciphertexts out.
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`mldsa_keygen`](StdPqc::mldsa_keygen) | ML-DSA key generation | `MlDsaVariant`, seed | `(pub_key, sec_key)` |
//! | [`mldsa_sign`](StdPqc::mldsa_sign) | ML-DSA sign | expanded key, message, ctx, randomness | signature |
//! | [`mldsa_verify`](StdPqc::mldsa_verify) | ML-DSA verify | public key, message, ctx, signature | `bool` |
//! | [`mlkem_keygen`](StdPqc::mlkem_keygen) | ML-KEM key generation | `MlKemVariant`, seed | `(pub_key, sec_key)` |
//! | [`mlkem_encapsulate`](StdPqc::mlkem_encapsulate) | ML-KEM encapsulate | public key, `m` | `(ciphertext, shared_secret)` |
//! | [`mlkem_decapsulate`](StdPqc::mlkem_decapsulate) | ML-KEM decapsulate | expanded key, ciphertext | shared secret |
//!
//! ## Thread model
//!
//! All methods copy their inputs into owned buffers and dispatch to the
//! tokio [`WorkerPool`]; the Embassy executor yields while the worker
//! runs. That matters more here than for the classical algorithms: an
//! ML-DSA-87 key generation is milliseconds of lattice arithmetic, and
//! running it inline would stall every other in-flight IO.
//!
//! It also mirrors the hardware. On Cortex-M7 these operations are
//! offloaded to a fastpath core over IPC and awaited, so keeping them
//! off the executor here models the platform rather than merely being
//! faster.
//!
//! ## Randomness
//!
//! Entropy is a parameter, not something this layer draws. The PAL
//! supplies it from the HSM's own generator, as CP1 does for the
//! fastpath cores, which have none of their own.

use tsra_crypto::DecapsulateOp;
use tsra_crypto::EncapsulateOp;
use tsra_crypto::ExportableKey;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaAlgo;
use tsra_crypto::MlDsaPrivateKey;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::MlDsaVariant;
use tsra_crypto::MlKemAlgo;
use tsra_crypto::MlKemPrivateKey;
use tsra_crypto::MlKemPublicKey;
use tsra_crypto::MlKemVariant;
use tsra_crypto::PrivateKey;
use tsra_crypto::Signer;
use tsra_crypto::Verifier;
use tsra_crypto::MLKEM_SHARED_SECRET_LEN;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::worker::WorkerPool;

/// Std PQC driver — software ML-DSA / ML-KEM with async worker dispatch.
pub struct StdPqc {
    pool: WorkerPool,
}

impl StdPqc {
    /// Create a new PQC driver backed by the given worker pool.
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    /// Generate an ML-DSA key pair from `seed`.
    ///
    /// Returns `(pub_key, sec_key)`, the second being the expanded
    /// secret key the masked blob stores.
    pub async fn mldsa_keygen(
        &self,
        variant: MlDsaVariant,
        seed: &[u8],
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let seed = seed.to_vec();
        self.pool
            .submit_with_result(async move {
                let sk =
                    MlDsaPrivateKey::from_seed(variant, &seed).map_err(|_| HsmError::InvalidArg)?;
                let pub_key = sk
                    .public_key()
                    .and_then(|pk| pk.to_vec())
                    .map_err(|_| HsmError::InvalidArg)?;
                let sec_key = sk.to_vec().map_err(|_| HsmError::InvalidArg)?;
                Ok((pub_key, sec_key))
            })
            .await
    }

    /// Sign `message` with an expanded ML-DSA secret key.
    ///
    /// Signing is hedged; the randomness is drawn by the crypto layer.
    pub async fn mldsa_sign(
        &self,
        variant: MlDsaVariant,
        sec_key: &[u8],
        message: &[u8],
        ctx: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let (sec_key, message, ctx) = (sec_key.to_vec(), message.to_vec(), ctx.to_vec());
        self.pool
            .submit_with_result(async move {
                let sk = MlDsaPrivateKey::from_bytes(&sec_key).map_err(|_| HsmError::InvalidArg)?;
                if sk.variant() != variant {
                    return Err(HsmError::InvalidArg);
                }
                let mut algo = MlDsaAlgo::new(&ctx).map_err(|_| HsmError::InvalidArg)?;
                Signer::sign_vec(&mut algo, &sk, &message).map_err(|_| HsmError::InvalidArg)
            })
            .await
    }

    /// Verify an ML-DSA signature, returning whether it authenticates
    /// `message`.
    pub async fn mldsa_verify(
        &self,
        variant: MlDsaVariant,
        pub_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let (pub_key, message, ctx, signature) = (
            pub_key.to_vec(),
            message.to_vec(),
            ctx.to_vec(),
            signature.to_vec(),
        );
        self.pool
            .submit_with_result(async move {
                let pk = MlDsaPublicKey::from_bytes(&pub_key).map_err(|_| HsmError::InvalidArg)?;
                if pk.variant() != variant {
                    return Err(HsmError::InvalidArg);
                }
                let mut algo = MlDsaAlgo::new(&ctx).map_err(|_| HsmError::InvalidArg)?;
                Verifier::verify(&mut algo, &pk, &message, &signature)
                    .map_err(|_| HsmError::InvalidArg)
            })
            .await
    }

    /// Generate an ML-KEM key pair from `seed`.
    ///
    /// Returns `(pub_key, sec_key)`, the second being the expanded
    /// decapsulation key.
    pub async fn mlkem_keygen(
        &self,
        variant: MlKemVariant,
        seed: &[u8],
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let seed = seed.to_vec();
        self.pool
            .submit_with_result(async move {
                let dk =
                    MlKemPrivateKey::from_seed(variant, &seed).map_err(|_| HsmError::InvalidArg)?;
                let pub_key = dk
                    .public_key()
                    .and_then(|ek| ek.to_vec())
                    .map_err(|_| HsmError::InvalidArg)?;
                let sec_key = dk.to_vec().map_err(|_| HsmError::InvalidArg)?;
                Ok((pub_key, sec_key))
            })
            .await
    }

    /// Encapsulate to an ML-KEM public key.
    ///
    /// The encapsulation message is drawn by the crypto layer.
    /// Returns `(ciphertext, shared_secret)`.
    pub async fn mlkem_encapsulate(
        &self,
        variant: MlKemVariant,
        pub_key: &[u8],
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let pub_key = pub_key.to_vec();
        self.pool
            .submit_with_result(async move {
                let ek = MlKemPublicKey::from_bytes(&pub_key).map_err(|_| HsmError::InvalidArg)?;
                if ek.variant() != variant {
                    return Err(HsmError::InvalidArg);
                }
                let mut ciphertext = vec![0u8; variant.ciphertext_len()];
                let mut shared_secret = vec![0u8; MLKEM_SHARED_SECRET_LEN];
                let mut algo = MlKemAlgo::new();
                algo.encapsulate(&ek, Some(&mut ciphertext), Some(&mut shared_secret))
                    .map_err(|_| HsmError::InvalidArg)?;
                Ok((ciphertext, shared_secret))
            })
            .await
    }

    /// Decapsulate `ciphertext` with an expanded ML-KEM secret key.
    ///
    /// A ciphertext that does not decrypt yields the implicit-rejection
    /// secret rather than an error.
    pub async fn mlkem_decapsulate(
        &self,
        variant: MlKemVariant,
        sec_key: &[u8],
        ciphertext: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let (sec_key, ciphertext) = (sec_key.to_vec(), ciphertext.to_vec());
        self.pool
            .submit_with_result(async move {
                let dk = MlKemPrivateKey::from_bytes(&sec_key).map_err(|_| HsmError::InvalidArg)?;
                if dk.variant() != variant {
                    return Err(HsmError::InvalidArg);
                }
                let mut shared_secret = vec![0u8; MLKEM_SHARED_SECRET_LEN];
                let mut algo = MlKemAlgo::new();
                algo.decapsulate(&dk, &ciphertext, Some(&mut shared_secret))
                    .map_err(|_| HsmError::InvalidArg)?;
                Ok(shared_secret)
            })
            .await
    }
}
