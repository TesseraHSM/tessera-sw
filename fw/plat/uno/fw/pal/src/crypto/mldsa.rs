// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmMlDsa`] and [`HsmMlKem`] implementations for the Uno PAL.
//!
//! ML-DSA does not run on the HSM core: this forwards to the
//! [`PqcDriver`], which offloads to a fastpath (FP) core. Operation inputs
//! and outputs use DMA-branded buffers.
//!
//! Signing and verification take the message itself or an external `μ`;
//! the pre-hash message types are not supported on Uno and are refused with
//! [`HsmError::UnsupportedCmd`].
//!
//! Signing is hedged, with randomness from the TRNG, unless the caller
//! requires deterministic signing, which uses FIPS 204's all-zero `rnd` and
//! draws nothing.
//!
//! With `bulk_crypto` the FP cores run the bulk-crypto firmware, which
//! has no PQC engine, so every call is refused with
//! [`HsmError::UnsupportedCmd`] before anything is drawn from the RNG or
//! written to the PQC mailboxes (which overlay that firmware's HSM↔FP IPC
//! rings in PSRAM), and the driver calls are compiled out.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlKem;
use tsra_fw_hsm_pal_traits::HsmMlKemParamSet;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::MLKEM_SHARED_SECRET_LEN;
use tsra_fw_uno_trace::tracing::*;

use crate::UnoHsmPal;

/// The vault key kind the PQC driver, and the FP core behind it, name an
/// ML-DSA parameter set by.
fn mldsa_kind(param_set: HsmMlDsaParamSet) -> HsmVaultKeyKind {
    match param_set {
        HsmMlDsaParamSet::MlDsa44 => HsmVaultKeyKind::MlDsa44Seed,
        HsmMlDsaParamSet::MlDsa65 => HsmVaultKeyKind::MlDsa65Seed,
        HsmMlDsaParamSet::MlDsa87 => HsmVaultKeyKind::MlDsa87Seed,
    }
}

/// The vault key kind the PQC driver, and the FP core behind it, name an
/// ML-KEM parameter set by.
fn mlkem_kind(param_set: HsmMlKemParamSet) -> HsmVaultKeyKind {
    match param_set {
        HsmMlKemParamSet::MlKem512 => HsmVaultKeyKind::MlKem512Seed,
        HsmMlKemParamSet::MlKem768 => HsmVaultKeyKind::MlKem768Seed,
        HsmMlKemParamSet::MlKem1024 => HsmVaultKeyKind::MlKem1024Seed,
    }
}

/// Check an ML-DSA input for what Uno supports: the message itself or an
/// external `μ`; the pre-hash types are not supported on Uno.
fn check_msg_type(msg_type: HsmMlDsaMsgType, message: &[u8], ctx: &[u8]) -> HsmResult<()> {
    match msg_type {
        HsmMlDsaMsgType::Pure | HsmMlDsaMsgType::ExternalMu => msg_type.check_input(message, ctx),
        HsmMlDsaMsgType::PreHash | HsmMlDsaMsgType::PreHashMessage => Err(HsmError::UnsupportedCmd),
    }
}

/// Whether to sign hedged: Uno always has the TRNG, so it hedges unless the
/// caller requires deterministic signing.
fn hedged(hedge: HsmMlDsaHedge) -> bool {
    match hedge {
        HsmMlDsaHedge::Preferred | HsmMlDsaHedge::Required => true,
        HsmMlDsaHedge::Deterministic => false,
    }
}

/// Length of the compact ML-DSA private seed (`xi`), identical for every
/// parameter set — which is why `param_set` has to be carried alongside it.
const MLDSA_SEED_LEN: usize = 32;

// With `bulk_crypto` each method returns before reaching the PQC driver; see
// the module docs.
#[cfg_attr(feature = "bulk_crypto", allow(unreachable_code))]
impl HsmMlDsa for UnoHsmPal {
    async fn mldsa_sign_in_place(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        key_signature: &mut HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        hedge: HsmMlDsaHedge,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
    ) -> HsmResult<()> {
        let mut rnd = [0u8; MLDSA_SEED_LEN];
        let result = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg_type(msg_type, message, ctx)?;
            if hedged(hedge) {
                self.rng_fill_bytes(io, &mut rnd)?;
            }
            self.pqc
                .with_engine(async |engine| {
                    engine
                        .mldsa_sign_in_place(
                            mldsa_kind(param_set),
                            key_signature,
                            &rnd,
                            msg_type,
                            message,
                            ctx,
                        )
                        .await
                })
                .await
        }
        .await;
        rnd.fill(0);
        result
    }

    async fn mldsa_gen_key(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        seed: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        sec_key: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // Bracketed so an early `?` cannot skip the closing mark: every
        // exit, error or not, leaves through the await below.
        let outcome: HsmResult<()> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            // Validate before handing anything to the driver, so buffer-size
            // bugs surface here rather than as a malformed FP request.
            let expected_pub = param_set.pub_key_len();
            if seed.len() != MLDSA_SEED_LEN || pub_key.len() != expected_pub {
                error!(
                    "pqc",
                    HsmError::InvalidArg,
                    "pal: mldsa_gen_key bad buffers seed_len={} (want {}) pub_len={} (want {})",
                    seed.len(),
                    MLDSA_SEED_LEN,
                    pub_key.len(),
                    expected_pub
                );
                return Err(HsmError::InvalidArg);
            }

            // Draw the ML-DSA seed here, not on FP. The seed *is* the private
            // key, and an FP core has no entropy source of its own -- the
            // device's certified TRNG belongs to this core. FP receives the
            // seed and derives the key pair. Both the seed and the expanded
            // secret key come back so the HSM can mask them together, which is
            // what lets signing skip the derivation entirely.
            self.rng.fill_bytes(seed)?;

            self.pqc
                .mldsa_gen_key(mldsa_kind(param_set), seed, pub_key, sec_key)
                .await
        }
        .await;

        outcome
    }

    async fn mldsa_sign(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        sec_key: &HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        hedge: HsmMlDsaHedge,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
        signature: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // Bracketed so a failed RNG draw still reaches the closing mark.
        let outcome: HsmResult<()> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg_type(msg_type, message, ctx)?;
            // Per-signature randomness for the hedged variant, drawn here for
            // the same reason as the seed: an FP core has no entropy source.
            // The deterministic variant leaves it zero.
            let mut rnd = [0u8; MLDSA_SEED_LEN];
            if hedged(hedge) {
                // SAFETY: `rnd` is a local of exactly the length the RNG driver
                // fills; `from_raw_mut` only re-types it.
                let dma = unsafe { HsmDmaBuf::from_raw_mut(&mut rnd[..]) };
                self.rng.fill_bytes(dma)?;
            }

            let result = self
                .pqc
                .mldsa_sign(
                    mldsa_kind(param_set),
                    sec_key,
                    &rnd,
                    msg_type,
                    message,
                    ctx,
                    signature,
                )
                .await;

            // The randomness is not a long-term secret, but it is signing input;
            // do not leave it on the stack for the next caller.
            rnd.fill(0);
            result
        }
        .await;

        outcome
    }

    async fn mldsa_verify(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        pub_key: &HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        // Bracketed so the `bulk_crypto` refusal still reaches the closing
        // mark; see `mldsa_gen_key`.
        let outcome: HsmResult<bool> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg_type(msg_type, message, ctx)?;
            self.pqc
                .mldsa_verify(
                    mldsa_kind(param_set),
                    pub_key,
                    msg_type,
                    message,
                    ctx,
                    signature,
                )
                .await
        }
        .await;

        outcome
    }
}

#[cfg_attr(feature = "bulk_crypto", allow(unreachable_code))]
impl HsmMlKem for UnoHsmPal {
    async fn mlkem_encaps_in_place(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        pub_key_ciphertext: &mut HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let mut m = [0u8; MLDSA_SEED_LEN];
        let result = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            self.rng_fill_bytes(io, &mut m)?;
            self.pqc
                .with_engine(async |engine| {
                    engine
                        .mlkem_encaps_in_place(
                            mlkem_kind(param_set),
                            pub_key_ciphertext,
                            &m,
                            shared_secret,
                        )
                        .await
                })
                .await
        }
        .await;
        m.fill(0);
        result
    }

    async fn mlkem_gen_key(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        seed: &mut HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // Bracketed so validation and RNG failures still reach the closing
        // mark; see `mldsa_gen_key`.
        let outcome: HsmResult<()> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            // `output` is the public key followed by the expanded private key.
            let pub_len = param_set.pub_key_len();
            if seed.len() != MLKEM_SEED_LEN || output.len() != pub_len + param_set.sec_key_len() {
                return Err(HsmError::InvalidArg);
            }
            let (pub_key, sec_key) = output.split_at_mut(pub_len);

            // Same reasoning as ML-DSA: the seed pair is the private key and an
            // FP core has no entropy source, so it is drawn here.
            self.rng.fill_bytes(seed)?;

            self.pqc
                .mlkem_gen_key(mlkem_kind(param_set), seed, pub_key, sec_key)
                .await
        }
        .await;

        outcome
    }

    async fn mlkem_encaps(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        pub_key: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // Bracketed so a failed RNG draw still reaches the closing mark.
        let outcome: HsmResult<()> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            // `output` is the shared secret followed by the ciphertext.
            if output.len() != MLKEM_SHARED_SECRET_LEN + param_set.ciphertext_len() {
                return Err(HsmError::InvalidArg);
            }
            let (shared_secret, ciphertext) = output.split_at_mut(MLKEM_SHARED_SECRET_LEN);

            // Encapsulation randomness, drawn here for the same reason as the
            // seeds: an FP core has no entropy source.
            let mut m = [0u8; 32];
            {
                // SAFETY: `m` is a local of exactly the length the RNG driver
                // fills; `from_raw_mut` only re-types it.
                let dma = unsafe { HsmDmaBuf::from_raw_mut(&mut m[..]) };
                self.rng.fill_bytes(dma)?;
            }

            let result = self
                .pqc
                .mlkem_encaps(
                    mlkem_kind(param_set),
                    pub_key,
                    &m,
                    ciphertext,
                    shared_secret,
                )
                .await;

            // The randomness determines the shared secret; do not leave it on
            // the stack for the next caller.
            m.fill(0);
            result
        }
        .await;

        outcome
    }

    async fn mlkem_decaps(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        sec_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        // Bracketed so the `bulk_crypto` refusal still reaches the closing
        // mark; see `mldsa_gen_key`.
        let outcome: HsmResult<()> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            self.pqc
                .mlkem_decaps(mlkem_kind(param_set), sec_key, ciphertext, shared_secret)
                .await
        }
        .await;

        outcome
    }
}

/// Length of the ML-KEM seed pair `(d ‖ z)`.
const MLKEM_SEED_LEN: usize = 64;
