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
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaParam;
use tsra_fw_hsm_pal_traits::HsmMlDsaPct;
use tsra_fw_hsm_pal_traits::HsmMlKem;
use tsra_fw_hsm_pal_traits::HsmMlKemParam;
use tsra_fw_hsm_pal_traits::HsmMlKemPct;
use tsra_fw_hsm_pal_traits::HsmMlSeedSrc;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::MLKEM_SEED_LEN;
use tsra_fw_hsm_pal_traits::MLKEM_SHARED_SECRET_LEN;
use tsra_fw_uno_drivers_pqc::mldsa_check_msg;
use tsra_fw_uno_trace::tracing::*;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// The vault key kind the PQC driver, and the FP core behind it, name an
/// ML-DSA parameter set by.
fn mldsa_kind(param: HsmMlDsaParam) -> HsmVaultKeyKind {
    match param {
        HsmMlDsaParam::MlDsa44 => HsmVaultKeyKind::MlDsa44Seed,
        HsmMlDsaParam::MlDsa65 => HsmVaultKeyKind::MlDsa65Seed,
        HsmMlDsaParam::MlDsa87 => HsmVaultKeyKind::MlDsa87Seed,
    }
}

/// The vault key kind the PQC driver, and the FP core behind it, name an
/// ML-KEM parameter set by.
fn mlkem_kind(param: HsmMlKemParam) -> HsmVaultKeyKind {
    match param {
        HsmMlKemParam::MlKem512 => HsmVaultKeyKind::MlKem512Seed,
        HsmMlKemParam::MlKem768 => HsmVaultKeyKind::MlKem768Seed,
        HsmMlKemParam::MlKem1024 => HsmVaultKeyKind::MlKem1024Seed,
    }
}

/// Check the message type and lengths before query returns or RNG draws.
fn check_msg(msg: &HsmMlDsaMsg<'_>) -> HsmResult<()> {
    mldsa_check_msg(msg.msg_type(), msg.message(), msg.ctx())
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
/// parameter set — which is why `param` has to be carried alongside it.
const MLDSA_SEED_LEN: usize = 32;

// With `bulk_crypto` each method returns before reaching the PQC driver; see
// the module docs.
#[cfg_attr(feature = "bulk_crypto", allow(unreachable_code, unused_assignments))]
impl HsmMlDsa for UnoHsmPal {
    /// PCTs are deferred: `pct` is accepted but not run; see
    /// <https://github.com/TesseraHSM/tessera-sw/issues/118>.
    async fn mldsa_gen_keypair(
        &self,
        _io: &UnoHsmIo,
        param: HsmMlDsaParam,
        seed_src: HsmMlSeedSrc,
        _pct: HsmMlDsaPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        // Bracketed so an early `?` cannot skip the closing mark: every
        // exit, error or not, leaves through the await below.
        let outcome: HsmResult<(usize, usize)> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            let sk_len = param.sk_len();
            let pk_len = param.pk_len();
            // Validated in both modes, so the error does not depend on `out`.
            if seed.len() != MLDSA_SEED_LEN {
                error!(
                    "pqc",
                    HsmError::InvalidArg,
                    "pal: mldsa_gen_keypair bad seed_len={} (want {})",
                    seed.len(),
                    MLDSA_SEED_LEN
                );
                return Err(HsmError::InvalidArg);
            }
            let Some((sk, pk)) = out else {
                return Ok((sk_len, pk_len));
            };
            // Validate before handing anything to the driver, so buffer-size
            // bugs surface here rather than as a malformed FP request.
            if sk.len() < sk_len || pk.len() < pk_len {
                error!(
                    "pqc",
                    HsmError::InvalidArg,
                    "pal: mldsa_gen_keypair short buffers sk_len={} (want {}) pk_len={} (want {})",
                    sk.len(),
                    sk_len,
                    pk.len(),
                    pk_len
                );
                return Err(HsmError::InvalidArg);
            }

            // A fresh seed is drawn here, not on FP. The seed *is* the
            // private key, and an FP core has no entropy source of its own --
            // the device's certified TRNG belongs to this core. FP receives
            // the seed and derives the key pair. Both the seed and the
            // expanded secret key come back so the HSM can mask them
            // together, which is what lets signing skip the derivation
            // entirely.
            if seed_src == HsmMlSeedSrc::Random {
                self.rng.fill_bytes(seed)?;
            }

            self.pqc
                .mldsa_gen_key(
                    mldsa_kind(param),
                    seed,
                    &mut pk[..pk_len],
                    &mut sk[..sk_len],
                )
                .await?;
            Ok((sk_len, pk_len))
        }
        .await;

        outcome
    }

    async fn mldsa_sign(
        &self,
        _io: &UnoHsmIo,
        param: HsmMlDsaParam,
        sk: &HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
        sig: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // Bracketed so a failed RNG draw still reaches the closing mark.
        let outcome: HsmResult<usize> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg(&msg)?;
            let sig_len = param.sig_len();
            if sk.len() != param.sk_len() {
                return Err(HsmError::InvalidArg);
            }
            let Some(sig) = sig else {
                return Ok(sig_len);
            };
            if sig.len() < sig_len {
                return Err(HsmError::InvalidArg);
            }
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
                    mldsa_kind(param),
                    sk,
                    &rnd,
                    msg.msg_type(),
                    msg.message(),
                    msg.ctx(),
                    &mut sig[..sig_len],
                )
                .await;

            // The randomness is not a long-term secret, but it is signing input;
            // do not leave it on the stack for the next caller.
            rnd.fill(0);
            result.map(|()| sig_len)
        }
        .await;

        outcome
    }

    async fn mldsa_sign_in_place(
        &self,
        io: &UnoHsmIo,
        param: HsmMlDsaParam,
        sk_sig: &mut HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
    ) -> HsmResult<usize> {
        let mut rnd = [0u8; MLDSA_SEED_LEN];
        let result = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg(&msg)?;
            if hedged(hedge) {
                self.rng_fill_bytes(io, &mut rnd)?;
            }
            self.pqc
                .with_engine(async |engine| {
                    engine
                        .mldsa_sign_in_place(
                            mldsa_kind(param),
                            sk_sig,
                            &rnd,
                            msg.msg_type(),
                            msg.message(),
                            msg.ctx(),
                        )
                        .await
                })
                .await?;
            Ok(param.sig_len())
        }
        .await;
        rnd.fill(0);
        result
    }

    async fn mldsa_verify(
        &self,
        _io: &UnoHsmIo,
        param: HsmMlDsaParam,
        pk: &HsmDmaBuf,
        msg: HsmMlDsaMsg<'_>,
        sig: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        // Bracketed so the `bulk_crypto` refusal still reaches the closing
        // mark; see `mldsa_gen_keypair`.
        let outcome: HsmResult<bool> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            check_msg(&msg)?;
            self.pqc
                .mldsa_verify(
                    mldsa_kind(param),
                    pk,
                    msg.msg_type(),
                    msg.message(),
                    msg.ctx(),
                    sig,
                )
                .await
        }
        .await;

        outcome
    }
}

#[cfg_attr(
    feature = "bulk_crypto",
    allow(unreachable_code, unused_assignments, unused_variables)
)]
impl HsmMlKem for UnoHsmPal {
    /// PCTs are deferred: `pct` is accepted but not run; see
    /// <https://github.com/TesseraHSM/tessera-sw/issues/118>.
    async fn mlkem_gen_keypair(
        &self,
        _io: &UnoHsmIo,
        param: HsmMlKemParam,
        seed_src: HsmMlSeedSrc,
        _pct: HsmMlKemPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        // Bracketed so an early `?` cannot skip the closing mark; see
        // `mldsa_gen_keypair`.
        let outcome: HsmResult<(usize, usize)> = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            let sk_len = param.sk_len();
            let pk_len = param.pk_len();
            // Validated in both modes, so the error does not depend on `out`.
            if seed.len() != MLKEM_SEED_LEN {
                error!(
                    "pqc",
                    HsmError::InvalidArg,
                    "pal: mlkem_gen_keypair bad seed_len={} (want {})",
                    seed.len(),
                    MLKEM_SEED_LEN
                );
                return Err(HsmError::InvalidArg);
            }
            let Some((sk, pk)) = out else {
                return Ok((sk_len, pk_len));
            };
            if sk.len() < sk_len || pk.len() < pk_len {
                error!(
                    "pqc",
                    HsmError::InvalidArg,
                    "pal: mlkem_gen_keypair short buffers sk_len={} (want {}) pk_len={} (want {})",
                    sk.len(),
                    sk_len,
                    pk.len(),
                    pk_len
                );
                return Err(HsmError::InvalidArg);
            }

            // Same reasoning as ML-DSA: the seed pair is the private key and an
            // FP core has no entropy source, so it is drawn here.
            if seed_src == HsmMlSeedSrc::Random {
                self.rng.fill_bytes(seed)?;
            }

            self.pqc
                .mlkem_gen_key(
                    mlkem_kind(param),
                    seed,
                    &mut pk[..pk_len],
                    &mut sk[..sk_len],
                )
                .await?;
            Ok((sk_len, pk_len))
        }
        .await;

        outcome
    }

    async fn mlkem_encaps(
        &self,
        io: &UnoHsmIo,
        param: HsmMlKemParam,
        pk: &HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        // Refused before the query return, so both modes agree.
        #[cfg(feature = "bulk_crypto")]
        return Err(HsmError::UnsupportedCmd);
        let ct_len = param.ct_len();
        let Some((ct, ss)) = out else {
            return Ok((ct_len, MLKEM_SHARED_SECRET_LEN));
        };
        if ct.len() < ct_len || ss.len() < MLKEM_SHARED_SECRET_LEN {
            return Err(HsmError::InvalidArg);
        }
        // Encapsulation randomness, drawn here for the same reason as the
        // seeds: an FP core has no entropy source.
        let mut m = [0u8; MLDSA_SEED_LEN];
        let result = async {
            self.rng_fill_bytes(io, &mut m)?;
            self.pqc
                .mlkem_encaps(
                    mlkem_kind(param),
                    pk,
                    &m,
                    &mut ct[..ct_len],
                    &mut ss[..MLKEM_SHARED_SECRET_LEN],
                )
                .await?;
            Ok((ct_len, MLKEM_SHARED_SECRET_LEN))
        }
        .await;
        // The randomness determines the shared secret; do not leave it on
        // the stack for the next caller.
        m.fill(0);
        result
    }

    async fn mlkem_encaps_in_place(
        &self,
        io: &UnoHsmIo,
        param: HsmMlKemParam,
        pk_ct: &mut HsmDmaBuf,
        ss: &mut HsmDmaBuf,
    ) -> HsmResult<(usize, usize)> {
        let pk_len = param.pk_len();
        if pk_ct.len() < pk_len || ss.len() < MLKEM_SHARED_SECRET_LEN {
            return Err(HsmError::InvalidArg);
        }
        let mut m = [0u8; MLDSA_SEED_LEN];
        let result = async {
            #[cfg(feature = "bulk_crypto")]
            return Err(HsmError::UnsupportedCmd);
            self.rng_fill_bytes(io, &mut m)?;
            self.pqc
                .with_engine(async |engine| {
                    engine
                        .mlkem_encaps_in_place(
                            mlkem_kind(param),
                            &mut pk_ct[..pk_len],
                            &m,
                            &mut ss[..MLKEM_SHARED_SECRET_LEN],
                        )
                        .await
                })
                .await?;
            Ok((param.ct_len(), MLKEM_SHARED_SECRET_LEN))
        }
        .await;
        m.fill(0);
        result
    }

    async fn mlkem_decaps(
        &self,
        _io: &UnoHsmIo,
        param: HsmMlKemParam,
        sk: &HsmDmaBuf,
        ct: &HsmDmaBuf,
        ss: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // Refused before the query return, so both modes agree.
        #[cfg(feature = "bulk_crypto")]
        return Err(HsmError::UnsupportedCmd);
        let Some(ss) = ss else {
            return Ok(MLKEM_SHARED_SECRET_LEN);
        };
        if ss.len() < MLKEM_SHARED_SECRET_LEN {
            return Err(HsmError::InvalidArg);
        }
        let outcome: HsmResult<usize> = async {
            self.pqc
                .mlkem_decaps(
                    mlkem_kind(param),
                    sk,
                    ct,
                    &mut ss[..MLKEM_SHARED_SECRET_LEN],
                )
                .await?;
            Ok(MLKEM_SHARED_SECRET_LEN)
        }
        .await;

        outcome
    }
}
