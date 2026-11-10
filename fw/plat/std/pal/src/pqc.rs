// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmMlDsa`] and [`HsmMlKem`] for the std PAL.
//!
//! Thin layer over [`StdPqc`](crate::drivers::pqc::StdPqc): it maps the
//! PAL parameter set onto its [`tsra_crypto`] variant, draws whatever entropy the
//! operation needs, and checks the caller's buffers. The arithmetic
//! itself lives in [`tsra_crypto`], and the driver dispatches it to a
//! worker thread.
//!
//! # Relationship to the hardware implementation
//!
//! On real hardware these are offloaded to a fastpath core running
//! `pqc_ml`. The std path deliberately uses an unrelated
//! implementation, so the known-answer and interop tests compare two
//! codebases rather than confirming one against itself. They agree on
//! bytes because both speak the FIPS 203 / 204 encodings.
//!
//! # Randomness
//!
//! Entropy is drawn here and passed down, mirroring Uno: there CP1 draws
//! it because the fastpath cores have no generator of their own. Signing
//! is therefore hedged on both platforms, so neither reproduces a
//! previous signature — tests must verify signatures rather than compare
//! them.
//!
//! The `cp` log is left untouched. It records cycle counts for hardware
//! latency analysis and the host has no cycle counter; marks here would
//! look like measurements without being any.

use tsra_crypto::MlDsaVariant;
use tsra_crypto::MlKemVariant;
use tsra_crypto::MLDSA_SEED_LEN;
use tsra_crypto::MLKEM_SEED_LEN;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParam;
use tsra_fw_hsm_pal_traits::HsmMlDsaPct;
use tsra_fw_hsm_pal_traits::HsmMlKem;
use tsra_fw_hsm_pal_traits::HsmMlKemParam;
use tsra_fw_hsm_pal_traits::HsmMlKemPct;
use tsra_fw_hsm_pal_traits::HsmMlSeedSrc;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::MLKEM_SHARED_SECRET_LEN;
use zeroize::Zeroizing;

use crate::StdHsmIo;
use crate::StdHsmPal;

/// Map an ML-DSA parameter set onto its [`tsra_crypto`] variant.
fn mldsa_variant(param: HsmMlDsaParam) -> MlDsaVariant {
    match param {
        HsmMlDsaParam::MlDsa44 => MlDsaVariant::MlDsa44,
        HsmMlDsaParam::MlDsa65 => MlDsaVariant::MlDsa65,
        HsmMlDsaParam::MlDsa87 => MlDsaVariant::MlDsa87,
    }
}

/// Map an ML-KEM parameter set onto its [`tsra_crypto`] variant.
fn mlkem_variant(param: HsmMlKemParam) -> MlKemVariant {
    match param {
        HsmMlKemParam::MlKem512 => MlKemVariant::MlKem512,
        HsmMlKemParam::MlKem768 => MlKemVariant::MlKem768,
        HsmMlKemParam::MlKem1024 => MlKemVariant::MlKem1024,
    }
}

/// Copy `src` into `dst`, rejecting a length the caller got wrong.
///
/// Output buffers are sized by the handler from the parameter set, so a
/// mismatch is a caller bug rather than bad input — but the PAL sits on
/// a trust boundary, so it is reported rather than panicked on.
fn write_exact(dst: &mut [u8], src: &[u8]) -> HsmResult<()> {
    if dst.len() != src.len() {
        return Err(HsmError::InvalidArg);
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// Whether `msg` is an external `μ` rather than the message itself.
///
/// # Errors
///
/// - [`HsmError::UnsupportedCmd`] — the pre-hash types, currently
///   unsupported.
fn external_mu(msg: &HsmMlDsaMsg<'_>) -> HsmResult<bool> {
    match msg.msg_type() {
        HsmMlDsaMsgType::Pure => Ok(false),
        HsmMlDsaMsgType::ExternalMu => Ok(true),
        HsmMlDsaMsgType::PreHash(_) | HsmMlDsaMsgType::HashMsg(_) => Err(HsmError::UnsupportedCmd),
    }
}

/// Whether to sign deterministically: the std PAL can always draw
/// randomness, so it hedges unless the caller requires deterministic signing.
fn deterministic(hedge: HsmMlDsaHedge) -> bool {
    match hedge {
        HsmMlDsaHedge::Preferred | HsmMlDsaHedge::Required => false,
        HsmMlDsaHedge::Deterministic => true,
    }
}

impl HsmMlDsa for StdHsmPal {
    /// PCTs are deferred: `pct` is accepted but not run; see
    /// <https://github.com/TesseraHSM/tessera-sw/issues/117>.
    async fn mldsa_gen_keypair(
        &self,
        io: &StdHsmIo,
        param: HsmMlDsaParam,
        seed_src: HsmMlSeedSrc,
        _pct: HsmMlDsaPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let variant = mldsa_variant(param);
        let sk_len = variant.sec_key_len();
        let pk_len = variant.pub_key_len();
        // Validated in both modes, so the error does not depend on `out`.
        if seed.len() != MLDSA_SEED_LEN {
            return Err(HsmError::InvalidArg);
        }
        let Some((sk, pk)) = out else {
            return Ok((sk_len, pk_len));
        };
        if sk.len() < sk_len || pk.len() < pk_len {
            return Err(HsmError::InvalidArg);
        }
        // A fresh seed *is* the private key, so it comes from the HSM's
        // generator rather than the caller.
        if seed_src == HsmMlSeedSrc::Random {
            self.rng_fill_bytes(io, seed)?;
        }

        let (pk_bytes, sk_bytes) = self.pqc.mldsa_keygen(variant, seed).await?;
        write_exact(&mut pk[..pk_len], &pk_bytes)?;
        write_exact(&mut sk[..sk_len], &sk_bytes)?;
        Ok((sk_len, pk_len))
    }

    async fn mldsa_sign(
        &self,
        _io: &StdHsmIo,
        param: HsmMlDsaParam,
        sk: &HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
        sig: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let variant = mldsa_variant(param);
        let external_mu = external_mu(&msg)?;
        let sig_len = variant.sig_len();
        if sk.len() != variant.sec_key_len() {
            return Err(HsmError::InvalidArg);
        }
        let Some(sig) = sig else {
            return Ok(sig_len);
        };
        if sig.len() < sig_len {
            return Err(HsmError::InvalidArg);
        }

        // Unlike the seed, the per-signature randomness is not drawn here:
        // it never leaves the crypto layer, so that layer draws it, exactly
        // as it does the ECDSA nonce.
        let result = self
            .pqc
            .mldsa_sign(
                variant,
                sk,
                external_mu,
                deterministic(hedge),
                msg.message(),
                msg.ctx(),
            )
            .await?;
        write_exact(&mut sig[..sig_len], &result)?;
        Ok(sig_len)
    }

    async fn mldsa_sign_in_place(
        &self,
        _io: &StdHsmIo,
        param: HsmMlDsaParam,
        sk_sig: &mut HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
    ) -> HsmResult<usize> {
        let variant = mldsa_variant(param);
        let external_mu = external_mu(&msg)?;
        let sig_len = variant.sig_len();
        let key_at = sk_sig
            .len()
            .checked_sub(variant.sec_key_len())
            .ok_or(HsmError::InvalidArg)?;
        if sk_sig.len() < sig_len {
            return Err(HsmError::InvalidArg);
        }
        let result = self
            .pqc
            .mldsa_sign(
                variant,
                &sk_sig[key_at..],
                external_mu,
                deterministic(hedge),
                msg.message(),
                msg.ctx(),
            )
            .await?;
        write_exact(&mut sk_sig[..sig_len], &result)?;
        Ok(sig_len)
    }

    async fn mldsa_verify(
        &self,
        _io: &StdHsmIo,
        param: HsmMlDsaParam,
        pk: &HsmDmaBuf,
        msg: HsmMlDsaMsg<'_>,
        sig: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        let variant = mldsa_variant(param);
        let external_mu = external_mu(&msg)?;
        self.pqc
            .mldsa_verify(variant, pk, external_mu, msg.message(), msg.ctx(), sig)
            .await
    }
}

impl HsmMlKem for StdHsmPal {
    /// PCTs are deferred: `pct` is accepted but not run; see
    /// <https://github.com/TesseraHSM/tessera-sw/issues/117>.
    async fn mlkem_gen_keypair(
        &self,
        io: &StdHsmIo,
        param: HsmMlKemParam,
        seed_src: HsmMlSeedSrc,
        _pct: HsmMlKemPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let variant = mlkem_variant(param);
        let sk_len = variant.sec_key_len();
        let pk_len = variant.pub_key_len();
        // Validated in both modes, so the error does not depend on `out`.
        if seed.len() != MLKEM_SEED_LEN {
            return Err(HsmError::InvalidArg);
        }
        let Some((sk, pk)) = out else {
            return Ok((sk_len, pk_len));
        };
        if sk.len() < sk_len || pk.len() < pk_len {
            return Err(HsmError::InvalidArg);
        }
        if seed_src == HsmMlSeedSrc::Random {
            self.rng_fill_bytes(io, seed)?;
        }

        let (pk_bytes, sk_bytes) = self.pqc.mlkem_keygen(variant, seed).await?;
        let sk_bytes = Zeroizing::new(sk_bytes);
        write_exact(&mut pk[..pk_len], &pk_bytes)?;
        write_exact(&mut sk[..sk_len], &sk_bytes)?;
        Ok((sk_len, pk_len))
    }

    async fn mlkem_encaps(
        &self,
        _io: &StdHsmIo,
        param: HsmMlKemParam,
        pk: &HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let variant = mlkem_variant(param);
        let ct_len = variant.ciphertext_len();
        let Some((ct, ss)) = out else {
            return Ok((ct_len, MLKEM_SHARED_SECRET_LEN));
        };
        if pk.len() != variant.pub_key_len()
            || ct.len() < ct_len
            || ss.len() < MLKEM_SHARED_SECRET_LEN
        {
            return Err(HsmError::InvalidArg);
        }

        // As with signing, the encapsulation message never leaves the crypto
        // layer, so that layer draws it.
        let (ct_bytes, ss_bytes) = self.pqc.mlkem_encapsulate(variant, pk).await?;
        let ss_bytes = Zeroizing::new(ss_bytes);
        write_exact(&mut ct[..ct_len], &ct_bytes)?;
        write_exact(&mut ss[..MLKEM_SHARED_SECRET_LEN], &ss_bytes)?;
        Ok((ct_len, MLKEM_SHARED_SECRET_LEN))
    }

    async fn mlkem_encaps_in_place(
        &self,
        _io: &StdHsmIo,
        param: HsmMlKemParam,
        pk_ct: &mut HsmDmaBuf,
        ss: &mut HsmDmaBuf,
    ) -> HsmResult<(usize, usize)> {
        let variant = mlkem_variant(param);
        let pk_len = variant.pub_key_len();
        let ct_len = variant.ciphertext_len();
        if pk_ct.len() < pk_len || ss.len() < MLKEM_SHARED_SECRET_LEN {
            return Err(HsmError::InvalidArg);
        }
        let (ct, ss_bytes) = self
            .pqc
            .mlkem_encapsulate(variant, &pk_ct[..pk_len])
            .await?;
        let ss_bytes = Zeroizing::new(ss_bytes);
        write_exact(&mut pk_ct[..ct_len], &ct)?;
        write_exact(&mut ss[..MLKEM_SHARED_SECRET_LEN], &ss_bytes)?;
        Ok((ct_len, MLKEM_SHARED_SECRET_LEN))
    }

    async fn mlkem_decaps(
        &self,
        _io: &StdHsmIo,
        param: HsmMlKemParam,
        sk: &HsmDmaBuf,
        ct: &HsmDmaBuf,
        ss: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let Some(ss) = ss else {
            return Ok(MLKEM_SHARED_SECRET_LEN);
        };
        let variant = mlkem_variant(param);
        if sk.len() != variant.sec_key_len()
            || ct.len() != variant.ciphertext_len()
            || ss.len() < MLKEM_SHARED_SECRET_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        let ss_bytes = Zeroizing::new(self.pqc.mlkem_decapsulate(variant, sk, ct).await?);
        write_exact(&mut ss[..MLKEM_SHARED_SECRET_LEN], &ss_bytes)?;
        Ok(MLKEM_SHARED_SECRET_LEN)
    }
}
#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;
    use tsra_crypto::HashAlgo;
    use tsra_crypto::Hasher;
    use tsra_crypto::ImportableKey;
    use tsra_crypto::MlDsaAlgo;
    use tsra_crypto::MlDsaPrivateKey;
    use tsra_crypto::MlDsaPublicKey;
    use tsra_crypto::Signer;
    use tsra_fw_hsm_pal_traits::HsmAlloc;
    use tsra_fw_hsm_pal_traits::HsmHashAlgo;

    use super::*;
    use crate::HsmPartId;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// ML-DSA `(param_set, pk, sk, sig)` lengths, FIPS 204.
    const MLDSA_SETS: [(HsmMlDsaParam, usize, usize, usize); 3] = [
        (HsmMlDsaParam::MlDsa44, 1312, 2560, 2420),
        (HsmMlDsaParam::MlDsa65, 1952, 4032, 3309),
        (HsmMlDsaParam::MlDsa87, 2592, 4896, 4627),
    ];

    /// ML-KEM `(param_set, pk, sk, ct)` lengths, FIPS 203.
    const MLKEM_SETS: [(HsmMlKemParam, usize, usize, usize); 3] = [
        (HsmMlKemParam::MlKem512, 800, 1632, 768),
        (HsmMlKemParam::MlKem768, 1184, 2400, 1088),
        (HsmMlKemParam::MlKem1024, 1568, 3168, 1568),
    ];

    /// Shared-secret length, identical across ML-KEM parameter sets.
    const SS_LEN: usize = 32;

    fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    #[allow(unsafe_code)]
    fn dma(bytes: &[u8]) -> &HsmDmaBuf {
        // SAFETY: the std PAL emulates DMA without memory-region restrictions.
        unsafe { HsmDmaBuf::from_raw(bytes) }
    }

    #[allow(unsafe_code)]
    fn dma_mut(bytes: &mut [u8]) -> &mut HsmDmaBuf {
        // SAFETY: the std PAL emulates DMA without memory-region restrictions.
        unsafe { HsmDmaBuf::from_raw_mut(bytes) }
    }

    /// An ML-DSA input of `msg_type` with `ctx || message` laid out
    /// contiguously, as a handler passes it. Leaked so call sites stay
    /// expressions; tests only.
    fn msg(msg_type: HsmMlDsaMsgType, message: &[u8], ctx: &[u8]) -> HsmMlDsaMsg<'static> {
        let data = dma(Vec::leak([ctx, message].concat()));
        HsmMlDsaMsg::new(msg_type, u8::try_from(ctx.len()).unwrap(), data).unwrap()
    }

    #[tokio::test]
    async fn overlapping_outputs_consume_pqc_inputs_first() {
        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (pal, io) = pal_and_io();
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .unwrap();
            let storage = pal.dma_alloc(&io, sk_len + 17).unwrap();
            for prefix in [0, 17] {
                let buffer = &mut storage[..sk_len + prefix];
                buffer.fill(0xA5);
                buffer[prefix..].copy_from_slice(&sk);
                pal.mldsa_sign_in_place(
                    &io,
                    param_set,
                    buffer,
                    HsmMlDsaHedge::Preferred,
                    msg(HsmMlDsaMsgType::Pure, b"m", b"ctx"),
                )
                .await
                .unwrap();
                assert!(pal
                    .mldsa_verify(
                        &io,
                        param_set,
                        dma(&pk),
                        msg(HsmMlDsaMsgType::Pure, b"m", b"ctx"),
                        &buffer[..sig_len]
                    )
                    .await
                    .unwrap());
            }
        }

        for (param_set, pk_len, sk_len, ct_len) in MLKEM_SETS {
            let (pal, io) = pal_and_io();
            let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
            mlkem_gen_keypair(&pal, &io, param_set, &mut seed, &mut keys)
                .await
                .unwrap();
            let (pk, sk) = keys.split_at(pk_len);
            let buffer = pal.dma_alloc(&io, pk_len.max(ct_len)).unwrap();
            buffer[..pk_len].copy_from_slice(dma(pk));
            let mut ss = [0u8; SS_LEN];
            pal.mlkem_encaps_in_place(&io, param_set, buffer, dma_mut(&mut ss))
                .await
                .unwrap();
            let mut decaps = [0u8; SS_LEN];
            pal.mlkem_decaps(
                &io,
                param_set,
                dma(sk),
                &buffer[..ct_len],
                Some(dma_mut(&mut decaps)),
            )
            .await
            .unwrap();
            assert_eq!(ss, decaps);
        }
    }

    #[tokio::test]
    async fn in_place_pqc_rejects_bad_buffer_lengths_without_writing() {
        let (pal, io) = pal_and_io();
        let buffer = pal.dma_alloc(&io, 5000).unwrap();
        buffer.fill(0x5a);
        for key_len in [0, 2559] {
            assert_eq!(
                pal.mldsa_sign_in_place(
                    &io,
                    HsmMlDsaParam::MlDsa44,
                    &mut buffer[..key_len],
                    HsmMlDsaHedge::Preferred,
                    msg(HsmMlDsaMsgType::Pure, b"", b"")
                )
                .await,
                Err(HsmError::InvalidArg),
            );
        }
        let mut ss = [0x5a; SS_LEN + 1];
        for (key_len, secret_len) in [(0, SS_LEN), (799, SS_LEN), (800, SS_LEN - 1), (800, 0)] {
            assert_eq!(
                pal.mlkem_encaps_in_place(
                    &io,
                    HsmMlKemParam::MlKem512,
                    &mut buffer[..key_len],
                    dma_mut(&mut ss[..secret_len]),
                )
                .await,
                Err(HsmError::InvalidArg),
            );
        }
        assert!(buffer.iter().all(|byte| *byte == 0x5a));
        assert_eq!(ss, [0x5a; SS_LEN + 1]);
    }

    /// Generate, sign and verify: the signature the PAL produces must
    /// verify under the public key it produced, and must stop verifying
    /// once the message changes.
    #[tokio::test]
    async fn mldsa_round_trip_verifies_and_rejects_tampering() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");
            assert_ne!(
                seed, [0u8; MLDSA_SEED_LEN],
                "{param_set:?}: seed left unset"
            );

            let mut sig = vec![0u8; sig_len];
            pal.mldsa_sign(
                &io,
                param_set,
                dma(&sk),
                HsmMlDsaHedge::Preferred,
                msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                Some(dma_mut(&mut sig)),
            )
            .await
            .expect("sign");

            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                    dma(&sig)
                )
                .await
                .expect("verify"),
                "{param_set:?}: own signature failed to verify"
            );
            assert!(
                !pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"messagf", b"ctx"),
                    dma(&sig)
                )
                .await
                .expect("verify"),
                "{param_set:?}: signature verified for the wrong message"
            );
            // The context string is bound into the signature, so changing
            // it must invalidate it just as changing the message does.
            assert!(
                !pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"message", b"other"),
                    dma(&sig)
                )
                .await
                .expect("verify"),
                "{param_set:?}: signature verified under the wrong context"
            );
        }
    }

    /// A signature that is not even well-formed is a failed
    /// verification, not an error: the caller asked whether these bytes
    /// authenticate the message.
    #[tokio::test]
    async fn mldsa_verify_reports_false_for_garbage_signature() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");

            let garbage = vec![0xAAu8; sig_len];
            assert!(
                !pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"m", b""),
                    dma(&garbage)
                )
                .await
                .expect("verify must not error on a bad signature"),
                "{param_set:?}: garbage signature verified"
            );
        }
    }

    /// Generate an ML-KEM key pair into `keys` = `pk || sk`, as the older
    /// tests lay it out.
    async fn mlkem_gen_keypair(
        pal: &StdHsmPal,
        io: &StdHsmIo,
        param: HsmMlKemParam,
        seed: &mut [u8],
        keys: &mut [u8],
    ) -> HsmResult<()> {
        let (pk, sk) = keys.split_at_mut(param.pk_len());
        let lens = pal
            .mlkem_gen_keypair(
                io,
                param,
                HsmMlSeedSrc::Random,
                HsmMlKemPct::None,
                dma_mut(seed),
                Some((dma_mut(sk), dma_mut(pk))),
            )
            .await?;
        assert_eq!(lens, (param.sk_len(), param.pk_len()));
        Ok(())
    }

    /// A seed of the wrong length is refused in both modes, and output
    /// buffers too short for either key are refused before the seed is
    /// drawn, so nothing is written.
    #[tokio::test]
    async fn mlkem_gen_keypair_rejects_bad_buffers() {
        let (pal, io) = pal_and_io();
        let (param, pk_len, sk_len, _) = MLKEM_SETS[0];
        let mut short_seed = [0x5a; MLKEM_SEED_LEN - 1];
        assert_eq!(
            pal.mlkem_gen_keypair(
                &io,
                param,
                HsmMlSeedSrc::Random,
                HsmMlKemPct::None,
                dma_mut(&mut short_seed),
                None
            )
            .await,
            Err(HsmError::InvalidArg)
        );
        for (sk_size, pk_size) in [(sk_len - 1, pk_len), (sk_len, pk_len - 1)] {
            let (mut seed, mut sk, mut pk) = (
                [0x5a; MLKEM_SEED_LEN],
                vec![0x5a; sk_size],
                vec![0x5a; pk_size],
            );
            assert_eq!(
                pal.mlkem_gen_keypair(
                    &io,
                    param,
                    HsmMlSeedSrc::Random,
                    HsmMlKemPct::None,
                    dma_mut(&mut seed),
                    Some((dma_mut(&mut sk), dma_mut(&mut pk))),
                )
                .await,
                Err(HsmError::InvalidArg),
                "sk={sk_size} pk={pk_size}"
            );
            assert!(seed.iter().chain(&sk).chain(&pk).all(|b| *b == 0x5a));
        }
    }

    /// Query mode returns the key lengths without touching the seed, and a
    /// caller-supplied seed reproduces the key pair it was generated with.
    #[tokio::test]
    async fn mlkem_gen_keypair_query_and_caller_seed() {
        let (pal, io) = pal_and_io();
        for (param, pk_len, sk_len, _) in MLKEM_SETS {
            let mut seed = [0x5a; MLKEM_SEED_LEN];
            assert_eq!(
                pal.mlkem_gen_keypair(
                    &io,
                    param,
                    HsmMlSeedSrc::Random,
                    HsmMlKemPct::None,
                    dma_mut(&mut seed),
                    None
                )
                .await,
                Ok((sk_len, pk_len))
            );
            assert_eq!(seed, [0x5a; MLKEM_SEED_LEN], "{param:?}: query drew a seed");

            let mut keys = vec![0u8; pk_len + sk_len];
            mlkem_gen_keypair(&pal, &io, param, &mut seed, &mut keys)
                .await
                .expect("gen");
            let (mut again_sk, mut again_pk) = (vec![0u8; sk_len + 1], vec![0u8; pk_len + 1]);
            let seed_before = seed;
            assert_eq!(
                pal.mlkem_gen_keypair(
                    &io,
                    param,
                    HsmMlSeedSrc::Caller,
                    HsmMlKemPct::None,
                    dma_mut(&mut seed),
                    Some((dma_mut(&mut again_sk), dma_mut(&mut again_pk))),
                )
                .await,
                Ok((sk_len, pk_len))
            );
            assert_eq!(seed, seed_before, "{param:?}: caller seed changed");
            assert_eq!(&again_pk[..pk_len], &keys[..pk_len], "{param:?}: pk");
            assert_eq!(&again_sk[..sk_len], &keys[pk_len..], "{param:?}: sk");
        }
    }

    /// Encaps and decaps answer a query (`None`) with the buffer sizes,
    /// refuse short buffers without writing, and accept longer ones,
    /// writing only the reported prefix.
    #[tokio::test]
    async fn mlkem_encaps_decaps_query_and_buffer_sizes() {
        let (pal, io) = pal_and_io();
        let (param_set, pk_len, sk_len, ct_len) = MLKEM_SETS[0];
        let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
        mlkem_gen_keypair(&pal, &io, param_set, &mut seed, &mut keys)
            .await
            .expect("gen_key");
        let (pk, sk) = keys.split_at(pk_len);

        assert_eq!(
            pal.mlkem_encaps(&io, param_set, dma(pk), None).await,
            Ok((ct_len, SS_LEN))
        );
        assert_eq!(
            pal.mlkem_decaps(&io, param_set, dma(sk), dma(&[]), None)
                .await,
            Ok(SS_LEN)
        );

        for (ct_buf_len, ss_buf_len) in [(ct_len - 1, SS_LEN), (ct_len, SS_LEN - 1), (0, 0)] {
            let (mut ct, mut ss) = (vec![0x5a; ct_buf_len], vec![0x5a; ss_buf_len]);
            assert_eq!(
                pal.mlkem_encaps(
                    &io,
                    param_set,
                    dma(pk),
                    Some((dma_mut(&mut ct), dma_mut(&mut ss)))
                )
                .await,
                Err(HsmError::InvalidArg),
                "ct={ct_buf_len} ss={ss_buf_len}"
            );
            assert!(ct.iter().chain(&ss).all(|b| *b == 0x5a));
        }

        let (mut ct, mut ss) = (vec![0x5a; ct_len + 3], vec![0x5a; SS_LEN + 3]);
        assert_eq!(
            pal.mlkem_encaps(
                &io,
                param_set,
                dma(pk),
                Some((dma_mut(&mut ct), dma_mut(&mut ss)))
            )
            .await,
            Ok((ct_len, SS_LEN))
        );
        assert_eq!(&ct[ct_len..], &[0x5a; 3]);
        assert_eq!(&ss[SS_LEN..], &[0x5a; 3]);

        let mut short = [0x5a; SS_LEN - 1];
        assert_eq!(
            pal.mlkem_decaps(
                &io,
                param_set,
                dma(sk),
                dma(&ct[..ct_len]),
                Some(dma_mut(&mut short))
            )
            .await,
            Err(HsmError::InvalidArg)
        );
        assert_eq!(short, [0x5a; SS_LEN - 1]);
        let mut long = [0x5a; SS_LEN + 3];
        assert_eq!(
            pal.mlkem_decaps(
                &io,
                param_set,
                dma(sk),
                dma(&ct[..ct_len]),
                Some(dma_mut(&mut long))
            )
            .await,
            Ok(SS_LEN)
        );
        assert_eq!(&long[..SS_LEN], &ss[..SS_LEN]);
        assert_eq!(&long[SS_LEN..], &[0x5a; 3]);
    }

    /// Encapsulate then decapsulate: both sides must derive the same
    /// secret, and a corrupted ciphertext must yield a *different* secret
    /// rather than an error -- FIPS 203 implicit rejection.
    #[tokio::test]
    async fn mlkem_round_trip_agrees_and_implicitly_rejects() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, ct_len) in MLKEM_SETS {
            let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
            mlkem_gen_keypair(&pal, &io, param_set, &mut seed, &mut keys)
                .await
                .expect("gen_key");
            let (pk, sk) = keys.split_at(pk_len);

            let (mut ct, mut ss_enc) = (vec![0u8; ct_len], [0u8; SS_LEN]);
            pal.mlkem_encaps(
                &io,
                param_set,
                dma(pk),
                Some((dma_mut(&mut ct), dma_mut(&mut ss_enc))),
            )
            .await
            .expect("encaps");

            let mut ss_dec = [0u8; SS_LEN];
            pal.mlkem_decaps(
                &io,
                param_set,
                dma(sk),
                dma(&ct),
                Some(dma_mut(&mut ss_dec)),
            )
            .await
            .expect("decaps");
            assert_eq!(ss_enc, ss_dec, "{param_set:?}: shared secrets disagree");

            ct[0] ^= 1;
            let mut ss_rej = [0u8; SS_LEN];
            pal.mlkem_decaps(
                &io,
                param_set,
                dma(sk),
                dma(&ct),
                Some(dma_mut(&mut ss_rej)),
            )
            .await
            .expect("decaps must not fail on a corrupted ciphertext");
            assert_ne!(
                ss_enc, ss_rej,
                "{param_set:?}: corrupted ciphertext produced the real secret"
            );
        }
    }

    /// Signing is hedged unless the caller requires deterministic signing,
    /// as on Uno: signing the same message twice under the same key must not
    /// produce the same bytes, and both must verify.  A regression to
    /// deterministic signing would still verify, so only the inequality
    /// catches it.
    #[tokio::test]
    async fn mldsa_signing_is_hedged() {
        let (pal, io) = pal_and_io();

        for ((param_set, pk_len, sk_len, sig_len), hedge) in
            MLDSA_SETS.into_iter().flat_map(|set| {
                [
                    (set, HsmMlDsaHedge::Preferred),
                    (set, HsmMlDsaHedge::Required),
                ]
            })
        {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");

            let mut sigs = Vec::new();
            for _ in 0..2 {
                let mut sig = vec![0u8; sig_len];
                pal.mldsa_sign(
                    &io,
                    param_set,
                    dma(&sk),
                    hedge,
                    msg(HsmMlDsaMsgType::Pure, b"same message", b""),
                    Some(dma_mut(&mut sig)),
                )
                .await
                .expect("sign");
                assert!(
                    pal.mldsa_verify(
                        &io,
                        param_set,
                        dma(&pk),
                        msg(HsmMlDsaMsgType::Pure, b"same message", b""),
                        dma(&sig)
                    )
                    .await
                    .expect("verify"),
                    "{param_set:?}: hedged signature failed to verify"
                );
                sigs.push(sig);
            }
            assert_ne!(
                sigs[0], sigs[1],
                "{param_set:?}: {hedge:?} signing is deterministic; Uno signs hedged"
            );
        }
    }

    /// Deterministic signing is FIPS 204's all-zero-randomness variant: the
    /// same key and input give `tsra_crypto`'s deterministic signature
    /// whether the input is the message or its `μ`, in place too, and it
    /// verifies.
    #[tokio::test]
    async fn mldsa_deterministic_signing_repeats() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");
            let mu = MlDsaPublicKey::from_bytes(&pk)
                .and_then(|pk| HashAlgo::mldsa_mu(&pk, b"ctx"))
                .and_then(|mut algo| Hasher::hash_vec(&mut algo, b"message"))
                .expect("host mu");
            let expected = Signer::sign_vec(
                &mut MlDsaAlgo::new(b"ctx").unwrap().deterministic(),
                &MlDsaPrivateKey::from_bytes(&sk).unwrap(),
                b"message",
            )
            .unwrap();

            let inputs: [(HsmMlDsaMsgType, &[u8], &[u8]); 3] = [
                (HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                (HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                (HsmMlDsaMsgType::ExternalMu, &mu[..], b""),
            ];
            for (msg_type, message, ctx) in inputs {
                let mut sig = vec![0u8; sig_len];
                pal.mldsa_sign(
                    &io,
                    param_set,
                    dma(&sk),
                    HsmMlDsaHedge::Deterministic,
                    msg(msg_type, message, ctx),
                    Some(dma_mut(&mut sig)),
                )
                .await
                .expect("sign");
                assert_eq!(sig, expected, "{param_set:?}: {msg_type:?} signature");
            }

            let buffer = pal.dma_alloc(&io, sk_len).unwrap();
            buffer.copy_from_slice(&sk);
            pal.mldsa_sign_in_place(
                &io,
                param_set,
                buffer,
                HsmMlDsaHedge::Deterministic,
                msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
            )
            .await
            .expect("sign in place");
            assert_eq!(
                &buffer[..sig_len],
                &expected[..],
                "{param_set:?}: in-place signature"
            );
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                    dma(&expected)
                )
                .await
                .expect("verify"),
                "{param_set:?}: deterministic signature failed to verify"
            );
        }
    }

    /// An external `μ` computed on the host signs and verifies exactly as
    /// the message it was computed from: a signature over either verifies
    /// over the other, in place too, on every parameter set.
    #[tokio::test]
    async fn mldsa_external_mu_matches_pure() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");
            let mu = MlDsaPublicKey::from_bytes(&pk)
                .and_then(|pk| HashAlgo::mldsa_mu(&pk, b"ctx"))
                .and_then(|mut algo| Hasher::hash_vec(&mut algo, b"message"))
                .expect("host mu");

            let mut sig = vec![0u8; sig_len];
            pal.mldsa_sign(
                &io,
                param_set,
                dma(&sk),
                HsmMlDsaHedge::Preferred,
                msg(HsmMlDsaMsgType::ExternalMu, &mu, b""),
                Some(dma_mut(&mut sig)),
            )
            .await
            .expect("sign mu");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                    dma(&sig)
                )
                .await
                .expect("verify"),
                "{param_set:?}: signature over mu failed pure verification"
            );

            pal.mldsa_sign(
                &io,
                param_set,
                dma(&sk),
                HsmMlDsaHedge::Preferred,
                msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                Some(dma_mut(&mut sig)),
            )
            .await
            .expect("sign");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::ExternalMu, &mu, b""),
                    dma(&sig)
                )
                .await
                .expect("verify mu"),
                "{param_set:?}: pure signature failed verification over mu"
            );

            let buffer = pal.dma_alloc(&io, sk_len).unwrap();
            buffer.copy_from_slice(&sk);
            pal.mldsa_sign_in_place(
                &io,
                param_set,
                buffer,
                HsmMlDsaHedge::Preferred,
                msg(HsmMlDsaMsgType::ExternalMu, &mu, b""),
            )
            .await
            .expect("sign mu in place");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg(HsmMlDsaMsgType::Pure, b"message", b"ctx"),
                    &buffer[..sig_len]
                )
                .await
                .expect("verify"),
                "{param_set:?}: in-place signature over mu failed pure verification"
            );
        }
    }

    /// Malformed inputs never reach the PAL: an external `μ` is exactly
    /// 64 bytes with no context, the context fits in `data`, and a pre-hash
    /// input starts with its hash's OID (plus, for `PreHash`, exactly one
    /// digest).
    #[test]
    fn mldsa_msg_rejects_malformed_input() {
        let mu = [7u8; 65];
        let mut phm = HsmHashAlgo::Sha256.mldsa_oid().unwrap().to_vec();
        phm.extend_from_slice(&[0u8; 32]);
        let cases: [(HsmMlDsaMsgType, u8, &[u8]); 7] = [
            (HsmMlDsaMsgType::ExternalMu, 0, &mu[..63]),
            (HsmMlDsaMsgType::ExternalMu, 0, &mu[..]),
            (HsmMlDsaMsgType::ExternalMu, 1, &mu[..]),
            (HsmMlDsaMsgType::Pure, 4, b"ctx"),
            (HsmMlDsaMsgType::PreHash(HsmHashAlgo::Sha256), 0, &phm[..42]),
            (HsmMlDsaMsgType::PreHash(HsmHashAlgo::Sha384), 0, &phm),
            (HsmMlDsaMsgType::HashMsg(HsmHashAlgo::Sha1), 0, b"m"),
        ];
        for (msg_type, ctx_len, data) in cases {
            assert_eq!(
                HsmMlDsaMsg::new(msg_type, ctx_len, dma(data)).err(),
                Some(HsmError::InvalidArg),
                "{msg_type:?}, ctx_len={ctx_len}, {} B",
                data.len()
            );
        }
        let ok = HsmMlDsaMsg::new(HsmMlDsaMsgType::Pure, 3, dma(b"ctxmessage")).unwrap();
        assert_eq!(
            (&**ok.ctx(), &**ok.message()),
            (&b"ctx"[..], &b"message"[..])
        );
    }

    /// The pre-hash types are well formed but unsupported on the std PAL:
    /// every entry point, including the sign query, refuses them.
    #[tokio::test]
    async fn mldsa_rejects_prehash() {
        let (pal, io) = pal_and_io();
        let (param_set, pk_len, sk_len, sig_len) = MLDSA_SETS[0];
        let (mut seed, mut pk, mut sk) =
            ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
        pal.mldsa_gen_keypair(
            &io,
            param_set,
            HsmMlSeedSrc::Random,
            HsmMlDsaPct::None,
            dma_mut(&mut seed),
            Some((dma_mut(&mut sk), dma_mut(&mut pk))),
        )
        .await
        .expect("gen_key");

        let algo = HsmHashAlgo::Sha256;
        let mut phm = algo.mldsa_oid().unwrap().to_vec();
        phm.extend_from_slice(&[0u8; 32]);
        let mut sig = vec![0u8; sig_len];
        for input in [
            msg(HsmMlDsaMsgType::PreHash(algo), &phm, b"ctx"),
            msg(HsmMlDsaMsgType::HashMsg(algo), &phm[..12], b""),
        ] {
            let msg_type = input.msg_type();
            for out in [None, Some(dma_mut(&mut sig))] {
                assert_eq!(
                    pal.mldsa_sign(
                        &io,
                        param_set,
                        dma(&sk),
                        HsmMlDsaHedge::Preferred,
                        input,
                        out
                    )
                    .await,
                    Err(HsmError::UnsupportedCmd),
                    "{msg_type:?} sign"
                );
            }
            assert_eq!(
                pal.mldsa_verify(&io, param_set, dma(&pk), input, dma(&sig))
                    .await,
                Err(HsmError::UnsupportedCmd),
                "{msg_type:?} verify"
            );
            let buffer = pal.dma_alloc(&io, sk_len).unwrap();
            buffer.copy_from_slice(&sk);
            assert_eq!(
                pal.mldsa_sign_in_place(&io, param_set, buffer, HsmMlDsaHedge::Preferred, input)
                    .await,
                Err(HsmError::UnsupportedCmd),
                "{msg_type:?} sign in place"
            );
        }
    }

    /// The sign query returns the signature length without signing; a
    /// buffer longer than that is accepted and only its prefix written.
    #[tokio::test]
    async fn mldsa_sign_query_and_long_buffer() {
        let (pal, io) = pal_and_io();
        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");
            let input = msg(HsmMlDsaMsgType::Pure, b"message", b"ctx");
            let hedge = HsmMlDsaHedge::Preferred;
            assert_eq!(
                pal.mldsa_sign(&io, param_set, dma(&sk), hedge, input, None)
                    .await,
                Ok(sig_len)
            );
            assert_eq!(
                pal.mldsa_sign(&io, param_set, dma(&sk[1..]), hedge, input, None)
                    .await,
                Err(HsmError::InvalidArg)
            );
            let mut sig = vec![0x5a; sig_len + 1];
            assert_eq!(
                pal.mldsa_sign(
                    &io,
                    param_set,
                    dma(&sk),
                    hedge,
                    input,
                    Some(dma_mut(&mut sig[..sig_len - 1]))
                )
                .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.mldsa_sign(
                    &io,
                    param_set,
                    dma(&sk),
                    hedge,
                    input,
                    Some(dma_mut(&mut sig))
                )
                .await,
                Ok(sig_len)
            );
            assert_eq!(sig[sig_len], 0x5a, "{param_set:?}: wrote past sig_len");
            assert!(pal
                .mldsa_verify(&io, param_set, dma(&pk), input, dma(&sig[..sig_len]))
                .await
                .unwrap());
        }
    }

    /// Two generations must not produce the same key: the seed comes from
    /// the RNG, so a stuck one would show up here rather than as a silent
    /// loss of entropy.
    #[tokio::test]
    async fn gen_key_is_not_deterministic() {
        let (pal, io) = pal_and_io();

        let (param_set, pk_len, sk_len, _) = MLDSA_SETS[0];
        let mut pks = Vec::new();
        for _ in 0..2 {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_key");
            pks.push(pk);
        }
        assert_ne!(pks[0], pks[1], "two generations produced the same key");
    }

    /// A buffer sized for a smaller parameter set is a caller error rather
    /// than a panic.
    #[tokio::test]
    async fn rejects_short_buffer() {
        let (pal, io) = pal_and_io();

        // ML-DSA-44 sizes requested under ML-DSA-65.
        let (mut seed, mut pk44, mut sk44) =
            ([0u8; MLDSA_SEED_LEN], vec![0u8; 1312], vec![0u8; 2560]);
        assert_eq!(
            pal.mldsa_gen_keypair(
                &io,
                HsmMlDsaParam::MlDsa65,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk44), dma_mut(&mut pk44))),
            )
            .await,
            Err(HsmError::InvalidArg),
            "short output buffer must be rejected"
        );
    }

    /// Query mode reports the key lengths without touching the seed, and a
    /// wrong-sized seed is rejected in query mode too.
    #[tokio::test]
    async fn gen_keypair_query_mode() {
        let (pal, io) = pal_and_io();
        for (param_set, pk_len, sk_len, _) in MLDSA_SETS {
            let mut seed = [0xA5u8; MLDSA_SEED_LEN];
            assert_eq!(
                pal.mldsa_gen_keypair(
                    &io,
                    param_set,
                    HsmMlSeedSrc::Random,
                    HsmMlDsaPct::None,
                    dma_mut(&mut seed),
                    None,
                )
                .await,
                Ok((sk_len, pk_len))
            );
            assert_eq!(seed, [0xA5u8; MLDSA_SEED_LEN], "query mode wrote the seed");

            let mut short = [0u8; MLDSA_SEED_LEN - 1];
            assert_eq!(
                pal.mldsa_gen_keypair(
                    &io,
                    param_set,
                    HsmMlSeedSrc::Random,
                    HsmMlDsaPct::None,
                    dma_mut(&mut short),
                    None,
                )
                .await,
                Err(HsmError::InvalidArg)
            );
        }
    }

    /// A caller-supplied seed is used as-is: it is left unchanged and
    /// re-expanding it reproduces the key pair it was generated with.
    #[tokio::test]
    async fn gen_keypair_from_caller_seed() {
        let (pal, io) = pal_and_io();
        for (param_set, pk_len, sk_len, _) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Random,
                HsmMlDsaPct::None,
                dma_mut(&mut seed),
                Some((dma_mut(&mut sk), dma_mut(&mut pk))),
            )
            .await
            .expect("gen_keypair");

            let mut seed2 = seed;
            let (mut pk2, mut sk2) = (vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_keypair(
                &io,
                param_set,
                HsmMlSeedSrc::Caller,
                HsmMlDsaPct::None,
                dma_mut(&mut seed2),
                Some((dma_mut(&mut sk2), dma_mut(&mut pk2))),
            )
            .await
            .expect("gen_keypair from seed");
            assert_eq!(seed2, seed, "{param_set:?}: caller seed was modified");
            assert_eq!(pk2, pk, "{param_set:?}: public key not reproduced");
            assert_eq!(sk2, sk, "{param_set:?}: private key not reproduced");
        }
    }
}
