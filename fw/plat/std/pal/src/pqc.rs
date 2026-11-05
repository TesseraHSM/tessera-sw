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
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaHedge;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlKem;
use tsra_fw_hsm_pal_traits::HsmMlKemParamSet;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::MLKEM_SHARED_SECRET_LEN;
use zeroize::Zeroizing;

use crate::StdHsmPal;

/// Map an ML-DSA parameter set onto its [`tsra_crypto`] variant.
fn mldsa_variant(param_set: HsmMlDsaParamSet) -> MlDsaVariant {
    match param_set {
        HsmMlDsaParamSet::MlDsa44 => MlDsaVariant::MlDsa44,
        HsmMlDsaParamSet::MlDsa65 => MlDsaVariant::MlDsa65,
        HsmMlDsaParamSet::MlDsa87 => MlDsaVariant::MlDsa87,
    }
}

/// Map an ML-KEM parameter set onto its [`tsra_crypto`] variant.
fn mlkem_variant(param_set: HsmMlKemParamSet) -> MlKemVariant {
    match param_set {
        HsmMlKemParamSet::MlKem512 => MlKemVariant::MlKem512,
        HsmMlKemParamSet::MlKem768 => MlKemVariant::MlKem768,
        HsmMlKemParamSet::MlKem1024 => MlKemVariant::MlKem1024,
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

/// Whether `msg_type` selects an external `μ`, once its input is checked.
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] — `message`/`ctx` not valid for `msg_type`.
/// - [`HsmError::UnsupportedCmd`] — the pre-hash types, currently
///   unsupported.
fn external_mu(msg_type: HsmMlDsaMsgType, message: &[u8], ctx: &[u8]) -> HsmResult<bool> {
    msg_type.check_input(message, ctx)?;
    match msg_type {
        HsmMlDsaMsgType::Pure => Ok(false),
        HsmMlDsaMsgType::ExternalMu => Ok(true),
        HsmMlDsaMsgType::PreHash | HsmMlDsaMsgType::PreHashMessage => Err(HsmError::UnsupportedCmd),
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
    async fn mldsa_sign_in_place(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        key_signature: &mut HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        hedge: HsmMlDsaHedge,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mldsa_variant(param_set);
        let external_mu = external_mu(msg_type, message, ctx)?;
        let key_at = key_signature
            .len()
            .checked_sub(variant.sec_key_len())
            .ok_or(HsmError::InvalidArg)?;
        if key_signature.len() < variant.sig_len() {
            return Err(HsmError::InvalidArg);
        }
        let result = self
            .pqc
            .mldsa_sign(
                variant,
                &key_signature[key_at..],
                external_mu,
                deterministic(hedge),
                message,
                ctx,
            )
            .await?;
        write_exact(&mut key_signature[..variant.sig_len()], &result)
    }

    async fn mldsa_gen_key(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        seed: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        sec_key: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mldsa_variant(param_set);
        if seed.len() != MLDSA_SEED_LEN {
            return Err(HsmError::InvalidArg);
        }
        // The seed *is* the private key, so it comes from the HSM's
        // generator rather than the caller.
        self.rng_fill_bytes(io, seed)?;

        let (pk, sk) = self.pqc.mldsa_keygen(variant, seed).await?;
        write_exact(pub_key, &pk)?;
        write_exact(sec_key, &sk)
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
        let variant = mldsa_variant(param_set);
        let external_mu = external_mu(msg_type, message, ctx)?;

        // Unlike the seed, the per-signature randomness is not drawn here:
        // it never leaves the crypto layer, so that layer draws it, exactly
        // as it does the ECDSA nonce.
        let outcome = self
            .pqc
            .mldsa_sign(
                variant,
                sec_key,
                external_mu,
                deterministic(hedge),
                message,
                ctx,
            )
            .await;

        // Not a long-term secret, but it is signing input; do not leave
        // it on the stack for the next caller.
        write_exact(signature, &outcome?)
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
        let variant = mldsa_variant(param_set);
        let external_mu = external_mu(msg_type, message, ctx)?;
        self.pqc
            .mldsa_verify(variant, pub_key, external_mu, message, ctx, signature)
            .await
    }
}

impl HsmMlKem for StdHsmPal {
    async fn mlkem_encaps_in_place(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        pub_key_ciphertext: &mut HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mlkem_variant(param_set);
        if pub_key_ciphertext.len() != variant.pub_key_len()
            || pub_key_ciphertext.len() < variant.ciphertext_len()
            || shared_secret.len() != tsra_crypto::MLKEM_SHARED_SECRET_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        let (ct, ss) = self
            .pqc
            .mlkem_encapsulate(variant, pub_key_ciphertext)
            .await?;
        let ss = Zeroizing::new(ss);
        write_exact(&mut pub_key_ciphertext[..variant.ciphertext_len()], &ct)?;
        write_exact(shared_secret, &ss)
    }

    async fn mlkem_gen_key(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        seed: &mut HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mlkem_variant(param_set);
        if seed.len() != MLKEM_SEED_LEN
            || output.len() != variant.pub_key_len() + variant.sec_key_len()
        {
            return Err(HsmError::InvalidArg);
        }
        self.rng_fill_bytes(io, seed)?;

        let (pk, sk) = self.pqc.mlkem_keygen(variant, seed).await?;
        let sk = Zeroizing::new(sk);
        let (pub_key, sec_key) = output.split_at_mut(variant.pub_key_len());
        write_exact(pub_key, &pk)?;
        write_exact(sec_key, &sk)
    }

    async fn mlkem_encaps(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        pub_key: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mlkem_variant(param_set);
        if output.len() != MLKEM_SHARED_SECRET_LEN + variant.ciphertext_len() {
            return Err(HsmError::InvalidArg);
        }

        // As with signing, the encapsulation message never leaves the crypto
        // layer, so that layer draws it.
        let (ct, ss) = self.pqc.mlkem_encapsulate(variant, pub_key).await?;
        let ss = Zeroizing::new(ss);
        let (shared_secret, ciphertext) = output.split_at_mut(MLKEM_SHARED_SECRET_LEN);
        write_exact(shared_secret, &ss)?;
        write_exact(ciphertext, &ct)
    }

    async fn mlkem_decaps(
        &self,
        _io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        sec_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let variant = mlkem_variant(param_set);
        let ss = self
            .pqc
            .mlkem_decapsulate(variant, sec_key, ciphertext)
            .await?;
        write_exact(shared_secret, &ss)
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

    use super::*;
    use crate::HsmPartId;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// ML-DSA `(param_set, pub_key, sec_key, signature)` lengths, FIPS 204.
    const MLDSA_SETS: [(HsmMlDsaParamSet, usize, usize, usize); 3] = [
        (HsmMlDsaParamSet::MlDsa44, 1312, 2560, 2420),
        (HsmMlDsaParamSet::MlDsa65, 1952, 4032, 3309),
        (HsmMlDsaParamSet::MlDsa87, 2592, 4896, 4627),
    ];

    /// ML-KEM `(param_set, pub_key, sec_key, ciphertext)` lengths, FIPS 203.
    const MLKEM_SETS: [(HsmMlKemParamSet, usize, usize, usize); 3] = [
        (HsmMlKemParamSet::MlKem512, 800, 1632, 768),
        (HsmMlKemParamSet::MlKem768, 1184, 2400, 1088),
        (HsmMlKemParamSet::MlKem1024, 1568, 3168, 1568),
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

    #[tokio::test]
    async fn overlapping_outputs_consume_pqc_inputs_first() {
        for (param_set, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (pal, io) = pal_and_io();
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
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
                    HsmMlDsaMsgType::Pure,
                    HsmMlDsaHedge::Preferred,
                    dma(b"m"),
                    dma(b"ctx"),
                )
                .await
                .unwrap();
                assert!(pal
                    .mldsa_verify(
                        &io,
                        param_set,
                        dma(&pk),
                        HsmMlDsaMsgType::Pure,
                        dma(b"m"),
                        dma(b"ctx"),
                        &buffer[..sig_len]
                    )
                    .await
                    .unwrap());
            }
        }

        for (param_set, pk_len, sk_len, ct_len) in MLKEM_SETS {
            let (pal, io) = pal_and_io();
            let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
            pal.mlkem_gen_key(&io, param_set, dma_mut(&mut seed), dma_mut(&mut keys))
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
                dma_mut(&mut decaps),
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
                    HsmMlDsaParamSet::MlDsa44,
                    &mut buffer[..key_len],
                    HsmMlDsaMsgType::Pure,
                    HsmMlDsaHedge::Preferred,
                    dma(b""),
                    dma(b""),
                )
                .await,
                Err(HsmError::InvalidArg),
            );
        }
        let mut ss = [0x5a; SS_LEN + 1];
        for (key_len, secret_len) in [
            (799, SS_LEN),
            (801, SS_LEN),
            (800, SS_LEN - 1),
            (800, SS_LEN + 1),
        ] {
            assert_eq!(
                pal.mlkem_encaps_in_place(
                    &io,
                    HsmMlKemParamSet::MlKem512,
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
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
                HsmMlDsaMsgType::Pure,
                HsmMlDsaHedge::Preferred,
                dma(b"message"),
                dma(b"ctx"),
                dma_mut(&mut sig),
            )
            .await
            .expect("sign");

            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    HsmMlDsaMsgType::Pure,
                    dma(b"message"),
                    dma(b"ctx"),
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
                    HsmMlDsaMsgType::Pure,
                    dma(b"messagf"),
                    dma(b"ctx"),
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
                    HsmMlDsaMsgType::Pure,
                    dma(b"message"),
                    dma(b"other"),
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
            )
            .await
            .expect("gen_key");

            let garbage = vec![0xAAu8; sig_len];
            assert!(
                !pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    HsmMlDsaMsgType::Pure,
                    dma(b"m"),
                    dma(b""),
                    dma(&garbage)
                )
                .await
                .expect("verify must not error on a bad signature"),
                "{param_set:?}: garbage signature verified"
            );
        }
    }

    /// `mlkem_gen_key` writes the public key then the expanded private key
    /// into one output of exactly their combined length; any other length
    /// is refused before the seed is drawn, so neither buffer is written.
    #[tokio::test]
    async fn mlkem_gen_key_rejects_a_mis_sized_output() {
        let (pal, io) = pal_and_io();
        let (param_set, pk_len, sk_len, _) = MLKEM_SETS[0];
        for len in [0, pk_len, pk_len + sk_len - 1, pk_len + sk_len + 1] {
            let (mut seed, mut keys) = ([0x5a; MLKEM_SEED_LEN], vec![0x5a; len]);
            assert_eq!(
                pal.mlkem_gen_key(&io, param_set, dma_mut(&mut seed), dma_mut(&mut keys))
                    .await,
                Err(HsmError::InvalidArg),
                "{len}-byte output"
            );
            assert!(
                seed.iter().chain(&keys).all(|b| *b == 0x5a),
                "{len}-byte output written"
            );
        }
    }

    /// `mlkem_encaps` writes the shared secret then the ciphertext into one
    /// output of exactly their combined length; any other length, including
    /// one too short for the secret alone, is refused without writing.
    #[tokio::test]
    async fn mlkem_encaps_rejects_a_mis_sized_output() {
        let (pal, io) = pal_and_io();
        let (param_set, pk_len, sk_len, ct_len) = MLKEM_SETS[0];
        let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
        pal.mlkem_gen_key(&io, param_set, dma_mut(&mut seed), dma_mut(&mut keys))
            .await
            .expect("gen_key");
        let pk = &keys[..pk_len];

        for len in [
            0,
            SS_LEN - 1,
            SS_LEN,
            SS_LEN + ct_len - 1,
            SS_LEN + ct_len + 1,
        ] {
            let mut out = vec![0x5a; len];
            assert_eq!(
                pal.mlkem_encaps(&io, param_set, dma(pk), dma_mut(&mut out))
                    .await,
                Err(HsmError::InvalidArg),
                "{len}-byte output"
            );
            assert!(out.iter().all(|b| *b == 0x5a), "{len}-byte output written");
        }
    }

    /// Encapsulate then decapsulate: both sides must derive the same
    /// secret, and a corrupted ciphertext must yield a *different* secret
    /// rather than an error -- FIPS 203 implicit rejection.
    #[tokio::test]
    async fn mlkem_round_trip_agrees_and_implicitly_rejects() {
        let (pal, io) = pal_and_io();

        for (param_set, pk_len, sk_len, ct_len) in MLKEM_SETS {
            let (mut seed, mut keys) = ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len + sk_len]);
            pal.mlkem_gen_key(&io, param_set, dma_mut(&mut seed), dma_mut(&mut keys))
                .await
                .expect("gen_key");
            let (pk, sk) = keys.split_at(pk_len);

            let mut out = vec![0u8; SS_LEN + ct_len];
            pal.mlkem_encaps(&io, param_set, dma(pk), dma_mut(&mut out))
                .await
                .expect("encaps");
            let (ss_enc, ct) = out.split_at(SS_LEN);
            let (ss_enc, mut ct) = (ss_enc.to_vec(), ct.to_vec());

            let mut ss_dec = [0u8; SS_LEN];
            pal.mlkem_decaps(&io, param_set, dma(sk), dma(&ct), dma_mut(&mut ss_dec))
                .await
                .expect("decaps");
            assert_eq!(ss_enc, ss_dec, "{param_set:?}: shared secrets disagree");

            ct[0] ^= 1;
            let mut ss_rej = [0u8; SS_LEN];
            pal.mlkem_decaps(&io, param_set, dma(sk), dma(&ct), dma_mut(&mut ss_rej))
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
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
                    HsmMlDsaMsgType::Pure,
                    hedge,
                    dma(b"same message"),
                    dma(b""),
                    dma_mut(&mut sig),
                )
                .await
                .expect("sign");
                assert!(
                    pal.mldsa_verify(
                        &io,
                        param_set,
                        dma(&pk),
                        HsmMlDsaMsgType::Pure,
                        dma(b"same message"),
                        dma(b""),
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
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
                    msg_type,
                    HsmMlDsaHedge::Deterministic,
                    dma(message),
                    dma(ctx),
                    dma_mut(&mut sig),
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
                HsmMlDsaMsgType::Pure,
                HsmMlDsaHedge::Deterministic,
                dma(b"message"),
                dma(b"ctx"),
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
                    HsmMlDsaMsgType::Pure,
                    dma(b"message"),
                    dma(b"ctx"),
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
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
                HsmMlDsaMsgType::ExternalMu,
                HsmMlDsaHedge::Preferred,
                dma(&mu),
                dma(b""),
                dma_mut(&mut sig),
            )
            .await
            .expect("sign mu");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    HsmMlDsaMsgType::Pure,
                    dma(b"message"),
                    dma(b"ctx"),
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
                HsmMlDsaMsgType::Pure,
                HsmMlDsaHedge::Preferred,
                dma(b"message"),
                dma(b"ctx"),
                dma_mut(&mut sig),
            )
            .await
            .expect("sign");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    HsmMlDsaMsgType::ExternalMu,
                    dma(&mu),
                    dma(b""),
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
                HsmMlDsaMsgType::ExternalMu,
                HsmMlDsaHedge::Preferred,
                dma(&mu),
                dma(b""),
            )
            .await
            .expect("sign mu in place");
            assert!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    HsmMlDsaMsgType::Pure,
                    dma(b"message"),
                    dma(b"ctx"),
                    &buffer[..sig_len]
                )
                .await
                .expect("verify"),
                "{param_set:?}: in-place signature over mu failed pure verification"
            );
        }
    }

    /// An external `μ` is exactly 64 bytes and comes without a context
    /// string; the pre-hash types are currently unsupported. Each is
    /// refused the same way by all three entry points.
    #[tokio::test]
    async fn mldsa_rejects_malformed_mu_and_prehash() {
        let (pal, io) = pal_and_io();
        let (param_set, pk_len, sk_len, sig_len) = MLDSA_SETS[0];
        let (mut seed, mut pk, mut sk) =
            ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
        pal.mldsa_gen_key(
            &io,
            param_set,
            dma_mut(&mut seed),
            dma_mut(&mut pk),
            dma_mut(&mut sk),
        )
        .await
        .expect("gen_key");

        let mu = [7u8; 65];
        let cases: [(HsmMlDsaMsgType, &[u8], &[u8], HsmError); 5] = [
            (
                HsmMlDsaMsgType::ExternalMu,
                &mu[..63],
                b"",
                HsmError::InvalidArg,
            ),
            (
                HsmMlDsaMsgType::ExternalMu,
                &mu[..],
                b"",
                HsmError::InvalidArg,
            ),
            (
                HsmMlDsaMsgType::ExternalMu,
                &mu[..64],
                b"ctx",
                HsmError::InvalidArg,
            ),
            (
                HsmMlDsaMsgType::PreHash,
                b"m",
                b"",
                HsmError::UnsupportedCmd,
            ),
            (
                HsmMlDsaMsgType::PreHashMessage,
                b"m",
                b"",
                HsmError::UnsupportedCmd,
            ),
        ];
        let mut sig = vec![0u8; sig_len];
        for (msg_type, message, ctx, expected) in cases {
            assert_eq!(
                pal.mldsa_sign(
                    &io,
                    param_set,
                    dma(&sk),
                    msg_type,
                    HsmMlDsaHedge::Preferred,
                    dma(message),
                    dma(ctx),
                    dma_mut(&mut sig),
                )
                .await,
                Err(expected),
                "{msg_type:?} sign, {} B",
                message.len()
            );
            assert_eq!(
                pal.mldsa_verify(
                    &io,
                    param_set,
                    dma(&pk),
                    msg_type,
                    dma(message),
                    dma(ctx),
                    dma(&sig)
                )
                .await,
                Err(expected),
                "{msg_type:?} verify, {} B",
                message.len()
            );
            let buffer = pal.dma_alloc(&io, sk_len).unwrap();
            buffer.copy_from_slice(&sk);
            assert_eq!(
                pal.mldsa_sign_in_place(
                    &io,
                    param_set,
                    buffer,
                    msg_type,
                    HsmMlDsaHedge::Preferred,
                    dma(message),
                    dma(ctx)
                )
                .await,
                Err(expected),
                "{msg_type:?} sign in place, {} B",
                message.len()
            );
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
            pal.mldsa_gen_key(
                &io,
                param_set,
                dma_mut(&mut seed),
                dma_mut(&mut pk),
                dma_mut(&mut sk),
            )
            .await
            .expect("gen_key");
            pks.push(pk);
        }
        assert_ne!(pks[0], pks[1], "two generations produced the same key");
    }

    /// A correctly-sized buffer for the wrong parameter set is a caller
    /// error rather than a panic.
    #[tokio::test]
    async fn rejects_wrong_buffer_length() {
        let (pal, io) = pal_and_io();

        // ML-DSA-65 sizes requested under ML-DSA-44.
        let (mut seed, mut pk65, mut sk65) =
            ([0u8; MLDSA_SEED_LEN], vec![0u8; 1952], vec![0u8; 4032]);
        assert_eq!(
            pal.mldsa_gen_key(
                &io,
                HsmMlDsaParamSet::MlDsa44,
                dma_mut(&mut seed),
                dma_mut(&mut pk65),
                dma_mut(&mut sk65)
            )
            .await,
            Err(HsmError::InvalidArg),
            "mismatched output length must be rejected"
        );
    }
}
