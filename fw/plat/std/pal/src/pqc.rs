// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmMlDsa`] for the std PAL — ML-DSA and ML-KEM.
//!
//! Thin layer over [`StdPqc`](crate::drivers::pqc::StdPqc): it maps the
//! vault key kind onto a parameter set, draws whatever entropy the
//! operation needs, and checks the caller's buffers. The arithmetic
//! itself lives in [`tsra_crypto`], and the driver dispatches it to a
//! worker thread.
//!
//! The trait is named for ML-DSA but carries the ML-KEM methods too, so
//! both live here.
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
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use crate::StdHsmPal;

/// Map a vault key kind onto its ML-DSA parameter set.
fn mldsa_variant(kind: HsmVaultKeyKind) -> HsmResult<MlDsaVariant> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(MlDsaVariant::MlDsa44),
        HsmVaultKeyKind::MlDsa65Seed => Ok(MlDsaVariant::MlDsa65),
        HsmVaultKeyKind::MlDsa87Seed => Ok(MlDsaVariant::MlDsa87),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map a vault key kind onto its ML-KEM parameter set.
fn mlkem_variant(kind: HsmVaultKeyKind) -> HsmResult<MlKemVariant> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(MlKemVariant::MlKem512),
        HsmVaultKeyKind::MlKem768Seed => Ok(MlKemVariant::MlKem768),
        HsmVaultKeyKind::MlKem1024Seed => Ok(MlKemVariant::MlKem1024),
        _ => Err(HsmError::InvalidArg),
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

impl HsmMlDsa for StdHsmPal {
    async fn mldsa_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let variant = mldsa_variant(kind)?;
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
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &mut [u8],
    ) -> HsmResult<()> {
        let variant = mldsa_variant(kind)?;

        // Unlike the seed, the per-signature randomness is not drawn here:
        // it never leaves the crypto layer, so that layer draws it, exactly
        // as it does the ECDSA nonce.
        let outcome = self.pqc.mldsa_sign(variant, sec_key, message, ctx).await;

        // Not a long-term secret, but it is signing input; do not leave
        // it on the stack for the next caller.
        write_exact(signature, &outcome?)
    }

    async fn mldsa_verify(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let variant = mldsa_variant(kind)?;
        self.pqc
            .mldsa_verify(variant, pub_key, message, ctx, signature)
            .await
    }

    async fn mlkem_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let variant = mlkem_variant(kind)?;
        if seed.len() != MLKEM_SEED_LEN {
            return Err(HsmError::InvalidArg);
        }
        self.rng_fill_bytes(io, seed)?;

        let (pk, sk) = self.pqc.mlkem_keygen(variant, seed).await?;
        write_exact(pub_key, &pk)?;
        write_exact(sec_key, &sk)
    }

    async fn mlkem_encaps(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        let variant = mlkem_variant(kind)?;

        // As with signing, the encapsulation message never leaves the crypto
        // layer, so that layer draws it.
        let outcome = self.pqc.mlkem_encapsulate(variant, pub_key).await;

        let (ct, ss) = outcome?;
        write_exact(ciphertext, &ct)?;
        write_exact(shared_secret, &ss)
    }

    async fn mlkem_decaps(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        let variant = mlkem_variant(kind)?;
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
    use tsra_fw_hsm_pal_traits::HsmPartId;

    use super::*;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// ML-DSA `(kind, pub_key, sec_key, signature)` lengths, FIPS 204.
    const MLDSA_SETS: [(HsmVaultKeyKind, usize, usize, usize); 3] = [
        (HsmVaultKeyKind::MlDsa44Seed, 1312, 2560, 2420),
        (HsmVaultKeyKind::MlDsa65Seed, 1952, 4032, 3309),
        (HsmVaultKeyKind::MlDsa87Seed, 2592, 4896, 4627),
    ];

    /// ML-KEM `(kind, pub_key, sec_key, ciphertext)` lengths, FIPS 203.
    const MLKEM_SETS: [(HsmVaultKeyKind, usize, usize, usize); 3] = [
        (HsmVaultKeyKind::MlKem512Seed, 800, 1632, 768),
        (HsmVaultKeyKind::MlKem768Seed, 1184, 2400, 1088),
        (HsmVaultKeyKind::MlKem1024Seed, 1568, 3168, 1568),
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

    /// Generate, sign and verify: the signature the PAL produces must
    /// verify under the public key it produced, and must stop verifying
    /// once the message changes.
    #[tokio::test]
    async fn mldsa_round_trip_verifies_and_rejects_tampering() {
        let (pal, io) = pal_and_io();

        for (kind, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_key(&io, kind, &mut seed, &mut pk, &mut sk)
                .await
                .expect("gen_key");
            assert_ne!(seed, [0u8; MLDSA_SEED_LEN], "{kind:?}: seed left unset");

            let mut sig = vec![0u8; sig_len];
            pal.mldsa_sign(&io, kind, &sk, b"message", b"ctx", &mut sig)
                .await
                .expect("sign");

            assert!(
                pal.mldsa_verify(&io, kind, &pk, b"message", b"ctx", &sig)
                    .await
                    .expect("verify"),
                "{kind:?}: own signature failed to verify"
            );
            assert!(
                !pal.mldsa_verify(&io, kind, &pk, b"messagf", b"ctx", &sig)
                    .await
                    .expect("verify"),
                "{kind:?}: signature verified for the wrong message"
            );
            // The context string is bound into the signature, so changing
            // it must invalidate it just as changing the message does.
            assert!(
                !pal.mldsa_verify(&io, kind, &pk, b"message", b"other", &sig)
                    .await
                    .expect("verify"),
                "{kind:?}: signature verified under the wrong context"
            );
        }
    }

    /// A signature that is not even well-formed is a failed
    /// verification, not an error: the caller asked whether these bytes
    /// authenticate the message.
    #[tokio::test]
    async fn mldsa_verify_reports_false_for_garbage_signature() {
        let (pal, io) = pal_and_io();

        for (kind, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_key(&io, kind, &mut seed, &mut pk, &mut sk)
                .await
                .expect("gen_key");

            let garbage = vec![0xAAu8; sig_len];
            assert!(
                !pal.mldsa_verify(&io, kind, &pk, b"m", b"", &garbage)
                    .await
                    .expect("verify must not error on a bad signature"),
                "{kind:?}: garbage signature verified"
            );
        }
    }

    /// Encapsulate then decapsulate: both sides must derive the same
    /// secret, and a corrupted ciphertext must yield a *different* secret
    /// rather than an error -- FIPS 203 implicit rejection.
    #[tokio::test]
    async fn mlkem_round_trip_agrees_and_implicitly_rejects() {
        let (pal, io) = pal_and_io();

        for (kind, pk_len, sk_len, ct_len) in MLKEM_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLKEM_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mlkem_gen_key(&io, kind, &mut seed, &mut pk, &mut sk)
                .await
                .expect("gen_key");

            let (mut ct, mut ss_enc) = (vec![0u8; ct_len], [0u8; SS_LEN]);
            pal.mlkem_encaps(&io, kind, &pk, &mut ct, &mut ss_enc)
                .await
                .expect("encaps");

            let mut ss_dec = [0u8; SS_LEN];
            pal.mlkem_decaps(&io, kind, &sk, &ct, &mut ss_dec)
                .await
                .expect("decaps");
            assert_eq!(ss_enc, ss_dec, "{kind:?}: shared secrets disagree");

            ct[0] ^= 1;
            let mut ss_rej = [0u8; SS_LEN];
            pal.mlkem_decaps(&io, kind, &sk, &ct, &mut ss_rej)
                .await
                .expect("decaps must not fail on a corrupted ciphertext");
            assert_ne!(
                ss_enc, ss_rej,
                "{kind:?}: corrupted ciphertext produced the real secret"
            );
        }
    }

    /// Signing is hedged, as it is on Uno: signing the same message
    /// twice under the same key must not produce the same bytes, and
    /// both must verify.  A regression to deterministic signing would
    /// still verify, so only the inequality catches it.
    #[tokio::test]
    async fn mldsa_signing_is_hedged() {
        let (pal, io) = pal_and_io();

        for (kind, pk_len, sk_len, sig_len) in MLDSA_SETS {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_key(&io, kind, &mut seed, &mut pk, &mut sk)
                .await
                .expect("gen_key");

            let mut sigs = Vec::new();
            for _ in 0..2 {
                let mut sig = vec![0u8; sig_len];
                pal.mldsa_sign(&io, kind, &sk, b"same message", b"", &mut sig)
                    .await
                    .expect("sign");
                assert!(
                    pal.mldsa_verify(&io, kind, &pk, b"same message", b"", &sig)
                        .await
                        .expect("verify"),
                    "{kind:?}: hedged signature failed to verify"
                );
                sigs.push(sig);
            }
            assert_ne!(
                sigs[0], sigs[1],
                "{kind:?}: signing is deterministic; Uno signs hedged"
            );
        }
    }

    /// Two generations must not produce the same key: the seed comes from
    /// the RNG, so a stuck one would show up here rather than as a silent
    /// loss of entropy.
    #[tokio::test]
    async fn gen_key_is_not_deterministic() {
        let (pal, io) = pal_and_io();

        let (kind, pk_len, sk_len, _) = MLDSA_SETS[0];
        let mut pks = Vec::new();
        for _ in 0..2 {
            let (mut seed, mut pk, mut sk) =
                ([0u8; MLDSA_SEED_LEN], vec![0u8; pk_len], vec![0u8; sk_len]);
            pal.mldsa_gen_key(&io, kind, &mut seed, &mut pk, &mut sk)
                .await
                .expect("gen_key");
            pks.push(pk);
        }
        assert_ne!(pks[0], pks[1], "two generations produced the same key");
    }

    /// A non-PQC key kind, and a correctly-sized buffer for the wrong
    /// parameter set, are both caller errors rather than panics.
    #[tokio::test]
    async fn rejects_wrong_kind_and_wrong_buffer_length() {
        let (pal, io) = pal_and_io();

        let (mut seed, mut pk, mut sk) = ([0u8; MLDSA_SEED_LEN], vec![0u8; 1312], vec![0u8; 2560]);
        assert_eq!(
            pal.mldsa_gen_key(
                &io,
                HsmVaultKeyKind::Ecc256Private,
                &mut seed,
                &mut pk,
                &mut sk
            )
            .await,
            Err(HsmError::InvalidArg),
            "an ECC kind must not reach the ML-DSA path"
        );

        // ML-DSA-65 sizes requested under the ML-DSA-44 kind.
        let (mut seed, mut pk65, mut sk65) =
            ([0u8; MLDSA_SEED_LEN], vec![0u8; 1952], vec![0u8; 4032]);
        assert_eq!(
            pal.mldsa_gen_key(
                &io,
                HsmVaultKeyKind::MlDsa44Seed,
                &mut seed,
                &mut pk65,
                &mut sk65
            )
            .await,
            Err(HsmError::InvalidArg),
            "mismatched output length must be rejected"
        );
    }
}
