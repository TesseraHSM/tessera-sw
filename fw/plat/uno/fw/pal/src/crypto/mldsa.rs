// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmMlDsa`] implementation for the Uno PAL.
//!
//! ML-DSA does not run on the HSM core: this forwards to the
//! [`PqcDriver`], which offloads to a fastpath (FP) core.  The driver is
//! a bring-up stub today, so every call currently fails there.
//!

use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_trace::tracing::*;

use crate::UnoHsmPal;

/// Public key length for each ML-DSA parameter set (FIPS 204 Table 2).
fn mldsa_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(1312),
        HsmVaultKeyKind::MlDsa65Seed => Ok(1952),
        HsmVaultKeyKind::MlDsa87Seed => Ok(2592),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Length of the compact ML-DSA private seed (`xi`), identical for every
/// parameter set — which is why `kind` has to be carried alongside it.
const MLDSA_SEED_LEN: usize = 32;

impl HsmMlDsa for UnoHsmPal {
    async fn mldsa_gen_key(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        // Bracketed so an early `?` cannot skip the closing mark: every
        // exit, error or not, leaves through the await below.
        let outcome: HsmResult<()> = async {
            // Validate before handing anything to the driver, so buffer-size
            // bugs surface here rather than as a malformed FP request.
            let expected_pub = mldsa_pub_key_len(kind)?;
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
            {
                // SAFETY: `seed` is caller-owned scratch of the length checked
                // above; `DmaBuf::from_raw_mut` only re-types it for the RNG
                // driver, which writes exactly `seed.len()` bytes.
                let dma = unsafe { DmaBuf::from_raw_mut(seed) };
                self.rng.fill_bytes(dma)?;
            }

            self.pqc.mldsa_gen_key(kind, seed, pub_key, sec_key).await
        }
        .await;

        outcome
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
        // Bracketed so a failed RNG draw still reaches the closing mark.
        let outcome: HsmResult<()> = async {
            // Per-signature randomness for the hedged variant, drawn here for
            // the same reason as the seed: an FP core has no entropy source.
            let mut rnd = [0u8; MLDSA_SEED_LEN];
            {
                // SAFETY: `rnd` is a local of exactly the length the RNG driver
                // fills; `from_raw_mut` only re-types it.
                let dma = unsafe { DmaBuf::from_raw_mut(&mut rnd[..]) };
                self.rng.fill_bytes(dma)?;
            }

            let result = self
                .pqc
                .mldsa_sign(kind, sec_key, &rnd, message, ctx, signature)
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
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        // No `?` before the call, so binding the result is enough to keep
        // the closing mark on every path.
        let outcome: HsmResult<bool> = self
            .pqc
            .mldsa_verify(kind, pub_key, message, ctx, signature)
            .await;

        outcome
    }

    async fn mlkem_gen_key(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        // Bracketed so validation and RNG failures still reach the closing
        // mark; see `mldsa_gen_key`.
        let outcome: HsmResult<()> = async {
            let expected_pub = mlkem_pub_key_len(kind)?;
            if seed.len() != MLKEM_SEED_LEN || pub_key.len() != expected_pub {
                return Err(HsmError::InvalidArg);
            }

            // Same reasoning as ML-DSA: the seed pair is the private key and an
            // FP core has no entropy source, so it is drawn here.
            {
                // SAFETY: `seed` is caller-owned scratch of the length checked
                // above; `from_raw_mut` only re-types it for the RNG driver.
                let dma = unsafe { DmaBuf::from_raw_mut(seed) };
                self.rng.fill_bytes(dma)?;
            }

            self.pqc.mlkem_gen_key(kind, seed, pub_key, sec_key).await
        }
        .await;

        outcome
    }

    async fn mlkem_encaps(
        &self,
        _io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        // Bracketed so a failed RNG draw still reaches the closing mark.
        let outcome: HsmResult<()> = async {
            // Encapsulation randomness, drawn here for the same reason as the
            // seeds: an FP core has no entropy source.
            let mut m = [0u8; 32];
            {
                // SAFETY: `m` is a local of exactly the length the RNG driver
                // fills; `from_raw_mut` only re-types it.
                let dma = unsafe { DmaBuf::from_raw_mut(&mut m[..]) };
                self.rng.fill_bytes(dma)?;
            }

            let result = self
                .pqc
                .mlkem_encaps(kind, pub_key, &m, ciphertext, shared_secret)
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
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        // No `?` before the call, so binding the result is enough to keep
        // the closing mark on every path.
        let outcome: HsmResult<()> = self
            .pqc
            .mlkem_decaps(kind, sec_key, ciphertext, shared_secret)
            .await;

        outcome
    }
}

/// Encapsulation-key length per ML-KEM parameter set (FIPS 203 Table 3).
fn mlkem_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(800),
        HsmVaultKeyKind::MlKem768Seed => Ok(1184),
        HsmVaultKeyKind::MlKem1024Seed => Ok(1568),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Length of the ML-KEM seed pair `(d ‖ z)`.
const MLKEM_SEED_LEN: usize = 64;
