// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE KEMs — Encap / Decap dispatch over the suite's KEM.
//!
//! * `dh` — DHKEM(P-256/P-384/P-521) (RFC 9180 §4.1), including the
//!   Auth variants.
//! * `mlkem` — ML-KEM-1024 (draft-ietf-hpke-pq §3).
//! * `hybrid` — MLKEM1024-P384 (draft-ietf-hpke-pq §4,
//!   draft-irtf-cfrg-concrete-hybrid-kems).
//!
//! The post-quantum KEMs have no Auth variants; [`auth_encap`] /
//! [`auth_decap`] reject them.

mod dh;
mod hybrid;
mod mlkem;

pub use dh::auth_decap;
pub use dh::auth_encap;
pub use mlkem::check_ek as validate_mlkem1024_public_key;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmMlKemPct;
use tsra_fw_hsm_pal_traits::HsmMlSeedSrc;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::suite::HpkeSuite;
use crate::suite::KemKind;

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut HsmDmaBuf> {
    alloc.dma_alloc(len)
}

/// `GenerateKeyPair` for the post-quantum KEMs, with a pairwise
/// consistency test on the ML-KEM component.
///
/// DHKEM keys are generated as ordinary ECC keys and are rejected here.
///
/// # Parameters
///
/// * `sk` — output private key ([`HpkeSuite::nsk`] bytes): the ML-KEM
///   `d ‖ z` seed or the 32-byte hybrid seed.
/// * `pk` — output public key ([`HpkeSuite::npk`] bytes), in its HPKE
///   `SerializePublicKey` encoding.
///
/// # Returns
///
/// * `Err(HsmError::InvalidArg)` — DHKEM suite or wrong buffer lengths.
/// * `Err(HsmError)` — RNG, PAL or PCT failure.
pub async fn generate_key_pair<'a, P>(
    pal: &P,
    io: &P::Io,
    suite: HpkeSuite,
    sk: &mut HsmDmaBuf,
    pk: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    match suite.kem() {
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521 => Err(HsmError::InvalidArg),
        KemKind::MlKem1024 => {
            mlkem::keypair(
                pal,
                io,
                HsmMlSeedSrc::Random,
                HsmMlKemPct::EncapsDecaps,
                sk,
                pk,
            )
            .await
        }
        KemKind::MlKem1024P384 => hybrid::generate(pal, io, sk, pk, alloc).await,
    }
}

/// Derives the serialized public key of a post-quantum KEM private key
/// (seed) `sk`, writing [`HpkeSuite::npk`] bytes to `pk`.
///
/// # Returns
///
/// * `Err(HsmError::InvalidArg)` — DHKEM suite, wrong lengths, or a hybrid
///   seed whose P-384 scalar is out of range.
pub async fn public_key<'a, P>(
    pal: &P,
    io: &P::Io,
    suite: HpkeSuite,
    sk: &[u8],
    pk: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    match suite.kem() {
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521 => Err(HsmError::InvalidArg),
        KemKind::MlKem1024 => {
            let seed = alloc_bytes(sk.len(), alloc)?;
            seed.copy_from_slice(sk);
            mlkem::keypair(pal, io, HsmMlSeedSrc::Caller, HsmMlKemPct::None, seed, pk).await
        }
        KemKind::MlKem1024P384 => hybrid::public_key(pal, io, sk, pk, alloc).await,
    }
}

/// KEM Encap (Base / PSK modes).
///
/// # Parameters
///
/// * `pal` — PAL providing the KEM primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `pk_r` — recipient public key (`Npk` bytes).
/// * `enc` — output: encapsulated key (at least `Nenc` bytes).
/// * `shared_secret` — output: KEM shared secret (`Nsecret` bytes).
/// * `alloc` — scoped allocator for intermediate buffers.
///
/// # Returns
///
/// * `Ok(())` — `enc[..Nenc]` and `shared_secret` populated.
/// * `Err(HsmError::InvalidArg)` — malformed `pk_r` or buffer sizes.
/// * `Err(HsmError)` — allocation or PAL failure.
pub async fn encap<'a, P>(
    pal: &P,
    io: &P::Io,
    suite: HpkeSuite,
    pk_r: &[u8],
    enc: &mut [u8],
    shared_secret: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    match suite.kem() {
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521 => {
            dh::encap(pal, io, suite, pk_r, enc, shared_secret, alloc).await
        }
        KemKind::MlKem1024 => mlkem::encap(pal, io, pk_r, enc, shared_secret, alloc).await,
        KemKind::MlKem1024P384 => hybrid::encap(pal, io, pk_r, enc, shared_secret, alloc).await,
    }
}

/// KEM Decap (Base / PSK modes).
///
/// # Parameters
///
/// * `pal` — PAL providing the KEM primitives.
/// * `io` — caller's I/O context (per-IO scope).
/// * `suite` — HPKE ciphersuite.
/// * `enc` — encapsulated key from the sender (`Nenc` bytes).
/// * `sk_r` — recipient private key (`Nsk` bytes): the raw scalar for
///   DHKEM, the `d ‖ z` seed for ML-KEM, the 32-byte seed for the
///   hybrid.
/// * `pk_r` — recipient public key; part of the DHKEM `kem_context`,
///   ignored by the post-quantum KEMs.
/// * `shared_secret` — output: KEM shared secret (`Nsecret` bytes).
/// * `alloc` — scoped allocator for intermediate buffers.
///
/// # Returns
///
/// * `Ok(())` — `shared_secret` populated.
/// * `Err(HsmError::InvalidArg)` — malformed inputs.
/// * `Err(HsmError)` — allocation or PAL failure.
pub async fn decap<'a, P>(
    pal: &P,
    io: &P::Io,
    suite: HpkeSuite,
    enc: &[u8],
    sk_r: &[u8],
    pk_r: &[u8],
    shared_secret: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    match suite.kem() {
        KemKind::DhP256 | KemKind::DhP384 | KemKind::DhP521 => {
            dh::decap(pal, io, suite, enc, sk_r, pk_r, shared_secret, alloc).await
        }
        KemKind::MlKem1024 => mlkem::decap(pal, io, enc, sk_r, shared_secret, alloc).await,
        KemKind::MlKem1024P384 => hybrid::decap(pal, io, enc, sk_r, shared_secret, alloc).await,
    }
}
