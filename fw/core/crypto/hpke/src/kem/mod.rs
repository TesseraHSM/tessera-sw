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
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::suite::HpkeSuite;
use crate::suite::KemKind;

fn alloc_bytes(len: usize, alloc: &impl HsmScopedAlloc) -> HsmResult<&mut HsmDmaBuf> {
    alloc.dma_alloc(len)
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
