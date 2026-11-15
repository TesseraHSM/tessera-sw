// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-KEM-1024 HPKE KEM (draft-ietf-hpke-pq §3), `kem_id = 0x0042`.
//!
//! * `pk` / `enc` — the FIPS 203 encapsulation key / ciphertext.
//! * `sk` — the 64-byte `d ‖ z` seed, expanded on every Decap with
//!   `ML-KEM.KeyGen_internal`.
//!
//! Encap runs the FIPS 203 §7.2 encapsulation-key check here because
//! not every PAL backend performs it.

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmMlKemParamSet;
use tsra_fw_hsm_pal_traits::HsmMlKemPct;
use tsra_fw_hsm_pal_traits::HsmMlKemPrivKey;
use tsra_fw_hsm_pal_traits::HsmMlKemPubKeyMut;
use tsra_fw_hsm_pal_traits::HsmMlSeedSrc;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::MLKEM_SEED_LEN;
use tsra_fw_hsm_pal_traits::MLKEM_SHARED_SECRET_LEN;

use super::alloc_bytes;
use crate::helpers::dma_copy_in;

/// The only ML-KEM parameter set used by HPKE here.
pub(super) const PARAM_SET: HsmMlKemParamSet = HsmMlKemParamSet::MlKem1024;

/// Encapsulation-key length (`Npk`).
pub(super) const EK_LEN: usize = PARAM_SET.pk_len();

/// Ciphertext length (`Nenc`).
pub(super) const CT_LEN: usize = PARAM_SET.ct_len();

/// ML-KEM modulus `q`.
const Q: u16 = 3329;

/// FIPS 203 §7.2 encapsulation-key check: `ek` is [`EK_LEN`] bytes and
/// every 12-bit coefficient of its `ByteEncode12` part is below `q`
/// (equivalently `ByteEncode12(ByteDecode12(ek)) == ek`).
///
/// `ek` is public, so the check need not be constant-time.
///
/// # Returns
///
/// * `Ok(())` — the key passes both checks.
/// * `Err(HsmError::InvalidArg)` — wrong length or a coefficient `≥ q`.
pub(super) fn check_ek(ek: &[u8]) -> HsmResult<()> {
    if ek.len() != EK_LEN {
        return Err(HsmError::InvalidArg);
    }
    // The trailing 32 bytes are the public seed `rho`.
    let packed = &ek[..EK_LEN - 32];
    for c in packed.chunks_exact(3) {
        let lo = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let hi = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        if lo >= Q || hi >= Q {
            return Err(HsmError::InvalidArg);
        }
    }
    Ok(())
}

/// Checks `ek`, encapsulates to it and writes the ciphertext to `ct`
/// and the ML-KEM shared secret to `ss`.
///
/// # Parameters
///
/// * `ek` — encapsulation key ([`EK_LEN`] bytes).
/// * `ct` — output ciphertext ([`CT_LEN`] bytes).
/// * `ss` — output shared secret (32 bytes).
pub(super) async fn encaps<'a, P>(
    pal: &P,
    io: &P::Io,
    ek: &[u8],
    ct: &mut [u8],
    ss: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    check_ek(ek)?;
    if ct.len() != CT_LEN || ss.len() != MLKEM_SHARED_SECRET_LEN {
        return Err(HsmError::InvalidArg);
    }
    // For ML-KEM-1024 `CT_LEN == EK_LEN`, so the key buffer is reused
    // for the ciphertext.
    let pk_ct = dma_copy_in(alloc, ek)?;
    let (ct_len, _) = pal
        .mlkem_encaps_in_place(io, PARAM_SET, HsmMlKemPubKeyMut::Encoded(pk_ct), ss)
        .await?;
    if ct_len != CT_LEN {
        return Err(HsmError::InvalidArg);
    }
    ct.copy_from_slice(&pk_ct[..CT_LEN]);
    Ok(())
}

/// Expands the `d ‖ z` `seed` and decapsulates `ct` into `ss`.
///
/// # Parameters
///
/// * `seed` — the 64-byte `d ‖ z` seed (left unchanged).
/// * `ct` — ciphertext ([`CT_LEN`] bytes).
/// * `ss` — output shared secret (32 bytes).
pub(super) async fn decaps<'a, P>(
    pal: &P,
    io: &P::Io,
    seed: &mut HsmDmaBuf,
    ct: &[u8],
    ss: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    if seed.len() != MLKEM_SEED_LEN || ct.len() != CT_LEN {
        return Err(HsmError::InvalidArg);
    }
    let keys = alloc_bytes(PARAM_SET.sk_len() + PARAM_SET.pk_len(), alloc)?;
    let (dk, ek) = keys.split_at_mut(PARAM_SET.sk_len());
    pal.mlkem_gen_keypair(
        io,
        PARAM_SET,
        HsmMlSeedSrc::Caller,
        HsmMlKemPct::None,
        seed,
        Some((&mut *dk, ek)),
    )
    .await?;
    let ct = dma_copy_in(alloc, ct)?;
    pal.mlkem_decaps(io, PARAM_SET, HsmMlKemPrivKey::Expanded(dk), ct, Some(ss))
        .await?;
    Ok(())
}

/// Runs `ML-KEM.KeyGen` (or `KeyGen_internal` for [`HsmMlSeedSrc::Caller`])
/// on `seed` and writes the encapsulation key to `ek`.
///
/// # Parameters
///
/// * `seed` — the 64-byte `d ‖ z` seed; filled for [`HsmMlSeedSrc::Random`].
/// * `ek` — output encapsulation key ([`EK_LEN`] bytes).
pub(super) async fn keypair<'a, P>(
    pal: &P,
    io: &P::Io,
    seed_src: HsmMlSeedSrc,
    pct: HsmMlKemPct,
    seed: &mut HsmDmaBuf,
    ek: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    if seed.len() != MLKEM_SEED_LEN || ek.len() != EK_LEN {
        return Err(HsmError::InvalidArg);
    }
    let keys = alloc_bytes(PARAM_SET.sk_len() + PARAM_SET.pk_len(), alloc)?;
    let (dk, pk) = keys.split_at_mut(PARAM_SET.sk_len());
    let (_, pk_len) = pal
        .mlkem_gen_keypair(io, PARAM_SET, seed_src, pct, seed, Some((dk, &mut *pk)))
        .await?;
    if pk_len != EK_LEN {
        return Err(HsmError::InvalidArg);
    }
    ek.copy_from_slice(&pk[..EK_LEN]);
    Ok(())
}

/// ML-KEM-1024 HPKE Encap: `enc` is the ciphertext.
pub(super) async fn encap<'a, P>(
    pal: &P,
    io: &P::Io,
    pk_r: &[u8],
    enc: &mut [u8],
    shared_secret: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    let ct = enc.get_mut(..CT_LEN).ok_or(HsmError::InvalidArg)?;
    encaps(pal, io, pk_r, ct, shared_secret, alloc).await
}

/// ML-KEM-1024 HPKE Decap: `sk_r` is the `d ‖ z` seed.
pub(super) async fn decap<'a, P>(
    pal: &P,
    io: &P::Io,
    enc: &[u8],
    sk_r: &[u8],
    shared_secret: &mut HsmDmaBuf,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    if sk_r.len() != MLKEM_SEED_LEN {
        return Err(HsmError::InvalidArg);
    }
    let seed = dma_copy_in(alloc, sk_r)?;
    decaps(pal, io, seed, enc, shared_secret, alloc).await
}
