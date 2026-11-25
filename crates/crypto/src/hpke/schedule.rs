// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE key schedule (RFC 9180 §5.1, draft-ietf-hpke-hpke §5.1).
//!
//! One-stage (SHAKE256) suites derive `key ‖ base_nonce ‖
//! exporter_secret` with a single `LabeledDerive` in
//! [`one_stage_secret`] (`CombineSecrets_OneStage`) and split it.
//!
//! For two-stage (HKDF) suites, both [`key_schedule`] and
//! [`key_schedule_export`] start by deriving `secret`, the
//! `key_schedule_context` (`KSC`), and the per-suite `hpke_suite_id`
//! from the shared inputs. They then diverge:
//!
//! * [`key_schedule`] expands `secret` into the AEAD `key` and
//!   `base_nonce`.
//! * [`key_schedule_export`] expands `secret` into the `exporter_secret`.
//!
//! [`export`] then turns `exporter_secret` into the caller's exported
//! value with the suite's `Export` function.

use zeroize::Zeroizing;

use super::kdf::i2osp2;
use super::kdf::labeled_derive;
use super::kdf::labeled_expand;
use super::kdf::labeled_extract;
use super::suite::HpkeSuite;
use crate::CryptoError;
use crate::HashAlgo;

/// Outputs of [`derive_secret_and_ksc`].
struct ScheduleState {
    /// HKDF hash of the suite.
    algo: HashAlgo,
    /// Cached HPKE suite identifier (`b"HPKE" || kem_id || kdf_id || aead_id`).
    suite_id: [u8; 10],
    /// `secret = LabeledExtract(shared_secret, "secret", psk)` (`Nh` bytes).
    secret: Zeroizing<Vec<u8>>,
    /// `key_schedule_context = mode || psk_id_hash || info_hash`
    /// (`1 + 2*Nh` bytes).
    ksc: Vec<u8>,
}

/// HKDF hash of a two-stage suite.
fn two_stage_hash(suite: HpkeSuite) -> Result<HashAlgo, CryptoError> {
    suite.kdf_hash().ok_or(CryptoError::HpkeKeyScheduleFailed)
}

/// Compute the shared `(secret, ksc)` pair used by every two-stage
/// HPKE key schedule (export and AEAD).
fn derive_secret_and_ksc(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<ScheduleState, CryptoError> {
    let algo = two_stage_hash(suite)?;
    let nh = suite.nh();
    let suite_id = suite.hpke_suite_id();

    let psk_id_hash = labeled_extract(&algo, &suite_id, &[], b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract(&algo, &suite_id, &[], b"info_hash", info)?;

    let mut ksc = Vec::with_capacity(1 + 2 * nh);
    ksc.push(mode);
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    let secret = Zeroizing::new(labeled_extract(
        &algo,
        &suite_id,
        shared_secret,
        b"secret",
        psk,
    )?);

    Ok(ScheduleState {
        algo,
        suite_id,
        secret,
        ksc,
    })
}

/// `CombineSecrets_OneStage` (draft-ietf-hpke-hpke §5.1): returns
/// `key ‖ base_nonce ‖ exporter_secret` (`Nk + Nn + Nh` bytes).
///
/// ```text
/// secrets = lengthPrefixed(psk) ‖ lengthPrefixed(shared_secret)
/// context = mode ‖ lengthPrefixed(psk_id) ‖ lengthPrefixed(info)
/// secret  = LabeledDerive(secrets, "secret", context, Nk + Nn + Nh)
/// ```
fn one_stage_secret(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let psk_len = i2osp2(psk.len())?;
    let ss_len = i2osp2(shared_secret.len())?;
    let psk_id_len = i2osp2(psk_id.len())?;
    let info_len = i2osp2(info.len())?;
    let mut secret = Zeroizing::new(vec![0u8; suite.nk() + suite.nn() + suite.nh()]);
    labeled_derive(
        &suite.hpke_suite_id(),
        &[&psk_len, psk, &ss_len, shared_secret],
        b"secret",
        &[&[mode], &psk_id_len, psk_id, &info_len, info],
        &mut secret,
    )?;
    Ok(secret)
}

/// Derive `(key, base_nonce)` from `shared_secret + info` per RFC 9180
/// §5.1 / draft-ietf-hpke-hpke §5.1. For Base / Auth modes pass empty
/// `psk` / `psk_id`.
pub(crate) fn key_schedule(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    if suite.is_one_stage() {
        let secret = one_stage_secret(suite, mode, shared_secret, info, psk, psk_id)?;
        let (nk, nn) = (suite.nk(), suite.nn());
        let key = Zeroizing::new(secret[..nk].to_vec());
        let base_nonce = secret[nk..nk + nn].to_vec();
        return Ok((key, base_nonce));
    }

    let st = derive_secret_and_ksc(suite, mode, shared_secret, info, psk, psk_id)?;
    let key = Zeroizing::new(labeled_expand(
        &st.algo,
        &st.suite_id,
        &st.secret,
        b"key",
        &st.ksc,
        suite.nk(),
    )?);
    let base_nonce = labeled_expand(
        &st.algo,
        &st.suite_id,
        &st.secret,
        b"base_nonce",
        &st.ksc,
        suite.nn(),
    )?;
    Ok((key, base_nonce))
}

/// Derive `exporter_secret` (`Nh` bytes) from `shared_secret + info`.
pub(crate) fn key_schedule_export(
    suite: HpkeSuite,
    mode: u8,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if suite.is_one_stage() {
        let secret = one_stage_secret(suite, mode, shared_secret, info, psk, psk_id)?;
        let off = suite.nk() + suite.nn();
        return Ok(Zeroizing::new(secret[off..].to_vec()));
    }

    let st = derive_secret_and_ksc(suite, mode, shared_secret, info, psk, psk_id)?;
    Ok(Zeroizing::new(labeled_expand(
        &st.algo,
        &st.suite_id,
        &st.secret,
        b"exp",
        &st.ksc,
        suite.nh(),
    )?))
}

/// `Context.Export(exporter_context, L)`, writing `out.len() = L`
/// bytes:
///
/// * two-stage: `LabeledExpand(exporter_secret, "sec", ctx, L)`.
/// * one-stage: `LabeledDerive(exporter_secret, "sec", ctx, L)`.
pub(crate) fn export(
    suite: HpkeSuite,
    exporter_secret: &[u8],
    exporter_context: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let suite_id = suite.hpke_suite_id();
    match suite.kdf_hash() {
        Some(algo) => {
            let bytes = Zeroizing::new(labeled_expand(
                &algo,
                &suite_id,
                exporter_secret,
                b"sec",
                exporter_context,
                out.len(),
            )?);
            out.copy_from_slice(&bytes);
            Ok(())
        }
        None => labeled_derive(
            &suite_id,
            &[exporter_secret],
            b"sec",
            &[exporter_context],
            out,
        )
        .map_err(|e| match e {
            CryptoError::HpkeInvalidBufferSize => CryptoError::HpkeExportTooLarge,
            e => e,
        }),
    }
}
