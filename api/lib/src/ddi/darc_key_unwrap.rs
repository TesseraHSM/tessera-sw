// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcKeyUnwrap` command
//! (opcode `0x22`) at the DDI layer.
//!
//! `DarcKeyUnwrap` installs a transferred key on the **target**. The
//! handler unmasks the TMK, AES-KWP-unwraps `wrapped_key` to the EC2
//! `COSE_Key`, re-derives and checks the public point, intersects the
//! requested `key_usage` with the transported `key_ops`, and re-masks the
//! recovered private key under the requested `scope`'s masking key,
//! returning the masked key, its wire public key, and its vault kind.
//!
//! Runs **inside an already-open** security-domain (V2) session.

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `DarcKeyUnwrap` (opcode `0x22`) on the active session and build
/// the recovered ECC key pair's properties.
///
/// DARC key transport is *kind-discovering*: the recovered key's kind and
/// curve come from the transported blob, not from the caller. The recovered
/// curve is validated against `priv_props` before the key objects are
/// built, so a caller asking for the wrong curve is rejected.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `masked_tmk` - The masked TMK (from
///   [`darc_tmk_import`](super::darc_tmk_import)), exactly
///   [`MASKED_TMK_LEN`] bytes.
/// * `wrapped_key` - The AES-KWP-wrapped `COSE_Key` from
///   [`darc_key_wrap`](super::darc_key_wrap), at most
///   [`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`] bytes.
/// * `priv_props` - The requested private-key properties. Its scope drives
///   the on-device re-masking and its usage (intersected on-device with
///   the transported `key_ops`) grants the recovered key's capabilities.
///
/// # Returns
///
/// The recovered private key's handle (always
/// [`HsmKeyHandle::Unpinned`](ddi::HsmKeyHandle) — the key is non-resident
/// and unmasked on use) together with the private and public key
/// properties.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length `masked_tmk`
/// or an empty/oversized `wrapped_key`, [`HsmError::InvalidKeyProps`] if
/// the recovered curve does not match `priv_props`, and surfaces
/// DDI/device failures.
pub(crate) fn darc_unwrap_key_pair(
    session: &HsmSession,
    masked_tmk: &[u8],
    wrapped_key: &[u8],
    priv_props: &HsmKeyProps,
) -> HsmResult<(ddi::HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let masked_tmk: [u8; MASKED_TMK_LEN] = masked_tmk
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    if wrapped_key.is_empty() || wrapped_key.len() > DARC_UNWRAP_WRAPPED_KEY_MAX_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let req = TborDarcKeyUnwrapReq {
        session_id: session.ex_session_id()?,
        scope: priv_props.tbor_scope(),
        key_usage: darc_ecc_key_usage(priv_props)?,
        masked_tmk,
        wrapped_key: wrapped_key.to_vec(),
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    // Kind-discovering: derive the recovered curve from the masked blob and
    // validate it matches what the caller requested.
    let recovered_curve = HsmMaskedKey::ecc_curve(&resp.masked_key)?;
    if priv_props.ecc_curve() != Some(recovered_curve) {
        return Err(HsmError::InvalidKeyProps);
    }

    let pub_key_der = ecc_wire_pub_key_to_der(recovered_curve, &resp.pub_key)?;
    let (priv_key_props, pub_key_props) =
        HsmMaskedKey::to_key_pair_props(&resp.masked_key, &pub_key_der)?;

    Ok((ddi::HsmKeyHandle::Unpinned, priv_key_props, pub_key_props))
}

/// Maps a recovered ECC private key's requested capabilities onto the TBOR
/// `KeyUsage` bitmask granted on `DarcKeyUnwrap`.
///
/// The requested usage is intersected on-device with the transported
/// `key_ops`. A signing key is granted the signature group
/// (`SIGN | VERIFY`) and a derivation key the derive usage; exactly one of
/// `SIGN`/`DERIVE` must be requested (matching key generation).
fn darc_ecc_key_usage(priv_props: &HsmKeyProps) -> HsmResult<u64> {
    match (priv_props.can_sign(), priv_props.can_derive()) {
        (true, false) => Ok(KEY_USAGE_SIGN | KEY_USAGE_VERIFY),
        (false, true) => Ok(KEY_USAGE_DERIVE),
        _ => Err(HsmError::InvalidKeyProps),
    }
}
