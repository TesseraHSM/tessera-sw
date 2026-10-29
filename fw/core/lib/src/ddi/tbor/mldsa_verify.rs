// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaVerify` command handler.
//!
//! Verifies a signature under a caller-supplied public key.  Unlike
//! [`MlDsaSign`](super::mldsa_sign) there is no key to unmask and no secret
//! anywhere in the request: every operand is public.
//!
//! # Why failure is a status, not a boolean
//!
//! The response is empty.  An invalid signature is reported as
//! [`HsmError::MlDsaVerifyFailed`], mirroring `EccVerifyFailed`, rather
//! than as a `verified: bool` field.  A caller who neglects to inspect a
//! boolean would silently treat a forged signature as valid; a caller who
//! neglects to inspect a status gets an error either way.
//!
//! # Parameter set
//!
//! There is no key kind on the wire.  It is recovered from the public
//! key's length, which is unique per parameter set — 1312 / 1952 / 2592 for
//! ML-DSA-44 / -65 / -87.  That is the same property the schema relies on
//! to keep the request small, and it is why seed-bearing commands must
//! carry an explicit kind while this one need not: seeds are 32 bytes
//! whatever the parameter set.

use tsra_fw_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_fw_ddi_tbor_types::TborMlDsaVerifyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Recover the parameter set from the public key length.
///
/// The three lengths are distinct, so this is unambiguous.
fn kind_from_pub_key_len(len: usize) -> HsmResult<HsmVaultKeyKind> {
    match len {
        1312 => Ok(HsmVaultKeyKind::MlDsa44Seed),
        1952 => Ok(HsmVaultKeyKind::MlDsa65Seed),
        2592 => Ok(HsmVaultKeyKind::MlDsa87Seed),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Signature length per ML-DSA parameter set (FIPS 204 Table 2).
fn mldsa_sig_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2420),
        HsmVaultKeyKind::MlDsa65Seed => Ok(3309),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4627),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle a TBOR `MlDsaVerify` request.
///
/// Persists nothing, holds no lock, and handles no secret material.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let req = TborMlDsaVerifyReq::decode(cmd_buf.request())?;

        let kind = kind_from_pub_key_len(req.pub_key().len())?;

        // A signature of the wrong length for the parameter set is malformed
        // input, not a failed verification: report it as such rather than
        // letting it read as a forgery.
        if req.signature().len() != mldsa_sig_len(kind)? {
            return Err(HsmError::InvalidArg);
        }
        if req.ctx().len() > 255 {
            return Err(HsmError::InvalidArg);
        }

        let verified = pal
            .mldsa_verify(
                io,
                kind,
                req.pub_key(),
                req.message(),
                req.ctx(),
                req.signature(),
            )
            .await?;

        if !verified {
            return Err(HsmError::MlDsaVerifyFailed);
        }

        // Success carries no payload: the response exists only to say so.
        let frame = TborMlDsaVerifyResp::encode(cmd_buf.buffer_mut(), 0, false)?.finish();
        Ok(frame.as_bytes().len())
    }
    .await
}
