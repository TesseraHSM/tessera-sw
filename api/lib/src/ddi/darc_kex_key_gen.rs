// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcKexKeyGen` command
//! (opcode `0x20`) at the DDI layer.
//!
//! `DarcKexKeyGen` generates a new DARC key-exchange key (ECC-P384) and
//! returns the **masked** (AEAD-GCM-256) private key plus its raw public
//! key. Run on the target it yields the HPKE receiver identity; run on
//! the source it yields the HPKE sender-auth identity. The private key is
//! not stored on the device; the caller retains the masked blob and
//! unmasks it on-use in [`darc_tmk_export`](super::darc_tmk_export) /
//! [`darc_tmk_import`](super::darc_tmk_import).
//!
//! It runs **inside an already-open** security-domain (V2) session; the
//! request carries the active session id and the requested key `scope`.

use tsra_crypto::aead_envelope;
use tsra_ddi_tbor_types::*;

use super::*;

/// Length of the masked KEX-key blob's AAD region: a fixed 192-byte
/// masked-key metadata record.
const KEX_META_LEN: usize = 192;

/// Sanity-checks the firmware-returned masked KEX key before it is handed
/// back for unmask-on-use. The host cannot verify the AEAD tag (the
/// masking key is device-internal) but can confirm a well-formed
/// AES-256-GCM masked-key envelope of the expected shape.
fn validate_masked_kex_key(masked_key: &[u8; MASKED_KEX_KEY_LEN]) -> HsmResult<()> {
    let env = aead_envelope::inspect(masked_key).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
    if !matches!(env.alg, aead_envelope::AeadAlg::AesGcm256) || env.aad.len() != KEX_META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    Ok(())
}

/// Issue `DarcKexKeyGen` (opcode `0x20`) on the active session.
///
/// Ships the active session id and the requested key `scope`. Returns the
/// new KEX key as a masked (AEAD-GCM-256) private-key blob plus its raw
/// P-384 public key (`x ‖ y`, 96 bytes). The key is not stored on-device.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `scope` - Requested key scope as the 1-byte `KeyScope` discriminant.
///
/// # Errors
///
/// Surfaces DDI/device failures from the round-trip and
/// [`HsmError::MaskedKeyDecodeFailed`] if the returned blob is malformed.
pub(crate) fn darc_kex_key_gen(
    session: &HsmSession,
    scope: u8,
) -> HsmResult<([u8; MASKED_KEX_KEY_LEN], [u8; KEX_PUB_KEY_LEN])> {
    let req = TborDarcKexKeyGenReq {
        session_id: session.ex_session_id()?,
        scope,
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    validate_masked_kex_key(&resp.masked_key)?;
    Ok((resp.masked_key, resp.pub_key))
}
