// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `VerifyKey` handler.
//!
//! Authenticates a **masked key** of any kind without using it. This lets
//! the host reject a tampered or wrong-session blob when it is unmasked,
//! rather than on the first operation that uses it.
//!
//! Flow:
//!
//! 1. Decode the request; gate to an `Active` session of either role.
//! 2. Peek the blob's scope and resolve its masking key. A `Session`-scope
//!    blob resolves to the calling session's key, so a blob from another
//!    session fails authentication.
//! 3. Unmask it: verifies the AEAD tag over the metadata (AAD) and key
//!    material, then validates the metadata.
//!
//! The command persists nothing; the plaintext key is unmasked in place in
//! the request buffer and wiped during IO teardown.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborVerifyKeyReq;
use tsra_fw_ddi_tbor_types::TborVerifyKeyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `VerifyKey` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    {
        let req = TborVerifyKeyReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;

        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        unmask(pal, io, masking_key, req.masked_key).await?;
    }

    cmd_buf.encode_response(|buf| {
        let frame = TborVerifyKeyResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
}
