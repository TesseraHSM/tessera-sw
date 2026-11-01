// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetPublicKey` handler.
//!
//! Takes a **masked private key** (RSA / RSA-CRT / ECC), unmasks it, and
//! returns its wire public key — the same format [`super::unwrap_key`]
//! returns (`n_le ‖ e_le` / `x ‖ y`). This lets a host that holds only the
//! masked blob rebuild the public half of a key pair.
//!
//! Flow:
//!
//! 1. Decode the request; gate to an `Active` session of either role.
//! 2. Peek the blob's scope, resolve its masking key, and unmask it
//!    (verifies the AEAD tag).
//! 3. Derive the public key from the recovered private key. Symmetric and
//!    other non-asymmetric kinds are rejected with
//!    [`HsmError::InvalidKeyType`], like `EccSign` / `EcdhDerive`.
//!
//! No key usage is required: a public key is not sensitive. The command
//! persists nothing; the plaintext key is unmasked in place in the request
//! buffer and wiped during IO teardown.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborGetPublicKeyReq;
use tsra_fw_ddi_tbor_types::TborGetPublicKeyResp;
use tsra_fw_ddi_tbor_types::GET_PUBLIC_KEY_PUB_KEY_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::unwrap_key::pub_deriv;
use super::unwrap_key::PubDeriv;
use super::validate_active_session;

/// Handle a TBOR `GetPublicKey` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborGetPublicKeyReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;

        let scope = peek_scope(req.masked_key)?;
        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let pub_key = derive_pub_key(pal, io, alloc, view.key_kind, view.target_key).await?;

        cmd_buf.encode_response(|buf| {
            let frame = TborGetPublicKeyResp::encode(buf, 0, false)?
                .pub_key(pub_key)?
                .finish();
            Ok(frame.as_bytes().len())
        })
    })
    .await
}

/// Derive the wire public key of `priv_key` into `alloc`-scoped scratch.
async fn derive_pub_key<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    kind: HsmVaultKeyKind,
    priv_key: &HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf> {
    let deriv = pub_deriv(kind).ok_or(HsmError::InvalidKeyType)?;
    let len = match deriv {
        PubDeriv::Rsa => pal.rsa_priv_pub_key(io, priv_key, None)?,
        PubDeriv::Ecc => pal.ecc_priv_pub_key(io, priv_key, None).await?,
    };
    if len > GET_PUBLIC_KEY_PUB_KEY_MAX_LEN {
        return Err(HsmError::InternalError);
    }
    let out = alloc.dma_alloc(len)?;
    let written = match deriv {
        PubDeriv::Rsa => pal.rsa_priv_pub_key(io, priv_key, Some(&mut *out))?,
        PubDeriv::Ecc => pal.ecc_priv_pub_key(io, priv_key, Some(&mut *out)).await?,
    };
    if written != len {
        return Err(HsmError::InternalError);
    }
    Ok(out)
}
