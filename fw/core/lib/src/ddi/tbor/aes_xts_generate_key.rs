// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesXtsGenerateKey` command handler.
//!
//! Within an open session, generate a fresh random AES-256-XTS key
//! (`K1 || K2`, 64 bytes, `K1 != K2`), mask it (AEAD-GCM-256) under the
//! requested [`KeyScope`](tsra_fw_ddi_tbor_types::KeyScope)'s masking key
//! as a single [`HsmVaultKeyKind::AesXts512`] blob, and return it.  The
//! key is **not** persisted on-device: the caller passes the masked blob
//! back to [`AesXtsEncryptDecrypt`](super::aes_xts_encrypt_decrypt).
//!
//! Scope, usage and label rules match
//! [`AesGenerateKey`](super::aes_generate_key).

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::TborAesXtsGenerateKeyReq;
use tsra_fw_ddi_tbor_types::TborAesXtsGenerateKeyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::HSM_AES_XTS_KEY_LEN;

use super::aes_generate_key::aes_key_attrs;
use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Handle a TBOR `AesXtsGenerateKey` request.
///
/// No partition lock or undo log is required: the command persists
/// nothing.  The masked blob is written straight into the reserved
/// response slot; IO teardown scrubs the raw key.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<usize> {
        let req = TborAesXtsGenerateKeyReq::decode(cmd_buf.request())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        let scope = HsmKeyScope(req.scope().0);
        validate_active_session(pal, io, sess_id)?;
        if scope != HsmKeyScope::Session
            && part_state::part_state(pal, io)? != HsmPartState::Initialized
        {
            return Err(HsmError::InvalidArg);
        }

        let caller_label = req.key_label();
        let masked_len = masked_blob_len(AeadAlg::AesGcm256, HSM_AES_XTS_KEY_LEN);
        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
        let attrs = aes_key_attrs(scope, req.key_usage())?;

        let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
        let key_label = alloc.dma_alloc(caller_label.len())?;
        key_label.copy_from_slice(caller_label);
        let len = cmd_buf.encode_response(|buf| {
            Ok(TborAesXtsGenerateKeyResp::encode(buf, 0, false)?
                .masked_key_reserve(masked_len)?
                .finish()
                .as_bytes()
                .len())
        })?;

        let out = TborAesXtsGenerateKeyResp::decode_mut(&mut cmd_buf.buffer_mut()[..len])?;
        let params = MaskParams {
            key_kind: HsmVaultKeyKind::AesXts512,
            key_attrs: attrs,
            svn,
            owner_seed_id: owner,
            key_label,
        };
        let key_buf = alloc.dma_alloc(HSM_AES_XTS_KEY_LEN)?;
        pal.aes_xts_gen_key(io, key_buf).await?;
        let written = mask(
            pal,
            io,
            alloc,
            AeadAlg::AesGcm256,
            masking_key,
            &params,
            key_buf,
            Some(out.masked_key),
        )
        .await?;
        // A short write would leave uninitialized response bytes.
        if written != masked_len {
            return Err(HsmError::InternalError);
        }

        Ok(len)
    })
    .await
}
