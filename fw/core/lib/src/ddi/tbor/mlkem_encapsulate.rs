// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemEncapsulate` command handler.
//!
//! Encapsulates to a caller-supplied ML-KEM public key, returning the
//! ciphertext and the shared secret **masked** under the requested scope.
//!
//! The public key is public and the ciphertext is public; the shared
//! secret is not, which is why `scope` is on the request even though there
//! is no long-term key involved.  It describes the output: the caller says
//! which masking domain the secret should come back in.
//!
//! The PAL consumes the public key before writing ciphertext directly at
//! its final shared-exchange response offset.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::TborMlKemEncapsulateReq;
use tsra_fw_ddi_tbor_types::TborMlKemEncapsulateResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Length of the ML-KEM shared secret.
const SHARED_SECRET_LEN: usize = 32;

/// Envelope key-label recorded in the masked blob's metadata.
const MLKEM_SS_LABEL: &[u8] = b"MlKemSs";

/// Recover the parameter set from the encapsulation key length.
///
/// The three lengths are distinct, so this is unambiguous — the same
/// property `MlDsaVerify` relies on, and the reason neither command needs
/// a key kind on the wire.
fn kind_from_pub_key_len(len: usize) -> HsmResult<HsmVaultKeyKind> {
    match len {
        800 => Ok(HsmVaultKeyKind::MlKem512Seed),
        1184 => Ok(HsmVaultKeyKind::MlKem768Seed),
        1568 => Ok(HsmVaultKeyKind::MlKem1024Seed),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Ciphertext length per ML-KEM parameter set (FIPS 203 Table 3).
fn mlkem_ct_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(768),
        HsmVaultKeyKind::MlKem768Seed => Ok(1088),
        HsmVaultKeyKind::MlKem1024Seed => Ok(1568),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Attributes recorded in the masked blob's metadata.  The shared secret
/// is derived material, usable for deriving further keys.
fn shared_secret_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_derive(true)
        .with_scope(scope)
}

/// Handle a TBOR `MlKemEncapsulate` request.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let base = cmd_buf.request().as_ptr() as usize;
        let req = TborMlKemEncapsulateReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        validate_active_session(pal, io, sess_id)?;
        let scope = req.scope;

        // No scope gate here: the masking key for `scope` is resolved (and its
        // availability validated per-scope) at mask time by
        // `resolve_masking_key`, which returns `UnsupportedKeyScope` for a
        // scope whose masking key has not been provisioned.  Mirrors
        // `EccGenerateKey` / `EcdhDerive` / `UnwrapKey`.  The old
        // `Ephemeral | Local` gate dated from the out-of-session bring-up,
        // when there was no session to scope a key to; these commands are
        // in-session now, so the restriction no longer has a reason.

        let kind = kind_from_pub_key_len(req.pub_key.len())?;
        let ct_len = mlkem_ct_len(kind)?;
        let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborMlKemEncapsulateReq::TOC_COUNT * 4;
        if (req.pub_key.as_ptr() as usize).checked_sub(base) != Some(data_start) {
            return Err(HsmError::InvalidArg);
        }

        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
        let attrs = shared_secret_attrs(HsmKeyScope(scope));

        let shared_secret = pal.dma_alloc(io, SHARED_SECRET_LEN)?;
        pal.mlkem_encaps_in_place(io, kind, req.pub_key, shared_secret)
            .await?;

        async {
            let masked_len = masked_blob_len(AeadAlg::AesGcm256, SHARED_SECRET_LEN);

            let resp = cmd_buf.buffer_mut();
            let len = TborMlKemEncapsulateResp::encode(resp, 0, false)?
                .ciphertext_existing(ct_len)?
                .masked_shared_secret_reserve(masked_len)?
                .finish()
                .as_bytes()
                .len();
            let resp = &mut resp[..len];

            {
                let out = TborMlKemEncapsulateResp::decode_mut(resp)?;
                pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
                    let masking_key = resolve_masking_key(pal, io, HsmKeyScope(scope), sess_id)?;

                    let key_label = alloc.dma_alloc(MLKEM_SS_LABEL.len())?;
                    key_label.copy_from_slice(MLKEM_SS_LABEL);

                    let params = MaskParams {
                        // TODO(known-issues 2.2): this is the ML-KEM seed kind
                        // of the key that produced the secret, not the kind of
                        // the blob. `EcdhDerive` binds `Secret256/384/521` here
                        // instead -- derived material, not the producing key --
                        // and this should follow it with `Secret256` (the ML-KEM
                        // shared secret is 32 B for every parameter set).
                        // Deferred deliberately: `key_label` already separates a
                        // shared secret from a masked seed, and nothing unmasks
                        // one today.
                        key_kind: kind,
                        key_attrs: attrs,
                        svn,
                        owner_seed_id: owner,
                        key_label,
                    };

                    let written = mask(
                        pal,
                        io,
                        alloc,
                        AeadAlg::AesGcm256,
                        masking_key,
                        &params,
                        shared_secret,
                        Some(out.masked_shared_secret),
                    )
                    .await?;

                    if written != masked_len {
                        return Err(HsmError::InternalError);
                    }
                    Ok(())
                })
                .await?;

                // Filled last so `ResponseBuilt` covers masking too, consistently
                // with the other commands that emit protected key material.
            }

            Ok(len)
        }
        .await
    }
    .await
}
