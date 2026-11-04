// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EcdhDerive` command handler.
//!
//! Within an open session, derive an ECDH shared secret from a caller-held
//! **masked** local ECC private key (from
//! [`EccGenerateKey`](super::ecc_generate_key) or imported via
//! [`UnwrapKey`](super::unwrap_key)) and a host-supplied peer public key,
//! then return the secret as a **masked** blob under the requested scope's
//! masking key.  The local key is unmasked **in place** in the request
//! buffer (no scratch copy); its curve is recovered from the blob's key
//! kind.  This is the TBOR analogue of MBOR `EcdhKeyExchange`, re-masking
//! the derived secret instead of vaulting it.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::TborEcdhDeriveReq;
use tsra_fw_ddi_tbor_types::TborEcdhDeriveResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;

use super::from_pal::ecc_private_curve;
use super::from_pal::ecdh_secret;
use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Attributes recorded in the derived-secret masked blob's metadata.  An
/// ECDH shared secret is derived on-device (so `local`) and usable only as
/// a key-derivation key (`derive`) for a further KDF — matching MBOR's
/// [`for_ecdh_secret`](crate::ddi::mbor::key_attrs::for_ecdh_secret).
/// `scope` records the lifecycle / visibility domain.
fn ecdh_secret_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_derive(true)
        .with_scope(scope)
}

/// Handle a TBOR `EcdhDerive` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it unmasks the local key, derives the secret, masks it, and
/// returns the blob in the consumed request storage.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<usize> {
        let req = TborEcdhDeriveReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));
        let target_scope = HsmKeyScope(req.scope);
        validate_active_session(pal, io, sess_id)?;

        // No partition-state pre-check: the derived secret is masked under
        // `target_scope`, whose masking key is resolved (and its availability
        // validated per-scope) at mask time by `resolve_masking_key` —
        // returning `UnsupportedKeyScope` for a scope whose masking key has not
        // been provisioned yet.  This mirrors `EccSign` / `UnwrapKey`, which
        // defer scope validation to masking-key resolution rather than gating on
        // a coarse `part_state`.

        // Platform identity bound into the derived-secret blob (anti-rollback
        // on re-import).
        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
        let attrs = ecdh_secret_attrs(target_scope);

        // The scope that masked the local key is recorded (cleartext,
        // tag-bound) in its blob metadata; resolve its masking key before
        // unmasking.  The peek borrow is transient — it ends before the in-place
        // unmask.
        let scope_local = peek_scope(req.masked_key)?;
        let masking_key_local = resolve_masking_key(pal, io, scope_local, sess_id)?;

        let view = unmask(pal, io, masking_key_local, req.masked_key).await?;
        let curve = ecc_private_curve(view.key_kind)?;
        if !view.key_attrs.derive() {
            return Err(HsmError::InvalidPermissions);
        }

        // The host emits a fixed-length peer public key for the curve; the
        // PAL requires exactly `wire_pub_key_len` bytes — reject any
        // non-exact length so trailing junk is not silently accepted.
        if req.peer_pub_key.len() != curve.wire_pub_key_len() {
            return Err(HsmError::InvalidArg);
        }

        let secret_len = curve.secret_len();
        let masked_len = masked_blob_len(AeadAlg::AesGcm256, secret_len);
        let kind = ecdh_secret(curve);

        // Resolve the target masking key and staging label before deriving.
        let masking_key_target = resolve_masking_key(pal, io, target_scope, sess_id)?;
        let key_label = alloc.dma_alloc(req.key_label.len())?;
        key_label.copy_from_slice(req.key_label);
        let params = MaskParams {
            key_kind: kind,
            key_attrs: attrs,
            svn,
            owner_seed_id: owner,
            key_label,
        };

        // Derive into DMA scratch, then mask it into the reserved
        // response slot.
        let secret = alloc.dma_alloc(secret_len)?;
        let derived = pal
            .ecdh_derive(io, curve, view.target_key, req.peer_pub_key, secret)
            .await;
        let derive_and_mask = async {
            derived?;
            // The private key and peer input are consumed; only the
            // preexisting derived-secret scratch remains live.
            let len = cmd_buf.encode_response(|buf| {
                Ok(TborEcdhDeriveResp::encode(buf, 0, false)?
                    .masked_secret_reserve(masked_len)?
                    .finish()
                    .as_bytes()
                    .len())
            })?;
            let out = TborEcdhDeriveResp::decode_mut(&mut cmd_buf.buffer_mut()[..len])?;
            let written = mask(
                pal,
                io,
                alloc,
                AeadAlg::AesGcm256,
                masking_key_target,
                &params,
                secret,
                Some(out.masked_secret),
            )
            .await?;
            // A short `mask` write would leave uninitialized bytes in
            // the reserved `masked_secret` slot (sized to `masked_len`).
            if written != masked_len {
                return Err(HsmError::InternalError);
            }
            Ok(len)
        }
        .await;
        derive_and_mask
    })
    .await
}
