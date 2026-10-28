// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemDecapsulate` command handler.
//!
//! Decapsulates a ciphertext with a caller-held **masked** ML-KEM key
//! (from [`MlKemGenerateKey`](super::mlkem_generate_key)), returning the
//! shared secret masked under the requested scope.
//!
//! Unmasking yields the 64-byte `(d ‖ z)` seed pair followed by the
//! expanded decapsulation key; only the expanded half is needed here, so
//! the fastpath core decapsulates with it directly rather than
//! re-deriving the key pair (`f0bf65c4`).
//!
//! # No failure path
//!
//! ML-KEM decapsulation does not fail.  A ciphertext that does not decrypt
//! yields an implicit-rejection secret — a value derived from the key and
//! the ciphertext — rather than an error, which is what stops an attacker
//! learning anything from whether decapsulation "worked".  So unlike
//! [`MlDsaVerify`](super::mldsa_verify) there is no verification status
//! here: every well-formed request produces a secret.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::TborMlKemDecapsulateReq;
use tsra_fw_ddi_tbor_types::TborMlKemDecapsulateResp;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::ddi::tbor::mlkem_generate_key::mlkem_sec_key_len;
use crate::ddi::tbor::mlkem_generate_key::MLKEM_SEED_LEN;
use crate::part_state;

/// Length of the ML-KEM shared secret.
const SHARED_SECRET_LEN: usize = 32;

/// Envelope key-label recorded in the masked blob's metadata.
const MLKEM_SS_LABEL: &[u8] = b"MlKemSs";

/// Attributes recorded in the masked blob's metadata.
fn shared_secret_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_derive(true)
        .with_scope(scope)
}

/// Handle a TBOR `MlKemDecapsulate` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlKemDecapsulateReq::decode_mut(req_buf)?;
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

    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = shared_secret_attrs(HsmKeyScope(scope));

    // Unmask, decapsulate and re-mask inside a block that yields a
    // `Result`, so every post-unmask path falls through to the wipe below:
    // the recovered seed pair is the private key and must not survive in
    // the request buffer.
    // The scope that masked this key is recorded (cleartext, tag-bound) in
    // the blob metadata; resolve its masking key before unmasking.
    let key_scope = peek_scope(req.masked_key)?;
    let masking_key_in = resolve_masking_key(pal, io, key_scope, sess_id)?;

    let outcome: HsmResult<&'p DmaBuf> = async {
        // Unmask in place; the AAD carries the parameter set.
        let view = unmask(pal, io, masking_key_in, req.masked_key).await?;
        let kind = view.key_kind;
        if !view.key_attrs.derive() {
            return Err(HsmError::InvalidPermissions);
        }
        let sec_len = mlkem_sec_key_len(kind)?;
        if view.target_key.len() != MLKEM_SEED_LEN + sec_len {
            return Err(HsmError::InvalidArg);
        }
        let key_blob: &DmaBuf = view.target_key;

        let shared_secret = pal.dma_alloc(io, SHARED_SECRET_LEN)?;

        let decaps = pal
            .mlkem_decaps(
                io,
                kind,
                &key_blob[MLKEM_SEED_LEN..],
                req.ciphertext,
                &mut shared_secret[..],
            )
            .await;
        decaps?;

        let masked_len = masked_blob_len(AeadAlg::AesGcm256, SHARED_SECRET_LEN);

        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborMlKemDecapsulateResp::encode(buf, 0, false)?
                .masked_shared_secret_reserve(masked_len)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;

        let masked = {
            let out = TborMlKemDecapsulateResp::decode_mut(resp)?;
            pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
                let key = resolve_masking_key(pal, io, HsmKeyScope(scope), sess_id)?;

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
                    key,
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
            .await
        };

        shared_secret.zeroize();
        masked?;

        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    // The unmask decrypted in place, so the request buffer holds the seed
    // pair on every path out of the block above.
    req.masked_key.zeroize();
    outcome
}
