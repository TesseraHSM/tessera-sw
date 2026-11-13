// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenFinish` handler — Phase 2 of session establishment.
//!
//! Runs on the encrypted channel: the PAL opened the request under the
//! Pending slot's VM→HSM transport key.  Loads the Pending slot's
//! handshake state, verifies the host's confirmation
//! `fin = HMAC-SHA-384(fin_key, T1)` in constant time (proving the host
//! holds the role's PSK), derives the per-session `param_key`, decrypts
//! the host-supplied `seed_envelope` to recover the 32-byte session
//! seed, draws a random `masking_key`, wraps it under
//! `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK", seed)` into the response
//! `bmk_session` AEAD envelope, and promotes the slot Pending → Active.
//!
//! On any failure the dispatcher's undo walk destroys the Pending slot
//! after the (sealed) error reply is sent, so a tampered `fin` or
//! envelope cannot be probed repeatedly against the same slot.
//!
//! All variable-length buffers live on the per-IO scoped allocator
//! per the firmware async-discipline convention; no DMA-sized arrays
//! sit on the async stack.

use tsra_fw_core_crypto_aead_envelope::open as aead_open;
use tsra_fw_core_crypto_aead_envelope::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::mask as mask_key;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

use super::session_open_init::PENDING_AUTH_OFF;
use super::session_open_init::PENDING_BLOB_LEN;
use super::session_open_init::PENDING_KEYS_OFF;
use super::session_open_init::PENDING_SUITE_OFF;
use super::session_open_init::PENDING_T1_OFF;
use super::session_open_init::PENDING_TYPE_OFF;

/// API-revision tag persisted into the session vault blob's first 8
/// bytes by [`HsmSessionManager::session_promote`].
const SESSION_API_REV: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];

/// AEAD algorithm shared by `bmk_session` and the seed envelope.
const AEAD_ALG: AeadAlg = AeadAlg::AesGcm256;

/// Caller-supplied label embedded in the `bmk_session`
/// [`MaskedKeyMetadata`]. Identifies the wrapped key as the
/// per-session boot-masking key recovered on resume.
const BMK_SESSION_KEY_LABEL: &[u8] = b"SESSION_BMK";

/// Validated `SessionOpenFinish` request fields.
struct ParsedRequest<'a> {
    /// Session Id
    sess_id: HsmSessId,
    /// Codec-supplied `&HsmDmaBuf` sub-view of the inbound request
    /// buffer; flows straight into the constant-time MAC compare.
    fin: &'a HsmDmaBuf,
    /// Codec-supplied `&mut HsmDmaBuf` sub-view of the inbound request
    /// buffer.  Decrypted in place by [`aead_open`] — no scratch copy.
    seed_envelope: &'a mut HsmDmaBuf,
}

/// Decoded Pending handshake state, split into the regions the PAL
/// crypto APIs need as distinct `&HsmDmaBuf` arguments (HMAC `key` and
/// `data` must not alias).
struct HandshakeState<'a> {
    hs: &'a mut HsmDmaBuf,
    t1: &'a mut HsmDmaBuf,
    auth_binding: &'a mut HsmDmaBuf,
    h2m: &'a mut HsmDmaBuf,
    m2h: &'a mut HsmDmaBuf,
}

/// Handle a TBOR `SessionOpenFinish` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let ParsedRequest {
            sess_id,
            fin,
            seed_envelope,
        } = parse_request(cmd_buf.request_mut())?;

        let HandshakeState {
            hs,
            t1,
            auth_binding,
            h2m,
            m2h,
        } = load_pending_state(pal, io, alloc, sess_id)?;

        // Record the session's teardown inverse up front: any failure below
        // (fin/envelope auth, key derivation, promote, response, or the CQE
        // post) reverts the session via the dispatcher's undo walk.  The
        // slot is not destroyed eagerly: its transport keys must outlive
        // this handler to seal the error reply, and a racing finish must
        // itself authenticate under those keys, so it gives a prober
        // nothing.
        undo.push_session_destroy(sess_id)?;

        verify_fin(pal, io, alloc, hs, t1, fin).await?;
        crate::session::validate_auth_binding(pal, io, alloc, sess_id, auth_binding).await?;

        // ── Derive param_key, use it to open the seed envelope ────
        let param_key = alloc.dma_alloc(SESSION_PARAM_KEY_LEN)?;
        hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_PARAM_KEY_LABEL, param_key).await?;
        let seed = open_seed_envelope(pal, io, param_key, seed_envelope).await?;

        // The masking key is **random**, not derived from `hs`: the host
        // computes `hs` too, so a masking key expanded from it would let
        // the host open any blob masked at `Session` scope.  Continuity
        // does not depend on re-derivation: the key leaves the HSM only as
        // `bmk_session`, wrapped under `BK_SESSION`, and `BK_BOOT` never
        // leaves the device.
        let masking_key = alloc.dma_alloc(SESSION_MASKING_KEY_LEN)?;
        pal.rng_fill_bytes(io, &mut masking_key[..])?;

        // ── Build bmk_session BEFORE promote, so no active session is
        //    ever created without a recovery blob.
        let bmk_session = build_bmk_session(pal, io, alloc, seed, masking_key).await?;

        // ── Promote Pending → Active ──────────────────────────────
        let api_rev = alloc.dma_alloc(SESSION_API_REV.len())?;
        api_rev.copy_from_slice(&SESSION_API_REV);
        pal.session_promote(
            io,
            sess_id,
            api_rev,
            param_key,
            masking_key,
            auth_binding,
            h2m,
            m2h,
        )
        .await?;

        encode_response(cmd_buf, bmk_session)
    })
    .await
}

/// Decode and validate the wire request.
fn parse_request<'a>(req_buf: &'a mut HsmDmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborSessionOpenFinishReq::decode_mut(req_buf)?;
    let id = HsmSessId::from(u16::from(req.session_id));
    let fin: &HsmDmaBuf = req.mac_fin;
    let seed_envelope: &mut HsmDmaBuf = req.seed_envelope;
    if fin.len() != MAC_FIN_LEN || seed_envelope.len() != SEED_ENVELOPE_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(ParsedRequest {
        sess_id: id,
        fin,
        seed_envelope,
    })
}

/// Load the Pending slot's blob and split it into scoped buffers,
/// validating its recorded session type and suite.
fn load_pending_state<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    id: HsmSessId,
) -> HsmResult<HandshakeState<'a>> {
    if pal.session_pending_state(io, id, None)? != PENDING_BLOB_LEN {
        return Err(HsmError::InvalidArg);
    }
    let blob = alloc.dma_alloc(PENDING_BLOB_LEN)?;
    pal.session_pending_state(io, id, Some(&mut *blob))?;
    HsmSessionType::from_u8(blob[PENDING_TYPE_OFF])?;
    HsmSessionSuite::from_u8(blob[PENDING_SUITE_OFF])?;

    let (hs, rest) = blob.split_at_mut(PENDING_T1_OFF);
    let (t1, rest) = rest.split_at_mut(PENDING_AUTH_OFF - PENDING_T1_OFF);
    let (auth_binding, rest) = rest.split_at_mut(PENDING_TYPE_OFF - PENDING_AUTH_OFF);
    let (h2m, m2h) =
        rest[PENDING_KEYS_OFF - PENDING_TYPE_OFF..].split_at_mut(SESSION_TRANSPORT_KEY_LEN);
    Ok(HandshakeState {
        hs,
        t1,
        auth_binding,
        h2m,
        m2h,
    })
}

/// Verify the host's confirmation `fin = HMAC-SHA-384(fin_key, T1)`, with
/// `fin_key = HKDF-Expand-Labeled(hs, "tsra-session-host-fin-v2", 48)`,
/// in constant time.
///
/// # Errors
///
/// [`HsmError::SessionAuthFailure`] if `fin` does not verify.
async fn verify_fin<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    hs: &HsmDmaBuf,
    t1: &HsmDmaBuf,
    fin: &HsmDmaBuf,
) -> HsmResult<()> {
    let fin_key = alloc.dma_alloc(SESSION_HS_LEN)?;
    hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_HOST_FIN_LABEL, fin_key).await?;
    let mut ctx = pal
        .hmac_begin(io, HsmHashAlgo::Sha384, fin_key, alloc)
        .await?;
    pal.hmac_continue(io, &mut ctx, t1).await?;
    if !pal.hmac_finish_verify(io, ctx, fin).await? {
        return Err(HsmError::SessionAuthFailure);
    }
    Ok(())
}

/// AEAD-open the host's `seed_envelope` under the freshly-derived
/// `param_key`.  Returns the 32-byte plaintext seed as a `&HsmDmaBuf`
/// sub-view of the envelope buffer (which was decrypted in place).
///
/// Any AEAD failure (bad magic, unsupported alg, tag mismatch) or a
/// wrong-length plaintext is treated as a session-establishment
/// authentication failure ([`HsmError::SessionAuthFailure`]); the undo
/// log then destroys the Pending session.
async fn open_seed_envelope<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    param_key: &HsmDmaBuf,
    seed_envelope: &'a mut HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf> {
    // Decrypt the envelope **in place** on the inbound request
    // buffer; the destructured `seed_envelope` is a `&mut HsmDmaBuf`
    // sub-view of the parent `req_buf`, so no scratch copy is
    // needed.
    let result = aead_open(pal, io, param_key, seed_envelope).await;
    let view = match result {
        Ok(v) => v,
        Err(_) => return Err(HsmError::SessionAuthFailure),
    };

    if view.payload.len() != SEED_LEN {
        return Err(HsmError::SessionAuthFailure);
    }
    // Hand the caller the AEAD plaintext view directly: it borrows
    // from the envelope buffer (the parent `req_buf`), which lives
    // until the enclosing scope exits.
    Ok(view.payload)
}

/// `HKDF-Expand(prk, label ‖ len_be, out.len())` into `out`.
pub(super) async fn hkdf_expand_labeled_into<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    prk: &HsmDmaBuf,
    label: &[u8],
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let info = alloc.dma_alloc(label.len() + 2)?;
    info[..label.len()].copy_from_slice(label);
    info[label.len()..].copy_from_slice(&(out.len() as u16).to_be_bytes());
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(info), out)
        .await
}

/// Derive `BK_SESSION = SP800-108-KBKDF-SHA-384(BK_BOOT, "SESSION_BK",
/// seed)` (32 bytes) and wrap `masking_key` under it via the
/// [`masked_key::aead`](tsra_fw_core_crypto_key_masking::aead) module
/// — an AEAD envelope whose 192 B AAD is a fixed
/// [`MaskedKeyMetadata`](tsra_fw_core_crypto_key_masking::aead::MaskedKeyMetadata)
/// binding `{key_kind = MaskingKey, key_attrs, svn, owner_seed_id,
/// key_label = "SESSION_BMK"}` to the ciphertext.
///
/// Only the `masking_key` is persisted in `bmk_session` — `param_key`
/// and the transport keys are always derived fresh from a new handshake,
/// preserving forward secrecy for every promoted session.
async fn build_bmk_session<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    seed: &HsmDmaBuf,
    masking_key: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let bk_session = derive_bk_session(pal, io, alloc, seed).await?;

    let svn = crate::part_state::part_mfgr_svn(pal);
    let owner_seed_id =
        u16::try_from(crate::part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;

    // `key_label` must be a HsmDmaBuf per the masking-lib API; stage
    // the constant label into one.
    let key_label = alloc.dma_alloc(BMK_SESSION_KEY_LABEL.len())?;
    key_label.copy_from_slice(BMK_SESSION_KEY_LABEL);

    let params = MaskParams {
        key_kind: HsmVaultKeyKind::MaskingKey,
        key_attrs: HsmVaultKeyAttrs::new(),
        svn,
        owner_seed_id,
        key_label,
    };

    // Compute blob size statically, then seal in a single pass.
    let bmk_len = masked_blob_len(AEAD_ALG, masking_key.len());
    let bmk_buf = alloc.dma_alloc(bmk_len)?;
    mask_key(
        pal,
        io,
        alloc,
        AEAD_ALG,
        bk_session,
        &params,
        masking_key,
        Some(bmk_buf),
    )
    .await?;
    Ok(bmk_buf)
}

/// Derive the 32-byte `BK_SESSION` wrap key into a freshly-allocated
/// scoped buffer.
async fn derive_bk_session<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    seed: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let bk_boot = alloc.dma_alloc(BK_BOOT_LEN)?;
    crate::ddi::recover_bk_boot(pal, io, bk_boot).await?;

    let label = alloc.dma_alloc(SESSION_BK_LABEL.len())?;
    label.copy_from_slice(SESSION_BK_LABEL);

    let bk_session = alloc.dma_alloc(SESSION_BK_LEN)?;
    pal.sp800_108_kdf(
        io,
        HsmHashAlgo::Sha384,
        bk_boot,
        Some(label),
        Some(seed),
        bk_session,
    )
    .await?;
    Ok(bk_session)
}

/// Encode the `SessionOpenFinish` response (carrying `bmk_session`)
/// into a fresh IO-scoped HsmDmaBuf.
fn encode_response(cmd_buf: &mut HsmCmdBuf<'_>, bmk_session: &HsmDmaBuf) -> HsmResult<usize> {
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborSessionOpenFinishResp::encode(buf, 0, false)?
            .bmk_session(bmk_session)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
