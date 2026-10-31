// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenFinish` handler — Phase 2 of session establishment.
//!
//! Loads the Pending slot's handshake state, verifies the client's
//! Phase-2 confirmation MAC in constant time, derives the per-session
//! `param_key`, decrypts the host-supplied `seed_envelope` to recover
//! the 32-byte session seed, derives the per-direction MAC keys (for
//! Authenticated sessions) and the `masking_key`, wraps the
//! `masking_key` under `BK_SESSION = KBKDF(BK_BOOT, "SESSION_BK",
//! seed)` into the response `bmk_session` AEAD envelope, and promotes
//! the slot Pending → Active.
//!
//! On any post-Pending failure (MAC mismatch, seed_envelope AEAD
//! authentication failure) the Pending slot is destroyed before the
//! error is returned to the host, so a tampered envelope cannot be
//! probed repeatedly against the same slot.
//!
//! All variable-length buffers live on the per-IO scoped allocator
//! per the firmware async-discipline convention; no DMA-sized arrays
//! sit on the async stack.

use tsra_fw_core_crypto_aead_envelope::open as aead_open;
use tsra_fw_core_crypto_aead_envelope::AeadAlg;
use tsra_fw_core_crypto_hpke::HpkeSuite;
use tsra_fw_core_crypto_key_masking::aead::mask as mask_key;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

/// Map a [`HsmSessionSuite`] to the concrete [`HpkeSuite`] used by the
/// session-establishment handshake.  Mirrors the function of the same
/// name in [`super::session_open_init`]; kept duplicated to avoid
/// pulling that module's internals into a public surface.
const fn hpke_suite_for(suite: HsmSessionSuite) -> HpkeSuite {
    match suite {
        HsmSessionSuite::P384HkdfSha384AesGcm256 => HpkeSuite::DHKemP384Sha384AesGcm256,
    }
}

/// HPKE suite used by the only currently registered `HsmSessionSuite`
/// (`P384HkdfSha384AesGcm256`).  Used at compile time to size the
/// Pending blob; the runtime handler always uses
/// [`hpke_suite_for`] for the actually-negotiated suite.
const DEFAULT_HPKE_SUITE: HpkeSuite = hpke_suite_for(HsmSessionSuite::P384HkdfSha384AesGcm256);

/// Length of the Pending blob; mirrors the layout written by
/// [`super::session_open_init`]:
/// `exported ‖ pk_init ‖ pk_resp ‖ session_type ‖ suite_id`.
const PENDING_BLOB_LEN: usize =
    DEFAULT_HPKE_SUITE.nh() + DEFAULT_HPKE_SUITE.npk() + DEFAULT_HPKE_SUITE.npk() + 1 + 1;

/// Length of the API revision tag persisted alongside the session blob.
const API_REV_LEN: usize = 8;

/// API-revision tag persisted into the session vault blob's first 8
/// bytes by [`HsmSessionManager::session_promote`].
const SESSION_API_REV: [u8; API_REV_LEN] = [1, 0, 0, 0, 0, 0, 0, 0];

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
    mac_fin: &'a HsmDmaBuf,
    /// Codec-supplied `&mut HsmDmaBuf` sub-view of the inbound request
    /// buffer.  Decrypted in place by [`aead_open`] — no scratch copy.
    seed_envelope: &'a mut HsmDmaBuf,
}

/// Per-session keys derived from the HPKE `exported` secret.
///
/// * `param_key` — 32 B AES-256 key used to AEAD-open `seed_envelope`
///   (this handler) and to authenticate per-parameter envelopes in
///   in-session commands like `PskChange`.  Always populated.
/// * `masking_key` — 32 B AES-256-GCM key for the `key_masking::aead`
///   TBOR masked-key system.  Always populated.
/// * `mac_tx_key` — 48 B HMAC-SHA-384 key for outbound (HSM → host)
///   message MACs.  `Some` iff `session_type` is `Authenticated`.
/// * `mac_rx_key` — 48 B HMAC-SHA-384 key for inbound (host → HSM)
///   message MACs.  `Some` iff `session_type` is `Authenticated`.
struct DerivedKeys<'a> {
    param_key: &'a mut HsmDmaBuf,
    masking_key: &'a mut HsmDmaBuf,
    mac_tx_key: Option<&'a mut HsmDmaBuf>,
    mac_rx_key: Option<&'a mut HsmDmaBuf>,
}

/// Decoded Pending handshake state, split into the regions the PAL
/// crypto APIs need as distinct `&HsmDmaBuf` arguments (HMAC `key` and
/// `data` must not alias, so the regions cannot be slices of a single
/// backing buffer).
struct HandshakeState<'a> {
    exported: &'a mut HsmDmaBuf,
    pk_init: &'a mut HsmDmaBuf,
    pk_resp: &'a mut HsmDmaBuf,
    session_type: HsmSessionType,
    /// Cryptographic suite recorded by Phase 1.  Drives every
    /// suite-derived size in this handler (Nh, Npk, AEAD parameters).
    suite: HpkeSuite,
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
            mac_fin,
            seed_envelope,
        } = parse_request(cmd_buf.request_mut())?;
        ensure_pending_blob_len(pal, io, sess_id)?;

        // ── Load Pending handshake state ──────────────────────────
        let HandshakeState {
            exported,
            pk_init,
            pk_resp,
            session_type,
            suite,
        } = load_pending_state(pal, io, alloc, sess_id)?;

        // Record the session's teardown inverse up front: any failure below
        // (MAC/envelope auth, key derivation, promote, response, or the CQE
        // post) reverts the session via the dispatcher's undo walk — the
        // same "destroy on failure" the bespoke rollback did, now uniform.
        undo.push_session_destroy(sess_id)?;
        let pk_hsm = load_pk_hsm(pal, io, alloc)?;

        // The `mac_fin` length is dictated by the suite recorded in
        // the Pending blob, not by the wire schema (which is fixed
        // for the only currently-implemented suite).  Validating here
        // — after the suite is known — keeps the handler honest if a
        // future suite ships with a different MAC length.
        if mac_fin.len() != suite.nh() {
            return Err(HsmError::InvalidArg);
        }

        // ── Verify Phase-2 confirm MAC ────────────────────────────
        // On any failure here (MAC mismatch → `SessionAuthFailure`, or an
        // internal HMAC error) eagerly destroy the still-Pending slot: IOs
        // run in a concurrent task pool, so a delayed teardown would let a
        // racing `SessionOpenFinish` re-probe the same slot in the window
        // before the dispatcher's undo walk runs.  The pushed
        // `session_destroy` undo entry stays as the backstop.
        if let Err(e) = verify_mac(
            pal, io, alloc, sess_id, mac_fin, exported, pk_init, pk_hsm, pk_resp,
        )
        .await
        {
            destroy_pending_on_auth_failure(pal, io, sess_id).await;
            return Err(e);
        }

        // ── Derive param_key once, use it to open the seed envelope
        let param_key = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_PARAM_KEY_LABEL,
            SESSION_PARAM_KEY_LEN,
        )
        .await?;

        // Same eager-teardown rationale as the MAC check above: a tampered
        // envelope must not be re-probable against a lingering Pending slot.
        let seed = match open_seed_envelope(pal, io, param_key, seed_envelope).await {
            Ok(seed) => seed,
            Err(e) => {
                destroy_pending_on_auth_failure(pal, io, sess_id).await;
                return Err(e);
            }
        };

        // ── Derive remaining per-session keys ─────────────────────
        let derived =
            derive_remaining_keys(pal, io, alloc, exported, session_type, param_key).await?;

        // ── Build bmk_session (BK_SESSION-wrapped masking-key blob)
        //    BEFORE promote, so no active session is ever created without a
        //    recovery blob.  A failure at this step (or any later one) tears
        //    the still-Pending session down via the dispatcher's undo walk.
        let bmk_session = build_bmk_session(pal, io, alloc, seed, derived.masking_key).await?;

        // ── Promote Pending → Active ──────────────────────────────
        promote_to_active(pal, io, alloc, sess_id, derived).await?;

        encode_response(cmd_buf, bmk_session)
    })
    .await
}

/// Eagerly tear down the still-Pending session after an authentication
/// failure, closing the window in which a tampered MAC or seed envelope
/// could be re-probed against the same slot.
///
/// `SessionOpenFinish` IOs run in a concurrent task pool, so relying only
/// on the dispatcher's post-command undo walk would leave the Pending slot
/// observable to a racing finish until that walk completes.  Destroying
/// here shrinks that window to nothing.
///
/// Best-effort: the [`UndoLog`] `session_destroy` entry pushed up front is
/// the authoritative backstop (its walk step is best-effort), so a failure
/// here — or the walk's later redundant destroy — is harmless.
async fn destroy_pending_on_auth_failure<P: HsmPal>(pal: &P, io: &P::Io, id: HsmSessId) {
    let _ = pal.session_destroy(io, id).await;
}

/// Decode and validate the wire request.
fn parse_request<'a>(req_buf: &'a mut HsmDmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborSessionOpenFinishReq::decode_mut(req_buf)?;
    let id = HsmSessId::from(u16::from(req.session_id));
    // `mac_fin` length is checked once the negotiated suite is known
    // (see [`handle`]); the schema already pins the wire field to 48 B.
    let mac_fin: &HsmDmaBuf = req.mac_fin;
    let seed_envelope: &mut HsmDmaBuf = req.seed_envelope;
    if seed_envelope.len() != SEED_ENVELOPE_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(ParsedRequest {
        sess_id: id,
        mac_fin,
        seed_envelope,
    })
}

/// Cheap pre-check that `id` refers to a live Pending slot whose blob
/// matches the canonical layout.  Done before entering the scoped
/// allocator so a malformed request rejects without consuming any
/// scratch.
fn ensure_pending_blob_len<P: HsmPal>(pal: &P, io: &P::Io, id: HsmSessId) -> HsmResult<()> {
    let pending_len = pal.session_pending_state(io, id, None)?;
    if pending_len != PENDING_BLOB_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Load the Pending slot's blob and split it into `(exported,
/// pk_init, pk_resp, session_type, suite)` scoped buffers.
fn load_pending_state<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    id: HsmSessId,
) -> HsmResult<HandshakeState<'a>> {
    let blob_len = pal.session_pending_state(io, id, None)?;
    let blob = alloc.dma_alloc(blob_len)?;
    pal.session_pending_state(io, id, Some(&mut *blob))?;

    // Recover the suite *before* using suite-derived sizes, in case a
    // future build supports more than one suite with different
    // Nh/Npk.  Today only `P384HkdfSha384AesGcm256` is registered, so
    // a mismatch with the wire length pre-check would already have
    // fired in [`ensure_pending_blob_len`].
    let suite = HsmSessionSuite::from_u8(blob[blob.len() - 1])?;
    let hpke_suite = hpke_suite_for(suite);

    let nh = hpke_suite.nh();
    let npk = hpke_suite.npk();
    let exported = alloc.dma_alloc(nh)?;
    exported.copy_from_slice(&blob[..nh]);
    let pk_init = alloc.dma_alloc(npk)?;
    pk_init.copy_from_slice(&blob[nh..nh + npk]);
    let pk_resp = alloc.dma_alloc(npk)?;
    pk_resp.copy_from_slice(&blob[nh + npk..nh + 2 * npk]);
    let session_type = HsmSessionType::from_u8(blob[nh + 2 * npk])?;

    Ok(HandshakeState {
        exported,
        pk_init,
        pk_resp,
        session_type,
        suite: hpke_suite,
    })
}

/// SEC1-uncompressed encoding (`0x04 ‖ X_be ‖ Y_be`) of the partition
/// identity public key, in a freshly-allocated scoped buffer.
fn load_pk_hsm<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let xy_len = crate::part_state::part_id_pub_key(pal, io)?.len();
    let pk_hsm = alloc.dma_alloc(xy_len + 1)?;
    pk_hsm[0] = 0x04;
    {
        let pk = crate::part_state::part_id_pub_key(pal, io)?;
        pk_hsm[1..1 + xy_len].copy_from_slice(&pk[..xy_len]);
    }
    Ok(pk_hsm)
}

/// Recompute and constant-time-verify the Phase-2 confirm MAC:
/// `HMAC-SHA384(exported, (label ‖ session_id_be) ‖ pk_init ‖ pk_hsm ‖ pk_resp)`.
///
/// On failure `HsmError::SessionAuthFailure` is returned; the caller's
/// undo log tears the session down.
#[allow(clippy::too_many_arguments)]
async fn verify_mac<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    id: HsmSessId,
    mac_fin: &HsmDmaBuf,
    exported: &HsmDmaBuf,
    pk_init: &HsmDmaBuf,
    pk_hsm: &HsmDmaBuf,
    pk_resp: &HsmDmaBuf,
) -> HsmResult<()> {
    debug_assert_eq!(SESSION_PHASE2_LABEL.len(), 14);
    let session_id_be = u16::from(id).to_be_bytes();
    let label_sid = alloc.dma_alloc(SESSION_PHASE2_LABEL.len() + 2)?;
    label_sid[..SESSION_PHASE2_LABEL.len()].copy_from_slice(SESSION_PHASE2_LABEL);
    label_sid[SESSION_PHASE2_LABEL.len()..].copy_from_slice(&session_id_be);

    let mut hmac_ctx = pal
        .hmac_begin(io, HsmHashAlgo::Sha384, exported, alloc)
        .await?;
    for chunk in &[label_sid as &HsmDmaBuf, pk_init, pk_hsm, pk_resp] {
        pal.hmac_continue(io, &mut hmac_ctx, chunk).await?;
    }
    let mac_verified = pal.hmac_finish_verify(io, hmac_ctx, mac_fin).await?;
    if !mac_verified {
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
/// authentication failure ([`HsmError::SessionAuthFailure`]).  The caller
/// eagerly destroys the Pending session on this error (with the undo log
/// as backstop), so a tampered envelope cannot be re-probed against the
/// same slot.
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

/// Derive the remaining per-session keys from the HPKE `exported`
/// secret.  Uses a loop over key specs to reduce async state machine
/// variants.  `param_key` was derived earlier (needed to open the
/// seed envelope) and is plumbed through so it can be moved straight
/// into the [`DerivedKeys`] carrier without re-deriving.
async fn derive_remaining_keys<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    exported: &HsmDmaBuf,
    session_type: HsmSessionType,
    param_key: &'a mut HsmDmaBuf,
) -> HsmResult<DerivedKeys<'a>> {
    // The masking key is **random**, not derived from `exported`.
    //
    // `exported` is an HPKE export secret: the host computes the same
    // value during the handshake, so anything expanded from it is
    // reproducible host-side.  That is right for the transport keys
    // below -- both ends need them -- but a masking key derived that way
    // lets the host open any blob masked at `Session` scope, recovering
    // private key material the HSM is supposed to hold.
    //
    // Every other masking key in the system is random and kept inside
    // the device (`PartLocalMK` and `EphemeralMK` at `PartFinal`, `SDMK`
    // and `BKS3` in the SD flows, `BK_BOOT` at partition allocation);
    // this brings sessions in line.  Continuity does not depend on
    // re-derivation: the key is carried out of the HSM only as
    // `bmk_session`, wrapped under `BK_SESSION`
    // (`KBKDF(BK_BOOT, "SESSION_BK", seed)`), and `BK_BOOT` never leaves
    // the device -- it is itself only ever persisted masked under `BKx`.
    let masking_key = alloc.dma_alloc(SESSION_MASKING_KEY_LEN)?;
    pal.rng_fill_bytes(io, &mut masking_key[..])?;

    // The MAC keys stay derived: they authenticate the channel, so both
    // ends must arrive at the same value without transmitting it.
    let is_auth = session_type.is_authenticated();
    let (mac_tx_key, mac_rx_key) = if is_auth {
        let tx = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_MAC_TX_LABEL,
            SESSION_MAC_DIR_KEY_LEN,
        )
        .await?;
        let rx = hkdf_expand_labeled(
            pal,
            io,
            alloc,
            exported,
            SESSION_MAC_RX_LABEL,
            SESSION_MAC_DIR_KEY_LEN,
        )
        .await?;
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    Ok(DerivedKeys {
        param_key,
        masking_key,
        mac_tx_key,
        mac_rx_key,
    })
}

/// `HKDF-Expand(prk, label ‖ len_be, len)` into a freshly-allocated
/// scoped buffer of size `out_len`.
async fn hkdf_expand_labeled<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    prk: &HsmDmaBuf,
    label: &[u8],
    out_len: usize,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let info = alloc.dma_alloc(label.len() + 2)?;
    info[..label.len()].copy_from_slice(label);
    info[label.len()..].copy_from_slice(&(out_len as u16).to_be_bytes());
    let out = alloc.dma_alloc(out_len)?;
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(info), out)
        .await?;
    Ok(out)
}

/// Derive `BK_SESSION = SP800-108-KBKDF-SHA-384(BK_BOOT, "SESSION_BK",
/// seed)` (32 bytes) and wrap `masking_key` under it via the
/// [`masked_key::aead`](tsra_fw_core_crypto_key_masking::aead) module
/// — an AEAD envelope whose 192 B AAD is a fixed
/// [`MaskedKeyMetadata`](tsra_fw_core_crypto_key_masking::aead::MaskedKeyMetadata)
/// binding `{key_kind = MaskingKey, key_attrs, svn, owner_seed_id,
/// key_label = "SESSION_BMK"}` to the ciphertext.
///
/// Only the `masking_key` is persisted in `bmk_session` — transport
/// keys (`param_key`, `mac_tx_key`, `mac_rx_key`) are always derived
/// fresh from the HPKE handshake on resume, preserving forward
/// secrecy for every promoted session.
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

/// Materialise the api-rev tag in a scoped HsmDmaBuf and call
/// `session_promote` to flip the slot from Pending to Active.
async fn promote_to_active<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    id: HsmSessId,
    derived: DerivedKeys<'_>,
) -> HsmResult<()> {
    let api_rev = alloc.dma_alloc(API_REV_LEN)?;
    api_rev.copy_from_slice(&SESSION_API_REV);
    pal.session_promote(
        io,
        id,
        api_rev,
        derived.param_key,
        derived.masking_key,
        derived.mac_tx_key.as_deref(),
        derived.mac_rx_key.as_deref(),
    )
    .await
}
