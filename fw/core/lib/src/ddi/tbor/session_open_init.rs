// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenInit` handler — Phase 1 of session establishment.
//!
//! Validates the request, encapsulates to the VM's ephemeral KEM key
//! (ECDH P-384), hashes the handshake transcript `T1`,
//! signs it with the partition identity key, derives the handshake
//! secret `hs` from the KEM secret and the role's PSK, reserves a
//! `Pending` session slot holding `hs`, `T1` and the transport keys, and
//! returns `(slot, enc, sig)` to the caller.
//!
//! ```text
//! T1   = SHA-384("TSRA-SESSION-v1" ‖ BE16(api_major) ‖ BE16(api_minor)
//!                ‖ suite_id ‖ psk_id ‖ session_type
//!                ‖ pk_hsm(97) ‖ len16 ‖ pk_init ‖ len16 ‖ enc)
//! sig  = ECDSA-P384(PID, T1)
//! prk  = HKDF-Extract(salt = "TSRA-SESSION-v1", Z ‖ PSK)
//! hs   = HKDF-Expand(prk, "tsra-session-hs-v1" ‖ T1, 48)
//! key ‖ salt = HKDF-Expand-Labeled(hs, "tsra-session-xport-{h2m,m2h}-v1", 36)
//! ```
//!
//! Each direction's AES-GCM nonce is `salt(4) ‖ be64(seq)`, `seq` being
//! the sender's per-direction message counter.
//!
//! The signature authenticates the HSM to the host; knowledge of the PSK
//! (proven by the host's `fin` in `SessionOpenFinish`) authenticates the
//! host to the HSM.
//!
//! A non-sentinel `reopen_id` recovers an existing stale slot through the
//! same handshake, with masking-key recovery deferred to Finish.
//!
//! On any error after the Pending slot is reserved, the dispatcher's undo
//! walk destroys a fresh slot or restores a recovery slot to renegotiation.
//!
//! All variable-length and crypto-sized buffers are allocated from the
//! per-IO scoped allocator — handler frames never put DMA-targeted
//! arrays on the async stack.

use tsra_fw_ddi_tbor_types::*;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_hsm_undo::UndoLog;

use super::session_open_finish::hkdf_expand_labeled_into;

/// Validated `SessionOpenInit` request fields.
struct ParsedRequest<'a> {
    api_rev: (u16, u16),
    reopen_id: u16,
    /// Role asserted by `psk_id`.
    role: HsmSessionRole,

    /// PSK identifier (0 or 1).
    psk_id: u8,

    /// Channel profile selected by the caller.
    session_type: HsmSessionType,

    /// Cryptographic suite negotiated by the caller.
    suite: HsmSessionSuite,

    /// Sub-view of the inbound request buffer (DMA-branded by the
    /// codec), so it can flow straight into the KEM and the transcript
    /// hash without an intermediate copy.
    pk_init: &'a HsmDmaBuf,
}

/// Curve of the ECDH suite and of the transcript signature.
const CURVE: HsmEccCurve = HsmEccCurve::P384;

/// Offset of `hs`, after the selected API revision.
pub(super) const PENDING_HS_OFF: usize = 4;

/// Offset of `T1` in the Pending blob.
pub(super) const PENDING_T1_OFF: usize = PENDING_HS_OFF + SESSION_HS_LEN;

/// Offset of `auth_binding` in the Pending blob.
pub(super) const PENDING_AUTH_OFF: usize = PENDING_T1_OFF + SESSION_HS_LEN;

/// Offset of the `session_type` byte in the Pending blob.
pub(super) const PENDING_TYPE_OFF: usize = PENDING_AUTH_OFF + SESSION_AUTH_BINDING_LEN;

/// Offset of the `suite_id` byte in the Pending blob.
pub(super) const PENDING_SUITE_OFF: usize = PENDING_TYPE_OFF + 1;

/// Offset of the transport secrets `h2m ‖ m2h` (each `key ‖ salt`) in the
/// Pending blob.
pub(super) const PENDING_REOPEN_OFF: usize = PENDING_SUITE_OFF + 1;
pub(super) const PENDING_KEYS_OFF: usize = PENDING_REOPEN_OFF + 1;

/// Length of the Pending handshake-state blob:
/// `selected_api_rev(4) ‖ hs(48) ‖ T1(48) ‖ auth_binding(68) ‖ session_type(1) ‖ suite_id(1)
/// ‖ reopen(1) ‖ h2m(36) ‖ m2h(36)`.
///
/// The transport secrets must end the blob (see
/// [`HsmSessionManager::session_create_pending`]), so `SessionOpenFinish`
/// already travels on the encrypted channel.
pub(super) const PENDING_BLOB_LEN: usize = PENDING_KEYS_OFF + 2 * SESSION_TRANSPORT_SECRET_LEN;

const _: () = assert!(PENDING_BLOB_LEN <= SESSION_PENDING_BLOB_MAX);

/// Handle a TBOR `SessionOpenInit` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
    cqe_sess_id: &mut Option<u16>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let ParsedRequest {
            api_rev,
            reopen_id,
            role,
            psk_id,
            session_type,
            suite,
            pk_init,
        } = parse_request(cmd_buf.request())?;
        let reopen = (reopen_id != u16::MAX).then(|| HsmSessId::from(reopen_id));
        if let Some(id) = reopen {
            if id.role() != role
                || !matches!(
                    pal.session_state(io, id),
                    HsmSessionState::NeedsRenegotiation | HsmSessionState::Pending
                )
            {
                return Err(HsmError::ProcessedIoEventInInvalidState);
            }
            if pal
                .session_recovery_binding(io, id)?
                .iter()
                .all(|&b| b == 0)
            {
                return Err(HsmError::InvalidPermissions);
            }
        }

        // ── Identity + PSK material (all on the scoped allocator) ──
        let psk = load_psk(pal, io, alloc, psk_id)?;
        let auth_binding = crate::session::capture_auth_binding(pal, io, alloc, role, psk).await?;
        let pk_hsm = load_pk_hsm_sec1(pal, io, alloc).await?;

        // ── KEM encapsulation to the VM's ephemeral key ────────────
        let (enc, z) = ecdh_encapsulate(pal, io, alloc, pk_init).await?;

        // ── Transcript, signature and handshake secret ─────────────
        let major = api_rev.0.to_be_bytes();
        let minor = api_rev.1.to_be_bytes();
        let t1 = transcript_hash(
            pal,
            io,
            alloc,
            [
                major[0],
                major[1],
                minor[0],
                minor[1],
                suite.to_u8(),
                psk_id,
                session_type.to_u8(),
            ],
            pk_hsm,
            pk_init,
            enc,
            reopen,
        )
        .await?;
        let sig = sign_transcript(pal, io, alloc, t1).await?;
        let hs = handshake_secret(pal, io, alloc, z, psk, t1).await?;

        // ── Pending slot allocation ────────────────────────────────
        let slot = create_pending_slot(
            pal,
            io,
            alloc,
            role,
            api_rev,
            session_type,
            suite,
            hs,
            t1,
            auth_binding,
            reopen,
        )
        .await?;
        // Record the just-created Pending session's teardown inverse, so a
        // failure below (response encode, or the CQE post) reverts it via
        // the dispatcher's undo walk rather than leaking the slot.
        if reopen.is_some() {
            undo.push_session_reopen(slot)?;
        } else {
            undo.push_session_destroy(slot)?;
        }
        let session_id = u16::from(slot);
        // Hand the freshly allocated slot to the IO layer so it lands in
        // the CQE: the host driver registers the session against the
        // calling file handle from that field, and without it every
        // follow-up in-session TBOR ioctl (SessionOpenFinish, PskChange,
        // SessionClose) is rejected with `NoExistingSession` before it
        // ever reaches the firmware.
        *cqe_sess_id = Some(session_id);

        encode_response(cmd_buf, session_id, enc, sig)
    })
    .await
}

/// Decode and validate the wire request.
fn parse_request<'a>(req_buf: &'a HsmDmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborSessionOpenInitReq::decode(req_buf)?;

    let role = match req.psk_id() {
        PskId::CryptoOfficer => HsmSessionRole::CryptoOfficer,
        PskId::CryptoUser => HsmSessionRole::CryptoUser,
        _ => return Err(HsmError::InvalidPskId),
    };
    let psk_id = req.psk_id().0;
    let session_type = HsmSessionType::from_u8(req.session_type().0)?;
    let suite = HsmSessionSuite::from_u8(req.suite_id().0)?;

    let pk_init: &HsmDmaBuf = req.pk_init();
    if pk_init.len() != suite.pk_init_len() {
        return Err(HsmError::InvalidArg);
    }

    Ok(ParsedRequest {
        api_rev: req.api_rev(),
        reopen_id: req.reopen_id(),
        role,
        psk_id,
        session_type,
        suite,
        pk_init,
    })
}

/// Load the partition's PSK into a freshly-allocated scoped buffer.
fn load_psk<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    psk_id: u8,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let psk = alloc.dma_alloc(PSK_LEN)?;
    let src = crate::part_state::part_psk(pal, io, psk_id)?;
    psk.copy_from_slice(&src[..PSK_LEN]);
    Ok(psk)
}

/// SEC1-uncompressed encoding (`0x04 ‖ X_be ‖ Y_be`) of the partition
/// identity public key, in a freshly-allocated scoped buffer.
///
/// The public point is derived from the vault-held identity private key.
async fn load_pk_hsm_sec1<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let pk_hsm = alloc
        .dma_alloc(HsmEccCurve::P384.pub_key_len() + 4)?
        .split_at_mut(3)
        .1;
    pk_hsm[0] = 0x04;
    crate::part_state::part_id_pub_key(pal, io, pk_hsm.split_at_mut(1).1).await?;
    Ok(pk_hsm)
}

/// Ephemeral ECDH P-384 against the SEC1 point `pk_init`.
async fn ecdh_encapsulate<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    pk_init: &HsmDmaBuf,
) -> HsmResult<(&'a mut HsmDmaBuf, &'a mut HsmDmaBuf)> {
    let coord = CURVE.wire_coord_len(P::ECC_COORD_PAD);
    if pk_init[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    let peer = alloc.dma_alloc(2 * coord)?;
    peer[..SESSION_P384_SEC1_LEN - 1].copy_from_slice(&pk_init[1..]);
    byte_order::pair_from_be::<P>(CURVE, peer)?;

    // The ephemeral key is used for ECDH, so its generation runs a
    // key-agreement PCT.
    let (priv_len, pub_len) = pal
        .ecc_gen_keypair(io, CURVE, HsmEccPct::KeyAgreement, None)
        .await?;
    let sk = alloc.dma_alloc(priv_len)?;
    let pk = alloc.dma_alloc(pub_len)?;
    pal.ecc_gen_keypair(
        io,
        CURVE,
        HsmEccPct::KeyAgreement,
        Some((&mut *sk, &mut *pk)),
    )
    .await?;

    let z = alloc.dma_alloc(coord)?;
    pal.ecdh_derive(io, CURVE, sk, peer, Some(z)).await?;
    let z_len = byte_order::coord_to_be::<P>(CURVE, z)?.len();

    let enc = alloc.dma_alloc(SESSION_P384_SEC1_LEN)?;
    enc[0] = 0x04;
    let xy = byte_order::pair_to_be::<P>(CURVE, pk)?;
    if xy.len() != SESSION_P384_SEC1_LEN - 1 {
        return Err(HsmError::InvalidArg);
    }
    enc[1..].copy_from_slice(xy);
    Ok((enc, &mut z[..z_len]))
}

/// `T1 = SHA-384(label ‖ BE16(api_major) ‖ BE16(api_minor)
/// ‖ suite_id ‖ psk_id ‖ session_type ‖ pk_hsm
/// ‖ len16 ‖ pk_init ‖ len16 ‖ enc)`, as a standard digest.
async fn transcript_hash<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: [u8; 7],
    pk_hsm: &HsmDmaBuf,
    pk_init: &HsmDmaBuf,
    enc: &HsmDmaBuf,
    reopen: Option<HsmSessId>,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let label = SESSION_TRANSCRIPT_LABEL;
    let head = alloc.dma_alloc(label.len() + params.len() + pk_hsm.len() + 2)?;
    let (l, rest) = head.split_at_mut(label.len());
    l.copy_from_slice(label);
    let (p, rest) = rest.split_at_mut(params.len());
    p.copy_from_slice(&params);
    let (k, n) = rest.split_at_mut(pk_hsm.len());
    k.copy_from_slice(pk_hsm);
    n.copy_from_slice(&len16(pk_init.len())?);
    let enc_len = alloc.dma_alloc(2)?;
    enc_len.copy_from_slice(&len16(enc.len())?);

    let state = alloc.dma_alloc(pal.hash_state_size(HsmHashAlgo::Sha384)?)?;
    let mut ctx = pal.hash_begin(io, HsmHashAlgo::Sha384, state)?;
    for chunk in [head as &HsmDmaBuf, pk_init, enc_len, enc] {
        pal.hash_continue(io, &mut ctx, chunk).await?;
    }
    if let Some(id) = reopen {
        let label = b"TSRA-REOPEN-v1:";
        let context = alloc.dma_alloc(label.len() + 2)?;
        context[..label.len()].copy_from_slice(label);
        context[label.len()..].copy_from_slice(&u16::from(id).to_be_bytes());
        pal.hash_continue(io, &mut ctx, context).await?;
    }
    let t1 = alloc.dma_alloc(SESSION_HS_LEN)?;
    pal.hash_finish(io, &mut ctx, HsmDigestForm::Standard, Some(t1))
        .await?;
    Ok(t1)
}

/// Big-endian 16-bit length prefix.
fn len16(len: usize) -> HsmResult<[u8; 2]> {
    u16::try_from(len)
        .map(u16::to_be_bytes)
        .map_err(|_| HsmError::InvalidArg)
}

/// Sign `T1` with the partition identity key, returning the raw
/// big-endian `r ‖ s` signature.
async fn sign_transcript<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    t1: &HsmDmaBuf,
) -> HsmResult<&'a mut [u8]> {
    let hash = HsmHashAlgo::Sha384;
    let coord = CURVE.wire_coord_len(P::ECC_COORD_PAD);
    let input = alloc.dma_alloc(CURVE.ecdsa_sign_input_len(hash, P::ECC_COORD_PAD))?;
    input.fill(0);
    byte_order::int_copy_from_be(P::BYTE_ORDER, &mut input[coord..coord + t1.len()], t1)?;
    let sig = alloc.dma_alloc(CURVE.wire_sig_len(P::ECC_COORD_PAD))?;
    let key_id = crate::part_state::part_id_key_id(pal, io)?;
    let sk_hsm = pal.vault_key(io, key_id)?;
    pal.ecc_sign(
        io,
        CURVE,
        hash,
        sk_hsm,
        HsmEcdsaNonce::Generated,
        input,
        Some(sig),
    )
    .await?;
    let sig = byte_order::pair_to_be::<P>(CURVE, sig)?;
    if sig.len() != SIG_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(sig)
}

/// `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v1", Z ‖ PSK),
/// "tsra-session-hs-v1" ‖ T1, 48)`.
async fn handshake_secret<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    z: &HsmDmaBuf,
    psk: &HsmDmaBuf,
    t1: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let ikm = alloc.dma_alloc(z.len() + psk.len())?;
    ikm[..z.len()].copy_from_slice(z);
    ikm[z.len()..].copy_from_slice(psk);
    let salt = alloc.dma_alloc(SESSION_TRANSCRIPT_LABEL.len())?;
    salt.copy_from_slice(SESSION_TRANSCRIPT_LABEL);
    let prk = alloc.dma_alloc(SESSION_HS_LEN)?;
    pal.hkdf_extract(io, HsmHashAlgo::Sha384, Some(salt), ikm, Some(prk))
        .await?;

    let info = alloc.dma_alloc(SESSION_HS_LABEL.len() + t1.len())?;
    info[..SESSION_HS_LABEL.len()].copy_from_slice(SESSION_HS_LABEL);
    info[SESSION_HS_LABEL.len()..].copy_from_slice(t1);
    let hs = alloc.dma_alloc(SESSION_HS_LEN)?;
    pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(info), hs)
        .await?;
    Ok(hs)
}

/// Pack `hs ‖ T1 ‖ auth_binding ‖ session_type ‖ suite_id ‖ h2m ‖ m2h`
/// into a Pending blob and hand it to `session_create_pending`.
#[allow(clippy::too_many_arguments)]
async fn create_pending_slot<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    role: HsmSessionRole,
    api_rev: (u16, u16),
    session_type: HsmSessionType,
    suite: HsmSessionSuite,
    hs: &HsmDmaBuf,
    t1: &HsmDmaBuf,
    auth_binding: &HsmDmaBuf,
    reopen: Option<HsmSessId>,
) -> HsmResult<HsmSessId> {
    let blob = alloc.dma_alloc(PENDING_BLOB_LEN)?;
    blob[..2].copy_from_slice(&api_rev.0.to_le_bytes());
    blob[2..PENDING_HS_OFF].copy_from_slice(&api_rev.1.to_le_bytes());
    blob[PENDING_HS_OFF..PENDING_T1_OFF].copy_from_slice(hs);
    blob[PENDING_T1_OFF..PENDING_AUTH_OFF].copy_from_slice(t1);
    blob[PENDING_AUTH_OFF..PENDING_TYPE_OFF].copy_from_slice(auth_binding);
    blob[PENDING_TYPE_OFF] = session_type.to_u8();
    blob[PENDING_SUITE_OFF] = suite.to_u8();
    blob[PENDING_REOPEN_OFF] = u8::from(reopen.is_some());
    let (h2m, m2h) = blob[PENDING_KEYS_OFF..].split_at_mut(SESSION_TRANSPORT_SECRET_LEN);
    hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_TRANSPORT_H2M_LABEL, h2m).await?;
    hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_TRANSPORT_M2H_LABEL, m2h).await?;
    if let Some(id) = reopen {
        pal.session_reopen_pending(io, id, blob).await?;
        Ok(id)
    } else {
        pal.session_create_pending(io, role, blob).await
    }
}

/// Encode the `SessionOpenInit` response.
fn encode_response(
    cmd_buf: &mut HsmCmdBuf<'_>,
    session_id: u16,
    enc: &HsmDmaBuf,
    sig: &[u8],
) -> HsmResult<usize> {
    cmd_buf.encode_response(|buf| {
        let frame = TborSessionOpenInitResp::encode_for_request(buf, 0, false)?
            .session_id(SessionId(session_id))?
            .enc(enc)?
            .sig(sig)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
