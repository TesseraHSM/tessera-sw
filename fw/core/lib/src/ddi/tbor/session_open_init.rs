// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenInit` handler — Phase 1 of session establishment.
//!
//! Validates the request, encapsulates to the VM's ephemeral KEM key
//! (ECDH P-384 or ML-KEM-1024), hashes the handshake transcript `T1`,
//! signs it with the partition identity key, derives the handshake
//! secret `hs` from the KEM secret and the role's PSK, reserves a
//! `Pending` session slot holding `hs`, `T1` and the transport keys, and
//! returns `(slot, enc, sig)` to the caller.
//!
//! ```text
//! T1   = SHA-384("TSRA-SESSION-v2" ‖ suite_id ‖ psk_id ‖ session_type
//!                ‖ pk_hsm(97) ‖ len16 ‖ pk_init ‖ len16 ‖ enc)
//! sig  = ECDSA-P384(PID, T1)
//! prk  = HKDF-Extract(salt = "TSRA-SESSION-v2", Z ‖ PSK)
//! hs   = HKDF-Expand(prk, "tsra-session-hs-v2" ‖ T1, 48)
//! h2m, m2h = HKDF-Expand-Labeled(hs, "tsra-session-xport-{h2m,m2h}-v2", 32)
//! ```
//!
//! The signature authenticates the HSM to the host; knowledge of the PSK
//! (proven by the host's `fin` in `SessionOpenFinish`) authenticates the
//! host to the HSM.
//!
//! Resume is not multiplexed onto this opcode; the host recovers a prior
//! session's `masking_key` via the MBOR `ReopenSession` command instead.
//!
//! On any error after the Pending slot is reserved, the dispatcher's undo
//! walk destroys it; no Pending slot is leaked.
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

/// Offset of `T1` in the Pending blob.
pub(super) const PENDING_T1_OFF: usize = SESSION_HS_LEN;

/// Offset of `auth_binding` in the Pending blob.
pub(super) const PENDING_AUTH_OFF: usize = PENDING_T1_OFF + SESSION_HS_LEN;

/// Offset of the `session_type` byte in the Pending blob.
pub(super) const PENDING_TYPE_OFF: usize = PENDING_AUTH_OFF + SESSION_AUTH_BINDING_LEN;

/// Offset of the `suite_id` byte in the Pending blob.
pub(super) const PENDING_SUITE_OFF: usize = PENDING_TYPE_OFF + 1;

/// Offset of the transport keys `h2m ‖ m2h` in the Pending blob.
pub(super) const PENDING_KEYS_OFF: usize = PENDING_SUITE_OFF + 1;

/// Length of the Pending handshake-state blob:
/// `hs(48) ‖ T1(48) ‖ auth_binding(68) ‖ session_type(1) ‖ suite_id(1)
/// ‖ h2m(32) ‖ m2h(32)`.
///
/// The transport keys must end the blob (see
/// [`HsmSessionManager::session_create_pending`]), so `SessionOpenFinish`
/// already travels on the encrypted channel.
pub(super) const PENDING_BLOB_LEN: usize = PENDING_KEYS_OFF + 2 * SESSION_TRANSPORT_KEY_LEN;

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
            role,
            psk_id,
            session_type,
            suite,
            pk_init,
        } = parse_request(cmd_buf.request())?;

        // ── Identity + PSK material (all on the scoped allocator) ──
        let psk = load_psk(pal, io, alloc, psk_id)?;
        let auth_binding = crate::session::capture_auth_binding(pal, io, alloc, role, psk).await?;
        let pk_hsm = load_pk_hsm_sec1(pal, io, alloc)?;

        // ── KEM encapsulation to the VM's ephemeral key ────────────
        let (enc, z) = encapsulate(pal, io, alloc, suite, pk_init).await?;

        // ── Transcript, signature and handshake secret ─────────────
        let t1 = transcript_hash(
            pal,
            io,
            alloc,
            [suite.to_u8(), psk_id, session_type.to_u8()],
            pk_hsm,
            pk_init,
            enc,
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
            session_type,
            suite,
            hs,
            t1,
            auth_binding,
        )
        .await?;
        // Record the just-created Pending session's teardown inverse, so a
        // failure below (response encode, or the CQE post) reverts it via
        // the dispatcher's undo walk rather than leaking the slot.
        undo.push_session_destroy(slot)?;
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
/// The PAL stores the partition identity public key as raw
/// `X_be ‖ Y_be` (the form used for cert generation); prefixing `0x04`
/// yields the SEC1 encoding the host recovers from the PID certificate.
pub(super) fn load_pk_hsm_sec1<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let xy_len = crate::part_state::part_id_pub_key(pal, io)?.len();
    if xy_len + 1 != SESSION_P384_SEC1_LEN {
        return Err(HsmError::InvalidArg);
    }
    let pk_hsm = alloc.dma_alloc(xy_len + 1)?;
    pk_hsm[0] = 0x04;
    {
        let pk = crate::part_state::part_id_pub_key(pal, io)?;
        pk_hsm[1..1 + xy_len].copy_from_slice(&pk[..xy_len]);
    }
    Ok(pk_hsm)
}

/// Encapsulate to `pk_init`, returning `(enc, Z)`.
///
/// * ECDH P-384: a fresh ephemeral keypair; `enc` is its SEC1 public
///   point and `Z` the 48 B big-endian x-coordinate of the shared point.
/// * ML-KEM-1024: `enc` is the 1568 B ciphertext and `Z` the 32 B shared
///   secret.
async fn encapsulate<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    suite: HsmSessionSuite,
    pk_init: &HsmDmaBuf,
) -> HsmResult<(&'a mut HsmDmaBuf, &'a mut HsmDmaBuf)> {
    match suite {
        HsmSessionSuite::EcdhP384EcdsaP384 => ecdh_encapsulate(pal, io, alloc, pk_init).await,
        HsmSessionSuite::MlKem1024EcdsaP384 => {
            let param = HsmMlKemParam::MlKem1024;
            let (ct_len, ss_len) = pal.mlkem_encaps(io, param, pk_init, None).await?;
            let enc = alloc.dma_alloc(ct_len)?;
            let z = alloc.dma_alloc(ss_len)?;
            pal.mlkem_encaps(io, param, pk_init, Some((&mut *enc, &mut *z)))
                .await?;
            Ok((enc, z))
        }
    }
}

/// Ephemeral ECDH P-384 against the SEC1 point `pk_init`.
async fn ecdh_encapsulate<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    pk_init: &HsmDmaBuf,
) -> HsmResult<(&'a mut HsmDmaBuf, &'a mut HsmDmaBuf)> {
    let order = P::BYTE_ORDER;
    let coord = CURVE.wire_coord_len(order);
    if pk_init[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    let peer = alloc.dma_alloc(2 * coord)?;
    peer[..SESSION_P384_SEC1_LEN - 1].copy_from_slice(&pk_init[1..]);
    byte_order::pair_from_be(order, CURVE, peer)?;

    // The ephemeral key is used for ECDH, so its generation runs a
    // key-agreement PCT.
    let (priv_len, pub_len) = pal
        .ecc_gen_keypair(io, alloc, CURVE, None, HsmEccPct::KeyAgreement)
        .await?;
    let sk = alloc.dma_alloc(priv_len)?;
    let pk = alloc.dma_alloc(pub_len)?;
    pal.ecc_gen_keypair(
        io,
        alloc,
        CURVE,
        Some((&mut *sk, &mut *pk)),
        HsmEccPct::KeyAgreement,
    )
    .await?;

    let z = alloc.dma_alloc(coord)?;
    pal.ecdh_derive(io, CURVE, sk, peer, z).await?;
    let z_len = byte_order::coord_to_be(order, CURVE, z)?.len();

    let enc = alloc.dma_alloc(SESSION_P384_SEC1_LEN)?;
    enc[0] = 0x04;
    let xy = byte_order::pair_to_be(order, CURVE, pk)?;
    if xy.len() != SESSION_P384_SEC1_LEN - 1 {
        return Err(HsmError::InvalidArg);
    }
    enc[1..].copy_from_slice(xy);
    Ok((enc, &mut z[..z_len]))
}

/// `T1 = SHA-384(label ‖ suite_id ‖ psk_id ‖ session_type ‖ pk_hsm
/// ‖ len16 ‖ pk_init ‖ len16 ‖ enc)`, as a standard digest.
async fn transcript_hash<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    params: [u8; 3],
    pk_hsm: &HsmDmaBuf,
    pk_init: &HsmDmaBuf,
    enc: &HsmDmaBuf,
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

    let mut ctx = pal.hash_begin(io, HsmHashAlgo::Sha384, alloc)?;
    for chunk in [head as &HsmDmaBuf, pk_init, enc_len, enc] {
        pal.hash_continue(io, &mut ctx, chunk).await?;
    }
    let t1 = alloc.dma_alloc(SESSION_HS_LEN)?;
    pal.hash_finish(io, ctx, t1, HsmDigestForm::Standard)
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
    let order = P::BYTE_ORDER;
    let digest = alloc.dma_alloc(t1.len())?;
    byte_order::int_copy_from_be(order, digest, t1)?;
    let sig = alloc.dma_alloc(CURVE.wire_sig_len(order))?;
    let key_id = crate::part_state::part_id_key_id(pal, io)?;
    let sk_hsm = pal.vault_key(io, key_id)?;
    pal.ecc_sign(io, CURVE, sk_hsm, digest, sig).await?;
    let sig = byte_order::pair_to_be(order, CURVE, sig)?;
    if sig.len() != SIG_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(sig)
}

/// `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v2", Z ‖ PSK),
/// "tsra-session-hs-v2" ‖ T1, 48)`.
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
    pal.hkdf_extract(io, HsmHashAlgo::Sha384, Some(salt), ikm, prk)
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
    session_type: HsmSessionType,
    suite: HsmSessionSuite,
    hs: &HsmDmaBuf,
    t1: &HsmDmaBuf,
    auth_binding: &HsmDmaBuf,
) -> HsmResult<HsmSessId> {
    let blob = alloc.dma_alloc(PENDING_BLOB_LEN)?;
    blob[..PENDING_T1_OFF].copy_from_slice(hs);
    blob[PENDING_T1_OFF..PENDING_AUTH_OFF].copy_from_slice(t1);
    blob[PENDING_AUTH_OFF..PENDING_TYPE_OFF].copy_from_slice(auth_binding);
    blob[PENDING_TYPE_OFF] = session_type.to_u8();
    blob[PENDING_SUITE_OFF] = suite.to_u8();
    let (h2m, m2h) = blob[PENDING_KEYS_OFF..].split_at_mut(SESSION_TRANSPORT_KEY_LEN);
    hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_TRANSPORT_H2M_LABEL, h2m).await?;
    hkdf_expand_labeled_into(pal, io, alloc, hs, SESSION_TRANSPORT_M2H_LABEL, m2h).await?;
    pal.session_create_pending(io, role, blob).await
}

/// Encode the `SessionOpenInit` response.
fn encode_response(
    cmd_buf: &mut HsmCmdBuf<'_>,
    session_id: u16,
    enc: &HsmDmaBuf,
    sig: &[u8],
) -> HsmResult<usize> {
    cmd_buf.encode_response(|buf| {
        let frame = TborSessionOpenInitResp::encode(buf, 0, false)?
            .session_id(SessionId(session_id))?
            .enc(enc)?
            .sig(sig)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
