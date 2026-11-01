// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain session establishment at the DDI layer.
//!
//! This module hosts the host-side dispatch for opening a session on an
//! HSM partition. Two transports coexist:
//!
//! * **MBOR** — the established single-round-trip `OpenSession` command
//!   implemented in [`super::session`], reached via
//!   [`HsmPartition::open_session`].
//! * **TBOR** — the two-phase HPKE handshake mirroring the firmware
//!   handlers `open_session_init` (opcode `0x10`) and
//!   `open_session_finish` (opcode `0x11`), reached via
//!   [`HsmPartition::open_session_ex`].
//!
//! Transport selection is driven solely by which call the caller makes:
//! [`open_session_ex`] always runs the TBOR handshake —
//! [`open_session_ex_init`] (Phase 1) followed by
//! [`open_session_ex_finish`] (Phase 2). The MBOR `OpenSession` path in
//! [`super::session`] is dispatched separately and is not reached
//! through this entry point.
//!
//! Both phases are wired. Their HPKE handshake crypto (VM ephemeral
//! generation, `receive_export`, the confirm MACs, `param_key`
//! derivation, and the `seed_envelope` AEAD seal) lives in the
//! standalone [`tsra_session_ex_crypto`] crate, the single host-side
//! source of truth for the wire protocol. `pk_hsm` retrieval reuses
//! the production cert chain via [`fetch_pk_hsm`].

use tsra_crypto::*;
use tsra_ddi_tbor_types::*;
use tsra_session_ex_crypto::*;
use x509::X509Certificate;
use x509::X509CertificateError;
use x509::X509CertificateOp;
use zeroize::Zeroizing;

use super::*;

/// Maps a [`SessionExCryptoError`] onto the API error domain. Malformed
/// inputs surface as [`HsmError::InvalidArgument`]; handshake-crypto
/// failures (key agreement, AEAD, confirm-MAC) surface as
/// [`HsmError::InternalError`].
impl From<SessionExCryptoError> for HsmError {
    fn from(err: SessionExCryptoError) -> Self {
        match err {
            SessionExCryptoError::InvalidInput => HsmError::InvalidArgument,
            SessionExCryptoError::Crypto => HsmError::InternalError,
            SessionExCryptoError::MacMismatch => HsmError::InvalidSignature,
        }
    }
}

impl TryFrom<HsmSessionExType> for SessionType {
    type Error = HsmError;

    /// Maps the API-layer [`HsmSessionExType`] onto the wire-level
    /// [`SessionType`]. `HsmSessionExType` is an `#[open_enum]`, so an
    /// unrecognized discriminant (anything beyond `PlainText` /
    /// `Authenticated`) surfaces as [`HsmError::InvalidArgument`]
    /// rather than silently mapping to a default channel profile.
    fn try_from(session_type: HsmSessionExType) -> Result<Self, Self::Error> {
        match session_type {
            HsmSessionExType::PlainText => Ok(SessionType::PlainText),
            HsmSessionExType::Authenticated => Ok(SessionType::Authenticated),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

#[derive(Debug)]
struct PendingHandshake {
    /// Reserved session identifier returned by the FW.
    pub session_id: u16,
    /// Caller-selected PSK id (0 = CO, 1 = CU).
    pub psk_id: u8,
    /// Caller-selected channel integrity profile.
    pub session_type: SessionType,
    /// HPKE export secret (`Nh = 48`) derived by HPKE
    /// `receive_export` after Phase 1 completes. Held in a
    /// [`Zeroizing`] buffer so it is wiped on every drop path
    /// (Phase-1 MAC rejection, Phase-2 failure, or after a successful
    /// Phase 2 has copied it into the session).
    pub exported: Zeroizing<Vec<u8>>,
    /// Wire `pk_init` (SEC1 uncompressed, 97 B).
    pub pk_init: [u8; PK_INIT_LEN],
    /// Wire `pk_resp` (SEC1 uncompressed, 97 B).
    pub pk_resp: [u8; PK_RESP_LEN],
    /// Wire `pk_hsm` (SEC1 uncompressed, 97 B) — partition identity
    /// public key fetched out-of-band via the TBOR cert chain
    /// (`GetCertChainInfo` / `GetCertificate`).
    pub pk_hsm: [u8; PK_RESP_LEN],
    /// Opaque continuity token recorded for this session's
    /// `SessionOpenInit` (`Open`) exchange by any DDI backend that
    /// tracks one (see `DdiCookie` in `ddi/interface`). Threaded into
    /// [`open_session_ex_finish`]'s own `exec_op_tbor` call so the
    /// Phase-2 `InSession` request is recognized as belonging to the
    /// same handshake rather than rejected as missing a token.
    pub ddi_cookie: Option<u64>,
}

pub(crate) struct OpenSessionExResult {
    /// Active session identifier.
    pub(crate) session_id: u16,
    /// PSK id used for the handshake (0 = CO, 1 = CU).
    pub(crate) psk_id: u8,
    /// Channel integrity profile pinned at handshake time.
    pub(crate) session_type: SessionType,
    /// HPKE exported secret (`Nh = 48`) used to derive `param_key`
    /// and (for authenticated sessions) the MAC keys. Held in a
    /// [`Zeroizing`] buffer so it is wiped on drop even when this
    /// result is dropped directly rather than moved into a session.
    pub(crate) exported: Zeroizing<Vec<u8>>,
    /// Per-session AES-256 wrap key derived from the HPKE export.
    pub(crate) param_key: AesKey,
    /// FW-emitted wrapped masking-key blob — opaque to the host.
    /// Held in a [`Zeroizing`] buffer so it is wiped on drop.
    pub(crate) bmk_session: Zeroizing<Vec<u8>>,
    /// Session seed sealed into `seed_envelope`. Retained because
    /// [`reopen_session_ex`] must re-send the **original** seed so the
    /// HSM can unwrap `bmk_session`. Wiped on drop.
    pub(crate) seed: Zeroizing<[u8; SESSION_SEED_LEN]>,
    /// Opaque continuity token for this session, as recorded by the
    /// Phase-2 `SessionOpenFinish` `InSession` exchange. Stored in
    /// the resulting [`HsmSession`](super::super::HsmSession) and
    /// threaded through every later in-session TBOR op (and the final
    /// `CloseSession`) so any DDI backend that tracks per-session
    /// continuity state (see `ddi/interface`) can recognize the same
    /// live handle across calls.
    pub(crate) ddi_cookie: Option<u64>,
}

/// Exchange one TBOR request as part of the SD handshake, threading
/// `cookie_in` into the call and returning the (possibly refreshed)
/// token the backend reports back.
///
/// Both handshake phases ([`open_session_ex_init`] and
/// [`open_session_ex_finish`]) route their `exec_op_tbor` call through
/// this one function so they can't drift in how they treat the cookie:
/// Phase 1's token must be threaded into Phase 2, and a refreshed
/// Phase-2 token must be retained.
fn exec_handshake_tbor<D: DdiDev, T: TborOpReq>(
    dev: &D,
    req: &T,
    cookie_in: Option<DdiCookie>,
) -> DdiResult<(T::OpResp, Option<DdiCookie>)> {
    let mut cookie = cookie_in;
    let resp = dev.exec_op_tbor(req, None, &mut cookie)?;
    Ok((resp, cookie))
}

/// production cert chain. Uses [`fetch_cert_chain_checked_tbor`] — the
/// out-of-session TBOR `GetCertChainInfo` / `GetCertificate` commands,
/// so the whole handshake stays on the TBOR transport — whose leaf cert
/// is the partition-ID cert; its SubjectPublicKeyInfo carries the P-384
/// key the FW uses as `pk_s` in HPKE `auth_psk`.
///
/// The SD handshake authenticates the entire session against this key,
/// so the partition cert chain is cryptographically verified (via
/// [`validate_part_cert_chain`]) before the leaf key is trusted.
///
/// The negotiated API revision is validated before issuing the TBOR cert
/// commands; revisions below [`TBOR_MIN_API_REV`] are unsupported.
pub(super) fn fetch_pk_hsm(
    dev: &HsmDev,
    rev: HsmApiRev,
) -> HsmResult<(EccPublicKey, [u8; PK_RESP_LEN])> {
    require_tbor_rev(rev)?;
    let (chain_pem, leaf_der) = fetch_cert_chain_checked_tbor(dev, 0)?;
    validate_part_cert_chain(&chain_pem)?;

    let leaf = X509Certificate::from_der(&leaf_der).map_err(|_| HsmError::InternalError)?;
    let pk_der = leaf
        .get_public_key_der()
        .map_err(|_| HsmError::InternalError)?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| HsmError::InternalError)?;
    let sec1 = ec_pub_to_sec1(&pk)?;
    Ok((pk, sec1))
}

/// Cryptographically verify the partition cert chain's internal
/// issuance/order (leaf issued by intermediate ... issued by root)
/// before its leaf key is trusted as `pk_hsm`.
///
/// `chain_pem` is the leaf->root PEM stack returned by
/// [`fetch_cert_chain_checked_tbor`]. [`X509CertificateOp::validate_chain`]
/// verifies internal consistency, not a pinned trust anchor. A single
/// self-signed cert (e.g. the sim backend) has no ordering to verify,
/// so chains shorter than two certs are accepted as-is.
///
/// # Errors
///
/// Returns [`HsmError::InternalError`] when the PEM stack is empty or
/// fails to parse, and [`HsmError::InvalidSignature`] when the chain
/// fails cryptographic verification.
fn validate_part_cert_chain(chain_pem: &str) -> HsmResult<()> {
    let certs = X509Certificate::from_pem_stack(chain_pem.as_bytes())
        .map_err(|_| HsmError::InternalError)?;
    let Some((leaf, rest)) = certs.split_first() else {
        return Err(HsmError::InternalError);
    };
    if rest.is_empty() {
        // Single self-signed cert (e.g. sim): no chain ordering to verify.
        return Ok(());
    }
    match leaf.validate_chain(rest) {
        Ok(true) => Ok(()),
        // A verification failure (bad signature / broken issuance chain)
        // surfaces as `Ok(false)` on Windows and `Err(VerifyError)` on
        // Linux; map both to `InvalidSignature`. Parse / store-setup
        // failures remain `InternalError`.
        Ok(false) | Err(X509CertificateError::VerifyError) => Err(HsmError::InvalidSignature),
        Err(_) => Err(HsmError::InternalError),
    }
}

/// Opens a session on an HSM partition over the TBOR transport.
///
/// Always runs the two-phase HPKE handshake —
/// [`open_session_ex_init`] (Phase 1) followed by
/// [`open_session_ex_finish`] (Phase 2) — over TBOR. The negotiated API
/// revision is validated for TBOR support rather than used to select a
/// transport.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `rev` - The negotiated API revision. A `session_ex` session is
///   TBOR-only and requires [`TBOR_MIN_API_REV`] or newer; an older revision
///   is rejected with [`HsmError::UnsupportedApiRevision`].
/// * `psk_id` - Pre-shared-key identity selecting the role (0 = CO,
///   1 = CU).
/// * `session_type` - Channel integrity profile to pin for the session.
///
/// # Returns
///
/// Returns an [`OpenSessionExResult`] with the session identifier and
/// the per-session key material derived by the handshake.
///
/// # Errors
///
/// Returns [`HsmError::UnsupportedApiRevision`] when `rev` does not
/// support TBOR, and propagates failures from the handshake.
pub(crate) fn open_session_ex(
    partition: &HsmPartition,
    rev: HsmApiRev,
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    session_type: HsmSessionExType,
) -> HsmResult<OpenSessionExResult> {
    require_tbor_rev(rev)?;

    // Convert the API-layer session type to the wire-level `SessionType`
    // here in the DDI layer, so the public API surface never handles the
    // DDI wire type.
    let session_type: SessionType = session_type.try_into()?;
    let pending = open_session_ex_init(partition, rev, psk_id, psk, session_type)?;
    open_session_ex_finish(partition, pending)
}

/// Phase 1 of the TBOR handshake — `OpenSessionInit` (opcode `0x10`).
///
/// Generates the VM per-handshake ephemeral keypair, fetches the
/// partition identity key (`pk_hsm`) from the production cert chain,
/// ships the request, runs HPKE `auth_psk receive_export` on the FW
/// response, and verifies the Phase-1 confirm MAC. Returns a
/// [`PendingHandshake`] for [`open_session_ex_finish`] to consume.
///
/// Uses the caller-supplied PSK when present, otherwise the partition
/// default PSK for `psk_id` (CO = 0, CU = 1).
///
/// The negotiated API revision is passed to [`fetch_pk_hsm`], which
/// validates that it supports TBOR before fetching the partition cert.
///
/// # Errors
///
/// Returns [`HsmError::UnsupportedApiRevision`] when `rev` does not
/// support TBOR, propagates DDI failures from the round-trip,
/// [`HsmError::InvalidArgument`] for malformed handshake inputs (e.g.
/// an unknown `psk_id`), and [`HsmError::InternalError`] for
/// handshake-crypto failures (e.g. a Phase-1 confirm MAC mismatch).
fn open_session_ex_init(
    partition: &HsmPartition,
    rev: HsmApiRev,
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    session_type: SessionType,
) -> HsmResult<PendingHandshake> {
    // Ensure the negotiated API revision supports TBOR before proceeding.
    require_tbor_rev(rev)?;

    let inner = partition.inner().read();
    let dev = inner.dev();

    // VM per-handshake ephemeral keypair (recipient side of the HPKE
    // auth_psk handshake).
    let eph = generate_vm_ephemeral()?;

    // Partition identity key (`pk_hsm`, HPKE sender) from the leaf
    // cert in the production cert chain.
    let (pk_hsm_key, pk_hsm_sec1) = fetch_pk_hsm(dev, rev)?;

    let suite_id = SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;
    let req = TborSessionOpenInitReq {
        psk_id,
        session_type: session_type.to_u8(),
        suite_id,
        pk_init: eph.pk_sec1,
    };

    let (resp, cookie) = exec_handshake_tbor(&**dev, &req, None).map_err(HsmError::from)?;

    complete_phase1(
        &eph,
        &pk_hsm_key,
        pk_hsm_sec1,
        resp.session_id,
        psk_id,
        session_type,
        psk,
        resp.pk_resp,
        &resp.mac_resp,
        cookie,
    )
}

/// Shared Phase-1 tail for `SessionOpenInit` and `SessionReopenInit`.
///
/// Runs HPKE `auth_psk receive_export` on the FW response, verifies the
/// Phase-1 confirm MAC (bound to `session_id`), and packages the
/// [`PendingHandshake`] for Phase 2, carrying the Phase-1 exchange's
/// `ddi_cookie` forward. Uses the caller-supplied PSK when present,
/// else the partition default PSK for `psk_id`.
#[allow(clippy::too_many_arguments)]
fn complete_phase1(
    eph: &VmEphemeralKey,
    pk_hsm_key: &EccPublicKey,
    pk_hsm_sec1: [u8; PK_RESP_LEN],
    session_id: u16,
    psk_id: u8,
    session_type: SessionType,
    psk: Option<&[u8; crate::PSK_LEN]>,
    pk_resp: [u8; PK_RESP_LEN],
    mac_resp: &[u8; MAC_RESP_LEN],
    ddi_cookie: Option<u64>,
) -> HsmResult<PendingHandshake> {
    // Derive the 48-byte HPKE `exported` secret, then verify the FW's
    // Phase-1 confirm MAC binds the negotiated role/type/suite.
    let info = build_hpke_info(
        psk_id,
        session_type.to_u8(),
        SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
    );
    // Use the caller-supplied PSK when present, else the partition
    // default PSK for the role (required before the default is rotated).
    let psk: &[u8; crate::PSK_LEN] = match psk {
        Some(p) => p,
        None => default_psk(psk_id)?,
    };
    let exported = Zeroizing::new(receive_exported(
        &eph.sk,
        &eph.pk,
        pk_hsm_key,
        &pk_resp,
        &info,
        psk,
        &[psk_id],
    )?);

    verify_phase1_mac(
        &exported,
        session_id,
        &eph.pk_sec1,
        &pk_hsm_sec1,
        &pk_resp,
        mac_resp,
    )?;

    Ok(PendingHandshake {
        session_id,
        psk_id,
        session_type,
        exported,
        pk_init: eph.pk_sec1,
        pk_resp,
        pk_hsm: pk_hsm_sec1,
        ddi_cookie,
    })
}

/// Phase 2 of the TBOR handshake — `OpenSessionFinish` (opcode `0x11`).
///
/// Derives the per-session `param_key` from the HPKE export, generates
/// a fresh 32-byte session seed and AEAD-seals it into `seed_envelope`,
/// computes the Phase-2 confirm MAC, ships `OpenSessionFinish`, and
/// folds the FW's `bmk_session` into an [`OpenSessionExResult`].
///
/// Consumes the [`PendingHandshake`] so stale Phase-1 state cannot be
/// reused for a second finish against the same session slot.
///
/// # Errors
///
/// Propagates DDI failures from the round-trip (including a Phase-2
/// confirm-MAC rejection by the FW), [`HsmError::InvalidArgument`] for
/// malformed handshake inputs, and [`HsmError::InternalError`] for
/// handshake-crypto failures.
/// Shared core of [`open_session_ex_finish`]'s Phase-2 exchange: derive
/// `param_key`, seal a fresh session seed, build the Phase-2 confirm
/// MAC, exchange `OpenSessionFinish` via [`exec_handshake_tbor`], and
/// fold the response into an [`OpenSessionExResult`] whose
/// `ddi_cookie` is Phase 2's (possibly refreshed) token.
fn finish_handshake_tbor<D: DdiDev>(
    dev: &D,
    pending: &PendingHandshake,
) -> HsmResult<OpenSessionExResult> {
    let mut seed = Zeroizing::new([0u8; SESSION_SEED_LEN]);
    Rng::rand_bytes(seed.as_mut_slice()).map_err(|_| HsmError::InternalError)?;
    let material = phase2_material(pending, seed)?;

    let req = TborSessionOpenFinishReq {
        session_id: pending.session_id,
        mac_fin: material.mac_fin,
        seed_envelope: material.seed_envelope,
    };
    // Carry the Phase-1 `Open` token forward so the Phase-2
    // `InSession` exchange is recognized as the same handshake rather
    // than rejected for lacking one.
    let (resp, cookie) =
        exec_handshake_tbor(dev, &req, pending.ddi_cookie).map_err(HsmError::from)?;

    Ok(material.into_result(pending, resp.bmk_session, cookie))
}

fn open_session_ex_finish(
    partition: &HsmPartition,
    pending: PendingHandshake,
) -> HsmResult<OpenSessionExResult> {
    let inner = partition.inner().read();
    let dev = inner.dev();
    finish_handshake_tbor(&**dev, &pending)
}

/// Host-side Phase-2 material shared by `SessionOpenFinish` and
/// `SessionReopenFinish`.
struct Phase2Material {
    param_key: AesKey,
    seed: Zeroizing<[u8; SESSION_SEED_LEN]>,
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
    mac_fin: [u8; MAC_FIN_LEN],
}

impl Phase2Material {
    /// Folds the FW-issued `bmk_session` and the Phase-2 exchange's
    /// (possibly refreshed) `ddi_cookie` into an [`OpenSessionExResult`].
    fn into_result(
        self,
        pending: &PendingHandshake,
        bmk_session: Vec<u8>,
        ddi_cookie: Option<u64>,
    ) -> OpenSessionExResult {
        OpenSessionExResult {
            session_id: pending.session_id,
            psk_id: pending.psk_id,
            session_type: pending.session_type,
            // Hand the session its own copy of the export secret; the copy
            // in `pending` is wiped when `pending` drops (its `exported`
            // is a `Zeroizing` buffer).
            exported: pending.exported.clone(),
            param_key: self.param_key,
            bmk_session: Zeroizing::new(bmk_session),
            seed: self.seed,
            ddi_cookie,
        }
    }
}

/// Derives the per-session `param_key` from the HPKE export, seals
/// `seed` under it as the `seed_envelope` wire blob, and computes the
/// Phase-2 confirm MAC over the Phase-1 transcript.
fn phase2_material(
    pending: &PendingHandshake,
    seed: Zeroizing<[u8; SESSION_SEED_LEN]>,
) -> HsmResult<Phase2Material> {
    let param_key = derive_param_key(&pending.exported)?;
    let envelope = seal_seed_envelope(&param_key, seed.as_slice())?;
    let seed_envelope: [u8; SEED_ENVELOPE_LEN] = envelope
        .as_slice()
        .try_into()
        .map_err(|_| HsmError::InternalError)?;

    // Phase-2 confirm MAC binds the same transcript as Phase 1 under
    // the Phase-2 label.
    let mac_fin = build_phase2_mac(
        &pending.exported,
        pending.session_id,
        &pending.pk_init,
        &pending.pk_hsm,
        &pending.pk_resp,
    )?;

    Ok(Phase2Material {
        param_key,
        seed,
        seed_envelope,
        mac_fin,
    })
}

/// Re-establishes an existing TBOR session that needs renegotiation
/// (e.g. after a partition reset) — `SessionReopenInit` (opcode `0x30`)
/// followed by `SessionReopenFinish` (opcode `0x31`).
///
/// Runs the same HPKE handshake as [`open_session_ex`] against the
/// existing `session_id`, using the PSK currently bound to the session's
/// role (`psk`, or the role default when `None`). Phase 2 re-sends the
/// session's **original** `seed` and its last `bmk_session` so the HSM
/// restores the same session masking key; session-scoped masked keys
/// therefore stay valid. Returns fresh `param_key` / `exported` material
/// and the refreshed `bmk_session`.
///
/// `ddi_cookie` is the session's current continuity token. It is
/// threaded through both in-session exchanges, and the result carries
/// the (possibly refreshed) token, which must replace the session's
/// cached cookie.
///
/// # Errors
///
/// Returns [`HsmError::UnsupportedApiRevision`] when `rev` does not
/// support TBOR, and propagates handshake and DDI failures.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reopen_session_ex(
    partition: &HsmPartition,
    rev: HsmApiRev,
    session_id: u16,
    ddi_cookie: Option<u64>,
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    session_type: SessionType,
    seed: &[u8; SESSION_SEED_LEN],
    bmk_session: &[u8],
) -> HsmResult<OpenSessionExResult> {
    require_tbor_rev(rev)?;

    let inner = partition.inner().read();
    let dev = inner.dev();

    let eph = generate_vm_ephemeral()?;
    let (pk_hsm_key, pk_hsm_sec1) = fetch_pk_hsm(dev, rev)?;

    let req = TborSessionReopenInitReq {
        session_id,
        session_type: session_type.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: eph.pk_sec1,
    };
    let (resp, cookie) = exec_handshake_tbor(&**dev, &req, ddi_cookie).map_err(HsmError::from)?;

    let pending = complete_phase1(
        &eph,
        &pk_hsm_key,
        pk_hsm_sec1,
        session_id,
        psk_id,
        session_type,
        psk,
        resp.pk_resp,
        &resp.mac_resp,
        cookie,
    )?;

    let material = phase2_material(&pending, Zeroizing::new(*seed))?;
    let req = TborSessionReopenFinishReq {
        session_id,
        mac_fin: material.mac_fin,
        seed_envelope: material.seed_envelope,
        bmk_session: bmk_session.to_vec(),
    };
    let (resp, cookie) =
        exec_handshake_tbor(&**dev, &req, pending.ddi_cookie).map_err(HsmError::from)?;

    Ok(material.into_result(&pending, resp.bmk_session, cookie))
}

/// Issue `PskChange` (opcode `0x06`) on the active session.
///
/// Seals `new_psk` under the session `param_key` (AAD-bound to the
/// session id via [`build_psk_change_aad`]) and ships it as the
/// `psk_envelope`. The firmware rotates the PSK slot implied by the
/// session role (CO session → CO slot, CU session → CU slot); the
/// request carries no slot-selection field.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `param_key` - The session's per-session AES wrap key used to seal
///   the new PSK.
/// * `new_psk` - The 32-byte replacement PSK ([`crate::PSK_LEN`]).
/// * `ddi_cookie` - The session's opaque continuity token, threaded
///   through so any DDI backend that tracks per-session continuity
///   state (see `ddi/interface`) recognizes this request as belonging
///   to the still-live session rather than rejecting it as missing a
///   token.
///
/// # Errors
///
/// Propagates [`HsmError::InternalError`] on an RNG / AEAD seal failure
/// and surfaces DDI/device failures from the round-trip.
pub(crate) fn psk_change(
    partition: &HsmPartition,
    session_id: u16,
    param_key: &AesKey,
    new_psk: &[u8; crate::PSK_LEN],
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<()> {
    let aad = build_psk_change_aad(session_id);
    let iv = Rng::rand_vec(tsra_crypto::aead_envelope::AeadAlg::AesGcm256.iv_len())
        .map_err(|_| HsmError::InternalError)?;

    // First pass sizes the output buffer; second pass writes the sealed
    // envelope into it.
    let total = tsra_crypto::aead_envelope::seal(
        tsra_crypto::aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        new_psk,
        None,
    )
    .map_err(|_| HsmError::InternalError)?;
    let mut envelope = vec![0u8; total];
    let written = tsra_crypto::aead_envelope::seal(
        tsra_crypto::aead_envelope::AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        new_psk,
        Some(&mut envelope),
    )
    .map_err(|_| HsmError::InternalError)?;
    envelope.truncate(written);

    let req = TborPskChangeReq {
        session_id,
        psk_envelope: envelope,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    with_explicit_cookie(ddi_cookie, |cookie| {
        let _resp: TborPskChangeResp = dev
            .exec_op_tbor(&req, None, cookie)
            .map_err(HsmError::from)?;
        Ok(())
    })
}

/// Closes an active TBOR security-domain session — `CloseSession`
/// (opcode `0x12`).
///
/// Tears down the FW-side session slot identified by `session_id`,
/// releasing its key material and invalidating the identifier.
///
/// Resiliency (retry / session reopen) is not yet wired for the TBOR
/// transport, so any DDI failure is surfaced to the caller as-is.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The TBOR session identifier to tear down.
/// * `ddi_cookie` - The session's generation-bound backend token; see
///   [`psk_change`].
///
/// # Errors
///
/// Propagates DDI failures from the round-trip.
pub(crate) fn close_session_ex(
    partition: &HsmPartition,
    session_id: u16,
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<()> {
    let inner = partition.inner().read();
    let dev = inner.dev();

    let req = TborSessionCloseReq { session_id };
    with_explicit_cookie(ddi_cookie, |cookie| {
        dev.exec_op_tbor(&req, None, cookie)
            .map_err(HsmError::from)
            .map(|_| ())
    })
}
