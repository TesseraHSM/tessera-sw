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
//! * **TBOR** — the two-phase signed-transcript KEM handshake mirroring
//!   the firmware handlers `open_session_init` and `open_session_finish`,
//!   reached via [`HsmPartition::open_session_ex`].
//!
//! [`open_session_ex`] runs [`open_session_ex_init`] (Phase 1: KEM
//! exchange, HSM signature over the transcript) followed by
//! [`open_session_ex_finish`] (Phase 2: host confirmation and session
//! seed, already encrypted under the session transport keys). Every later
//! in-session command and the close are encrypted with the same keys.
//!
//! The handshake crypto lives in the standalone [`tsra_session_ex_crypto`]
//! crate, the single host-side source of truth for the wire protocol.
//! `pk_hsm` retrieval reuses the production cert chain via
//! [`fetch_pk_hsm`].

use tsra_crypto::*;
use tsra_ddi_tbor_types::*;
use tsra_session_ex_crypto::*;
use x509::X509Certificate;
use x509::X509CertificateError;
use x509::X509CertificateOp;
use zeroize::Zeroizing;

use super::*;

#[cfg(all(test, target_os = "linux"))]
#[path = "session_ex_tests.rs"]
mod tests;

/// Maps a [`SessionExCryptoError`] onto the API error domain. Malformed
/// inputs surface as [`HsmError::InvalidArgument`]; a transcript
/// signature or transport authentication failure as
/// [`HsmError::InvalidSignature`]; other crypto failures as
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

impl TryFrom<HsmSessionSuite> for SessionSuite {
    type Error = HsmError;

    /// Maps the API-layer [`HsmSessionSuite`] onto the handshake suite.
    /// `HsmSessionSuite` is an `#[open_enum]`, so an unrecognized
    /// discriminant surfaces as [`HsmError::InvalidArgument`].
    fn try_from(suite: HsmSessionSuite) -> Result<Self, Self::Error> {
        match suite {
            HsmSessionSuite::EcdhP384 => Ok(SessionSuite::EcdhP384),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

/// Phase-1 outcome, consumed by [`open_session_ex_finish`].
struct PendingHandshake {
    api_rev: HsmApiRev,
    /// Reserved session identifier returned by the FW.
    session_id: u16,
    /// Caller-selected PSK id (0 = CO, 1 = CU).
    psk_id: u8,
    /// Key-establishment suite of the handshake.
    suite: HsmSessionSuite,
    /// Verified handshake secret and transcript.
    handshake: SessionHandshake,
}

pub(crate) struct OpenSessionExResult {
    /// Active session identifier.
    pub(crate) session_id: u16,
    /// PSK id used for the handshake (0 = CO, 1 = CU).
    pub(crate) psk_id: u8,
    /// Key-establishment suite of the handshake.
    pub(crate) suite: HsmSessionSuite,
    /// Per-session AES-256 wrap key derived from the handshake secret.
    pub(crate) param_key: AesKey,
    /// FW-emitted wrapped masking-key blob — opaque to the host.
    /// Held in a [`Zeroizing`] buffer so it is wiped on drop.
    pub(crate) bmk_session: Zeroizing<Vec<u8>>,
    /// Secret recovery context used to unwrap the original masking key.
    pub(crate) seed: Zeroizing<[u8; SESSION_SEED_LEN]>,
    /// Opaque continuity token for this session, stored in the resulting
    /// [`HsmSession`](super::super::HsmSession) and threaded through every
    /// later in-session TBOR op (and the final `CloseSession`) so any DDI
    /// backend that tracks per-session continuity state (see
    /// `ddi/interface`) can recognize the same live handle across calls.
    pub(crate) ddi_cookie: Option<u64>,
}

/// Fetch the partition identity public key (`pk_hsm`) from the
/// production cert chain. Uses [`fetch_cert_chain_checked_tbor`] — the
/// out-of-session TBOR `GetCertChainInfo` / `GetCertificate` commands,
/// so the whole handshake stays on the TBOR transport — whose leaf cert
/// is the partition-ID cert; its SubjectPublicKeyInfo carries the P-384
/// key the FW signs the handshake transcript with.
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
    root_spki_thumbprint: &[u8; 48],
) -> HsmResult<EccPublicKey> {
    require_tbor_rev(rev)?;
    let (chain_pem, _) = fetch_cert_chain_checked_tbor(dev, rev, 0)?;
    validate_part_cert_chain(&chain_pem, root_spki_thumbprint)
}

/// Authenticate the PID path against the caller's root SPKI thumbprint and require
/// DICE layer zero plus the Tessera EKU on the same non-PID certificate.
fn validate_part_cert_chain(
    chain_pem: &str,
    root_spki_thumbprint: &[u8; 48],
) -> HsmResult<EccPublicKey> {
    let certs = X509Certificate::from_pem_stack(chain_pem.as_bytes())
        .map_err(|_| HsmError::InvalidSignature)?;
    let Some((leaf, rest)) = certs.split_first() else {
        return Err(HsmError::InvalidSignature);
    };
    if rest.is_empty() {
        return Err(HsmError::InvalidSignature);
    }
    let path = match leaf.verified_chain(rest) {
        Ok(Some(path)) => path,
        Ok(None) | Err(X509CertificateError::VerifyError) => {
            return Err(HsmError::InvalidSignature);
        }
        Err(_) => return Err(HsmError::InternalError),
    };
    let root = path.last().ok_or(HsmError::InvalidSignature)?;
    let root_spki = root
        .subject_public_key_info_der()
        .map_err(|_| HsmError::InvalidSignature)?;
    let actual = Hasher::hash_vec(&mut HashAlgo::sha384(), root_spki)
        .map_err(|_| HsmError::InternalError)?;
    if actual.as_slice() != root_spki_thumbprint {
        return Err(HsmError::InvalidSignature);
    }
    // The thumbprint identifies the root key, not its certificate's extensions.
    // Trust stores may skip this signature, but the root may supply the profile.
    if !root
        .verify_signature(root)
        .map_err(|_| HsmError::InvalidSignature)?
    {
        return Err(HsmError::InvalidSignature);
    }
    let mut tessera_device = false;
    for certificate in path.iter().skip(1) {
        let layer_zero = certificate
            .has_dice_tcb_info_layer(0)
            .map_err(|_| HsmError::InvalidSignature)?;
        let tessera_eku = certificate
            .has_extended_key_usage("1.3.6.1.4.1.311.102.1.50.1")
            .map_err(|_| HsmError::InvalidSignature)?;
        tessera_device |= layer_zero && tessera_eku;
    }
    if !tessera_device {
        return Err(HsmError::InvalidSignature);
    }
    let pk_der = leaf
        .subject_public_key_info_der()
        .map_err(|_| HsmError::InvalidSignature)?;
    EccPublicKey::from_bytes(pk_der).map_err(|_| HsmError::InvalidSignature)
}

/// Opens a session on an HSM partition over the TBOR transport.
///
/// Runs [`open_session_ex_init`] (Phase 1) followed by
/// [`open_session_ex_finish`] (Phase 2).
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `rev` - The negotiated API revision. A `session_ex` session is
///   TBOR-only and requires [`TBOR_MIN_API_REV`] or newer; an older revision
///   is rejected with [`HsmError::UnsupportedApiRevision`].
/// * `root_spki_thumbprint` - Independently provisioned root SPKI SHA-384 digest.
/// * `psk_id` - Pre-shared-key identity selecting the role (0 = CO,
///   1 = CU).
/// * `psk` - Caller-supplied PSK; `None` selects the partition default.
/// * `suite` - Key-establishment suite of the handshake.
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
    root_spki_thumbprint: &[u8; 48],
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    suite: HsmSessionSuite,
) -> HsmResult<OpenSessionExResult> {
    require_tbor_rev(rev)?;
    let pending = open_session_ex_init(partition, rev, root_spki_thumbprint, psk_id, psk, suite)?;
    open_session_ex_finish(partition, pending)
}

/// Phase 1 of the TBOR handshake — `SessionOpenInit`.
///
/// Generates the per-handshake KEM ephemeral, fetches the partition
/// identity key (`pk_hsm`) from the production cert chain, ships
/// `pk_init`, verifies the HSM's signature over the transcript `T1` and
/// derives the handshake secret from the KEM shared secret and the PSK.
///
/// Uses the caller-supplied PSK when present, otherwise the partition
/// default PSK for `psk_id` (CO = 0, CU = 1).
///
/// # Errors
///
/// Returns [`HsmError::UnsupportedApiRevision`] when `rev` does not
/// support TBOR, propagates DDI failures from the round-trip,
/// [`HsmError::InvalidArgument`] for malformed handshake inputs (e.g.
/// an unknown `psk_id` or suite), and [`HsmError::InvalidSignature`]
/// when the transcript signature does not verify.
fn open_session_ex_init(
    partition: &HsmPartition,
    rev: HsmApiRev,
    root_spki_thumbprint: &[u8; 48],
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    suite: HsmSessionSuite,
) -> HsmResult<PendingHandshake> {
    establish_session_ex_init(
        partition,
        rev,
        root_spki_thumbprint,
        psk_id,
        psk,
        suite,
        u16::MAX,
    )
}

#[allow(clippy::too_many_arguments)]
fn establish_session_ex_init(
    partition: &HsmPartition,
    rev: HsmApiRev,
    root_spki_thumbprint: &[u8; 48],
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    suite: HsmSessionSuite,
    reopen_id: u16,
) -> HsmResult<PendingHandshake> {
    let session_suite: SessionSuite = suite.try_into()?;
    // Resolve the PSK before touching the device so an unknown role
    // fails without reserving a session slot.
    let psk: &[u8; crate::PSK_LEN] = match psk {
        Some(p) => p,
        None => default_psk(psk_id)?,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();

    let pk_hsm = fetch_pk_hsm(dev, rev, root_spki_thumbprint)?;
    let initiator = SessionInitiator::generate(session_suite, rev.tbor().map_err(HsmError::from)?)?
        .for_reopen(reopen_id);
    let session_type = SessionType::Encrypted.to_u8();
    let req = TborSessionOpenInitReq {
        reopen_id,
        psk_id,
        session_type,
        suite_id: session_suite.id(),
        pk_init: initiator.pk_init().to_vec(),
    };
    let resp = dev
        .exec_op_tbor(rev, &req, None, &mut None)
        .map_err(HsmError::from)?;
    if reopen_id != u16::MAX && resp.session_id != reopen_id {
        return Err(HsmError::InvalidSession);
    }

    match initiator.complete(psk_id, session_type, &pk_hsm, psk, &resp.enc, &resp.sig) {
        Ok(handshake) => Ok(PendingHandshake {
            api_rev: rev,
            session_id: resp.session_id,
            psk_id,
            suite,
            handshake,
        }),
        Err(err) => {
            // Release the reserved slot; the error is the handshake failure.
            if reopen_id == u16::MAX {
                let _ = dev.flush_session(resp.session_id);
            }
            Err(err.into())
        }
    }
}

/// Phase 2 of the TBOR handshake — `SessionOpenFinish`.
///
/// Derives the session transport keys and `param_key`, generates a fresh
/// 32-byte session seed sealed under `param_key`, and ships the host
/// confirmation `fin` with it, encrypted under the transport keys. On
/// success the transport is installed for the session's later commands.
///
/// Consumes the [`PendingHandshake`] so stale Phase-1 state cannot be
/// reused for a second finish against the same session slot.
///
/// # Errors
///
/// Propagates DDI failures from the round-trip (including a `fin`
/// rejection by the FW) and [`HsmError::InternalError`] for crypto
/// failures. The reserved slot is released on failure.
fn open_session_ex_finish(
    partition: &HsmPartition,
    pending: PendingHandshake,
) -> HsmResult<OpenSessionExResult> {
    let mut seed = Zeroizing::new([0u8; SESSION_SEED_LEN]);
    Rng::rand_bytes(seed.as_mut_slice()).map_err(|_| HsmError::InternalError)?;
    finish_session_ex(partition, pending, seed, &[])
}

fn finish_session_ex(
    partition: &HsmPartition,
    pending: PendingHandshake,
    seed: Zeroizing<[u8; SESSION_SEED_LEN]>,
    recovery: &[u8],
) -> HsmResult<OpenSessionExResult> {
    let inner = partition.inner().read();
    let dev = inner.dev();
    let session_id = pending.session_id;
    let finish = || -> HsmResult<(SessionTransport, OpenSessionExResult)> {
        let handshake = &pending.handshake;
        let transport = handshake.transport()?;
        let param_key = handshake.param_key()?;
        let seed_envelope: [u8; SEED_ENVELOPE_LEN] = seal_seed_envelope(&param_key, &*seed)?
            .as_slice()
            .try_into()
            .map_err(|_| HsmError::InternalError)?;
        let req = TborSessionOpenFinishReq {
            session_id,
            mac_fin: handshake.fin()?,
            seed_envelope,
            bmk_session: recovery.to_vec(),
        };
        let resp =
            dev.exec_op_tbor_sealed(pending.api_rev, session_id, &transport, &req, &mut [])?;
        Ok((
            transport,
            OpenSessionExResult {
                session_id,
                psk_id: pending.psk_id,
                suite: pending.suite,
                param_key,
                bmk_session: Zeroizing::new(resp.bmk_session),
                seed,
                ddi_cookie: None,
            },
        ))
    };
    match finish() {
        Ok((transport, result)) => {
            dev.set_session_transport(session_id, transport);
            Ok(result)
        }
        Err(err) => {
            // Release the reserved slot; the error is the finish failure.
            if recovery.is_empty() {
                let _ = dev.flush_session(session_id);
            }
            Err(err)
        }
    }
}

/// Recover a logical TBOR session using the same establishment pipeline as open.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reopen_session_ex(
    partition: &HsmPartition,
    rev: HsmApiRev,
    root: &[u8; 48],
    psk_id: u8,
    psk: Option<&[u8; crate::PSK_LEN]>,
    suite: HsmSessionSuite,
    id: u16,
    seed: &[u8; SESSION_SEED_LEN],
    bmk: &[u8],
) -> HsmResult<OpenSessionExResult> {
    require_tbor_rev(rev)?;
    let pending = establish_session_ex_init(partition, rev, root, psk_id, psk, suite, id)?;
    finish_session_ex(partition, pending, Zeroizing::new(*seed), bmk)
}

/// Issue `PskChange` (opcode `0x06`) on the active session.
///
/// Seals `new_psk` under the session `param_key` (AAD-bound to the
/// session id via [`build_psk_change_aad`]) and ships it as the
/// `psk_envelope`. The firmware rotates the PSK slot implied by the
/// session role (CO session → CO slot, CU session → CU slot); the
/// request carries no slot-selection field.
///
/// Successful rotation rebinds the caller to the new credential without
/// reopening. Each logical session allows one successful change.
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
    rev: HsmApiRev,
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
            .exec_op_tbor(rev, &req, None, cookie)
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
/// A dedicated renegotiation response permits plaintext stale-slot cleanup;
/// authentication failures never trigger that fallback.
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
    rev: HsmApiRev,
    session_id: u16,
    ddi_cookie: &parking_lot::Mutex<Option<u64>>,
) -> HsmResult<()> {
    let inner = partition.inner().read();
    let dev = inner.dev();

    let req = TborSessionCloseReq { session_id };
    let result = with_explicit_cookie(ddi_cookie, |cookie| {
        dev.exec_op_tbor(rev, &req, None, cookie)
            .map_err(HsmError::from)
            .map(|_| ())
    });
    let result = if result == Err(HsmError::SessionNeedsRenegotiation) {
        with_explicit_cookie(ddi_cookie, |cookie| {
            dev.exec_op_tbor(rev, &TborSessionClosePlainReq { session_id }, None, cookie)
                .map_err(HsmError::from)
                .map(|_| ())
        })
    } else {
        result
    };
    if dev.remove_session_transport(session_id) && result.is_err() {
        // Release the slot of an encrypted session the close left open.
        let _ = dev.flush_session(session_id);
    }
    result
}
