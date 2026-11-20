// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR session-establishment crypto.
//!
//! Pure helpers implementing the host side of the signed-transcript KEM
//! session handshake:
//!
//! 1. [`SessionInitiator::generate`] makes the per-handshake ephemeral
//!    for the chosen [`SessionSuite`]; its [`pk_init`](SessionInitiator::pk_init)
//!    travels in `SessionOpenInit`.
//! 2. [`SessionInitiator::complete`] takes the HSM's `enc` and `sig`,
//!    verifies `sig` over the transcript hash `T1` with the partition
//!    identity key, recovers the KEM shared secret `Z`, and derives the
//!    handshake secret
//!    `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v1", Z ‖ PSK), "tsra-session-hs-v1" ‖ T1, 48)`.
//! 3. The resulting [`SessionHandshake`] produces the `SessionOpenFinish`
//!    confirmation [`fin`](SessionHandshake::fin), the per-session
//!    [`param_key`](SessionHandshake::param_key) and the
//!    [`SessionTransport`] that encrypts every in-session message.
//!
//! The handshake conforms to the **wire protocol** (shared constants
//! and labels live in [`tsra_ddi_tbor_types`]); it does not share code
//! with any firmware backend. Conformance is checked by the in-crate
//! tests, which play the device side with independent primitives, and
//! by interop against a live backend.
//!
//! This crate is the single host-side source of truth, consumed by
//! `tsra_api`. Callers map [`SessionExCryptoError`] onto their own error
//! domain at the boundary.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use tsra_crypto::aead_envelope::*;
use tsra_crypto::*;
use tsra_ddi_tbor_types::*;
use zeroize::Zeroizing;

/// Result alias for the session-establishment crypto helpers.
///
/// Distinctly named (not `Result`) so a glob import of this crate
/// cannot shadow the standard `Result` at call sites.
pub type SessionExCryptoResult<T> = core::result::Result<T, SessionExCryptoError>;

/// P-384 coordinate length in bytes.
const P384_COORD_LEN: usize = 48;

/// HMAC-SHA-384 output length in bytes.
const MAC_LEN: usize = 48;

/// AES block size; a sealed Uno frame's plaintext is a multiple of it.
pub const SEALED_BLOCK_LEN: usize = 16;

/// Length of the `iv ‖ tag` trailer of a sealed Uno frame.
pub const SEALED_TRAILER_LEN: usize = SESSION_TRANSPORT_IV_LEN + SESSION_TRANSPORT_TAG_LEN;

/// Length of the sealed Uno frame of a `msg_len`-byte message.
pub const fn sealed_frame_len(msg_len: usize) -> usize {
    (msg_len + 1).next_multiple_of(SEALED_BLOCK_LEN) + SEALED_TRAILER_LEN
}

/// Errors returned by the session-establishment crypto helpers.
///
/// Deliberately coarse and backend-agnostic; consumers map these onto
/// their own error domain at the call boundary.
#[derive(Debug, thiserror::Error)]
pub enum SessionExCryptoError {
    /// A cryptographic primitive (key import, KEM, HMAC, HKDF, AEAD,
    /// RNG, …) failed.
    #[error("session handshake crypto operation failed")]
    Crypto,
    /// Malformed input (e.g. a wrongly sized/encoded public key or an
    /// unknown PSK id or suite).
    #[error("malformed input for session handshake crypto")]
    InvalidInput,
    /// An authentication check failed: the transcript signature, or the
    /// tag or padding of a transport message.
    #[error("session authentication failed")]
    MacMismatch,
}

/// Key-establishment suite of a session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSuite {
    /// Ephemeral ECDH P-384 ([`SESSION_SUITE_ECDH_P384_ECDSA_P384`]).
    EcdhP384,
}

impl SessionSuite {
    /// Wire `suite_id`.
    pub const fn id(self) -> u8 {
        match self {
            Self::EcdhP384 => SESSION_SUITE_ECDH_P384_ECDSA_P384,
        }
    }

    /// Length of this suite's `enc`.
    pub const fn enc_len(self) -> usize {
        match self {
            Self::EcdhP384 => SESSION_P384_SEC1_LEN,
        }
    }
}

/// Decode a 97-byte SEC1 uncompressed P-384 point into a typed
/// [`EccPublicKey`].
pub fn ec_pub_from_sec1(sec1: &[u8]) -> SessionExCryptoResult<EccPublicKey> {
    if sec1.len() != SESSION_P384_SEC1_LEN || sec1[0] != 0x04 {
        return Err(SessionExCryptoError::InvalidInput);
    }
    let x_be = &sec1[1..1 + P384_COORD_LEN];
    let y_be = &sec1[1 + P384_COORD_LEN..];
    EccPublicKey::from_coordinates(EccCurve::P384, x_be, y_be)
        .map_err(|_| SessionExCryptoError::InvalidInput)
}

/// Encode a P-384 public key as SEC1 uncompressed
/// (`0x04 ‖ X_be ‖ Y_be`, 97 B).
pub fn ec_pub_to_sec1(pk: &EccPublicKey) -> SessionExCryptoResult<[u8; SESSION_P384_SEC1_LEN]> {
    let (x_be, y_be) = pk.coord_vec().map_err(|_| SessionExCryptoError::Crypto)?;
    if x_be.len() != P384_COORD_LEN || y_be.len() != P384_COORD_LEN {
        return Err(SessionExCryptoError::InvalidInput);
    }
    let mut out = [0u8; SESSION_P384_SEC1_LEN];
    out[0] = 0x04;
    out[1..1 + P384_COORD_LEN].copy_from_slice(&x_be);
    out[1 + P384_COORD_LEN..].copy_from_slice(&y_be);
    Ok(out)
}

/// Canonical default PSK for the given `psk_id` (`0` = CO,
/// `1` = CU) on a partition that has not been rotated.
pub fn default_psk(psk_id: u8) -> SessionExCryptoResult<&'static [u8; PSK_LEN]> {
    match psk_id {
        0 => Ok(&DEFAULT_PSK_CO),
        1 => Ok(&DEFAULT_PSK_CU),
        _ => Err(SessionExCryptoError::InvalidInput),
    }
}

/// Big-endian 16-bit length prefix.
fn len16(len: usize) -> SessionExCryptoResult<[u8; 2]> {
    u16::try_from(len)
        .map(u16::to_be_bytes)
        .map_err(|_| SessionExCryptoError::InvalidInput)
}

/// Handshake transcript hash
/// `T1 = SHA-384("TSRA-SESSION-v1" ‖ BE16(api_major) ‖ BE16(api_minor)
/// ‖ suite_id ‖ psk_id ‖ session_type
/// ‖ pk_hsm ‖ len16 ‖ pk_init ‖ len16 ‖ enc)`, where `pk_hsm` is the
/// partition identity key as a SEC1 point and lengths are big-endian.
pub fn transcript_hash(
    api_rev: (u16, u16),
    suite_id: u8,
    psk_id: u8,
    session_type: u8,
    pk_hsm_sec1: &[u8],
    pk_init: &[u8],
    enc: &[u8],
) -> SessionExCryptoResult<[u8; SESSION_HS_LEN]> {
    transcript_hash_for_reopen(
        api_rev,
        suite_id,
        psk_id,
        session_type,
        pk_hsm_sec1,
        pk_init,
        enc,
        u16::MAX,
    )
}

/// Hash the shared establishment transcript, binding recovery to its target slot.
#[allow(clippy::too_many_arguments)]
pub fn transcript_hash_for_reopen(
    api_rev: (u16, u16),
    suite_id: u8,
    psk_id: u8,
    session_type: u8,
    pk_hsm_sec1: &[u8],
    pk_init: &[u8],
    enc: &[u8],
    reopen_id: u16,
) -> SessionExCryptoResult<[u8; SESSION_HS_LEN]> {
    let mut data = Vec::with_capacity(
        SESSION_TRANSCRIPT_LABEL.len() + 7 + pk_hsm_sec1.len() + 4 + pk_init.len() + enc.len(),
    );
    data.extend_from_slice(SESSION_TRANSCRIPT_LABEL);
    data.extend_from_slice(&api_rev.0.to_be_bytes());
    data.extend_from_slice(&api_rev.1.to_be_bytes());
    data.extend_from_slice(&[suite_id, psk_id, session_type]);
    data.extend_from_slice(pk_hsm_sec1);
    data.extend_from_slice(&len16(pk_init.len())?);
    data.extend_from_slice(pk_init);
    data.extend_from_slice(&len16(enc.len())?);
    data.extend_from_slice(enc);
    if reopen_id != u16::MAX {
        data.extend_from_slice(b"TSRA-REOPEN-v1:");
        data.extend_from_slice(&reopen_id.to_be_bytes());
    }
    let mut t1 = [0u8; SESSION_HS_LEN];
    HashAlgo::sha384()
        .hash(&data, Some(&mut t1))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    Ok(t1)
}

/// `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v1", Z ‖ PSK),
/// "tsra-session-hs-v1" ‖ T1, 48)`.
pub fn handshake_secret(
    z: &[u8],
    psk: &[u8],
    t1: &[u8; SESSION_HS_LEN],
) -> SessionExCryptoResult<Zeroizing<[u8; SESSION_HS_LEN]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(z.len() + psk.len()));
    ikm.extend_from_slice(z);
    ikm.extend_from_slice(psk);
    let hash = HashAlgo::sha384();
    let ikm_key = GenericSecretKey::from_bytes(&ikm).map_err(|_| SessionExCryptoError::Crypto)?;
    let prk = HkdfAlgo::new(
        HkdfMode::Extract,
        &hash,
        Some(SESSION_TRANSCRIPT_LABEL),
        None,
    )
    .derive(&ikm_key, SESSION_HS_LEN)
    .map_err(|_| SessionExCryptoError::Crypto)?;

    let mut info = Vec::with_capacity(SESSION_HS_LABEL.len() + t1.len());
    info.extend_from_slice(SESSION_HS_LABEL);
    info.extend_from_slice(t1);
    let hs = HkdfAlgo::new(HkdfMode::Expand, &hash, None, Some(&info))
        .derive(&prk, SESSION_HS_LEN)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    let bytes = Zeroizing::new(hs.to_vec().map_err(|_| SessionExCryptoError::Crypto)?);
    let mut out = Zeroizing::new([0u8; SESSION_HS_LEN]);
    if bytes.len() != SESSION_HS_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `HKDF-Expand(prk, label ‖ len_be16, len)` — mirrors the firmware's
/// `hkdf_expand_labeled_into`.
fn hkdf_expand_labeled(
    prk: &[u8],
    label: &[u8],
    out_len: usize,
) -> SessionExCryptoResult<Zeroizing<Vec<u8>>> {
    let mut info = Vec::with_capacity(label.len() + 2);
    info.extend_from_slice(label);
    info.extend_from_slice(&len16(out_len)?);

    let hash = HashAlgo::sha384();
    let algo = HkdfAlgo::new(HkdfMode::Expand, &hash, None, Some(&info));
    let prk_key = GenericSecretKey::from_bytes(prk).map_err(|_| SessionExCryptoError::Crypto)?;
    let derived = algo
        .derive(&prk_key, out_len)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    derived
        .to_vec()
        .map(Zeroizing::new)
        .map_err(|_| SessionExCryptoError::Crypto)
}

/// AES-256 key derived from `hs` under `label`.
fn derive_aes_key(hs: &[u8], label: &[u8]) -> SessionExCryptoResult<AesKey> {
    let bytes = hkdf_expand_labeled(hs, label, SESSION_TRANSPORT_KEY_LEN)?;
    AesKey::from_bytes(&bytes).map_err(|_| SessionExCryptoError::Crypto)
}

/// One direction's transport key and nonce salt.
struct TransportDir {
    key: AesKey,
    salt: [u8; SESSION_TRANSPORT_SALT_LEN],
}

impl TransportDir {
    /// Expand the direction's `key ‖ salt` from `hs` under `label`.
    fn derive(hs: &[u8], label: &[u8]) -> SessionExCryptoResult<Self> {
        let bytes = hkdf_expand_labeled(hs, label, SESSION_TRANSPORT_SECRET_LEN)?;
        let (key, salt) = bytes.split_at(SESSION_TRANSPORT_KEY_LEN);
        Ok(Self {
            key: AesKey::from_bytes(key).map_err(|_| SessionExCryptoError::Crypto)?,
            salt: salt.try_into().map_err(|_| SessionExCryptoError::Crypto)?,
        })
    }

    /// The nonce of message `seq`: `salt ‖ be64(seq)`.
    fn nonce(&self, seq: u64) -> [u8; SESSION_TRANSPORT_IV_LEN] {
        let mut iv = [0u8; SESSION_TRANSPORT_IV_LEN];
        let (salt, ctr) = iv.split_at_mut(SESSION_TRANSPORT_SALT_LEN);
        salt.copy_from_slice(&self.salt);
        ctr.copy_from_slice(&seq.to_be_bytes());
        iv
    }
}

/// Host side of one handshake, between `SessionOpenInit`'s request and
/// its response.
pub struct SessionInitiator {
    api_rev: (u16, u16),
    suite: SessionSuite,
    eph: EccPrivateKey,
    pk_init: Vec<u8>,
    reopen_id: u16,
}

impl SessionInitiator {
    /// Generate a fresh ephemeral for `suite`.
    pub fn generate(suite: SessionSuite, api_rev: (u16, u16)) -> SessionExCryptoResult<Self> {
        match suite {
            SessionSuite::EcdhP384 => {
                let mut scalar = Zeroizing::new([0u8; P384_COORD_LEN]);
                let sk = loop {
                    Rng::rand_bytes(scalar.as_mut_slice())
                        .map_err(|_| SessionExCryptoError::Crypto)?;
                    if let Ok(sk) = EccPrivateKey::from_scalar(EccCurve::P384, scalar.as_slice()) {
                        break sk;
                    }
                };
                let pk = sk.public_key().map_err(|_| SessionExCryptoError::Crypto)?;
                let pk_init = ec_pub_to_sec1(&pk)?.to_vec();
                Ok(Self {
                    api_rev,
                    suite,
                    eph: sk,
                    pk_init,
                    reopen_id: u16::MAX,
                })
            }
        }
    }

    /// The suite this handshake runs.
    pub fn suite(&self) -> SessionSuite {
        self.suite
    }

    /// The wire `pk_init`.
    pub fn pk_init(&self) -> &[u8] {
        &self.pk_init
    }

    /// Bind this fresh handshake to recovery of an existing logical slot.
    pub fn for_reopen(mut self, session_id: u16) -> Self {
        self.reopen_id = session_id;
        self
    }

    /// Complete the handshake from the `SessionOpenInit` response.
    ///
    /// Verifies `sig` over `T1` with the partition identity key `pk_hsm`,
    /// recovers `Z` from `enc`, and derives `hs` with `psk`.
    ///
    /// # Errors
    ///
    /// [`SessionExCryptoError::InvalidInput`] if `enc` or `sig` is
    /// malformed, [`SessionExCryptoError::MacMismatch`] if `sig` does not
    /// verify, [`SessionExCryptoError::Crypto`] if a primitive fails.
    pub fn complete(
        &self,
        psk_id: u8,
        session_type: u8,
        pk_hsm: &EccPublicKey,
        psk: &[u8],
        enc: &[u8],
        sig: &[u8],
    ) -> SessionExCryptoResult<SessionHandshake> {
        if enc.len() != self.suite.enc_len() || sig.len() != SIG_LEN {
            return Err(SessionExCryptoError::InvalidInput);
        }
        let pk_hsm_sec1 = ec_pub_to_sec1(pk_hsm)?;
        let t1 = transcript_hash_for_reopen(
            self.api_rev,
            self.suite.id(),
            psk_id,
            session_type,
            &pk_hsm_sec1,
            &self.pk_init,
            enc,
            self.reopen_id,
        )?;
        let mut verifier = EccAlgo::default();
        if !verifier.verify(pk_hsm, &t1, sig).unwrap_or(false) {
            return Err(SessionExCryptoError::MacMismatch);
        }

        let z = self.shared_secret(enc)?;
        let hs = handshake_secret(&z, psk, &t1)?;
        Ok(SessionHandshake { hs, t1 })
    }

    /// KEM shared secret `Z` for `enc`.
    fn shared_secret(&self, enc: &[u8]) -> SessionExCryptoResult<Zeroizing<Vec<u8>>> {
        let peer = ec_pub_from_sec1(enc)?;
        EcdhAlgo::new(&peer)
            .derive(&self.eph, P384_COORD_LEN)
            .and_then(|z| z.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| SessionExCryptoError::Crypto)
    }
}

/// Outcome of a verified handshake: the handshake secret `hs` and
/// transcript hash `T1`.
pub struct SessionHandshake {
    hs: Zeroizing<[u8; SESSION_HS_LEN]>,
    t1: [u8; SESSION_HS_LEN],
}

impl SessionHandshake {
    /// Build from a known `hs` and `T1`.
    pub fn from_parts(hs: [u8; SESSION_HS_LEN], t1: [u8; SESSION_HS_LEN]) -> Self {
        Self {
            hs: Zeroizing::new(hs),
            t1,
        }
    }

    /// The transcript hash `T1`.
    pub fn transcript_hash(&self) -> &[u8; SESSION_HS_LEN] {
        &self.t1
    }

    /// The host confirmation for `SessionOpenFinish`:
    /// `fin = HMAC-SHA-384(HKDF-Expand-Labeled(hs, "tsra-session-host-fin-v1", 48), T1)`.
    pub fn fin(&self) -> SessionExCryptoResult<[u8; MAC_FIN_LEN]> {
        let fin_key = hkdf_expand_labeled(self.hs.as_slice(), SESSION_HOST_FIN_LABEL, MAC_LEN)?;
        let key = HmacKey::from_bytes(&fin_key).map_err(|_| SessionExCryptoError::Crypto)?;
        let mut algo = HmacAlgo::new(HashAlgo::sha384());
        let mut tag = [0u8; MAC_FIN_LEN];
        algo.sign(&key, &self.t1, Some(&mut tag))
            .map_err(|_| SessionExCryptoError::Crypto)?;
        Ok(tag)
    }

    /// The per-session `param_key` (AES-256) that seals the
    /// `seed_envelope` and in-session parameter envelopes.
    pub fn param_key(&self) -> SessionExCryptoResult<AesKey> {
        derive_aes_key(self.hs.as_slice(), SESSION_PARAM_KEY_LABEL)
    }

    /// The session's transport keys.
    pub fn transport(&self) -> SessionExCryptoResult<SessionTransport> {
        SessionTransport::derive(self.hs.as_slice())
    }
}

/// Authenticate the exact masked key and report data for a KeyReport request.
pub fn seal_key_report_auth(
    param_key: &AesKey,
    request: &TborKeyReportReq,
) -> SessionExCryptoResult<Vec<u8>> {
    let mut data = Vec::with_capacity(request.masked_key.len() + KEY_REPORT_DATA_LEN);
    data.extend_from_slice(&request.masked_key);
    data.extend_from_slice(&request.report_data);
    let mut digest = [0u8; 48];
    HashAlgo::sha384()
        .hash(&data, Some(&mut digest))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    let aad = build_key_report_auth_aad(request.session_id);
    let iv =
        Rng::rand_vec(AeadAlg::AesGcm256.iv_len()).map_err(|_| SessionExCryptoError::Crypto)?;
    let mut envelope = vec![0u8; KEY_REPORT_AUTH_ENVELOPE_LEN];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        &aad,
        &digest,
        Some(&mut envelope),
    )
    .map_err(|_| SessionExCryptoError::Crypto)?;
    if written != envelope.len() {
        return Err(SessionExCryptoError::Crypto);
    }
    Ok(envelope)
}

/// Seal a 32-byte `seed` under `param_key` as a no-AAD AEAD-GCM
/// envelope. Returns the exact `SEED_ENVELOPE_LEN`-byte wire blob that
/// occupies the `seed_envelope` field of `TborSessionOpenFinishReq`.
pub fn seal_seed_envelope(param_key: &AesKey, seed: &[u8]) -> SessionExCryptoResult<Vec<u8>> {
    // Check seed length
    if seed.len() != SESSION_SEED_LEN {
        return Err(SessionExCryptoError::InvalidInput);
    }

    let iv =
        Rng::rand_vec(AeadAlg::AesGcm256.iv_len()).map_err(|_| SessionExCryptoError::Crypto)?;
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, &[], seed, None)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    // The framed envelope is a fixed-size wire blob; reject any sizing
    // that does not match the `SEED_ENVELOPE_LEN` contract here rather
    // than letting a mismatch surface as a late `try_into` failure in
    // the caller.
    if total != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    let mut envelope = vec![0u8; SEED_ENVELOPE_LEN];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        &[],
        seed,
        Some(&mut envelope),
    )
    .map_err(|_| SessionExCryptoError::Crypto)?;
    if written != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    Ok(envelope)
}

/// AES-GCM IV and tag of one Duo session transport message, carried in
/// the SQE (request) or CQE (response) rather than in the payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionTransportSeal {
    /// Per-message IV: the direction's `salt ‖ be64(seq)`.
    pub iv: [u8; SESSION_TRANSPORT_IV_LEN],

    /// Authentication tag.
    pub tag: [u8; SESSION_TRANSPORT_TAG_LEN],
}

/// Local authentication context for exactly one outstanding request.
///
/// Consumed when opening its response; never reconstructed from a response.
pub struct SessionTransportRequest {
    response_aad: [u8; 32],
}

/// Mirrors the firmware transport AAD: domain(16), request IV(12),
/// session id(2, LE), session control(1), protocol(1: Uno=1, Duo=2).
fn transport_aad(
    iv: &[u8; SESSION_TRANSPORT_IV_LEN],
    session_id: u16,
    control: u8,
    protocol: u8,
    response: bool,
) -> [u8; 32] {
    let mut aad = [0; 32];
    aad[..16].copy_from_slice(if response {
        b"TSRA-RSP-AAD-V1\0"
    } else {
        b"TSRA-REQ-AAD-V1\0"
    });
    aad[16..28].copy_from_slice(iv);
    aad[28..30].copy_from_slice(&session_id.to_le_bytes());
    aad[30] = control;
    aad[31] = protocol;
    aad
}

/// Per-session transport encryption.
///
/// Holds the VM→HSM and HSM→VM AES-256-GCM keys and nonce salts derived
/// from the handshake secret. Every in-session request (including
/// `SessionOpenFinish` and the close) is sealed with one, and its
/// response opened with the other. Implicit 32-byte AAD binds each response
/// to the original request IV and transport context without adding wire bytes.
/// Each direction's nonce is
/// `salt(4) ‖ be64(seq)`, where `seq` counts the sender's messages, so
/// sealing draws no randomness. Requests take the next value of this
/// value's VM→HSM counter, so concurrent senders sharing one session
/// never reuse a nonce.
/// On Duo the IV and tag ride in the SQE/CQE
/// ([`seal_request`](Self::seal_request) /
/// [`open_response`](Self::open_response)); on Uno they trail the
/// block-padded ciphertext in-band ([`seal_frame`](Self::seal_frame) /
/// [`open_frame`](Self::open_frame)). Like the device, the receiver uses
/// the IV it is given, but authenticates the response against the locally
/// retained request context. Responses may complete in any order. This does
/// not prevent the device from executing a replayed request.
/// The keys are zeroized when this value is dropped.
pub struct SessionTransport {
    h2m: TransportDir,
    m2h: TransportDir,
    h2m_seq: AtomicU64,
}

impl SessionTransport {
    /// Derive both directional keys and salts from the handshake secret
    /// `hs`.
    pub fn derive(hs: &[u8]) -> SessionExCryptoResult<Self> {
        Ok(Self {
            h2m: TransportDir::derive(hs, SESSION_TRANSPORT_H2M_LABEL)?,
            m2h: TransportDir::derive(hs, SESSION_TRANSPORT_M2H_LABEL)?,
            h2m_seq: AtomicU64::new(0),
        })
    }

    /// Reserve the next VM→HSM sequence number; fails rather than wrap.
    fn next_h2m_seq(&self) -> SessionExCryptoResult<u64> {
        self.h2m_seq
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |seq| {
                seq.checked_add(1)
            })
            .map_err(|_| SessionExCryptoError::Crypto)
    }

    /// Encrypt a request payload in place with the VM→HSM key under the
    /// next VM→HSM nonce (Duo).
    pub fn seal_request(
        &self,
        session_id: u16,
        buf: &mut [u8],
    ) -> SessionExCryptoResult<(SessionTransportSeal, SessionTransportRequest)> {
        let iv = self.h2m.nonce(self.next_h2m_seq()?);
        let aad = transport_aad(&iv, session_id, 0, 2, false);
        let tag = gcm_encrypt(&self.h2m.key, &iv, &aad, buf)?;
        Ok((
            SessionTransportSeal { iv, tag },
            SessionTransportRequest {
                response_aad: transport_aad(&iv, session_id, 0, 2, true),
            },
        ))
    }

    /// Decrypt a response payload in place with the HSM→VM key (Duo).
    ///
    /// On a tag mismatch `buf` is zeroed and
    /// [`SessionExCryptoError::MacMismatch`] is returned.
    pub fn open_response(
        &self,
        request: SessionTransportRequest,
        sealed: &SessionTransportSeal,
        buf: &mut [u8],
    ) -> SessionExCryptoResult<()> {
        gcm_decrypt(
            &self.m2h.key,
            &sealed.iv,
            &sealed.tag,
            &request.response_aad,
            buf,
        )
    }

    /// Seal a request message into a Uno frame
    /// `ct ‖ iv(12) ‖ tag(16)`, where the plaintext is
    /// `msg ‖ 0^p ‖ p` padded to whole AES blocks and the IV is the next
    /// VM→HSM nonce.
    pub fn seal_frame(
        &self,
        session_id: u16,
        control: SessionControlKind,
        msg: &[u8],
    ) -> SessionExCryptoResult<(Vec<u8>, SessionTransportRequest)> {
        if !matches!(
            control,
            SessionControlKind::InSession | SessionControlKind::Close
        ) {
            return Err(SessionExCryptoError::InvalidInput);
        }
        let frame_len = sealed_frame_len(msg.len());
        let pt_len = frame_len - SEALED_TRAILER_LEN;
        let mut frame = vec![0u8; frame_len];
        let (pt, trailer) = frame.split_at_mut(pt_len);
        pt[..msg.len()].copy_from_slice(msg);
        // `sealed_frame_len` pads by 1..=16 bytes, so this fits in a byte.
        pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
        let iv = self.h2m.nonce(self.next_h2m_seq()?);
        let (iv_out, tag) = trailer.split_at_mut(SESSION_TRANSPORT_IV_LEN);
        iv_out.copy_from_slice(&iv);
        let aad = transport_aad(&iv, session_id, control.into(), 1, false);
        tag.copy_from_slice(&gcm_encrypt(&self.h2m.key, &iv, &aad, pt)?);
        Ok((
            frame,
            SessionTransportRequest {
                response_aad: transport_aad(&iv, session_id, control.into(), 1, true),
            },
        ))
    }

    /// Open a sealed Uno response frame in place with the HSM→VM key,
    /// truncating `frame` to the message.
    ///
    /// # Errors
    ///
    /// [`SessionExCryptoError::MacMismatch`] (with `frame` cleared) if
    /// the frame is malformed, its tag does not verify or its padding is
    /// invalid.
    pub fn open_frame(
        &self,
        request: SessionTransportRequest,
        frame: &mut Vec<u8>,
    ) -> SessionExCryptoResult<()> {
        let Some(ct_len) = frame
            .len()
            .checked_sub(SEALED_TRAILER_LEN)
            .filter(|&n| n != 0 && n % SEALED_BLOCK_LEN == 0)
        else {
            frame.fill(0);
            frame.clear();
            return Err(SessionExCryptoError::MacMismatch);
        };
        let (ct, trailer) = frame.split_at_mut(ct_len);
        let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
        let opened = gcm_decrypt(&self.m2h.key, iv, tag, &request.response_aad, ct)
            .ok()
            .and_then(|()| unpad(ct));
        match opened {
            Some(msg_len) => {
                frame.truncate(msg_len);
                Ok(())
            }
            None => {
                frame.fill(0);
                frame.clear();
                Err(SessionExCryptoError::MacMismatch)
            }
        }
    }
}

/// A Uno sealed frame (see [`SessionTransport::seal_frame`]), sent as the
/// raw payload of an in-session or close TBOR command.
///
/// The opcode travels inside the sealed frame, so the transport only
/// needs the session control kind and id carried here.
pub struct SealedFrameReq {
    /// Session control kind of the sealed command.
    pub session_ctrl: SessionControlKind,
    /// Session the frame is sealed under.
    pub session_id: u16,
    /// The sealed frame.
    pub frame: Vec<u8>,
}

impl TborOpReq for SealedFrameReq {
    // The opcode is inside the sealed frame; the transport never reads it.
    const OPCODE: u8 = 0;
    type OpResp = SealedFrameResp;

    fn get_session_id(&self) -> Option<u16> {
        Some(self.session_id)
    }

    fn session_ctrl(&self) -> SessionControlKind {
        self.session_ctrl
    }

    fn encode_request<'b>(
        &self,
        buf: &'b mut [u8],
        _api_rev: (u16, u16),
    ) -> Result<&'b [u8], codec::EncodeError> {
        let out = buf
            .get_mut(..self.frame.len())
            .ok_or(codec::EncodeError::BufferTooSmall)?;
        out.copy_from_slice(&self.frame);
        Ok(out)
    }
}

/// The sealed response frame of a [`SealedFrameReq`]; open it with
/// [`SessionTransport::open_frame`].
pub struct SealedFrameResp(pub Vec<u8>);

impl TborResp for SealedFrameResp {
    const FIELD_TOC_COUNT: usize = 0;

    fn decode_response(buf: &[u8]) -> Result<Self, codec::DecodeError> {
        Ok(Self(buf.to_vec()))
    }

    fn decode_response_for_api_rev(
        buf: &[u8],
        _api_rev: (u16, u16),
    ) -> Result<Self, codec::DecodeError> {
        // The caller validates the inner header after authenticating the frame.
        Self::decode_response(buf)
    }
}

impl TborRespSessionId for SealedFrameResp {
    fn resp_session_id(&self) -> Option<u16> {
        None
    }
}

/// AES-256-GCM encrypt `buf` in place, returning the tag.
fn gcm_encrypt(
    key: &AesKey,
    iv: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> SessionExCryptoResult<[u8; SESSION_TRANSPORT_TAG_LEN]> {
    let mut algo =
        AesGcmAlgo::for_encrypt(iv, Some(aad)).map_err(|_| SessionExCryptoError::Crypto)?;
    let plaintext = Zeroizing::new(buf.to_vec());
    algo.encrypt(key, &plaintext, Some(buf))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    algo.tag()
        .try_into()
        .map_err(|_| SessionExCryptoError::Crypto)
}

/// AES-256-GCM decrypt `buf` in place; on a tag mismatch
/// `buf` is zeroed.
fn gcm_decrypt(
    key: &AesKey,
    iv: &[u8],
    tag: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> SessionExCryptoResult<()> {
    let mut algo =
        AesGcmAlgo::for_decrypt(iv, tag, Some(aad)).map_err(|_| SessionExCryptoError::Crypto)?;
    let ciphertext = buf.to_vec();
    if algo.decrypt(key, &ciphertext, Some(buf)).is_err() {
        buf.fill(0);
        return Err(SessionExCryptoError::MacMismatch);
    }
    Ok(())
}

/// Message length of the block-padded plaintext `pt`, or `None` if its
/// padding is invalid.
fn unpad(pt: &[u8]) -> Option<usize> {
    let (&pad, body) = pt.split_last()?;
    let pad = usize::from(pad);
    if pad >= SEALED_BLOCK_LEN {
        return None;
    }
    let msg_len = body.len().checked_sub(pad)?;
    body[msg_len..].iter().all(|&b| b == 0).then_some(msg_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HS: [u8; SESSION_HS_LEN] = [0x5a; SESSION_HS_LEN];
    const PSK: [u8; PSK_LEN] = [0x33; PSK_LEN];

    /// The device's key for one direction.
    fn device_key(label: &[u8]) -> AesKey {
        let bytes =
            hkdf_expand_labeled(&HS, label, SESSION_TRANSPORT_SECRET_LEN).expect("test crypto");
        AesKey::from_bytes(&bytes[..SESSION_TRANSPORT_KEY_LEN]).expect("test crypto")
    }

    /// The device's nonce for message `seq` in one direction.
    fn device_nonce(label: &[u8], seq: u64) -> [u8; SESSION_TRANSPORT_IV_LEN] {
        let bytes =
            hkdf_expand_labeled(&HS, label, SESSION_TRANSPORT_SECRET_LEN).expect("test crypto");
        let mut iv = [0u8; SESSION_TRANSPORT_IV_LEN];
        iv[..SESSION_TRANSPORT_SALT_LEN].copy_from_slice(&bytes[SESSION_TRANSPORT_KEY_LEN..]);
        iv[SESSION_TRANSPORT_SALT_LEN..].copy_from_slice(&seq.to_be_bytes());
        iv
    }

    /// The device side of `SessionOpenInit`: encapsulates to `pk_init`,
    /// signs `T1` with `sk_hsm` and derives `hs`, independently of
    /// [`SessionInitiator`]. Returns `(enc, sig, hs)`.
    fn device_open_init(
        suite: SessionSuite,
        sk_hsm: &EccPrivateKey,
        pk_init: &[u8],
        api_rev: (u16, u16),
    ) -> (Vec<u8>, Vec<u8>, Zeroizing<[u8; SESSION_HS_LEN]>) {
        let (enc, z) = match suite {
            SessionSuite::EcdhP384 => {
                let peer = ec_pub_from_sec1(pk_init).expect("test crypto");
                let eph =
                    EccPrivateKey::from_scalar(EccCurve::P384, &[0x42; 48]).expect("test crypto");
                let z = EcdhAlgo::new(&peer)
                    .derive(&eph, 48)
                    .and_then(|z| z.to_vec())
                    .expect("test crypto");
                let enc =
                    ec_pub_to_sec1(&eph.public_key().expect("test crypto")).expect("test crypto");
                (enc.to_vec(), z)
            }
        };
        let pk_hsm =
            ec_pub_to_sec1(&sk_hsm.public_key().expect("test crypto")).expect("test crypto");
        let t1 = transcript_hash(api_rev, suite.id(), 1, 0, &pk_hsm, pk_init, &enc)
            .expect("test crypto");
        let mut sig = vec![0u8; SIG_LEN];
        EccAlgo::default()
            .sign(sk_hsm, &t1, Some(&mut sig))
            .expect("test crypto");
        let hs = handshake_secret(&z, &PSK, &t1).expect("test crypto");
        (enc, sig, hs)
    }

    fn handshake_agrees(suite: SessionSuite, api_rev: (u16, u16)) {
        let sk_hsm = EccPrivateKey::from_scalar(EccCurve::P384, &[0x17; 48]).expect("test crypto");
        let pk_hsm = sk_hsm.public_key().expect("test crypto");
        let init = SessionInitiator::generate(suite, api_rev).expect("test crypto");
        let (enc, sig, hs) = device_open_init(suite, &sk_hsm, init.pk_init(), api_rev);

        let done = init
            .complete(1, 0, &pk_hsm, &PSK, &enc, &sig)
            .expect("handshake");
        assert_eq!(done.hs.as_slice(), hs.as_slice());

        // A wrong PSK yields a different secret; a tampered signature or
        // transcript field is rejected.
        let other = init
            .complete(1, 0, &pk_hsm, &[0u8; PSK_LEN], &enc, &sig)
            .expect("handshake");
        assert_ne!(other.hs.as_slice(), hs.as_slice());
        let mut bad_sig = sig.clone();
        bad_sig[10] ^= 1;
        assert!(matches!(
            init.complete(1, 0, &pk_hsm, &PSK, &enc, &bad_sig),
            Err(SessionExCryptoError::MacMismatch)
        ));
        assert!(matches!(
            init.complete(0, 0, &pk_hsm, &PSK, &enc, &sig),
            Err(SessionExCryptoError::MacMismatch)
        ));
        assert!(matches!(
            init.complete(1, 0, &pk_hsm, &PSK, &enc[1..], &sig),
            Err(SessionExCryptoError::InvalidInput)
        ));
        for changed in [(api_rev.0 ^ 1, api_rev.1), (api_rev.0, api_rev.1 ^ 1)] {
            let (enc, sig, _) = device_open_init(suite, &sk_hsm, init.pk_init(), changed);
            assert!(matches!(
                init.complete(1, 0, &pk_hsm, &PSK, &enc, &sig),
                Err(SessionExCryptoError::MacMismatch)
            ));
        }
    }

    #[test]
    fn ecdh_handshake_agrees_with_device() {
        for api_rev in [(1, 1), (2, 0)] {
            handshake_agrees(SessionSuite::EcdhP384, api_rev);
        }
    }

    #[test]
    fn fin_is_bound_to_transcript() {
        let a = SessionHandshake::from_parts(HS, [1; SESSION_HS_LEN]);
        let b = SessionHandshake::from_parts(HS, [2; SESSION_HS_LEN]);
        assert_ne!(a.fin().expect("fin"), b.fin().expect("fin"));
    }

    #[test]
    fn recovery_transcript_binds_mode_and_target() {
        let hash = |id| {
            transcript_hash_for_reopen((2, 0), 1, 1, 0, &[1; 97], &[2; 97], &[3; 97], id)
                .expect("transcript")
        };
        let fresh = transcript_hash((2, 0), 1, 1, 0, &[1; 97], &[2; 97], &[3; 97])
            .expect("fresh transcript");
        assert_eq!(hash(u16::MAX), fresh);
        assert_ne!(hash(1), fresh);
        assert_ne!(hash(1), hash(2));
    }

    #[test]
    fn transport_interoperates_with_device_keys() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");

        let mut request = *b"tbor secure request";
        let (sealed, context) = transport
            .seal_request(7, &mut request)
            .expect("test crypto");
        assert_ne!(&request, b"tbor secure request");
        assert_eq!(sealed.iv, device_nonce(SESSION_TRANSPORT_H2M_LABEL, 0));
        let mut next = *b"x";
        let (next, _) = transport.seal_request(7, &mut next).expect("test crypto");
        assert_eq!(next.iv, device_nonce(SESSION_TRANSPORT_H2M_LABEL, 1));
        gcm_decrypt(
            &device_key(SESSION_TRANSPORT_H2M_LABEL),
            &sealed.iv,
            &sealed.tag,
            &transport_aad(&sealed.iv, 7, 0, 2, false),
            &mut request,
        )
        .expect("test crypto");
        assert_eq!(&request, b"tbor secure request");

        let mut response = *b"tbor response";
        let iv = [7; SESSION_TRANSPORT_IV_LEN];
        let tag = gcm_encrypt(
            &device_key(SESSION_TRANSPORT_M2H_LABEL),
            &iv,
            &context.response_aad,
            &mut response,
        )
        .expect("test crypto");
        transport
            .open_response(context, &SessionTransportSeal { iv, tag }, &mut response)
            .expect("test crypto");
        assert_eq!(&response, b"tbor response");
    }

    #[test]
    fn open_response_rejects_reflection_and_tampering() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        let mut buf = *b"payload";
        let (sealed, context) = transport.seal_request(7, &mut buf).expect("test crypto");

        // A reflected request is under the VM→HSM key.
        let mut reflected = buf;
        assert!(matches!(
            transport.open_response(context, &sealed, &mut reflected),
            Err(SessionExCryptoError::MacMismatch)
        ));
        assert_eq!(reflected, [0; 7]);

        let (mut tampered, context) = transport.seal_request(7, &mut buf).expect("test crypto");
        tampered.tag[0] ^= 1;
        assert!(
            transport
                .open_response(context, &tampered, &mut buf)
                .is_err()
        );
    }

    /// Seal `msg` as the device would: `ct ‖ iv ‖ tag` under the HSM→VM
    /// key and nonce `salt ‖ seq`.
    fn device_seal_frame(msg: &[u8], seq: u64, context: &SessionTransportRequest) -> Vec<u8> {
        let pt_len = sealed_frame_len(msg.len()) - SEALED_TRAILER_LEN;
        let mut frame = msg.to_vec();
        frame.resize(pt_len, 0);
        frame[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
        let iv = device_nonce(SESSION_TRANSPORT_M2H_LABEL, seq);
        let tag = gcm_encrypt(
            &device_key(SESSION_TRANSPORT_M2H_LABEL),
            &iv,
            &context.response_aad,
            &mut frame,
        )
        .expect("test crypto");
        frame.extend_from_slice(&iv);
        frame.extend_from_slice(&tag);
        frame
    }

    #[test]
    fn frames_interoperate_with_device_keys() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        for (seq, len) in [0, 1, 15, 16, 17, 100].into_iter().enumerate() {
            let seq = seq as u64;
            let msg: Vec<u8> = (0..len as u8).collect();

            let (frame, context) = transport
                .seal_frame(7, SessionControlKind::InSession, &msg)
                .expect("test crypto");
            assert_eq!(frame.len(), sealed_frame_len(len));
            let ct_len = frame.len() - SEALED_TRAILER_LEN;
            assert_eq!(ct_len % SEALED_BLOCK_LEN, 0);
            let (ct, trailer) = frame.split_at(ct_len);
            let mut pt = ct.to_vec();
            let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
            assert_eq!(iv, device_nonce(SESSION_TRANSPORT_H2M_LABEL, seq));
            let aad = transport_aad(&iv.try_into().expect("IV"), 7, 3, 1, false);
            gcm_decrypt(
                &device_key(SESSION_TRANSPORT_H2M_LABEL),
                iv,
                tag,
                &aad,
                &mut pt,
            )
            .expect("test crypto");
            assert_eq!(unpad(&pt), Some(len));
            assert_eq!(&pt[..len], msg.as_slice());

            let mut frame = device_seal_frame(&msg, seq * 3, &context);
            transport
                .open_frame(context, &mut frame)
                .expect("test crypto");
            assert_eq!(frame, msg);
        }
    }

    #[test]
    fn open_frame_rejects_bad_frames() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        for defect in 0..4 {
            let (reflected, context) = transport
                .seal_frame(7, SessionControlKind::InSession, b"response")
                .expect("test crypto");
            let mut frame = device_seal_frame(b"response", defect, &context);
            match defect {
                0 => frame[0] ^= 1,
                1 => {
                    let index = frame.len() - SEALED_TRAILER_LEN + SESSION_TRANSPORT_IV_LEN - 1;
                    frame[index] ^= 1;
                }
                2 => {
                    frame.pop();
                }
                _ => frame = reflected,
            }
            assert!(matches!(
                transport.open_frame(context, &mut frame),
                Err(SessionExCryptoError::MacMismatch)
            ));
            assert!(frame.is_empty());
        }
    }

    #[test]
    fn duo_responses_complete_out_of_order_but_cannot_be_substituted() {
        let transport = SessionTransport::derive(&HS).expect("transport");
        let (_, first) = transport.seal_request(7, &mut [1; 16]).expect("first");
        let (_, second) = transport.seal_request(7, &mut [1; 16]).expect("second");
        let seal_response = |context: &SessionTransportRequest, seq| {
            let mut response = [0x42; 16];
            let iv = device_nonce(SESSION_TRANSPORT_M2H_LABEL, seq);
            let tag = gcm_encrypt(
                &device_key(SESSION_TRANSPORT_M2H_LABEL),
                &iv,
                &context.response_aad,
                &mut response,
            )
            .expect("device seal");
            (SessionTransportSeal { iv, tag }, response)
        };
        let (first_seal, mut first_response) = seal_response(&first, 10);
        let (second_seal, mut second_response) = seal_response(&second, 11);
        transport
            .open_response(second, &second_seal, &mut second_response)
            .expect("second completes first");
        transport
            .open_response(first, &first_seal, &mut first_response)
            .expect("first completes second");
        assert_eq!(first_response, [0x42; 16]);
        assert_eq!(second_response, first_response);

        let (_, old) = transport.seal_request(7, &mut [1; 16]).expect("old");
        let (old_seal, mut old_response) = seal_response(&old, 12);
        let (_, fresh) = transport.seal_request(7, &mut [1; 16]).expect("fresh");
        assert!(
            transport
                .open_response(fresh, &old_seal, &mut old_response)
                .is_err()
        );
        assert_eq!(old_response, [0; 16]);
    }

    #[test]
    fn uno_responses_complete_out_of_order_but_cannot_be_substituted() {
        let transport = SessionTransport::derive(&HS).expect("transport");
        let (_, first) = transport
            .seal_frame(7, SessionControlKind::InSession, b"request")
            .expect("first");
        let (_, second) = transport
            .seal_frame(7, SessionControlKind::InSession, b"request")
            .expect("second");
        let mut first_response = device_seal_frame(b"response", 10, &first);
        let mut second_response = device_seal_frame(b"response", 11, &second);
        let mut replayed = first_response.clone();
        transport
            .open_frame(second, &mut second_response)
            .expect("second completes first");
        transport
            .open_frame(first, &mut first_response)
            .expect("first completes second");
        assert_eq!(first_response, b"response");
        assert_eq!(second_response, first_response);
        let (_, fresh) = transport
            .seal_frame(7, SessionControlKind::InSession, b"request")
            .expect("fresh");
        assert!(transport.open_frame(fresh, &mut replayed).is_err());
        assert!(replayed.is_empty());
    }

    #[test]
    fn duo_response_tampering_is_rejected_and_wiped() {
        let transport = SessionTransport::derive(&HS).expect("transport");
        for field in 0..3 {
            let (_, context) = transport.seal_request(7, &mut [1; 16]).expect("request");
            let mut response = [0x42; 16];
            let iv = device_nonce(SESSION_TRANSPORT_M2H_LABEL, field);
            let tag = gcm_encrypt(
                &device_key(SESSION_TRANSPORT_M2H_LABEL),
                &iv,
                &context.response_aad,
                &mut response,
            )
            .expect("device response");
            let mut sealed = SessionTransportSeal { iv, tag };
            match field {
                0 => response[0] ^= 1,
                1 => sealed.iv[0] ^= 1,
                _ => sealed.tag[0] ^= 1,
            }
            assert!(
                transport
                    .open_response(context, &sealed, &mut response)
                    .is_err()
            );
            assert_eq!(response, [0; 16]);
        }
    }

    #[test]
    fn request_aad_authenticates_metadata_and_direction() {
        let transport = SessionTransport::derive(&HS).expect("transport");
        let mut request = [1; 16];
        let (sealed, _) = transport.seal_request(7, &mut request).expect("seal");
        for aad in [
            transport_aad(&sealed.iv, 8, 0, 2, false),
            transport_aad(&sealed.iv, 7, 3, 2, false),
            transport_aad(&sealed.iv, 7, 0, 1, false),
            transport_aad(&sealed.iv, 7, 0, 2, true),
        ] {
            let mut altered = request;
            assert!(
                gcm_decrypt(
                    &device_key(SESSION_TRANSPORT_H2M_LABEL),
                    &sealed.iv,
                    &sealed.tag,
                    &aad,
                    &mut altered
                )
                .is_err()
            );
            assert_eq!(altered, [0; 16]);
        }
    }

    #[test]
    fn unpad_checks_padding() {
        let mut pt = [0u8; 16];
        pt[..5].copy_from_slice(b"hello");
        pt[15] = 10;
        assert_eq!(unpad(&pt), Some(5));
        pt[15] = 11;
        assert_eq!(unpad(&pt), None);
        pt[15] = 16;
        assert_eq!(unpad(&pt), None);
        pt[15] = 10;
        pt[14] = 1;
        assert_eq!(unpad(&pt), None);
    }
}
