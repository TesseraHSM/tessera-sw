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
//!    `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v2", Z ‖ PSK), "tsra-session-hs-v2" ‖ T1, 48)`.
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
    /// ML-KEM-1024 ([`SESSION_SUITE_MLKEM1024_ECDSA_P384`]).
    MlKem1024,
}

impl SessionSuite {
    /// Wire `suite_id`.
    pub const fn id(self) -> u8 {
        match self {
            Self::EcdhP384 => SESSION_SUITE_ECDH_P384_ECDSA_P384,
            Self::MlKem1024 => SESSION_SUITE_MLKEM1024_ECDSA_P384,
        }
    }

    /// Length of this suite's `enc`.
    pub const fn enc_len(self) -> usize {
        match self {
            Self::EcdhP384 => SESSION_P384_SEC1_LEN,
            Self::MlKem1024 => SESSION_MLKEM1024_CT_LEN,
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
/// `T1 = SHA-384("TSRA-SESSION-v2" ‖ suite_id ‖ psk_id ‖ session_type
/// ‖ pk_hsm ‖ len16 ‖ pk_init ‖ len16 ‖ enc)`, where `pk_hsm` is the
/// partition identity key as a SEC1 point and lengths are big-endian.
pub fn transcript_hash(
    suite_id: u8,
    psk_id: u8,
    session_type: u8,
    pk_hsm_sec1: &[u8],
    pk_init: &[u8],
    enc: &[u8],
) -> SessionExCryptoResult<[u8; SESSION_HS_LEN]> {
    let mut data = Vec::with_capacity(
        SESSION_TRANSCRIPT_LABEL.len() + 3 + pk_hsm_sec1.len() + 4 + pk_init.len() + enc.len(),
    );
    data.extend_from_slice(SESSION_TRANSCRIPT_LABEL);
    data.extend_from_slice(&[suite_id, psk_id, session_type]);
    data.extend_from_slice(pk_hsm_sec1);
    data.extend_from_slice(&len16(pk_init.len())?);
    data.extend_from_slice(pk_init);
    data.extend_from_slice(&len16(enc.len())?);
    data.extend_from_slice(enc);
    let mut t1 = [0u8; SESSION_HS_LEN];
    HashAlgo::sha384()
        .hash(&data, Some(&mut t1))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    Ok(t1)
}

/// `hs = HKDF-Expand(HKDF-Extract("TSRA-SESSION-v2", Z ‖ PSK),
/// "tsra-session-hs-v2" ‖ T1, 48)`.
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

/// The per-handshake ephemeral key.
enum Ephemeral {
    Ecdh(EccPrivateKey),
    MlKem(MlKemPrivateKey),
}

/// Host side of one handshake, between `SessionOpenInit`'s request and
/// its response.
pub struct SessionInitiator {
    suite: SessionSuite,
    eph: Ephemeral,
    pk_init: Vec<u8>,
}

impl SessionInitiator {
    /// Generate a fresh ephemeral for `suite`.
    pub fn generate(suite: SessionSuite) -> SessionExCryptoResult<Self> {
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
                    suite,
                    eph: Ephemeral::Ecdh(sk),
                    pk_init,
                })
            }
            SessionSuite::MlKem1024 => {
                let mut seed = Zeroizing::new([0u8; MLKEM_SEED_LEN]);
                Rng::rand_bytes(seed.as_mut_slice()).map_err(|_| SessionExCryptoError::Crypto)?;
                let sk = MlKemPrivateKey::from_seed(MlKemVariant::MlKem1024, seed.as_slice())
                    .map_err(|_| SessionExCryptoError::Crypto)?;
                let pk_init = sk
                    .public_key()
                    .and_then(|pk| pk.to_vec())
                    .map_err(|_| SessionExCryptoError::Crypto)?;
                if pk_init.len() != SESSION_MLKEM1024_PK_LEN {
                    return Err(SessionExCryptoError::Crypto);
                }
                Ok(Self {
                    suite,
                    eph: Ephemeral::MlKem(sk),
                    pk_init,
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
        let t1 = transcript_hash(
            self.suite.id(),
            psk_id,
            session_type,
            &pk_hsm_sec1,
            &self.pk_init,
            enc,
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
        match &self.eph {
            Ephemeral::Ecdh(sk) => {
                let peer = ec_pub_from_sec1(enc)?;
                EcdhAlgo::new(&peer)
                    .derive(sk, P384_COORD_LEN)
                    .and_then(|z| z.to_vec())
                    .map(Zeroizing::new)
                    .map_err(|_| SessionExCryptoError::Crypto)
            }
            Ephemeral::MlKem(sk) => {
                let mut z = Zeroizing::new(vec![0u8; MLKEM_SHARED_SECRET_LEN]);
                MlKemAlgo::new()
                    .decapsulate(sk, enc, Some(z.as_mut_slice()))
                    .map_err(|_| SessionExCryptoError::Crypto)?;
                Ok(z)
            }
        }
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
    /// `fin = HMAC-SHA-384(HKDF-Expand-Labeled(hs, "tsra-session-host-fin-v2", 48), T1)`.
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
    /// Random per-message IV.
    pub iv: [u8; SESSION_TRANSPORT_IV_LEN],

    /// Authentication tag.
    pub tag: [u8; SESSION_TRANSPORT_TAG_LEN],
}

/// Per-session transport encryption.
///
/// Holds the VM→HSM and HSM→VM AES-256-GCM keys derived from the
/// handshake secret. Every in-session request (including
/// `SessionOpenFinish` and the close) is sealed with one, and its
/// response opened with the other, under a random 96-bit IV and no AAD.
/// On Duo the IV and tag ride in the SQE/CQE
/// ([`seal_request`](Self::seal_request) /
/// [`open_response`](Self::open_response)); on Uno they trail the
/// block-padded ciphertext in-band ([`seal_frame`](Self::seal_frame) /
/// [`open_frame`](Self::open_frame)). The keys are zeroized when this
/// value is dropped.
pub struct SessionTransport {
    h2m: AesKey,
    m2h: AesKey,
}

impl SessionTransport {
    /// Derive both directional keys from the handshake secret `hs`.
    pub fn derive(hs: &[u8]) -> SessionExCryptoResult<Self> {
        Ok(Self {
            h2m: derive_aes_key(hs, SESSION_TRANSPORT_H2M_LABEL)?,
            m2h: derive_aes_key(hs, SESSION_TRANSPORT_M2H_LABEL)?,
        })
    }

    /// Encrypt a request payload in place with the VM→HSM key under a
    /// fresh random IV (Duo).
    pub fn seal_request(&self, buf: &mut [u8]) -> SessionExCryptoResult<SessionTransportSeal> {
        let mut sealed = SessionTransportSeal::default();
        Rng::rand_bytes(&mut sealed.iv).map_err(|_| SessionExCryptoError::Crypto)?;
        sealed.tag = gcm_encrypt(&self.h2m, &sealed.iv, buf)?;
        Ok(sealed)
    }

    /// Decrypt a response payload in place with the HSM→VM key (Duo).
    ///
    /// On a tag mismatch `buf` is zeroed and
    /// [`SessionExCryptoError::MacMismatch`] is returned.
    pub fn open_response(
        &self,
        sealed: &SessionTransportSeal,
        buf: &mut [u8],
    ) -> SessionExCryptoResult<()> {
        gcm_decrypt(&self.m2h, &sealed.iv, &sealed.tag, buf)
    }

    /// Seal a request message into a Uno frame
    /// `ct ‖ iv(12) ‖ tag(16)`, where the plaintext is
    /// `msg ‖ 0^p ‖ p` padded to whole AES blocks.
    pub fn seal_frame(&self, msg: &[u8]) -> SessionExCryptoResult<Vec<u8>> {
        let frame_len = sealed_frame_len(msg.len());
        let pt_len = frame_len - SEALED_TRAILER_LEN;
        let mut frame = vec![0u8; frame_len];
        let (pt, trailer) = frame.split_at_mut(pt_len);
        pt[..msg.len()].copy_from_slice(msg);
        // `sealed_frame_len` pads by 1..=16 bytes, so this fits in a byte.
        pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
        let (iv, tag) = trailer.split_at_mut(SESSION_TRANSPORT_IV_LEN);
        Rng::rand_bytes(iv).map_err(|_| SessionExCryptoError::Crypto)?;
        let iv: [u8; SESSION_TRANSPORT_IV_LEN] = (&*iv)
            .try_into()
            .map_err(|_| SessionExCryptoError::Crypto)?;
        tag.copy_from_slice(&gcm_encrypt(&self.h2m, &iv, pt)?);
        Ok(frame)
    }

    /// Open a sealed Uno response frame in place with the HSM→VM key,
    /// truncating `frame` to the message.
    ///
    /// # Errors
    ///
    /// [`SessionExCryptoError::MacMismatch`] (with `frame` cleared) if
    /// the frame is malformed, its tag does not verify or its padding is
    /// invalid.
    pub fn open_frame(&self, frame: &mut Vec<u8>) -> SessionExCryptoResult<()> {
        let Some(ct_len) = frame
            .len()
            .checked_sub(SEALED_TRAILER_LEN)
            .filter(|&n| n != 0 && n % SEALED_BLOCK_LEN == 0)
        else {
            frame.clear();
            return Err(SessionExCryptoError::MacMismatch);
        };
        let (ct, trailer) = frame.split_at_mut(ct_len);
        let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
        let opened = gcm_decrypt(&self.m2h, iv, tag, ct)
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

    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], codec::EncodeError> {
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
}

impl TborRespSessionId for SealedFrameResp {
    fn resp_session_id(&self) -> Option<u16> {
        None
    }
}

/// AES-256-GCM encrypt `buf` in place without AAD, returning the tag.
fn gcm_encrypt(
    key: &AesKey,
    iv: &[u8],
    buf: &mut [u8],
) -> SessionExCryptoResult<[u8; SESSION_TRANSPORT_TAG_LEN]> {
    let mut algo = AesGcmAlgo::for_encrypt(iv, None).map_err(|_| SessionExCryptoError::Crypto)?;
    let plaintext = Zeroizing::new(buf.to_vec());
    algo.encrypt(key, &plaintext, Some(buf))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    algo.tag()
        .try_into()
        .map_err(|_| SessionExCryptoError::Crypto)
}

/// AES-256-GCM decrypt `buf` in place without AAD; on a tag mismatch
/// `buf` is zeroed.
fn gcm_decrypt(key: &AesKey, iv: &[u8], tag: &[u8], buf: &mut [u8]) -> SessionExCryptoResult<()> {
    let mut algo =
        AesGcmAlgo::for_decrypt(iv, tag, None).map_err(|_| SessionExCryptoError::Crypto)?;
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
            hkdf_expand_labeled(&HS, label, SESSION_TRANSPORT_KEY_LEN).expect("test crypto");
        AesKey::from_bytes(&bytes).expect("test crypto")
    }

    /// The device side of `SessionOpenInit`: encapsulates to `pk_init`,
    /// signs `T1` with `sk_hsm` and derives `hs`, independently of
    /// [`SessionInitiator`]. Returns `(enc, sig, hs)`.
    fn device_open_init(
        suite: SessionSuite,
        sk_hsm: &EccPrivateKey,
        pk_init: &[u8],
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
            SessionSuite::MlKem1024 => {
                let ek = MlKemPublicKey::from_bytes(pk_init).expect("test crypto");
                let mut ct = vec![0u8; SESSION_MLKEM1024_CT_LEN];
                let mut z = vec![0u8; MLKEM_SHARED_SECRET_LEN];
                MlKemAlgo::new()
                    .encapsulate(&ek, Some(&mut ct), Some(&mut z))
                    .expect("test crypto");
                (ct, z)
            }
        };
        let pk_hsm =
            ec_pub_to_sec1(&sk_hsm.public_key().expect("test crypto")).expect("test crypto");
        let t1 = transcript_hash(suite.id(), 1, 0, &pk_hsm, pk_init, &enc).expect("test crypto");
        let mut sig = vec![0u8; SIG_LEN];
        EccAlgo::default()
            .sign(sk_hsm, &t1, Some(&mut sig))
            .expect("test crypto");
        let hs = handshake_secret(&z, &PSK, &t1).expect("test crypto");
        (enc, sig, hs)
    }

    fn handshake_agrees(suite: SessionSuite) {
        let sk_hsm = EccPrivateKey::from_scalar(EccCurve::P384, &[0x17; 48]).expect("test crypto");
        let pk_hsm = sk_hsm.public_key().expect("test crypto");
        let init = SessionInitiator::generate(suite).expect("test crypto");
        let (enc, sig, hs) = device_open_init(suite, &sk_hsm, init.pk_init());

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
    }

    #[test]
    fn ecdh_handshake_agrees_with_device() {
        handshake_agrees(SessionSuite::EcdhP384);
    }

    #[test]
    fn mlkem_handshake_agrees_with_device() {
        handshake_agrees(SessionSuite::MlKem1024);
    }

    #[test]
    fn fin_is_bound_to_transcript() {
        let a = SessionHandshake::from_parts(HS, [1; SESSION_HS_LEN]);
        let b = SessionHandshake::from_parts(HS, [2; SESSION_HS_LEN]);
        assert_ne!(a.fin().expect("fin"), b.fin().expect("fin"));
    }

    #[test]
    fn transport_interoperates_with_device_keys() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");

        let mut request = *b"tbor secure request";
        let sealed = transport.seal_request(&mut request).expect("test crypto");
        assert_ne!(&request, b"tbor secure request");
        gcm_decrypt(
            &device_key(SESSION_TRANSPORT_H2M_LABEL),
            &sealed.iv,
            &sealed.tag,
            &mut request,
        )
        .expect("test crypto");
        assert_eq!(&request, b"tbor secure request");

        let mut response = *b"tbor response";
        let iv = [7; SESSION_TRANSPORT_IV_LEN];
        let tag = gcm_encrypt(&device_key(SESSION_TRANSPORT_M2H_LABEL), &iv, &mut response)
            .expect("test crypto");
        transport
            .open_response(&SessionTransportSeal { iv, tag }, &mut response)
            .expect("test crypto");
        assert_eq!(&response, b"tbor response");
    }

    #[test]
    fn open_response_rejects_reflection_and_tampering() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        let mut buf = *b"payload";
        let sealed = transport.seal_request(&mut buf).expect("test crypto");

        // A reflected request is under the VM→HSM key.
        let mut reflected = buf;
        assert!(matches!(
            transport.open_response(&sealed, &mut reflected),
            Err(SessionExCryptoError::MacMismatch)
        ));
        assert_eq!(reflected, [0; 7]);

        let mut tampered = sealed;
        tampered.tag[0] ^= 1;
        assert!(transport.open_response(&tampered, &mut buf).is_err());
    }

    /// Seal `msg` as the device would: `ct ‖ iv ‖ tag` under the HSM→VM key.
    fn device_seal_frame(msg: &[u8]) -> Vec<u8> {
        let pt_len = sealed_frame_len(msg.len()) - SEALED_TRAILER_LEN;
        let mut frame = msg.to_vec();
        frame.resize(pt_len, 0);
        frame[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
        let iv = [9; SESSION_TRANSPORT_IV_LEN];
        let tag = gcm_encrypt(&device_key(SESSION_TRANSPORT_M2H_LABEL), &iv, &mut frame)
            .expect("test crypto");
        frame.extend_from_slice(&iv);
        frame.extend_from_slice(&tag);
        frame
    }

    #[test]
    fn frames_interoperate_with_device_keys() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        for len in [0, 1, 15, 16, 17, 100] {
            let msg: Vec<u8> = (0..len as u8).collect();

            let frame = transport.seal_frame(&msg).expect("test crypto");
            assert_eq!(frame.len(), sealed_frame_len(len));
            let ct_len = frame.len() - SEALED_TRAILER_LEN;
            assert_eq!(ct_len % SEALED_BLOCK_LEN, 0);
            let (ct, trailer) = frame.split_at(ct_len);
            let mut pt = ct.to_vec();
            let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
            gcm_decrypt(&device_key(SESSION_TRANSPORT_H2M_LABEL), iv, tag, &mut pt)
                .expect("test crypto");
            assert_eq!(unpad(&pt), Some(len));
            assert_eq!(&pt[..len], msg.as_slice());

            let mut frame = device_seal_frame(&msg);
            transport.open_frame(&mut frame).expect("test crypto");
            assert_eq!(frame, msg);
        }
    }

    #[test]
    fn open_frame_rejects_bad_frames() {
        let transport = SessionTransport::derive(&HS).expect("test crypto");
        let good = device_seal_frame(b"response");

        let mut tampered = good.clone();
        tampered[0] ^= 1;
        let mut short = good[..good.len() - 1].to_vec();
        // A request frame is under the VM→HSM key.
        let mut reflected = transport.seal_frame(b"response").expect("test crypto");
        for frame in [&mut tampered, &mut short, &mut reflected] {
            assert!(matches!(
                transport.open_frame(frame),
                Err(SessionExCryptoError::MacMismatch)
            ));
            assert!(frame.is_empty());
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
