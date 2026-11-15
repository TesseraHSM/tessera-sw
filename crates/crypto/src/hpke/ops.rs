// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE single-shot seal / open / export entry points.
//!
//! Sync, single-shot HPKE built on the existing `tsra_crypto`
//! primitives. Mirrors the firmware HPKE crate
//! (`fw/core/crypto/hpke`) in structure; the differences are forced
//! by the host being `std` + sync rather than `no_std` + async + PAL.
//!
//! # Pattern overview
//!
//! Recipient keys are [`HpkePublicKey`] / [`HpkePrivateKey`]: typed
//! [`EccPublicKey`] / [`EccPrivateKey`] handles for DHKEM (passed via
//! `From`), raw HPKE encodings for the post-quantum KEMs. Auth-mode
//! sender keys are always ECC. Wire-only quantities (`enc`, AEAD
//! ciphertext, AAD, info, exporter context, plaintext, PSK material)
//! stay as `&[u8]` / `&mut [u8]`.
//!
//! Each operation takes a configuration struct constructed via a
//! mode-named constructor (`base` / `psk` / `auth` / `auth_psk`),
//! mirroring [`crate::AesGcmAlgo::for_encrypt`] /
//! [`crate::AesGcmAlgo::for_decrypt`]. The constructors enforce the
//! mode / auth / PSK invariants at compile time.
//!
//! # Public surface
//!
//! Four operations, each with a `_vec` convenience sibling that
//! allocates owned outputs:
//!
//! | Operation        | Slice form        | Owned form                  |
//! |------------------|-------------------|-----------------------------|
//! | Seal             | [`seal`]          | [`seal_vec`] → [`HpkeSealed`]      |
//! | Open             | [`open`]          | [`open_vec`] → `Vec<u8>`           |
//! | Send export      | [`send_export`]   | [`send_export_vec`] → [`HpkeExportSent`] |
//! | Receive export   | [`receive_export`]| [`receive_export_vec`] → `Vec<u8>` |
//!
//! Seal and send-export return the serialized encapsulated key `enc`
//! (SEC1 uncompressed for DHKEM, `Nenc` bytes for the post-quantum
//! KEMs); open and receive-export take it back as bytes.
//!
//! The post-quantum suites support the Base and PSK modes only; Auth
//! configs for them fail with [`CryptoError::HpkeInvalidModeConfig`].

use zeroize::Zeroizing;

use super::aead;
use super::kem;
use super::keys::HpkePrivateKey;
use super::keys::HpkePublicKey;
use super::schedule;
use super::suite::HpkeSuite;
use crate::CryptoError;
use crate::EccPrivateKey;
use crate::EccPublicKey;

// =============================================================================
// Mode helpers
// =============================================================================

/// HPKE operating mode byte (RFC 9180 §5.1 Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Mode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

/// Pre-shared key parameters for `Config::psk` / `Config::auth_psk`.
#[derive(Debug, Clone, Copy)]
pub struct PskParams<'a> {
    /// Pre-shared key (≥ 32 bytes of entropy recommended by RFC 9180).
    pub psk: &'a [u8],
    /// PSK identifier.
    pub psk_id: &'a [u8],
}

// =============================================================================
// Result types
// =============================================================================

/// Owned outputs from [`seal_vec`].
#[derive(Debug, Clone)]
pub struct HpkeSealed {
    /// Serialized encapsulated key (the wire `enc` value).
    pub enc: Vec<u8>,
    /// Ciphertext.
    pub ct: Vec<u8>,
}

/// Owned outputs from [`send_export_vec`].
#[derive(Debug, Clone)]
pub struct HpkeExportSent {
    /// Serialized encapsulated key (the wire `enc` value).
    pub enc: Vec<u8>,
    /// Exported key material (`exported.len() = L`).
    pub exported: Vec<u8>,
}

// =============================================================================
// Config: HpkeSealConfig
// =============================================================================

/// Configuration for an HPKE seal (`encrypt`) operation. Construct via
/// a mode-named constructor; the chosen mode determines which of
/// `sk_s` (sender private key) and [`PskParams`] are required.
#[derive(Debug, Clone, Copy)]
pub struct HpkeSealConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient public key.
    pub pk_r: HpkePublicKey<'a>,
    /// Application-supplied info (may be empty).
    pub info: &'a [u8],
    /// Additional authenticated data (may be empty).
    pub aad: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth: Option<&'a EccPrivateKey>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeSealConfig<'a> {
    /// Base mode — encrypt to the recipient's public key alone.
    pub fn base(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Base,
            auth: None,
            psk: None,
        }
    }

    /// PSK mode — encrypt with shared PSK authentication.
    pub fn psk(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Psk,
            auth: None,
            psk: Some(psk),
        }
    }

    /// Auth mode — encrypt with sender-key authentication.
    pub fn auth(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        sk_s: &'a EccPrivateKey,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Auth,
            auth: Some(sk_s),
            psk: None,
        }
    }

    /// AuthPSK mode — combines [`Self::auth`] and [`Self::psk`].
    pub fn auth_psk(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        sk_s: &'a EccPrivateKey,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::AuthPsk,
            auth: Some(sk_s),
            psk: Some(psk),
        }
    }

    /// Compute the required ciphertext buffer length for a plaintext
    /// of `pt_len` bytes. Pure helper; does not perform any crypto.
    pub fn ct_len(&self, pt_len: usize) -> usize {
        aead::ct_len(self.suite, pt_len)
    }
}

// =============================================================================
// Config: HpkeOpenConfig
// =============================================================================

/// Configuration for an HPKE open (`decrypt`) operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeOpenConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient private key.
    pub sk_r: HpkePrivateKey<'a>,
    /// Recipient public key.
    pub pk_r: HpkePublicKey<'a>,
    /// Application-supplied info — must equal the sender's value.
    pub info: &'a [u8],
    /// Additional authenticated data — must equal the sender's value.
    pub aad: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth_pk_s: Option<&'a EccPublicKey>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeOpenConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Base,
            auth_pk_s: None,
            psk: None,
        }
    }

    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Psk,
            auth_pk_s: None,
            psk: Some(psk),
        }
    }

    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        auth_pk_s: &'a EccPublicKey,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::Auth,
            auth_pk_s: Some(auth_pk_s),
            psk: None,
        }
    }

    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        aad: &'a [u8],
        auth_pk_s: &'a EccPublicKey,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            aad,
            mode: Mode::AuthPsk,
            auth_pk_s: Some(auth_pk_s),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Config: HpkeSendExportConfig
// =============================================================================

/// Configuration for an HPKE send-export operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeSendExportConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient public key.
    pub pk_r: HpkePublicKey<'a>,
    /// Application-supplied info.
    pub info: &'a [u8],
    /// Exporter context bytes — must equal the receiver's value.
    pub exporter_context: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth: Option<&'a EccPrivateKey>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeSendExportConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Base,
            auth: None,
            psk: None,
        }
    }

    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Psk,
            auth: None,
            psk: Some(psk),
        }
    }

    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        sk_s: &'a EccPrivateKey,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Auth,
            auth: Some(sk_s),
            psk: None,
        }
    }

    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        sk_s: &'a EccPrivateKey,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::AuthPsk,
            auth: Some(sk_s),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Config: HpkeReceiveExportConfig
// =============================================================================

/// Configuration for an HPKE receive-export operation.
#[derive(Debug, Clone, Copy)]
pub struct HpkeReceiveExportConfig<'a> {
    /// HPKE ciphersuite.
    pub suite: HpkeSuite,
    /// Recipient private key.
    pub sk_r: HpkePrivateKey<'a>,
    /// Recipient public key.
    pub pk_r: HpkePublicKey<'a>,
    /// Application-supplied info — must equal sender's.
    pub info: &'a [u8],
    /// Exporter context bytes — must equal sender's.
    pub exporter_context: &'a [u8],
    pub(crate) mode: Mode,
    pub(crate) auth_pk_s: Option<&'a EccPublicKey>,
    pub(crate) psk: Option<PskParams<'a>>,
}

impl<'a> HpkeReceiveExportConfig<'a> {
    /// Base mode.
    pub fn base(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Base,
            auth_pk_s: None,
            psk: None,
        }
    }

    /// PSK mode.
    pub fn psk(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Psk,
            auth_pk_s: None,
            psk: Some(psk),
        }
    }

    /// Auth mode.
    pub fn auth(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth_pk_s: &'a EccPublicKey,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::Auth,
            auth_pk_s: Some(auth_pk_s),
            psk: None,
        }
    }

    /// AuthPSK mode.
    pub fn auth_psk(
        suite: HpkeSuite,
        sk_r: impl Into<HpkePrivateKey<'a>>,
        pk_r: impl Into<HpkePublicKey<'a>>,
        info: &'a [u8],
        exporter_context: &'a [u8],
        auth_pk_s: &'a EccPublicKey,
        psk: PskParams<'a>,
    ) -> Self {
        Self {
            suite,
            sk_r: sk_r.into(),
            pk_r: pk_r.into(),
            info,
            exporter_context,
            mode: Mode::AuthPsk,
            auth_pk_s: Some(auth_pk_s),
            psk: Some(psk),
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Run (Auth)Encap for a sender-side config.
fn encap_for(
    suite: HpkeSuite,
    mode: Mode,
    pk_r: HpkePublicKey<'_>,
    auth: Option<&EccPrivateKey>,
) -> Result<kem::EncapOutput, CryptoError> {
    match (mode, auth) {
        (Mode::Base, None) | (Mode::Psk, None) => kem::encap(suite, pk_r),
        (Mode::Auth, Some(sk_s)) | (Mode::AuthPsk, Some(sk_s)) => {
            kem::auth_encap(suite, pk_r, sk_s)
        }
        _ => Err(CryptoError::HpkeInvalidModeConfig),
    }
}

/// Run (Auth)Decap for a receiver-side config.
fn decap_for(
    suite: HpkeSuite,
    mode: Mode,
    enc: &[u8],
    sk_r: HpkePrivateKey<'_>,
    pk_r: HpkePublicKey<'_>,
    auth_pk_s: Option<&EccPublicKey>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match (mode, auth_pk_s) {
        (Mode::Base, None) | (Mode::Psk, None) => kem::decap(suite, enc, sk_r, pk_r),
        (Mode::Auth, Some(pk_s)) | (Mode::AuthPsk, Some(pk_s)) => {
            kem::auth_decap(suite, enc, sk_r, pk_r, pk_s)
        }
        _ => Err(CryptoError::HpkeInvalidModeConfig),
    }
}

fn psk_bytes<'a>(psk: &Option<PskParams<'a>>) -> (&'a [u8], &'a [u8]) {
    match psk {
        Some(p) => (p.psk, p.psk_id),
        None => (&[], &[]),
    }
}

/// Run the AEAD key schedule for a config's mode / info / PSK.
fn key_schedule_inputs(
    cfg_mode: Mode,
    cfg_info: &[u8],
    psk: &Option<PskParams<'_>>,
    suite: HpkeSuite,
    shared_secret: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let (psk_b, psk_id) = psk_bytes(psk);
    schedule::key_schedule(
        suite,
        cfg_mode as u8,
        shared_secret,
        cfg_info,
        psk_b,
        psk_id,
    )
}

// =============================================================================
// seal
// =============================================================================

/// HPKE seal (encrypt). Writes ciphertext to `ct_out` and returns the
/// serialized encapsulated key `enc`.
///
/// Use [`HpkeSealConfig::ct_len`] to compute the required `ct_out`
/// length, or call [`seal_vec`] for an allocating convenience that
/// returns both outputs.
///
/// # Errors
///
/// * [`CryptoError::HpkeOutputBufferTooSmall`] if `ct_out` is shorter
///   than `cfg.ct_len(pt.len())`.
/// * [`CryptoError::HpkeInvalidPublicKey`] if `cfg.pk_r` does not
///   belong to `cfg.suite` (wrong kind, curve or length, or a rejected
///   ML-KEM / P-384 public key).
/// * [`CryptoError::HpkeInvalidModeConfig`] for an Auth mode on a
///   post-quantum suite.
/// * Other [`CryptoError`] variants propagated from the KEM, key
///   schedule, or AEAD.
pub fn seal(
    cfg: &HpkeSealConfig<'_>,
    pt: &[u8],
    ct_out: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    let needed = cfg.ct_len(pt.len());
    if ct_out.len() < needed {
        return Err(CryptoError::HpkeOutputBufferTooSmall);
    }

    // 1. (Auth)Encap → (enc, shared_secret)
    let (enc, shared_secret) = encap_for(cfg.suite, cfg.mode, cfg.pk_r, cfg.auth)?;

    // 2. Key schedule
    let (key, base_nonce) =
        key_schedule_inputs(cfg.mode, cfg.info, &cfg.psk, cfg.suite, &shared_secret)?;

    // 3. AEAD seal
    let n = aead::seal(
        cfg.suite,
        &key,
        &base_nonce,
        cfg.aad,
        pt,
        &mut ct_out[..needed],
    )?;
    if n != needed {
        return Err(CryptoError::HpkeAeadSealFailed);
    }
    Ok(enc)
}

/// Owned-output convenience around [`seal`].
pub fn seal_vec(cfg: &HpkeSealConfig<'_>, pt: &[u8]) -> Result<HpkeSealed, CryptoError> {
    let mut ct = vec![0u8; cfg.ct_len(pt.len())];
    let enc = seal(cfg, pt, &mut ct)?;
    Ok(HpkeSealed { enc, ct })
}

// =============================================================================
// open
// =============================================================================

/// HPKE open (decrypt). Writes plaintext to `pt_out` (size-query via
/// `None`, write via `Some(_)`).
///
/// `pt_out = None` returns the upper-bound plaintext length
/// (= `ct.len()`); the actual byte count is returned when
/// `pt_out = Some(_)`.
pub fn open(
    cfg: &HpkeOpenConfig<'_>,
    enc: &[u8],
    ct: &[u8],
    pt_out: Option<&mut [u8]>,
) -> Result<usize, CryptoError> {
    let max_pt = ct.len();
    let pt = match pt_out {
        None => return Ok(max_pt),
        Some(buf) => {
            if buf.len() < max_pt {
                return Err(CryptoError::HpkeOutputBufferTooSmall);
            }
            buf
        }
    };

    let shared_secret = decap_for(cfg.suite, cfg.mode, enc, cfg.sk_r, cfg.pk_r, cfg.auth_pk_s)?;

    let (key, base_nonce) =
        key_schedule_inputs(cfg.mode, cfg.info, &cfg.psk, cfg.suite, &shared_secret)?;

    aead::open(cfg.suite, &key, &base_nonce, cfg.aad, ct, pt)
}

/// Owned-output convenience around [`open`].
pub fn open_vec(cfg: &HpkeOpenConfig<'_>, enc: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let max = open(cfg, enc, ct, None)?;
    let mut pt = vec![0u8; max];
    let n = open(cfg, enc, ct, Some(&mut pt))?;
    pt.truncate(n);
    Ok(pt)
}

// =============================================================================
// send_export
// =============================================================================

/// HPKE send-export. Writes `exported_out.len()` bytes of exported key
/// material into `exported_out` and returns the serialized
/// encapsulated key `enc`.
pub fn send_export(
    cfg: &HpkeSendExportConfig<'_>,
    exported_out: &mut [u8],
) -> Result<Vec<u8>, CryptoError> {
    let (enc, shared_secret) = encap_for(cfg.suite, cfg.mode, cfg.pk_r, cfg.auth)?;

    derive_exported(
        cfg.suite,
        cfg.mode,
        &shared_secret,
        cfg.info,
        &cfg.psk,
        cfg.exporter_context,
        exported_out,
    )?;
    Ok(enc)
}

/// Owned-output convenience around [`send_export`]. `l` is the
/// requested export length (the receiver must use the same value).
pub fn send_export_vec(
    cfg: &HpkeSendExportConfig<'_>,
    l: usize,
) -> Result<HpkeExportSent, CryptoError> {
    let mut exported = vec![0u8; l];
    let enc = send_export(cfg, &mut exported)?;
    Ok(HpkeExportSent { enc, exported })
}

// =============================================================================
// receive_export
// =============================================================================

/// HPKE receive-export. Writes `exported_out.len()` bytes of exported
/// key material into `exported_out`.
pub fn receive_export(
    cfg: &HpkeReceiveExportConfig<'_>,
    enc: &[u8],
    exported_out: &mut [u8],
) -> Result<(), CryptoError> {
    let shared_secret = decap_for(cfg.suite, cfg.mode, enc, cfg.sk_r, cfg.pk_r, cfg.auth_pk_s)?;

    derive_exported(
        cfg.suite,
        cfg.mode,
        &shared_secret,
        cfg.info,
        &cfg.psk,
        cfg.exporter_context,
        exported_out,
    )
}

/// Owned-output convenience around [`receive_export`].
pub fn receive_export_vec(
    cfg: &HpkeReceiveExportConfig<'_>,
    enc: &[u8],
    l: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut exported = vec![0u8; l];
    receive_export(cfg, enc, &mut exported)?;
    Ok(exported)
}

/// Shared "derive exporter secret + expand" step for both export sides.
fn derive_exported(
    suite: HpkeSuite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &Option<PskParams<'_>>,
    exporter_context: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let (psk_bytes, psk_id) = psk_bytes(psk);
    let exporter_secret =
        schedule::key_schedule_export(suite, mode as u8, shared_secret, info, psk_bytes, psk_id)?;
    schedule::export(suite, &exporter_secret, exporter_context, out)
}
