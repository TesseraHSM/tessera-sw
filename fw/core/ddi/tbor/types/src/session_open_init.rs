// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionOpenInit` wire schema (session-establishment Phase 1).
//!
//! Carries the VM's per-handshake ephemeral KEM public key plus the
//! `psk_id` identifying the caller role (`0` = Crypto Officer,
//! `1` = Crypto User).  The response advertises the slot the HSM
//! reserved for the in-flight handshake, the KEM encapsulation, and the
//! HSM's partition-identity signature over the handshake transcript.
//!
//! All byte fields are declared as `&[u8]` slices with length
//! constraints rather than fixed-size arrays so that handler code
//! can pass and receive slices end-to-end without materializing
//! stack-allocated arrays at any layer.

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

/// Typed wire wrapper for the `SessionOpenInit` `psk_id` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire,
/// identifying the caller role asserted for the handshake. Being **open**
/// keeps it forward-compatible: an unrecognized byte surfaces as
/// `PskId(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`HsmSessionRole`](tsra_fw_hsm_pal_traits::HsmSessionRole), rejecting any
/// value outside the two below with
/// [`InvalidPskId`](tsra_fw_hsm_pal_traits::HsmError::InvalidPskId).
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskId {
    /// Crypto Officer role.
    CryptoOfficer = 0,

    /// Crypto User role.
    CryptoUser = 1,
}

/// Typed wire wrapper for the `SessionOpenInit` `session_type` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire, so the
/// schema field and its accessor are self-documenting (`SessionKind` with
/// named variants rather than a bare `u8`) without coupling the wire type
/// to the firmware-internal
/// [`HsmSessionType`](tsra_fw_hsm_pal_traits::HsmSessionType) enum. Being
/// **open** keeps it forward-compatible: an unrecognized byte surfaces as
/// `SessionKind(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`HsmSessionType`] via `HsmSessionType::from_u8(kind.0)`, which is where
/// an invalid value is rejected with [`InvalidSessionType`].
///
/// [`HsmSessionType`]: tsra_fw_hsm_pal_traits::HsmSessionType
/// [`InvalidSessionType`]: tsra_fw_hsm_pal_traits::HsmError::InvalidSessionType
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Every in-session request and response is AES-256-GCM protected.
    /// The only session type, for both CO and CU.
    Encrypted = 0,
}

/// Typed wire wrapper for the `SessionOpenInit` `suite_id` byte.
///
/// An [`open_enum`] newtype over the raw `u8` carried on the wire, so the
/// schema field and its accessor are self-documenting (`SuiteId` with
/// named variants rather than a bare `u8`) without coupling the wire type
/// to the firmware-internal
/// [`HsmSessionSuite`](tsra_fw_hsm_pal_traits::HsmSessionSuite) enum. Being
/// **open** keeps it forward-compatible: an unrecognized byte surfaces as
/// `SuiteId(x)` rather than failing to decode. The value is **not**
/// validated at decode (any byte round-trips); the handler maps it to a
/// [`HsmSessionSuite`] via `HsmSessionSuite::from_u8(id.0)`, which is where an
/// unsupported suite is rejected with [`UnsupportedSessionSuite`].
///
/// [`HsmSessionSuite`]: tsra_fw_hsm_pal_traits::HsmSessionSuite
/// [`UnsupportedSessionSuite`]: tsra_fw_hsm_pal_traits::HsmError::UnsupportedSessionSuite
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteId {
    /// Ephemeral ECDH P-384, transcript signed with ECDSA P-384.
    EcdhP384EcdsaP384 = 0x01,

    /// ML-KEM-1024, transcript signed with ECDSA P-384.
    MlKem1024EcdsaP384 = 0x02,
}

/// Largest `pk_init`: the ML-KEM-1024 encapsulation key.  An ECDH P-384
/// `pk_init` is a 97 B SEC1 uncompressed point.
pub const PK_INIT_MAX_LEN: usize = 1568;

/// Largest `enc`: the ML-KEM-1024 ciphertext.  An ECDH P-384 `enc` is the
/// HSM's 97 B SEC1 uncompressed ephemeral point.
pub const ENC_MAX_LEN: usize = 1568;

/// Length of the transcript signature: raw big-endian ECDSA P-384 `r ‖ s`.
pub const SIG_LEN: usize = 96;

/// `SessionOpenInit` request schema.
///
/// Always starts a fresh handshake bound to the partition identity key
/// and the caller-asserted PSK.  Resume (recovery of a prior session's
/// `masking_key`) is handled separately by the MBOR `ReopenSession`
/// command.
///
/// `psk_id`, `session_type`, `suite_id` and `pk_init` are all bound into
/// the transcript the HSM signs, so a downgrade or substitution fails
/// the host's signature check.  See
/// [`tsra_fw_hsm_pal_traits::HsmSessionSuite`] for the suite registry.
#[tbor(opcode = 0x03, pair = TborSessionOpenInitResp)]
pub struct TborSessionOpenInitReq<'a> {
    /// PSK identifier asserting the caller role (`CryptoOfficer` = `0`,
    /// `CryptoUser` = `1`). Any other value is rejected with
    /// `InvalidPskId` by the handler.
    #[tbor(U8)]
    pub psk_id: PskId,

    /// Channel profile; only `Encrypted` (`0`) is defined.  Any other
    /// value is rejected with `InvalidSessionType` by the handler.
    #[tbor(U8)]
    pub session_type: SessionKind,

    /// Cryptographic suite identifier.  Any unregistered value is
    /// rejected with `UnsupportedSessionSuite` by the handler.
    #[tbor(U8)]
    pub suite_id: SuiteId,

    /// The VM's per-handshake ephemeral KEM public key; its length must
    /// match the suite (97 B SEC1 point for ECDH P-384, 1568 B
    /// encapsulation key for ML-KEM-1024).
    #[tbor(align = 4, buffer, max_len = 1568)]
    pub pk_init: &'a [u8],
}

/// `SessionOpenInit` response schema.
///
/// The `session_id` field is typed
/// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId) and marked
/// `#[tbor(session_id)]` so the codec emits it as a 16-bit `SessionId`
/// TOC entry (matching MBOR's session-id encoding).
#[tbor(response, pair = TborSessionOpenInitReq)]
pub struct TborSessionOpenInitResp<'a> {
    /// Reserved session identifier (slot index).
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// KEM encapsulation for `pk_init`: the HSM's 97 B SEC1 ephemeral
    /// point (ECDH P-384) or the 1568 B ciphertext (ML-KEM-1024).
    #[tbor(align = 4, buffer, max_len = 1568)]
    pub enc: &'a [u8],

    /// Partition-identity ECDSA P-384 signature over the transcript hash
    /// `T1`, raw big-endian `r ‖ s`.
    #[tbor(buffer, len = 96)]
    pub sig: &'a [u8],
}
