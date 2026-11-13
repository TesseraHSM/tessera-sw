// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionOpenInit` command.

use alloc::vec;
use alloc::vec::Vec;

use crate::tbor;
use crate::tbor_int::U8;

/// TBOR opcode for `SessionOpenInit`.
pub const TBOR_OP_SESSION_OPEN_INIT: u8 = 0x03;

/// Wire identifier of the ECDH P-384 suite: ephemeral ECDH P-384 key
/// agreement, transcript signed with the partition identity key
/// (ECDSA P-384).
///
/// Mirrors the FW-side `HsmSessionSuite::EcdhP384EcdsaP384` discriminant.
pub const SESSION_SUITE_ECDH_P384_ECDSA_P384: u8 = 0x01;

/// Wire identifier of the ML-KEM-1024 suite: ML-KEM-1024 key
/// encapsulation, transcript signed with the partition identity key
/// (ECDSA P-384).
///
/// Mirrors the FW-side `HsmSessionSuite::MlKem1024EcdsaP384` discriminant.
pub const SESSION_SUITE_MLKEM1024_ECDSA_P384: u8 = 0x02;

/// Length of a SEC1 uncompressed P-384 point (`0x04 ‖ X ‖ Y`): the ECDH
/// suite's `pk_init`, `enc` and the partition identity key in the
/// transcript.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_P384_SEC1_LEN`.
pub const SESSION_P384_SEC1_LEN: usize = 97;

/// Length of an ML-KEM-1024 encapsulation key (the ML-KEM suite's
/// `pk_init`).
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_MLKEM1024_PK_LEN`.
pub const SESSION_MLKEM1024_PK_LEN: usize = 1568;

/// Length of an ML-KEM-1024 ciphertext (the ML-KEM suite's `enc`).
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_MLKEM1024_CT_LEN`.
pub const SESSION_MLKEM1024_CT_LEN: usize = 1568;

/// Largest `pk_init` on the wire.
pub const PK_INIT_MAX_LEN: usize = SESSION_MLKEM1024_PK_LEN;

/// Largest `enc` on the wire.
pub const ENC_MAX_LEN: usize = SESSION_MLKEM1024_CT_LEN;

/// Length of the transcript signature: raw big-endian ECDSA P-384 `r ‖ s`.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_SIG_LEN`.
pub const SIG_LEN: usize = 96;

/// Domain-separation label prefixed to the handshake transcript and used
/// as the HKDF-Extract salt.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSCRIPT_LABEL`.
pub const SESSION_TRANSCRIPT_LABEL: &[u8] = b"TSRA-SESSION-v2";

/// Channel profile of a TBOR session.
///
/// Host-side mirror of `tsra_fw_hsm_pal_traits::HsmSessionType` —
/// kept here as an independent definition so the host crate does not
/// have to pull in the firmware PAL traits.  The on-wire `u8`
/// encoding matches the FW enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    /// Every in-session request and response is AES-256-GCM protected.
    /// The only session type, for both CO and CU.
    Encrypted = 0,
}

impl SessionType {
    /// Wire-encode this `SessionType` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Host-facing TBOR `SessionOpenInit` request.
///
/// Always starts a fresh handshake.  The 32-byte session seed is
/// generated client-side and shipped AEAD-encrypted in
/// [`TborSessionOpenFinishReq`](crate::TborSessionOpenFinishReq).
/// Resume is handled by the MBOR `ReopenSession` command, not by this
/// opcode.
#[tbor(opcode = TBOR_OP_SESSION_OPEN_INIT, session_ctrl = open)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSessionOpenInitReq {
    /// PSK identifier asserting the caller role (`0` = CO, `1` = CU).
    pub psk_id: U8,

    /// Channel profile; only `Encrypted (0)` is defined.
    pub session_type: U8,

    /// Cryptographic suite identifier
    /// ([`SESSION_SUITE_ECDH_P384_ECDSA_P384`] or
    /// [`SESSION_SUITE_MLKEM1024_ECDSA_P384`]).
    pub suite_id: U8,

    /// The VM's per-handshake ephemeral KEM public key: a 97 B SEC1
    /// point (ECDH P-384) or a 1568 B encapsulation key (ML-KEM-1024).
    #[tbor(align = 4, max_len = 1568)]
    pub pk_init: Vec<u8>,
}

impl Default for TborSessionOpenInitReq {
    fn default() -> Self {
        Self {
            psk_id: 0,
            session_type: SessionType::Encrypted.to_u8(),
            suite_id: SESSION_SUITE_ECDH_P384_ECDSA_P384,
            pk_init: vec![0u8; SESSION_P384_SEC1_LEN],
        }
    }
}

/// Host-facing TBOR `SessionOpenInit` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSessionOpenInitResp {
    /// Reserved session identifier.
    #[tbor(session_id)]
    pub session_id: u16,
    /// KEM encapsulation for `pk_init`: the HSM's 97 B SEC1 ephemeral
    /// point (ECDH P-384) or the 1568 B ciphertext (ML-KEM-1024).
    #[tbor(align = 4, max_len = 1568)]
    pub enc: Vec<u8>,
    /// Partition-identity ECDSA P-384 signature over the transcript hash
    /// `T1`, raw big-endian `r ‖ s`.
    #[tbor(min_len = 96, max_len = 96)]
    pub sig: Vec<u8>,
}
