// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO opcodes and session-control classification.
//!
//! The SQE/CQE wire layout belongs to each platform's PAL; the core only
//! sees the raw opcode via [`HsmSqe::opcode`] and dispatches on the values
//! defined here. Platforms that build or decode SQEs must use the same
//! values. This module also classifies session control from DDI opcodes
//! ([`sess_ctrl_from_mbor_op`], [`sess_ctrl_from_tbor_opcode`]).

use super::*;

// ── Uno opcodes ─────────────────────────────────────────────────────

/// MBOR opcode — IO command carrying an MBOR-encoded DDI body.
pub const OP_MBOR: u16 = 0;

/// Flush opcode — tears down the session named by the SQE.
pub const OP_FLUSH: u16 = 1;

/// TBOR opcode — IO command carrying a TBOR-encoded DDI body.
pub const OP_TBOR: u16 = 2;

// ── Duo opcodes ─────────────────────────────────────────────────────

/// Duo SQE opcode.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuoOp {
    /// Plain TBOR command.
    Tbor = 0,

    /// TBOR command protected by the session transport keys.
    TborSecure = 1,

    /// Tears down the session named by the SQE.
    FlushSession = 2,
}

// ── Session control ─────────────────────────────────────────────────

/// Maps an MBOR DDI opcode to its session control kind.
pub(crate) fn sess_ctrl_from_mbor_op(op: tsra_fw_ddi_mbor_types::DdiOp) -> HsmSessCtrl {
    use tsra_fw_ddi_mbor_types::DdiOp;
    match op {
        DdiOp::GetApiRev
        | DdiOp::GetDeviceInfo
        | DdiOp::GetCertChainInfo
        | DdiOp::GetCertificate
        | DdiOp::GetEstablishCredEncryptionKey
        | DdiOp::GetSessionEncryptionKey
        | DdiOp::GetSealedBk3
        | DdiOp::InitBk3
        | DdiOp::SetSealedBk3
        | DdiOp::EstablishCredential => HsmSessCtrl::NoSession,
        DdiOp::OpenSession => HsmSessCtrl::Open,
        DdiOp::CloseSession => HsmSessCtrl::Close,
        _ => HsmSessCtrl::InSession,
    }
}

/// Maps a TBOR opcode to its session control kind.
///
/// `GetApiRev` is session-less.
///
/// `OpenSessionInit` is classified as `Open` — it initiates the
/// session-open flow; the SQE carries no session id (the FW
/// allocates a pending slot and returns its id in the response).
///
/// `OpenSessionFinish`, `ChangePsk`, and `PartInit` reference the
/// pending/active slot, so the SQE must carry the slot's
/// `session_id` (`InSession`).  `CloseSession` carries the slot
/// id and is classified as `Close` so the CQE flags signal the
/// slot transition to the host.
///
/// Unknown opcodes default to `NoSession` so that dispatch can
/// surface `HsmError::UnsupportedCmd` from the handler layer
/// rather than being rejected as a session-flag mismatch first.
pub(crate) fn sess_ctrl_from_tbor_opcode(opcode: u8) -> HsmSessCtrl {
    use crate::ddi::tbor::opcode;
    match opcode {
        opcode::API_REV
        | opcode::PART_INFO
        | opcode::GET_CERT_CHAIN_INFO
        | opcode::GET_CERTIFICATE => HsmSessCtrl::NoSession,
        opcode::SESSION_OPEN_INIT => HsmSessCtrl::Open,
        opcode::SESSION_OPEN_FINISH
        | opcode::PSK_CHANGE
        | opcode::PART_INIT
        | opcode::PART_FINAL
        | opcode::SD_SEALING_KEY_GEN
        | opcode::SD_CREATE_REMOTE_BACKUP
        | opcode::SD_RESEAL_REMOTE_BACKUP
        | opcode::SD_RESTORE_REMOTE_BACKUP
        | opcode::SD_RESTORE_LOCAL_BACKUP
        | opcode::SD_CREATE_PEER_BACKUP
        | opcode::SD_RESTORE_PEER_BACKUP
        | opcode::KEY_REPORT
        | opcode::HMAC_GENERATE_KEY
        | opcode::HMAC
        | opcode::GET_UNWRAPPING_KEY
        | opcode::UNWRAP_KEY
        | opcode::AES_GENERATE_KEY
        | opcode::AES_ENCRYPT_DECRYPT
        | opcode::ECC_GENERATE_KEY
        | opcode::ECC_SIGN
        | opcode::ECDH_DERIVE
        | opcode::RSA_MOD_EXP
        | opcode::HASH
        | opcode::HKDF_DERIVE
        | opcode::CONCAT_KDF_DERIVE
        | opcode::DARC_KEX_KEY_GEN
        | opcode::DARC_TMK_IMPORT
        | opcode::DARC_KEY_UNWRAP
        | opcode::DARC_TMK_GEN
        | opcode::DARC_TMK_EXPORT
        | opcode::DARC_KEY_WRAP
        | opcode::MLDSA_GENERATE_KEY
        | opcode::MLDSA_SIGN
        | opcode::MLDSA_VERIFY
        | opcode::MLKEM_GENERATE_KEY
        | opcode::MLKEM_ENCAPSULATE
        | opcode::MLKEM_DECAPSULATE
        | opcode::AES_GCM_ENCRYPT_DECRYPT
        | opcode::AES_XTS_ENCRYPT_DECRYPT
        | opcode::AES_XTS_GENERATE_KEY
        | opcode::GET_PUBLIC_KEY
        | opcode::VERIFY_KEY => HsmSessCtrl::InSession,
        opcode::SESSION_CLOSE => HsmSessCtrl::Close,
        _ => HsmSessCtrl::NoSession,
    }
}
