// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionOpenFinish` command
//! (session-establishment Phase 2).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `SessionOpenFinish`.
pub const TBOR_OP_SESSION_OPEN_FINISH: u8 = 0x04;

/// Length of the host's handshake confirmation
/// `fin = HMAC-SHA-384(fin_key, T1)`.
pub const MAC_FIN_LEN: usize = 48;

/// Length of the host-supplied `seed`, encrypted inside
/// `seed_envelope` and used by the FW as the KBKDF context that
/// produces `BK_SESSION`.
pub const SEED_LEN: usize = 32;

/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_SEED_LEN` — alias of
/// [`SEED_LEN`].  Provided so host helpers can mirror the FW spec
/// constant name verbatim.
pub const SESSION_SEED_LEN: usize = SEED_LEN;

/// HKDF-Expand label (followed by `T1`) producing the 48 B handshake
/// secret `hs` from the handshake PRK.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_HS_LABEL`.
pub const SESSION_HS_LABEL: &[u8] = b"tsra-session-hs-v2";

/// Length in bytes of the handshake secret `hs`.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_HS_LEN`.
pub const SESSION_HS_LEN: usize = 48;

/// HKDF-Expand-Labeled label producing the 48 B `fin_key` from `hs`.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_HOST_FIN_LABEL`.
pub const SESSION_HOST_FIN_LABEL: &[u8] = b"tsra-session-host-fin-v2";

/// HKDF-Expand-Labeled label producing the per-session **param key** — a
/// raw 32-byte AES-256 key consumed by the AEAD-envelope crate to
/// AEAD-seal/open the `seed_envelope` and per-parameter envelopes
/// carried by in-session commands such as `PskChange` / `PartInit`.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_PARAM_KEY_LABEL`.
pub const SESSION_PARAM_KEY_LABEL: &[u8] = b"tsra-session-param-v2";

/// Length in bytes of the per-session `param_key`
/// (TBOR per-parameter confidentiality).
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN`.
pub const SESSION_PARAM_KEY_LEN: usize = 32;

/// HKDF-Expand-Labeled label producing the **VM→HSM** session transport
/// key.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_H2M_LABEL`.
pub const SESSION_TRANSPORT_H2M_LABEL: &[u8] = b"tsra-session-xport-h2m-v2";

/// HKDF-Expand-Labeled label producing the **HSM→VM** session transport
/// key.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_M2H_LABEL`.
pub const SESSION_TRANSPORT_M2H_LABEL: &[u8] = b"tsra-session-xport-m2h-v2";

/// Length in bytes of each directional AES-256-GCM session transport key.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_KEY_LEN`.
pub const SESSION_TRANSPORT_KEY_LEN: usize = 32;

/// AES-GCM IV length of a session transport message.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_IV_LEN`.
pub const SESSION_TRANSPORT_IV_LEN: usize = 12;

/// AES-GCM tag length of a session transport message.
///
/// Mirror of `tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_TAG_LEN`.
pub const SESSION_TRANSPORT_TAG_LEN: usize = 16;

/// Length of the AEAD `seed_envelope` on the wire.
///
/// `"AEAD"(4) ‖ alg=AesGcm256(1) ‖ rsv=0(1) ‖ aad_len_be=0(2) ‖
///  IV(16) ‖ seed(32) ‖ TAG(16)` = 72 B.
pub const SEED_ENVELOPE_LEN: usize = 8 + 16 + SEED_LEN + 16;

/// Host-facing TBOR `SessionOpenFinish` request.
#[tbor(opcode = TBOR_OP_SESSION_OPEN_FINISH, session_ctrl = in_session)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionOpenFinishReq {
    /// Pending session identifier reserved in Phase 1.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Handshake confirmation `fin = HMAC-SHA-384(fin_key, T1)` (48 B).
    pub mac_fin: [u8; MAC_FIN_LEN],
    /// AEAD `seed_envelope` wrapping the 32-byte session seed under
    /// the session's `param_key`.  See [`SEED_ENVELOPE_LEN`] for the
    /// fixed wire layout.
    pub seed_envelope: [u8; SEED_ENVELOPE_LEN],
}

impl Default for TborSessionOpenFinishReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mac_fin: [0u8; MAC_FIN_LEN],
            seed_envelope: [0u8; SEED_ENVELOPE_LEN],
        }
    }
}

/// Host-facing TBOR `SessionOpenFinish` response.
///
/// `bmk_session` is owned and right-sized — the host has `alloc`
/// available, so we avoid carrying a fixed-size padding buffer and
/// a separate length field.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSessionOpenFinishResp {
    /// Wrapped session-key blob (AEAD-GCM envelope of `masking_key`).
    pub bmk_session: Vec<u8>,
}
