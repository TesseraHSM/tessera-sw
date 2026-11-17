// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Malformed-request rejection across every TBOR command.
//!
//! For each known opcode that takes request fields (everything except
//! `ApiRev` and `PartInfo`), a request whose TOC holds only `none`
//! entries is sent in a live session. Firmware must reject it with a TBOR
//! error status, and the session must remain usable afterwards.

use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_codec::EncodeError;
use tsra_ddi_tbor_codec::RequestEncoder;
use tsra_ddi_tbor_codec::MAX_TOC_ENTRIES;
use tsra_ddi_tbor_codec::PROTOCOL_VERSION;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborSessionCloseResp;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::TBOR_OP_AES_ENCRYPT_DECRYPT;
use tsra_ddi_tbor_types::TBOR_OP_AES_GCM_ENCRYPT_DECRYPT;
use tsra_ddi_tbor_types::TBOR_OP_AES_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_AES_XTS_ENCRYPT_DECRYPT;
use tsra_ddi_tbor_types::TBOR_OP_AES_XTS_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_CONCAT_KDF_DERIVE;
use tsra_ddi_tbor_types::TBOR_OP_DARC_KEX_KEY_GEN;
use tsra_ddi_tbor_types::TBOR_OP_DARC_KEY_UNWRAP;
use tsra_ddi_tbor_types::TBOR_OP_DARC_KEY_WRAP;
use tsra_ddi_tbor_types::TBOR_OP_DARC_TMK_EXPORT;
use tsra_ddi_tbor_types::TBOR_OP_DARC_TMK_GEN;
use tsra_ddi_tbor_types::TBOR_OP_DARC_TMK_IMPORT;
use tsra_ddi_tbor_types::TBOR_OP_ECC_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_ECC_SIGN;
use tsra_ddi_tbor_types::TBOR_OP_ECDH_DERIVE;
use tsra_ddi_tbor_types::TBOR_OP_GET_CERTIFICATE;
use tsra_ddi_tbor_types::TBOR_OP_GET_CERT_CHAIN_INFO;
use tsra_ddi_tbor_types::TBOR_OP_GET_PUBLIC_KEY;
use tsra_ddi_tbor_types::TBOR_OP_GET_UNWRAPPING_KEY;
use tsra_ddi_tbor_types::TBOR_OP_HASH;
use tsra_ddi_tbor_types::TBOR_OP_HKDF_DERIVE;
use tsra_ddi_tbor_types::TBOR_OP_HMAC;
use tsra_ddi_tbor_types::TBOR_OP_HMAC_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_KEY_REPORT;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_SIGN;
use tsra_ddi_tbor_types::TBOR_OP_MLDSA_VERIFY;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_DECAPSULATE;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_ENCAPSULATE;
use tsra_ddi_tbor_types::TBOR_OP_MLKEM_GENERATE_KEY;
use tsra_ddi_tbor_types::TBOR_OP_PART_FINAL;
use tsra_ddi_tbor_types::TBOR_OP_PART_INIT;
use tsra_ddi_tbor_types::TBOR_OP_PSK_CHANGE;
use tsra_ddi_tbor_types::TBOR_OP_RSA_MOD_EXP;
use tsra_ddi_tbor_types::TBOR_OP_SD_CREATE_PEER_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_CREATE_REMOTE_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_RESEAL_REMOTE_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_RESTORE_LOCAL_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_RESTORE_PEER_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_RESTORE_REMOTE_BACKUP;
use tsra_ddi_tbor_types::TBOR_OP_SD_SEALING_KEY_GEN;
use tsra_ddi_tbor_types::TBOR_OP_SESSION_CLOSE;
use tsra_ddi_tbor_types::TBOR_OP_SESSION_OPEN_FINISH;
use tsra_ddi_tbor_types::TBOR_OP_SESSION_OPEN_INIT;
use tsra_ddi_tbor_types::TBOR_OP_UNWRAP_KEY;
use tsra_ddi_tbor_types::TBOR_OP_VERIFY_KEY;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// Every known opcode that carries request fields, i.e. all of them
/// except `ApiRev` and `PartInfo`.
const OPCODES: &[u8] = &[
    TBOR_OP_SESSION_OPEN_INIT,
    TBOR_OP_SESSION_OPEN_FINISH,
    TBOR_OP_SESSION_CLOSE,
    TBOR_OP_PSK_CHANGE,
    TBOR_OP_PART_INIT,
    TBOR_OP_PART_FINAL,
    TBOR_OP_SD_SEALING_KEY_GEN,
    TBOR_OP_SD_CREATE_REMOTE_BACKUP,
    TBOR_OP_SD_RESEAL_REMOTE_BACKUP,
    TBOR_OP_SD_RESTORE_REMOTE_BACKUP,
    TBOR_OP_SD_RESTORE_LOCAL_BACKUP,
    TBOR_OP_SD_CREATE_PEER_BACKUP,
    TBOR_OP_SD_RESTORE_PEER_BACKUP,
    TBOR_OP_KEY_REPORT,
    TBOR_OP_HMAC_GENERATE_KEY,
    TBOR_OP_HMAC,
    TBOR_OP_GET_UNWRAPPING_KEY,
    TBOR_OP_UNWRAP_KEY,
    TBOR_OP_AES_GENERATE_KEY,
    TBOR_OP_AES_ENCRYPT_DECRYPT,
    TBOR_OP_ECC_GENERATE_KEY,
    TBOR_OP_ECC_SIGN,
    TBOR_OP_ECDH_DERIVE,
    TBOR_OP_RSA_MOD_EXP,
    TBOR_OP_HASH,
    TBOR_OP_HKDF_DERIVE,
    TBOR_OP_CONCAT_KDF_DERIVE,
    TBOR_OP_GET_CERT_CHAIN_INFO,
    TBOR_OP_GET_CERTIFICATE,
    TBOR_OP_DARC_KEX_KEY_GEN,
    TBOR_OP_DARC_TMK_IMPORT,
    TBOR_OP_DARC_KEY_UNWRAP,
    TBOR_OP_DARC_TMK_GEN,
    TBOR_OP_DARC_TMK_EXPORT,
    TBOR_OP_DARC_KEY_WRAP,
    TBOR_OP_MLDSA_GENERATE_KEY,
    TBOR_OP_MLDSA_SIGN,
    TBOR_OP_MLDSA_VERIFY,
    TBOR_OP_MLKEM_GENERATE_KEY,
    TBOR_OP_MLKEM_ENCAPSULATE,
    TBOR_OP_MLKEM_DECAPSULATE,
    TBOR_OP_AES_GCM_ENCRYPT_DECRYPT,
    TBOR_OP_AES_XTS_ENCRYPT_DECRYPT,
    TBOR_OP_AES_XTS_GENERATE_KEY,
    TBOR_OP_GET_PUBLIC_KEY,
    TBOR_OP_VERIFY_KEY,
];

/// A request for `opcode` whose TOC is [`MAX_TOC_ENTRIES`] `none` entries.
struct AllNoneReq {
    opcode: u8,
    session_id: u16,
}

impl TborOpReq for AllNoneReq {
    // Transports take the opcode from the encoded header, which carries
    // the runtime `opcode`; this constant is only used for diagnostics.
    const OPCODE: u8 = 0;
    type OpResp = TborSessionCloseResp;

    fn get_session_id(&self) -> Option<u16> {
        match self.session_ctrl() {
            SessionControlKind::InSession | SessionControlKind::Close => Some(self.session_id),
            SessionControlKind::NoSession | SessionControlKind::Open => None,
        }
    }

    /// Mirrors the `session_ctrl` declared by the opcode's request type.
    fn session_ctrl(&self) -> SessionControlKind {
        match self.opcode {
            TBOR_OP_SESSION_OPEN_INIT => SessionControlKind::Open,
            TBOR_OP_SESSION_CLOSE => SessionControlKind::Close,
            TBOR_OP_GET_CERT_CHAIN_INFO | TBOR_OP_GET_CERTIFICATE => SessionControlKind::NoSession,
            _ => SessionControlKind::InSession,
        }
    }

    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], EncodeError> {
        let mut encoder = RequestEncoder::new(buf, PROTOCOL_VERSION, self.opcode);
        for _ in 0..MAX_TOC_ENTRIES {
            encoder = encoder.none()?;
        }
        encoder.finish()
    }
}

/// Every command rejects an all-`none` request with a TBOR error status,
/// and the session it was sent in stays usable.
#[test]
fn malformed_requests_for_every_command_are_rejected_and_session_survives() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for &opcode in OPCODES {
        let result = ctx.tbor(&AllNoneReq {
            opcode,
            session_id: session.session_id,
        });
        match result {
            Err(DdiError::TborStatus(status)) => assert_ne!(
                status.0, 0,
                "opcode {opcode:#04x}: rejection carries a non-zero status"
            ),
            other => panic!(
                "opcode {opcode:#04x}: expected a FW TBOR status rejection of an \
                 all-none request, got {other:?}"
            ),
        }

        let digest = ctx
            .tbor(&TborHashReq {
                session_id: session.session_id,
                algo: HASH_ALGO_SHA256,
                out_len: None,
                msg: b"abc".to_vec(),
            })
            .unwrap_or_else(|e| {
                panic!("opcode {opcode:#04x}: session unusable after malformed request: {e:?}")
            })
            .digest;
        assert_eq!(digest.len(), 32, "opcode {opcode:#04x}: SHA-256 digest");
    }
}
