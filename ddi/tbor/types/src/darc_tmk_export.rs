// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcTmkExport` command.
//!
//! `DarcTmkExport` is an **in-session** Crypto-Officer command that seals
//! a locally-masked DARC Transfer Masking Key (TMK) to a remote target so
//! the target can import it with `DarcTmkImport`.  It is the source-side
//! mirror of `DarcTmkImport`: it unmasks the caller's `masked_tmk`,
//! recovers the HPKE sender private key from `masked_sender_key`, verifies
//! the target's `target_cert_chain` anchored to the policy `DATAPubKey`
//! (recovering the target's public key), and HPKE-Auth-seals the 32-byte
//! TMK to it — producing a 145-byte `sealed_tmk` byte-compatible with
//! what `DarcTmkImport` consumes.
//!
//! The wire schema is shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::darc_tmk_export`; this module adds the
//! host-facing value types so `exec_op_tbor` returns owned response
//! values.  The DER certificate bytes of `target_cert_chain` travel out
//! of band (as SGL Data Blocks) alongside the request.

use alloc::vec::Vec;

use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
use crate::darc_tmk_import::MASKED_TMK_LEN;
use crate::darc_tmk_import::SEALED_TMK_LEN;
use crate::policy::PartPolicy;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `DarcTmkExport`.
pub const TBOR_OP_DARC_TMK_EXPORT: u8 = 0x24;

/// Host-facing TBOR `DarcTmkExport` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches
/// the device.
#[tbor(opcode = TBOR_OP_DARC_TMK_EXPORT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcTmkExportReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The source's masked DARC key-exchange key (from `DarcKexKeyGen`),
    /// exactly [`MASKED_KEX_KEY_LEN`] (280 B).  Unmasked on-device to
    /// recover the HPKE sender private key (`SndrPriv`).
    pub masked_sender_key: [u8; MASKED_KEX_KEY_LEN],

    /// The locally-masked TMK envelope (from `DarcTmkGen` /
    /// `DarcTmkImport`), exactly [`MASKED_TMK_LEN`] (264 B).  Unmasked
    /// on-device to recover the 32-byte TMK plaintext.
    pub masked_tmk: [u8; MASKED_TMK_LEN],

    /// Unified [`PartPolicy`] whose `DATAPubKey` anchors
    /// `target_cert_chain`.  Encoded as its 584-byte little-endian image.
    pub policy: PartPolicy,

    /// Target certificate-chain descriptors `(index, length)` referencing
    /// the out-of-band SGL Data Blocks; carries 1..=2 entries.  The chain
    /// must be DATA-anchored; its terminal certificate carries the
    /// target's HPKE receiver public key that `sealed_tmk` is sealed to.
    #[tbor(min_len = 3, max_len = 6)]
    pub target_cert_chain: Vec<CertDescriptor>,
}

/// Host-facing TBOR `DarcTmkExport` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborDarcTmkExportResp {
    /// The HPKE-Auth-sealed TMK (exactly [`SEALED_TMK_LEN`] = 145 B on the
    /// wire; the firmware schema is the length authority).  A fixed-length
    /// `[u8; N]` field so host decode enforces the exact length —
    /// rejecting any malformed frame — instead of allocating from the
    /// encoded length.  Byte-for-byte what `DarcTmkImport` consumes.
    pub sealed_tmk: [u8; SEALED_TMK_LEN],
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_encodes_all_fields() {
        let req = TborDarcTmkExportReq {
            session_id: 9,
            masked_sender_key: [0u8; MASKED_KEX_KEY_LEN],
            masked_tmk: [0u8; MASKED_TMK_LEN],
            policy: PartPolicy::zeroed(),
            target_cert_chain: alloc::vec![
                CertDescriptor {
                    index: 0,
                    length: U16::new(32),
                },
                CertDescriptor {
                    index: 1,
                    length: U16::new(64),
                },
            ],
        };

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 584-byte policy plus the masked keys must be carried in the
        // data section.
        assert!(frame.len() > 584 + MASKED_KEX_KEY_LEN + MASKED_TMK_LEN);
    }
}
