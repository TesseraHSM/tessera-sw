// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `DarcTmkImport` command.
//!
//! `DarcTmkImport` is an **in-session** Crypto-Officer command that
//! imports a DARC Transfer Masking Key (TMK) sealed off-device to a DARC
//! key-exchange key (see `DarcKexKeyGen`) and re-masks it locally under
//! the partition security-domain masking key (SDMK).  The 32-byte TMK is
//! recovered by HPKE Base after checking its operation report against the
//! POTA-endorsed source PID and its binding to the actual recipient key.
//!
//! The wire schema is shared with the firmware handler via
//! `tsra_fw_ddi_tbor_types::darc_tmk_import`; this module adds the
//! host-facing value types so `exec_op_tbor` returns owned response
//! values.  The DER certificate bytes of `remote_cert_chain` travel out
//! of band (as SGL Data Blocks) alongside the request.

use alloc::vec::Vec;

use crate::tbor;
use crate::CertDescriptor;
use crate::ReportDescriptor;

/// TBOR opcode for `DarcTmkImport`.
pub const TBOR_OP_DARC_TMK_IMPORT: u8 = 0x21;

/// Plaintext length of a DARC Transfer Masking Key (256-bit key).
pub const TMK_LEN: usize = 32;

/// On-the-wire length of a P-384 envelope: `header(113) || enc(97) ||
/// ct(TMK 32 + tag 16)` (matches the firmware schema's `SEALED_TMK_LEN`).
pub const SEALED_TMK_LEN: usize = 258;
/// Largest envelope (MLKEM1024-P384 `enc` of 1665 bytes).
pub const SEALED_TMK_MAX_LEN: usize = 113 + 1665 + TMK_LEN + 16;

/// Maximum PID-signed DARC operation-report length (ML-DSA-87 signer).
pub const DARC_REPORT_MAX_LEN: usize = 5120;
/// Out-of-band item that receives the `DarcTmkExport` report; request
/// descriptors index the items after it.
pub const DARC_REPORT_OOB_INDEX: usize = 0;
/// Maximum source-chain depth, including POTA -> PTA -> PID.
pub const DARC_SOURCE_CERT_CHAIN_MAX_CERTS: usize = 3;

/// On-the-wire length of the `masked_tmk` output envelope (matches the
/// firmware schema's `MASKED_TMK_LEN`).
pub const MASKED_TMK_LEN: usize = 264;

/// Host-facing TBOR `DarcTmkImport` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches
/// the device.
#[tbor(opcode = TBOR_OP_DARC_TMK_IMPORT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcTmkImportReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The receiver's masked DARC key-exchange key (from `DarcKexKeyGen`;
    /// 264..=296 B).  Unmasked on-device to recover the receiver's private
    /// HPKE key (`RcvrPriv`).
    #[tbor(align = 4, min_len = 264, max_len = 296)]
    pub masked_kex_key: Vec<u8>,

    /// Unified [`PartPolicy`] whose `pota_spki_thumbprint` anchors
    /// `remote_cert_chain`.  Encoded as its 584-byte little-endian image.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,

    /// Canonical HPKE Base envelope of the 32-byte TMK (258..=1826 B).
    #[tbor(min_len = 258, max_len = 1826)]
    pub sealed_tmk: Vec<u8>,

    /// Descriptor of the out-of-band PID-signed `Darc` report binding this
    /// envelope.
    pub report: ReportDescriptor,

    /// Sender certificate-chain descriptors `(index, length)` referencing
    /// the out-of-band SGL Data Blocks; carries 1..=3 entries. The chain
    /// must be POTA-anchored and its leaf must carry the reporting PID key
    /// (P-384 or ML-DSA-87).
    #[tbor(min_len = 3, max_len = 9)]
    pub remote_cert_chain: Vec<CertDescriptor>,
}

/// Host-facing TBOR `DarcTmkImport` response.
///
/// The byte field is an owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborDarcTmkImportResp {
    /// The imported TMK, masked under the partition SDMK (exactly 264 B on
    /// the wire; the firmware schema is the length authority).
    #[tbor(align = 4, max_len = 264)]
    pub masked_tmk: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_encodes_all_fields() {
        let req = TborDarcTmkImportReq {
            session_id: 9,
            masked_kex_key: alloc::vec![0; crate::MASKED_KEX_KEY_MAX_LEN],
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            sealed_tmk: alloc::vec![0xAB; SEALED_TMK_MAX_LEN],
            report: ReportDescriptor {
                index: 3,
                length: U16::new(4700),
            },
            remote_cert_chain: alloc::vec![
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

        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The policy plus the masked key and sealed TMK must be carried in
        // the data section.
        assert!(
            frame.len()
                > crate::policy::PART_POLICY_MAX_LEN
                    + crate::MASKED_KEX_KEY_MAX_LEN
                    + SEALED_TMK_MAX_LEN,
            "encoded frame must carry the policy, masked key, and sealed TMK",
        );
    }
}
