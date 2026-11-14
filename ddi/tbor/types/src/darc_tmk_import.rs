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

use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `DarcTmkImport`.
pub const TBOR_OP_DARC_TMK_IMPORT: u8 = 0x21;

/// Plaintext length of a DARC Transfer Masking Key (256-bit key).
pub const TMK_LEN: usize = 32;

/// On-the-wire length: `header(113) || enc(97) || ct(TMK 32 + tag 16)`
/// (matches the firmware schema's `SEALED_TMK_LEN`).
pub const SEALED_TMK_LEN: usize = 258;

/// Maximum PID-signed DARC operation-report length.
pub const DARC_REPORT_MAX_LEN: usize = 896;
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

    /// The receiver's masked DARC key-exchange key (from `DarcKexKeyGen`),
    /// exactly [`MASKED_KEX_KEY_LEN`] (280 B).  Unmasked on-device to
    /// recover the receiver's private HPKE key (`RcvrPriv`).
    #[tbor(align = 4)]
    pub masked_kex_key: [u8; MASKED_KEX_KEY_LEN],

    /// Unified [`PartPolicy`] whose `pota_spki_thumbprint` anchors
    /// `remote_cert_chain`.  Encoded as its 584-byte little-endian image.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,

    /// Canonical HPKE Base envelope of the 32-byte TMK, exactly 258 bytes.
    pub sealed_tmk: [u8; SEALED_TMK_LEN],

    /// PID-signed version-3 `Darc` report binding this envelope.
    #[tbor(min_len = 1, max_len = 896)]
    pub report: Vec<u8>,

    /// Sender certificate-chain descriptors `(index, length)` referencing
    /// the out-of-band SGL Data Blocks; carries 1..=3 entries. The chain
    /// must be POTA-anchored and its leaf must carry the reporting PID key,
    /// not the former sender KEX key.
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
            masked_kex_key: [0u8; MASKED_KEX_KEY_LEN],
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            sealed_tmk: [0xABu8; SEALED_TMK_LEN],
            report: alloc::vec![0xCD; 320],
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

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 584-byte policy plus the masked key and sealed TMK must be
        // carried in the data section.
        assert!(
            frame.len() > 584 + MASKED_KEX_KEY_LEN + SEALED_TMK_LEN,
            "encoded frame must carry the policy, masked key, and sealed TMK",
        );
    }
}
