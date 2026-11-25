// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetCertificate` command.
//!
//! `GetCertificate` is an **out-of-session** command — the TBOR analogue
//! of MBOR `GetCertificate`. The host sends a `(slot_id, bank, cert_id)`
//! triple; the firmware writes the DER-encoded X.509 certificate at that
//! index of the partition slot's chain in that bank to out-of-band item
//! `0`, and reports the written length in the response. The firmware
//! returns the chain root->leaf: index `0` is the root and the last index
//! (`count - 1`) is the partition leaf (see
//! [`GetCertChainInfo`](crate::get_cert_chain_info) for the chain length).
//! No session is required.
//!
//! Both the request and response wire schemas are shared with the
//! firmware handler via `tsra_fw_ddi_tbor_types::get_cert`
//! (`fw/core/ddi/tbor/types/src/get_cert.rs`); this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values rather than borrowing `View<'a>` accessors.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use crate::tbor;
use crate::tbor_int::U16;

/// TBOR opcode for `GetCertificate`.
pub const TBOR_OP_GET_CERTIFICATE: u8 = 0x1F;

/// Maximum DER-encoded certificate length in bytes; an out-of-band
/// buffer of this size always holds the certificate.
pub const CERT_MAX_LEN: usize = 8192;

/// Certificate bank holding the P-384 chain.
pub const CERT_BANK_ECC: u8 = 0;

/// Certificate bank holding the ML-DSA-87 chain.
pub const CERT_BANK_MLDSA: u8 = 1;

/// Host-facing TBOR `GetCertificate` request.
///
/// The certificate is returned through out-of-band item `0`, which the
/// caller supplies as an output buffer of at least the certificate's
/// length ([`CERT_MAX_LEN`] always suffices).
#[tbor(opcode = TBOR_OP_GET_CERTIFICATE, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetCertReq {
    /// Certificate chain slot within the caller's partition.
    pub slot_id: u8,

    /// Certificate bank ([`CERT_BANK_ECC`] or [`CERT_BANK_MLDSA`]).
    pub bank: u8,

    /// Zero-based index into the chain.
    pub cert_id: u8,
}

impl TborGetCertReq {
    /// Construct a `GetCertificate` request.
    #[inline]
    pub const fn new(slot_id: u8, bank: u8, cert_id: u8) -> Self {
        Self {
            slot_id,
            bank,
            cert_id,
        }
    }
}

/// Host-facing TBOR `GetCertificate` response.
///
/// Field order mirrors the firmware schema in
/// `tsra_fw_ddi_tbor_types::get_cert`; the two MUST stay in sync so the
/// TOC layouts match.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetCertResp {
    /// Number of DER bytes written to out-of-band item `0`.
    pub cert_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborGetCertReq::new(1, CERT_BANK_MLDSA, 2);
        let mut buf = [0u8; 64];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");
        assert!(
            frame.contains(&1u8) && frame.contains(&2u8),
            "encoded frame must carry the slot, bank and cert ids",
        );
    }
}
