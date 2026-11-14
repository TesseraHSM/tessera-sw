// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertificate` wire schema.
//!
//! `GetCertificate` is an **out-of-session** command — the TBOR analogue
//! of MBOR `GetCertificate`.  The host sends a `(slot_id, bank, cert_id)`
//! triple; the firmware writes the DER-encoded X.509 certificate at that
//! index of the partition slot's chain in the requested bank to
//! out-of-band item `0`.  The firmware returns the chain root->leaf:
//! index `0` is the root and the last index (`count - 1`) is the
//! partition leaf (see [`GetCertChainInfo`](crate::get_cert_chain_info)
//! for the chain length).  No session is required.
//!
//! Inputs:
//!
//! * `slot_id` — the certificate chain slot within the caller's
//!   partition.
//! * `bank` — the chain's bank: [`CERT_BANK_ECC`] for the P-384 chain,
//!   [`CERT_BANK_MLDSA`] for the ML-DSA-87 chain.
//! * `cert_id` — zero-based certificate index; must satisfy
//!   `cert_id < num_certs` from `GetCertChainInfo` for the same slot and
//!   bank.
//! * Out-of-band item `0` — host buffer that receives the certificate.
//!   Its length is a capacity; [`CERT_MAX_LEN`] always suffices.
//!
//! Outputs:
//!
//! * `cert_len` — the number of DER bytes written to out-of-band item
//!   `0`, at most [`CERT_MAX_LEN`] (8192).

use tsra_fw_ddi_tbor_api::tbor;

use crate::tbor_int::U16;

/// TBOR opcode for `GetCertificate`.
pub const TBOR_OP_GET_CERTIFICATE: u8 = 0x1F;

/// Maximum DER-encoded certificate length in bytes.  Large enough for an
/// ML-DSA-87 certificate signed by an ML-DSA-87 issuer.
pub const CERT_MAX_LEN: usize = 8192;

/// Certificate bank holding the P-384 chain.
pub const CERT_BANK_ECC: u8 = 0;

/// Certificate bank holding the ML-DSA-87 chain.
pub const CERT_BANK_MLDSA: u8 = 1;

/// Out-of-band item that receives the certificate.
pub const CERT_OOB_INDEX: usize = 0;

/// `GetCertificate` request schema.
#[tbor(opcode = 0x1F, pair = TborGetCertResp)]
pub struct TborGetCertReq {
    /// Certificate chain slot within the caller's partition.
    #[tbor(U8)]
    pub slot_id: u8,

    /// Certificate bank ([`CERT_BANK_ECC`] or [`CERT_BANK_MLDSA`]).
    #[tbor(U8)]
    pub bank: u8,

    /// Zero-based index into the chain.
    #[tbor(U8)]
    pub cert_id: u8,
}

/// `GetCertificate` response schema.
#[tbor(response, pair = TborGetCertReq)]
pub struct TborGetCertResp {
    /// Number of DER bytes written to out-of-band item `0`.
    pub cert_len: U16,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 64];
        let frame = TborGetCertReq::encode(&mut buf)
            .unwrap()
            .slot_id(1)
            .unwrap()
            .bank(CERT_BANK_MLDSA)
            .unwrap()
            .cert_id(2)
            .unwrap()
            .finish();
        assert_eq!(frame.slot_id(), 1);
        assert_eq!(frame.bank(), CERT_BANK_MLDSA);
        assert_eq!(frame.cert_id(), 2);
    }

    #[test]
    fn response_round_trips_cert_len() {
        let mut buf = [0u8; 64];
        let frame = TborGetCertResp::encode(&mut buf, 0, false)
            .unwrap()
            .cert_len(U16::new(7700))
            .unwrap()
            .finish();
        assert_eq!(frame.cert_len().get(), 7700);
    }
}
