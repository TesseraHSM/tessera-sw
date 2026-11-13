// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device-IO half of the TBOR session-establishment harness.
//!
//! The pure session crypto — ephemeral keygen, SEC1 ↔ `EccPublicKey`
//! conversion, HPKE `auth_psk` receive-export, confirm MACs, and the
//! `param_key` / `seed_envelope` derivations — lives in the reusable
//! [`tsra_session_ex_crypto`] crate and is called directly from
//! [`init`](super::init) and [`finish`](super::finish).
//!
//! Only the step that must touch the device stays here:
//!
//! * `pk_hsm` retrieval via the cert-chain (`GetCertChainInfo` +
//!   `GetCertificate`; MBOR on Uno, TBOR on Duo) — the production
//!   attestation path that reads the partition-ID cert (its
//!   SubjectPublicKeyInfo carries the P-384 key the FW uses as `pk_s`
//!   in HPKE `auth_psk`).

use tsra_crypto::*;
use tsra_ddi_interface::DdiError;
use tsra_ddi_mbor_test_helpers::helper_get_cert_chain_info;
use tsra_ddi_mbor_test_helpers::helper_get_certificate;
use tsra_ddi_tbor_types::*;

use crate::fixture::TestDev;

/// Fetch the DER partition-ID (leaf) certificate of cert slot 0 — the
/// production attestation path. Uno reads it over the MBOR cert-chain
/// commands; Duo, which has no MBOR, over their out-of-session TBOR
/// counterparts.
pub fn fetch_leaf_cert_der(dev: &TestDev) -> Result<Vec<u8>, DdiError> {
    if dev.uses_session_transport() {
        let mut cookie = None;
        let info: TborGetCertChainInfoResp =
            dev.exec_op_tbor(&TborGetCertChainInfoReq::new(0), None, &mut cookie)?;
        let num_certs = info.num_certs;
        if num_certs == 0 {
            return Err(DdiError::InvalidParameter);
        }
        let leaf: TborGetCertResp =
            dev.exec_op_tbor(&TborGetCertReq::new(0, num_certs - 1), None, &mut cookie)?;
        return Ok(leaf.certificate);
    }
    let info = helper_get_cert_chain_info(dev)?;
    let num_certs = info.data.num_certs;
    if num_certs == 0 {
        return Err(DdiError::InvalidParameter);
    }
    let leaf = helper_get_certificate(dev, num_certs - 1)?;
    Ok(leaf.data.certificate.as_slice().to_vec())
}

/// Look up the partition identity public key (`pk_hsm`) from the leaf
/// of the device cert chain (see [`fetch_leaf_cert_der`]). The leaf cert
/// is the partition-ID cert; its SubjectPublicKeyInfo carries the P-384
/// key the FW uses as `pk_s` in HPKE `auth_psk`.
///
/// Device IO is intentionally kept here (out of the pure
/// [`tsra_session_ex_crypto`] crate).
pub(super) fn fetch_pk_hsm(dev: &TestDev) -> Result<(EccPublicKey, [u8; PK_RESP_LEN]), DdiError> {
    let der = fetch_leaf_cert_der(dev)?;
    let pk_der = extract_subject_public_key_der(&der)?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| DdiError::InvalidParameter)?;
    let sec1 =
        tsra_session_ex_crypto::ec_pub_to_sec1(&pk).map_err(|_| DdiError::InvalidParameter)?;
    Ok((pk, sec1))
}

/// Pull the DER-encoded SubjectPublicKeyInfo out of an X.509
/// certificate. Uses [`x509::X509Certificate`] — the same parser the
/// MBOR test harness uses for the same purpose.
fn extract_subject_public_key_der(cert_der: &[u8]) -> Result<Vec<u8>, DdiError> {
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let cert = X509Certificate::from_der(cert_der).map_err(|_| DdiError::InvalidParameter)?;
    cert.get_public_key_der()
        .map_err(|_| DdiError::InvalidParameter)
}

/// Per-curve wire sizes: `(wire_coord_len, raw_coord_len)`.
///
/// `wire_coord_len` is the on-wire component size (P-521: 68 padded on a
/// little-endian device, 66 on a big-endian one); `raw_coord_len` is the
/// cryptographic component size (P-521: 66).
///
/// # Panics
///
/// Panics if `pub_len` is not a supported wire public-key length (64, 96,
/// 132, or 136).
pub fn coord_sizes(pub_len: usize) -> (usize, usize) {
    match pub_len {
        64 => (32, 32),
        96 => (48, 48),
        132 => (66, 66),
        136 => (68, 66),
        _ => panic!("unexpected public-key length {pub_len}"),
    }
}
