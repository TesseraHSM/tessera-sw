// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side PKI for the sealing example: a synthetic P-384 certificate
//! authority (`CaKey`) and the X.509 chains the security-domain flow
//! needs — the POTA-anchored PTA chain handed back to `part_final_ex`,
//! and the root → leaf attestation/receiver chains carried in the backup
//! evidence.
//!
//! Demo trust keys and certificate issuance belong to the root service,
//! not the reusable device-facing sealing API.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmCert;
use tsra_crypto::x509_builder::cert_builder;
use tsra_crypto::x509_builder::cert_builder::IntermediateCertParams;
use tsra_crypto::x509_builder::cert_builder::KeyUsage;
use tsra_crypto::x509_builder::cert_builder::LeafCertParams;
use tsra_crypto::x509_builder::cert_builder::RootCertParams;
use tsra_crypto::x509_builder::cert_builder::CN_LEN;
use tsra_crypto::x509_builder::cert_builder::SN_LEN;
use tsra_crypto::x509_builder::leaf_cert;
use tsra_crypto::x509_builder::root_cert;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::SignOp;
use tsra_sealing_api::RAW_PUB_LEN;

/// Length of a SEC1 uncompressed P-384 public point (`0x04 ‖ X ‖ Y`).
pub const SEC1_PUB_LEN: usize = 97;

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "TSRA POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const LEAF_CN: &str = "TSRA Evidence Leaf";
const LEAF_SN: &str = "EVLEAF001";

/// A synthetic P-384 CA key — a policy trust anchor (POTA / SATA /
/// SAPOTA) that signs certificates and exposes its public key.
pub struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    pub fn generate() -> Self {
        let private_key = EccPrivateKey::from_curve(EccCurve::P384).expect("P-384 key");
        Self::from_private_key(private_key).expect("P-384 CA key")
    }

    /// Reopen the original POTA signer from its saved private-key DER.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let private_key = EccPrivateKey::from_bytes(bytes).context("import saved POTA key")?;
        Self::from_private_key(private_key)
    }

    /// Export the demo signer for protected recovery storage, never for output.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        self.private_key
            .to_vec()
            .context("export POTA key for recovery")
    }

    fn from_private_key(private_key: EccPrivateKey) -> Result<Self> {
        anyhow::ensure!(
            private_key.curve() == EccCurve::P384,
            "POTA signing key must use P-384"
        );
        let (x, y) = private_key.coord_vec().context("POTA public coordinates")?;
        anyhow::ensure!(
            x.len() == 48 && y.len() == 48,
            "invalid POTA public coordinates"
        );
        let mut pub_sec1 = [0u8; SEC1_PUB_LEN];
        pub_sec1[0] = 0x04;
        pub_sec1[1..49].copy_from_slice(&x);
        pub_sec1[49..97].copy_from_slice(&y);
        Ok(Self {
            private_key,
            pub_sec1,
        })
    }

    /// Raw `X ‖ Y` (96-byte) public coordinates — the policy `PubKey`
    /// form.
    pub fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        self.pub_sec1[1..].try_into().expect("raw pub")
    }

    /// Self-signed root certificate (DER) for this CA.
    pub fn self_cert(&self) -> Vec<u8> {
        build_root(self)
    }

    /// SHA-1 of the SEC1 public key — the Subject Key Identifier.
    fn ski(&self) -> [u8; 20] {
        sha1_ski(&self.pub_sec1)
    }

    /// ECDSA-P384 / SHA-384 sign `tbs`, returning `(r, s)` (48 bytes each).
    fn sign(&self, tbs: &[u8]) -> ([u8; 48], [u8; 48]) {
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        let mut sig = [0u8; 96];
        let written = algo
            .sign(&self.private_key, tbs, Some(&mut sig))
            .expect("sign");
        assert_eq!(written, 96, "P-384 raw signature is 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..]);
        (r, s)
    }
}

/// SHA-384 thumbprint of a DER certificate — the policy anchor thumbprint
/// (POTA / SATA / SAPOTA) bound at `part_init_ex`. SHA-384 produces exactly
/// the 48-byte `*_THUMBPRINT_LEN` the firmware stores.
pub fn thumbprint(cert_der: &[u8]) -> [u8; 48] {
    let mut algo = HashAlgo::sha384();
    let mut out = [0u8; 48];
    algo.hash(cert_der, Some(&mut out)).expect("sha384");
    out
}

/// SHA-1 of a SEC1 public key (Subject / Authority Key Identifier).
fn sha1_ski(sec1: &[u8; SEC1_PUB_LEN]) -> [u8; 20] {
    let mut algo = HashAlgo::sha1();
    let mut out = [0u8; 20];
    algo.hash(sec1, Some(&mut out)).expect("sha1");
    out
}

/// A 20-byte positive DER serial number seeded from `tag`.
fn serial(tag: u8) -> [u8; 20] {
    let mut s = [0u8; 20];
    s[0] = tag & 0x7F;
    for (i, b) in s.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    s
}

/// Pad a common name to the template's fixed CN field width.
fn pad_cn(cn: &str) -> [u8; CN_LEN] {
    let mut out = [b' '; CN_LEN];
    out[..cn.len()].copy_from_slice(cn.as_bytes());
    out
}

/// Pad a serial-number string to the template's fixed SN field width.
fn pad_sn(sn: &str) -> [u8; SN_LEN] {
    let mut out = [b'0'; SN_LEN];
    out[..sn.len()].copy_from_slice(sn.as_bytes());
    out
}

/// Build a self-signed POTA root CA certificate (DER).
fn build_root(ca: &CaKey) -> Vec<u8> {
    let params = RootCertParams {
        public_key: &ca.pub_sec1,
        serial_number: &serial(1),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: ROOT_SN,
        subject_key_id: &ca.ski(),
    };
    let mut tbs = root_cert::TBS_TEMPLATE;
    patch_tbs_root(&mut tbs, &params);
    let (r, s) = ca.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_root_cert(&params, &r, &s, &mut out).expect("root cert");
    out.truncate(len);
    out
}

/// Build the PTA intermediate CA certificate carrying the partition PTA
/// key (`pta_pub_sec1`), signed by `issuer` (the POTA CA).
fn build_pta_intermediate(
    pta_pub_sec1: &[u8; SEC1_PUB_LEN],
    issuer: &CaKey,
    subject: &[u8],
) -> Result<Vec<u8>> {
    let params = IntermediateCertParams {
        public_key: pta_pub_sec1,
        serial_number: &serial(2),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: "",
        subject_sn: "",
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(pta_pub_sec1),
        authority_key_id: &issuer.ski(),
        path_len: 0,
    };
    let mut tbs = [0u8; 1024];
    let tbs_len = cert_builder::intermediate_cert_tbs_with_subject_name(&params, subject, &mut tbs)
        .context("invalid or oversized PTA subject")?;
    let (r, s) = issuer.sign(&tbs[..tbs_len]);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::assemble_cert(&tbs[..tbs_len], &r, &s, &mut out)
        .context("assemble PTA certificate")?;
    out.truncate(len);
    Ok(out)
}

/// Build a POTA-anchored root → PTA chain preserving the partition CSR subject.
///
/// This is the local POTA **signing** step. When the POTA key lives
/// outside this process, sign remotely instead and return the complete
/// root-first list of DER certificates; `create` takes the signer as a
/// callback so the choice is the application's.
pub fn make_pta_chain(pota_ca: &CaKey, csr: &[u8]) -> Result<Vec<Vec<u8>>> {
    let public = pta_pub_from_csr(csr)?;
    let (_, cr, _) = der_tlv(csr)?;
    let (_, cri, _) = der_tlv(cr)?;
    let (_, _, after_version) = der_tlv(cri)?;
    let (_, _, after_subject) = der_tlv(after_version)?;
    let subject = &after_version[..after_version.len() - after_subject.len()];
    Ok(vec![
        build_root(pota_ca),
        build_pta_intermediate(&public, pota_ca, subject)?,
    ])
}

/// Build an **end-entity** leaf certificate whose subject public key is
/// `leaf_pub_sec1`, signed by `issuer`. `cA=false`, `digitalSignature`.
fn build_leaf(leaf_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = LeafCertParams {
        public_key: leaf_pub_sec1,
        serial_number: &serial(3),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: LEAF_CN,
        subject_sn: LEAF_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(leaf_pub_sec1),
        authority_key_id: &issuer.ski(),
        key_usage: KeyUsage::DIGITAL_SIGNATURE,
    };
    let mut tbs = leaf_cert::TBS_TEMPLATE;
    patch_tbs_leaf(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut out).expect("leaf cert");
    out.truncate(len);
    out
}

/// A generated root → leaf chain, DER-encoded: a self-signed root CA and
/// an end-entity leaf it certifies carrying the caller-supplied key.
pub struct GeneratedChain {
    pub root_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
}

impl GeneratedChain {
    /// The chain as an ordered `[root, leaf]` `HsmCert` list.
    pub fn certs(&self) -> [HsmCert<'_>; 2] {
        [
            HsmCert {
                cert: &self.root_der,
            },
            HsmCert {
                cert: &self.leaf_der,
            },
        ]
    }
}

/// Build a root → leaf chain: a self-signed root CA (`ca`) certifying an
/// end-entity leaf that carries `leaf_pub_raw` (raw `X ‖ Y`).
pub fn make_chain(ca: &CaKey, leaf_pub_raw: &[u8; RAW_PUB_LEN]) -> GeneratedChain {
    let mut leaf_sec1 = [0u8; SEC1_PUB_LEN];
    leaf_sec1[0] = 0x04;
    leaf_sec1[1..].copy_from_slice(leaf_pub_raw);
    GeneratedChain {
        root_der: build_root(ca),
        leaf_der: build_leaf(&leaf_sec1, ca),
    }
}

/// Extract the SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`) from a DER
/// PKCS#10 CSR (e.g. the `pta_csr` returned by `part_init_ex`).
pub fn pta_pub_from_csr(csr: &[u8]) -> Result<[u8; SEC1_PUB_LEN]> {
    use tsra_crypto::EccPublicKey;
    use x509::X509Csr;
    use x509::X509CsrOp;

    let csr = X509Csr::from_der(csr).context("parse PTA CSR")?;
    anyhow::ensure!(csr.verify()?, "invalid PTA CSR signature");
    let key = EccPublicKey::from_bytes(&csr.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    [vec![4], x, y]
        .concat()
        .try_into()
        .map_err(|_| anyhow::anyhow!("PTA CSR must contain a P-384 key"))
}

/// Read one bounded DER TLV: `(tag, contents, rest)`.
fn der_tlv(der: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    anyhow::ensure!(der.len() >= 2, "DER TLV: missing tag/length octet");
    let tag = der[0];
    let len_octet = der[1];
    let (len, header) = if len_octet & 0x80 == 0 {
        (usize::from(len_octet), 2)
    } else {
        let n = usize::from(len_octet & 0x7F);
        anyhow::ensure!(n > 0 && n <= 4 && der.len() >= 2 + n, "invalid DER length");
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(b)))
                .context("DER length overflow")?;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len).context("DER length overflow")?;
    anyhow::ensure!(der.len() >= end, "DER TLV: truncated content");
    Ok((tag, &der[header..end], &der[end..]))
}

/// Patch a root-cert TBS template with the variable field values.
fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    let cn = pad_cn(params.subject_cn);
    let sn = pad_sn(params.subject_sn);
    tbs[root_cert::PUBLIC_KEY_OFFSET..root_cert::PUBLIC_KEY_OFFSET + 97]
        .copy_from_slice(params.public_key);
    tbs[root_cert::SERIAL_NUMBER_OFFSET..root_cert::SERIAL_NUMBER_OFFSET + 20]
        .copy_from_slice(params.serial_number);
    tbs[root_cert::NOT_BEFORE_OFFSET..root_cert::NOT_BEFORE_OFFSET + 15]
        .copy_from_slice(params.not_before);
    tbs[root_cert::NOT_AFTER_OFFSET..root_cert::NOT_AFTER_OFFSET + 15]
        .copy_from_slice(params.not_after);
    tbs[root_cert::ISSUER_CN_OFFSET..root_cert::ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[root_cert::SUBJECT_CN_OFFSET..root_cert::SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[root_cert::ISSUER_SN_OFFSET..root_cert::ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[root_cert::SUBJECT_SN_OFFSET..root_cert::SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[root_cert::SUBJECT_KEY_ID_OFFSET..root_cert::SUBJECT_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.subject_key_id);
}

/// Patch a leaf-cert TBS template with the variable field values.
fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    let s_cn = pad_cn(params.subject_cn);
    let i_cn = pad_cn(params.issuer_cn);
    let s_sn = pad_sn(params.subject_sn);
    let i_sn = pad_sn(params.issuer_sn);
    tbs[leaf_cert::PUBLIC_KEY_OFFSET..leaf_cert::PUBLIC_KEY_OFFSET + 97]
        .copy_from_slice(params.public_key);
    tbs[leaf_cert::SERIAL_NUMBER_OFFSET..leaf_cert::SERIAL_NUMBER_OFFSET + 20]
        .copy_from_slice(params.serial_number);
    tbs[leaf_cert::NOT_BEFORE_OFFSET..leaf_cert::NOT_BEFORE_OFFSET + 15]
        .copy_from_slice(params.not_before);
    tbs[leaf_cert::NOT_AFTER_OFFSET..leaf_cert::NOT_AFTER_OFFSET + 15]
        .copy_from_slice(params.not_after);
    tbs[leaf_cert::ISSUER_CN_OFFSET..leaf_cert::ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&i_cn);
    tbs[leaf_cert::SUBJECT_CN_OFFSET..leaf_cert::SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&s_cn);
    tbs[leaf_cert::ISSUER_SN_OFFSET..leaf_cert::ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&i_sn);
    tbs[leaf_cert::SUBJECT_SN_OFFSET..leaf_cert::SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&s_sn);
    tbs[leaf_cert::SUBJECT_KEY_ID_OFFSET..leaf_cert::SUBJECT_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.subject_key_id);
    tbs[leaf_cert::AUTHORITY_KEY_ID_OFFSET..leaf_cert::AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[leaf_cert::KEY_USAGE_OFFSET..leaf_cert::KEY_USAGE_OFFSET + 2]
        .copy_from_slice(&params.key_usage.to_bytes());
}
