// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain sealing-key minting for the sealing example.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmKeyClass;
use tsra_api::HsmKeyCommonProps;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmKeyProps;
use tsra_api::HsmKeyPropsBuilder;
use tsra_api::HsmKeyReportOp;
use tsra_api::HsmPartition;
use tsra_api::HsmSealingKeyGenAlgo;
use tsra_api::HsmSession;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPublicKey;
use tsra_crypto::ImportableKey;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Length of raw P-384 public coordinates (`X || Y`).
pub const RAW_PUB_LEN: usize = 96;

/// Read a device's leaf-first PEM slot as root-first DER certificates.
/// Its leaf must certify the partition PID key. Slot 2 supplies only the PID
/// leaf; the application supplies the POTA/PTA prefix.
pub fn device_cert_chain(partition: &HsmPartition, slot: u8) -> Result<Vec<Vec<u8>>> {
    let pem = partition
        .cert_chain(slot)
        .with_context(|| format!("read certificate slot {slot}"))?;
    let certs = X509Certificate::from_pem_stack(pem.as_bytes())
        .with_context(|| format!("parse certificate slot {slot}"))?;
    let leaf = certs.first().context("device certificate slot is empty")?;
    let key = EccPublicKey::from_bytes(&leaf.get_public_key_der()?)?;
    let (x, y) = key.coord_vec()?;
    let mut public = x;
    public.extend_from_slice(&y);
    anyhow::ensure!(
        public == partition.ex_pub_key()?,
        "certificate slot {slot} does not certify the partition PID key",
    );
    Ok(certs
        .iter()
        .rev()
        .map(|cert| cert.as_der().to_vec())
        .collect())
}

/// A freshly minted security-domain sealing key.
pub struct SealingKey {
    /// The masked sealing-key blob (sealed under the partition-local
    /// masking key). `sd_create_remote_backup` uses it as the sender key.
    pub masked: Vec<u8>,
    /// COSE_Sign1 `KeyReport` containing the public key and attesting it
    /// (signed by the PID).
    pub report: Vec<u8>,
}

/// Well-formed sealing-key props: a `Sealing`-kind P-384 secret key
/// permitted for derivation only.
pub fn sealing_props() -> Result<HsmKeyProps> {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .context("build sealing key props")
}

/// Mint an SD sealing key on `session` and return its masked blob and a
/// COSE_Sign1 `KeyReport` containing and attesting its public key.
pub fn mint_sealing_key(session: &HsmSession) -> Result<SealingKey> {
    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(session, &mut algo, sealing_props()?)
        .context("generate sealing key")?;

    let masked = key.masked_key_vec().context("masked sealing key")?;

    let report_data = [0u8; KEY_REPORT_DATA_LEN];
    let report_len = key
        .generate_key_report(&report_data, None)
        .context("key report size")?;
    let mut report = vec![0u8; report_len];
    let written = key
        .generate_key_report(&report_data, Some(&mut report))
        .context("key report")?;
    report.truncate(written);

    Ok(SealingKey { masked, report })
}
