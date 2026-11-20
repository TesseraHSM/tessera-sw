// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the TBOR security-domain (`session_ex`) integration
//! tests, which run against a real backend (the FW emulator or hardware).
//!
//! These exercise the public `tsra_api` surface end to end.
//! `open_session_ex` / `part_*` run against the partition's *default* PSK
//! and identity key, so they need only a freshly reset partition — no MBOR
//! credential establishment (`init`).

use std::collections::HashSet;
use std::sync::LazyLock;

use parking_lot::Mutex;
use tsra_api::*;

pub(crate) use crate::utils::partition::PARTITION_LOCK;

/// Controlled test enrollment only: trust the root advertised by the test
/// backend. Applications must provision this pin independently of the device.
pub(crate) fn test_root_spki_sha384(part: &HsmPartition) -> [u8; 48] {
    use tsra_crypto::HashAlgo;
    use tsra_crypto::Hasher;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let pem = part.cert_chain(0).expect("test certificate chain");
    let certificates = X509Certificate::from_pem_stack(pem.as_bytes()).expect("test certificates");
    let spki = certificates
        .last()
        .expect("test root certificate")
        .subject_public_key_info_der()
        .expect("test root SPKI");
    Hasher::hash_vec(&mut HashAlgo::sha384(), spki)
        .expect("test root hash")
        .try_into()
        .expect("SHA-384 length")
}

/// Open the backend's partition at its maximum supported revision and
/// reset its provisioning state. NSSR preserves PSKs and live session
/// reservations. Returns the partition and negotiated API revision.
pub(crate) fn new_partition() -> (HsmPartition, HsmApiRev) {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .expect("backend should advertise a partition");
    let rev = info
        .api_rev_range
        .expect("partition should report an api-rev range")
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev).expect("open partition");
    part.reset().expect("reset partition");
    (part, rev)
}

/// Open a provisioned-fixture CO session, retaining the known PSK across NSSR.
pub(crate) fn open_rotated_co_session(part: &HsmPartition, rev: HsmApiRev) -> HsmSession {
    static ROTATED_PARTITIONS: LazyLock<Mutex<HashSet<String>>> =
        LazyLock::new(|| Mutex::new(HashSet::new()));
    let mut rotated = ROTATED_PARTITIONS.lock();
    let path = part.path();
    let root = test_root_spki_sha384(part);
    let psk = &crate::utils::sd_provision::ROTATED_CO_PSK;
    if !rotated.contains(&path) {
        let bootstrap = part
            .open_session_ex(
                rev,
                &root,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionSuite::EcdhP384,
            )
            .expect("open bootstrap CO session");
        bootstrap.change_psk(psk).expect("rotate CO PSK");
        rotated.insert(path);
        drop(bootstrap);
    }
    part.open_session_ex(
        rev,
        &root,
        HsmSessionPsk::with_psk(HsmPskId::CO, psk),
        HsmSessionSuite::EcdhP384,
    )
    .expect("open rotated CO session")
}

/// Open a fresh partition and bring up a Crypto-Officer V2 session,
/// ready for the in-session provisioning commands (`part_init_ex` /
/// `part_final_ex`).
pub(crate) fn new_co_session() -> HsmSession {
    let (part, rev) = new_partition();
    part.open_session_ex(
        rev,
        &test_root_spki_sha384(&part),
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionSuite::EcdhP384,
    )
    .expect("open CO session")
}
