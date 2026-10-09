// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "emu")]

use std::cell::Cell;
use std::cell::RefCell;

use anyhow::Result;
use tsra_api::HsmEccCurve;
use tsra_api::HsmEccKeyGenAlgo;
use tsra_api::HsmEccSignAlgo;
use tsra_api::HsmError;
use tsra_api::HsmKeyClass;
use tsra_api::HsmKeyCommonProps;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmKeyPropsBuilder;
use tsra_api::HsmKeyScope;
use tsra_api::HsmPartition;
use tsra_api::HsmSession;
use tsra_api::HsmSignOp;
use tsra_api::PartPolicy;
use tsra_api::PartPolicyBuilder;
use tsra_api::PolicyKeyKind;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::VerifyOp;
use tsra_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::POLICY_INFO_LEN;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;
use tsra_sealing_api::device_cert_chain;
use tsra_sealing_api::mint_sealing_key;
use tsra_sealing_api::Error;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::PartitionState;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::SealingSession;
use tsra_sealing_api::SecurityDomain;
use tsra_sealing_api::SecurityDomainEnv;
use tsra_sealing_api::SecurityDomainState;
use tsra_sealing_api::SecurityDomainStore;
use tsra_sealing_api::RAW_PUB_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;
use zerocopy::IntoBytes;

#[path = "../../common/src/pki.rs"]
mod pki;

use pki::make_chain;
use pki::make_pta_chain;
use pki::thumbprint;
use pki::CaKey;

#[derive(Default)]
struct MemoryStore {
    records: RefCell<Option<(PartitionState, SecurityDomainState)>>,
    fail_save: Cell<bool>,
    saves: Cell<usize>,
}

impl SecurityDomainStore for MemoryStore {
    fn save_creation(
        &self,
        partition: &PartitionState,
        domain: &SecurityDomainState,
    ) -> Result<()> {
        self.saves.set(self.saves.get() + 1);
        anyhow::ensure!(!self.fail_save.get(), "recovery storage unavailable");
        *self.records.borrow_mut() = Some((partition.clone(), domain.clone()));
        Ok(())
    }

    fn load_partition(&self) -> Result<Option<PartitionState>> {
        Ok(self
            .records
            .borrow()
            .as_ref()
            .map(|(partition, _)| partition.clone()))
    }

    fn load_security_domain(&self) -> Result<Option<SecurityDomainState>> {
        Ok(self
            .records
            .borrow()
            .as_ref()
            .map(|(_, domain)| domain.clone()))
    }
}

struct TestEnv {
    policy: PartPolicy,
    pota_thumbprint: [u8; 48],
    sata_thumbprint: [u8; 48],
    mfgr_cert_chain: Vec<Vec<u8>>,
    fail_evidence: bool,
    store: MemoryStore,
}

impl SecurityDomainEnv for TestEnv {
    type Store = MemoryStore;

    fn policy(&self) -> &PartPolicy {
        &self.policy
    }

    fn pota_thumbprint(&self) -> &[u8] {
        &self.pota_thumbprint
    }

    fn sata_thumbprint(&self) -> &[u8] {
        &self.sata_thumbprint
    }

    fn sapota_thumbprint(&self) -> Option<&[u8]> {
        None
    }

    fn mfgr_cert_chain(&self) -> &[Vec<u8>] {
        &self.mfgr_cert_chain
    }

    fn owner_cert_chain(&self) -> &[Vec<u8>] {
        &[]
    }

    fn part_owner_cert_chain(
        &self,
        partition: &HsmPartition,
        pta_cert_chain: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        anyhow::ensure!(
            !self.fail_evidence,
            "sender certificate retrieval unavailable"
        );
        let pid = device_cert_chain(partition, 2)?;
        assert_eq!(pid.len(), 1, "slot 2 contains only the PID leaf");
        assert_ne!(
            pid,
            device_cert_chain(partition, 2)?,
            "each read signs a fresh PID certificate"
        );
        let mut chain = pta_cert_chain.to_vec();
        chain.extend(pid);
        Ok(chain)
    }

    fn store(&self) -> &Self::Store {
        &self.store
    }
}

fn assert_identity_chain(chain: &[Vec<u8>]) -> EccPublicKey {
    let certs = chain
        .iter()
        .rev()
        .map(|der| X509Certificate::from_der(der).expect("DER certificate"))
        .collect::<Vec<_>>();
    let leaf = certs.first().expect("PID leaf");
    assert!(
        leaf.validate_chain(&certs[1..])
            .expect("validate identity chain"),
        "{}-certificate PID chain failed validation",
        chain.len(),
    );
    EccPublicKey::from_bytes(&leaf.get_public_key_der().expect("PID SPKI")).expect("PID public key")
}

fn assert_sender_attestation(
    result: &RemoteBackup,
    policy: &PartPolicy,
    receiver_pub: &[u8; RAW_PUB_LEN],
) {
    assert_eq!(result.evidence.mfgr_cert_chain.len(), 4);
    assert!(result.evidence.owner_cert_chain.is_empty());
    assert_eq!(result.evidence.part_owner_cert_chain.len(), 3);
    let mfgr_pid = assert_identity_chain(&result.evidence.mfgr_cert_chain);
    let owner_pid = assert_identity_chain(&result.evidence.part_owner_cert_chain);
    result.evidence.with_hsm_evidence(|evidence| {
        assert_eq!(
            evidence.mfgr_cert_chain[0].cert,
            result.evidence.mfgr_cert_chain[0]
        );
        assert_eq!(
            evidence.part_owner_cert_chain[2].cert,
            result.evidence.part_owner_cert_chain[2]
        );
        assert!(evidence.owner_cert_chain.is_empty());
        assert_eq!(evidence.report, result.evidence.report);
    });
    let mut envelope = minicbor::Decoder::new(&result.evidence.report);
    assert_eq!(
        envelope.tag().expect("COSE tag"),
        minicbor::data::Tag::Unassigned(18),
    );
    assert_eq!(envelope.array().expect("COSE array"), Some(4));
    let protected = envelope.bytes().expect("protected header");
    envelope.skip().expect("unprotected header");
    let payload = envelope.bytes().expect("key-report payload");
    let signature = envelope.bytes().expect("ES384 signature");
    assert_eq!(signature.len(), 96);
    assert_eq!(envelope.position(), result.evidence.report.len());
    let mut encoded = minicbor::Encoder::new(Vec::new());
    encoded
        .array(4)
        .expect("Sig_structure")
        .str("Signature1")
        .expect("signature context")
        .bytes(protected)
        .expect("protected header")
        .bytes(&[])
        .expect("empty external AAD")
        .bytes(payload)
        .expect("payload");
    let signed = encoded.into_writer();
    for pid_key in [mfgr_pid, owner_pid] {
        assert!(EcdsaAlgo::new(HashAlgo::sha384())
            .verify(&pid_key, &signed, signature)
            .expect("verify PID report signature"));
    }

    let mut report = minicbor::Decoder::new(payload);
    let mut key = None;
    let mut key_size = None;
    let mut policy_hash = None;
    for _ in 0..report
        .map()
        .expect("report map")
        .expect("definite report map")
    {
        match report.u8().expect("report label") {
            0 => assert_eq!(report.u16().expect("report version"), 2),
            1 => key = Some(report.bytes().expect("COSE key")),
            2 => key_size = Some(usize::from(report.u16().expect("COSE key size"))),
            7 => policy_hash = Some(report.bytes().expect("policy hash")),
            _ => report.skip().expect("skip report field"),
        }
    }
    let key = key.expect("attested public key");
    let mut key = minicbor::Decoder::new(
        key.get(..key_size.expect("attested key size"))
            .expect("valid key size"),
    );
    let mut x = None;
    let mut y = None;
    for _ in 0..key.map().expect("key map").expect("definite key map") {
        match key.i64().expect("key label") {
            -2 => x = Some(key.bytes().expect("X coordinate")),
            -3 => y = Some(key.bytes().expect("Y coordinate")),
            _ => key.skip().expect("skip key field"),
        }
    }
    let mut sender_pub = x.expect("attested X").to_vec();
    assert_eq!(sender_pub.len(), 48);
    let y = y.expect("attested Y");
    assert_eq!(y.len(), 48);
    sender_pub.extend_from_slice(y);
    assert_ne!(
        sender_pub, receiver_pub,
        "sender key is distinct from receiver"
    );
    let mut expected_hash = [0u8; 48];
    HashAlgo::sha384()
        .hash(policy.as_bytes(), Some(&mut expected_hash))
        .expect("policy digest");
    assert_eq!(policy_hash.expect("attested policy hash"), expected_hash);
}

#[test]
fn evidence_adapter_preserves_all_attestation_material() {
    for evidence in [
        Evidence {
            mfgr_cert_chain: Vec::new(),
            owner_cert_chain: Vec::new(),
            part_owner_cert_chain: Vec::new(),
            report: Vec::new(),
        },
        Evidence {
            mfgr_cert_chain: vec![vec![1, 2], vec![3, 4]],
            owner_cert_chain: vec![vec![5, 6]],
            part_owner_cert_chain: vec![vec![7, 8], vec![9, 10]],
            report: vec![11, 12],
        },
    ] {
        evidence.with_hsm_evidence(|borrowed| {
            for (borrowed_chain, owned_chain) in [
                (borrowed.mfgr_cert_chain, &evidence.mfgr_cert_chain),
                (borrowed.owner_cert_chain, &evidence.owner_cert_chain),
                (
                    borrowed.part_owner_cert_chain,
                    &evidence.part_owner_cert_chain,
                ),
            ] {
                assert_eq!(borrowed_chain.len(), owned_chain.len());
                for (cert, bytes) in borrowed_chain.iter().zip(owned_chain) {
                    assert_eq!(cert.cert, bytes);
                    assert_eq!(cert.cert.as_ptr(), bytes.as_ptr());
                }
            }
            assert_eq!(borrowed.report, evidence.report);
            assert_eq!(borrowed.report.as_ptr(), evidence.report.as_ptr());
        });
    }
}

#[test]
fn pota_signer_private_der_roundtrip() -> Result<()> {
    let original = CaKey::generate();
    let reopened = CaKey::from_der(&original.private_key_der()?)?;
    assert_eq!(original.raw_pub(), reopened.raw_pub());
    assert!(CaKey::from_der(&[]).is_err());
    assert!(CaKey::from_der(&[0x30, 0x00]).is_err());
    Ok(())
}

#[test]
fn create_uses_external_receiver_credentials_and_restores_local_state() -> Result<()> {
    let mut tee_seed = [0u8; MACH_SEED_LEN];
    HashAlgo::sha256().hash(b"external-receiver-test", Some(&mut tee_seed))?;
    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let receiver = CaKey::generate();
    let pota_thumbprint = thumbprint(&pota.self_cert());
    let sata_thumbprint = thumbprint(&sata.self_cert());
    let evidence = Evidence {
        mfgr_cert_chain: Vec::new(),
        owner_cert_chain: Vec::new(),
        part_owner_cert_chain: Vec::new(),
        report: Vec::new(),
    };

    // Prepare the receiver before the source partition is initialized.
    // Also check that create forwards the chain, rather than replacing it.
    for (valid_anchor, fail_save, fail_evidence) in [
        (true, false, false),
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let chain = if valid_anchor {
            make_chain(&sata, &receiver.raw_pub())
        } else {
            make_chain(&CaKey::generate(), &receiver.raw_pub())
        };
        let session = SealingSession::open_reset()?;
        assert!(
            session.partition.cert_chain(2).is_err(),
            "slot 2 is unavailable before finalization"
        );
        let pid = session.partition.pid()?;
        let pid_pub = session.partition.ex_pub_key()?;
        let pid_pub: [u8; RAW_PUB_LEN] = pid_pub.as_slice().try_into()?;
        let env = TestEnv {
            policy: PartPolicyBuilder::new()
                .version(1, 0)
                .pota_key(PolicyKeyKind::Ecc384, &pota.raw_pub())
                .sata_key(PolicyKeyKind::Ecc384, &sata.raw_pub())
                .backup_part_id(&pid)
                .backup_part_pub_key(PolicyKeyKind::Ecc384, &pid_pub)
                .info(&[0xAB; POLICY_INFO_LEN])
                .allow_peer_cloning(true)
                .require_trusted_sa_key(false)
                .build()?,
            pota_thumbprint,
            sata_thumbprint,
            mfgr_cert_chain: device_cert_chain(&session.partition, 0)?,
            fail_evidence,
            store: MemoryStore {
                fail_save: Cell::new(fail_save),
                ..MemoryStore::default()
            },
        };
        let domain = SecurityDomain::new(env);
        let mut signer_called = false;
        let mut expected_pta_chain = Vec::new();
        let result = domain.create(
            &session,
            &tee_seed,
            &chain.certs(),
            &evidence,
            |csr, report| {
                signer_called = true;
                assert!(!csr.is_empty());
                assert!(!report.is_empty());
                let pta_chain = make_pta_chain(&pota, csr)?;
                expected_pta_chain = pta_chain.clone();
                Ok(pta_chain)
            },
        );
        assert!(signer_called);
        let store = domain.env().store();
        let partition = store.load_partition()?;
        let local = store.load_security_domain()?;
        if fail_save {
            assert!(partition.is_none());
            assert!(local.is_none());
            assert_eq!(store.saves.get(), 1);
            let error = result.expect_err("recovery persistence must fail");
            let Some(Error::SecurityDomainPersistence {
                partition,
                state,
                result: created,
                ..
            }) = error.downcast_ref::<Error>()
            else {
                panic!("missing unsaved recovery records");
            };
            assert_eq!(partition.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
            assert_eq!(partition.pta_cert_chain, expected_pta_chain);
            assert_eq!(state.pok_local_backup.len(), MASKED_SD_LEN);
            assert_eq!(state.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
            assert_eq!(created.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
            assert_sender_attestation(created, domain.env().policy(), &receiver.raw_pub());
        } else if fail_evidence {
            assert!(partition.is_none());
            assert!(local.is_none());
            assert_eq!(store.saves.get(), 0);
            let error = result.expect_err("retrieval must fail");
            let Some(Error::PartitionPersistence { state, .. }) = error.downcast_ref::<Error>()
            else {
                panic!("missing unsaved partition state");
            };
            assert_eq!(state.pta_cert_chain, expected_pta_chain);
            assert_eq!(state.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
            assert!(format!("{error:#}").contains("sender certificate retrieval unavailable"));
        } else if valid_anchor {
            assert_eq!(store.saves.get(), 1);
            let created = result?;
            assert_eq!(created.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
            assert!(created.pok_remote_backup.iter().any(|&byte| byte != 0));
            assert_sender_attestation(&created, domain.env().policy(), &receiver.raw_pub());
            assert_ecc_generation_compatibility(&session.session)?;
            assert_eq!(
                created.evidence.mfgr_cert_chain,
                device_cert_chain(&session.partition, 0)?
            );
            let partition = partition.expect("partition must be saved");
            assert_eq!(partition.policy, domain.env().policy().as_bytes());
            assert_eq!(partition.pta_cert_chain, expected_pta_chain);
            assert_eq!(partition.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
            let local = local.expect("local SD state must be saved");
            assert_eq!(local.pok_local_backup.len(), MASKED_SD_LEN);
            assert_eq!(local.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
            let retry = domain.create(&session, &tee_seed, &chain.certs(), &evidence, |_, _| {
                panic!("existing state must be rejected before initialization")
            });
            assert!(retry.is_err());
            assert!(store.load_partition()?.as_ref() == Some(&partition));
            assert!(store.load_security_domain()?.as_ref() == Some(&local));

            let original = (partition.clone(), local.clone());
            let mut short_backup = local.clone();
            short_backup.sd_mk_backup.pop();
            let mut changed_policy = domain.env().policy().clone();
            changed_policy.info[0] ^= 1;
            let mut changed_partition = partition.clone();
            changed_partition.policy = changed_policy.as_bytes().to_vec();
            for (records, expected) in [
                (None, "partition recovery state is missing"),
                (
                    Some((partition.clone(), short_backup)),
                    "invalid stored SD masking-key backup length",
                ),
                (
                    Some((changed_partition, local.clone())),
                    "stored partition policy does not match",
                ),
            ] {
                *store.records.borrow_mut() = records;
                let error = domain
                    .restore_local(&session, &tee_seed, |_, _| {
                        panic!("invalid state must be rejected before signing")
                    })
                    .expect_err("invalid recovery state must fail");
                assert!(error.to_string().contains(expected));
            }

            fn assert_ecc_generation_compatibility(session: &HsmSession) -> Result<()> {
                let challenge = b"existing ECC generation and signing remain compatible";
                let mut digest = [0u8; 48];
                HashAlgo::sha384().hash(challenge, Some(&mut digest))?;
                for is_session in [false, true] {
                    let expected_scope = if is_session {
                        HsmKeyScope::Session
                    } else {
                        HsmKeyScope::Local
                    };
                    let private_props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Private)
                        .key_kind(HsmKeyKind::Ecc)
                        .ecc_curve(HsmEccCurve::P384)
                        .is_session(is_session)
                        .scope(expected_scope)
                        .can_sign(true)
                        .build()?;
                    let public_props = HsmKeyPropsBuilder::default()
                        .class(HsmKeyClass::Public)
                        .key_kind(HsmKeyKind::Ecc)
                        .ecc_curve(HsmEccCurve::P384)
                        .is_session(is_session)
                        .can_verify(true)
                        .build()?;
                    let (private_key, public_key) = HsmKeyManager::generate_key_pair(
                        session,
                        &mut HsmEccKeyGenAlgo::default(),
                        private_props.clone(),
                        public_props.clone(),
                    )?;
                    let masked = private_key.masked_key_vec()?;
                    assert_eq!(
                        HsmEccSignAlgo::masked_key_info(&masked)?,
                        (expected_scope, HsmEccCurve::P384)
                    );
                    assert_eq!(
                        HsmEccSignAlgo::sign_masked(session, &masked, &digest, None)?,
                        96
                    );
                    let mut short_signature = [0u8; 95];
                    assert_eq!(
                        HsmEccSignAlgo::sign_masked(
                            session,
                            &masked,
                            &digest,
                            Some(&mut short_signature)
                        ),
                        Err(HsmError::BufferTooSmall)
                    );
                    assert_eq!(
                        HsmEccSignAlgo::sign_masked(session, &masked, &[0u8; 31], None),
                        Err(HsmError::InvalidArgument)
                    );
                    let mut signature = [0u8; 96];
                    HsmEccSignAlgo::default().sign(&private_key, &digest, Some(&mut signature))?;
                    let public_key = EccPublicKey::from_bytes(&public_key.pub_key_der_vec()?)?;
                    assert!(EcdsaAlgo::new(HashAlgo::sha384()).verify(
                        &public_key,
                        challenge,
                        &signature
                    )?);
                    HsmEccSignAlgo::sign_masked(session, &masked, &digest, Some(&mut signature))?;
                    assert!(EcdsaAlgo::new(HashAlgo::sha384()).verify(
                        &public_key,
                        challenge,
                        &signature
                    )?);
                    let (scoped_key, _) = HsmKeyManager::generate_key_pair(
                        session,
                        &mut HsmEccKeyGenAlgo::default(),
                        private_props,
                        public_props,
                    )?;
                    assert_eq!(
                        HsmEccSignAlgo::masked_key_info(&scoped_key.masked_key_vec()?)?,
                        (expected_scope, HsmEccCurve::P384)
                    );
                }
                Ok(())
            }
            *store.records.borrow_mut() = Some(original.clone());
            drop(session);

            let mut tampered = local;
            tampered.pok_local_backup[0] ^= 1;
            let invalid = (partition, tampered);
            *store.records.borrow_mut() = Some(invalid.clone());
            let reboot = SealingSession::open_reset()?;
            let error = domain
                .restore_local(&reboot, &tee_seed, |csr, _| make_pta_chain(&pota, csr))
                .expect_err("tampered local backup must fail");
            assert!(matches!(
                error.downcast_ref::<Error>(),
                Some(Error::PartitionPersistence { .. })
            ));
            assert!(format!("{error:#}").contains("sd_restore_local_backup"));
            assert!(store.records.borrow().as_ref() == Some(&invalid));
            assert_eq!(store.saves.get(), 1);
            drop(reboot);

            *store.records.borrow_mut() = Some(original);
            let reboot = SealingSession::open_reset()?;
            domain.restore_local(&reboot, &tee_seed, |csr, _| make_pta_chain(&pota, csr))?;
            assert_eq!(store.saves.get(), 2);
            mint_sealing_key(&reboot.session)?;
            let before_failure = store.records.borrow().clone();
            drop(reboot);

            store.fail_save.set(true);
            let reboot = SealingSession::open_reset()?;
            let error = domain
                .restore_local(&reboot, &tee_seed, |csr, _| make_pta_chain(&pota, csr))
                .expect_err("saving refreshed recovery must fail");
            let Some(Error::LocalRestorePersistence {
                partition, state, ..
            }) = error.downcast_ref::<Error>()
            else {
                panic!("missing refreshed local-restore recovery material");
            };
            assert_eq!(partition.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
            assert_eq!(state.pok_local_backup.len(), MASKED_SD_LEN);
            assert_eq!(state.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
            assert!(store.records.borrow().as_ref() == before_failure.as_ref());
            mint_sealing_key(&reboot.session)?;
            store.fail_save.set(false);
            store.save_creation(partition, state)?;
            assert!(store.load_partition()?.as_ref() == Some(partition));
            assert!(store.load_security_domain()?.as_ref() == Some(state));
        } else {
            let error = result.expect_err("receiver must be anchored to policy SATA");
            let Some(Error::PartitionPersistence { state, .. }) = error.downcast_ref::<Error>()
            else {
                panic!("missing unsaved partition state");
            };
            assert_eq!(state.local_mk_backup.len(), LOCAL_MK_BACKUP_LEN);
            assert_eq!(state.pta_cert_chain, expected_pta_chain);
            assert!(partition.is_none());
            assert!(local.is_none());
            assert_eq!(store.saves.get(), 0);
        }
    }
    let reset = SealingSession::open_reset()?;
    assert!(
        reset.partition.cert_chain(2).is_err(),
        "reset revokes the previous slot-2 certificate"
    );
    Ok(())
}
