// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::COORD_LEN;
use common::SdOob;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_tbor_test_harness::x509_fixture::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::tbor_int::U16;
use tsra_ddi_tbor_types::*;

const CHAIN_LEAF_INDEX: usize = 1;
const POLICY_MUTATION_MASK: u8 = 1;

/// Every case starts with real keys, evidence, policy, and a source backup.
/// Mutations therefore exercise handler validation and crypto paths rather
/// than spending most fuzz iterations on undecodable request bytes.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Mutation {
    Valid,
    ResealTwice,
    MissingOob,
    EmptySourceChain,
    EmptyDestinationChain,
    PolicyHashMismatch,
    SourceCertificateOutOfRange,
    DestinationReportOutOfRange,
    TamperSourceEvidence { mask: u8 },
    TamperDestinationEvidence { mask: u8 },
    WrongReceiverKey,
    TamperSourceBackup { offset: u16, mask: u8 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    mutation: Mutation,
    key_scope: common::KeyScope,
}

struct ResealEvidence {
    oob_items: Vec<Vec<u8>>,
    src_mfgr: Vec<CertDescriptor>,
    src_owner: Vec<CertDescriptor>,
    src_part_owner: Vec<CertDescriptor>,
    dest_mfgr: Vec<CertDescriptor>,
    dest_owner: Vec<CertDescriptor>,
    dest_part_owner: Vec<CertDescriptor>,
    dest_report: ReportDescriptor,
    src_leaf_index: usize,
    dest_leaf_index: usize,
}

impl ResealEvidence {
    /// Borrow the source and destination OOB evidence items as request slices.
    fn oob(&self) -> Vec<&[u8]> {
        self.oob_items.iter().map(Vec::as_slice).collect()
    }
}

struct Fixture {
    session_id: u16,
    request: TborSdResealRemoteBackupReq,
    evidence: ResealEvidence,
    src_remote_backup: Vec<u8>,
    wrong_receiver_key: Option<Vec<u8>>,
}

/// Append a certificate or report to the OOB items and return its descriptor.
fn push_item(items: &mut Vec<Vec<u8>>, bytes: &[u8]) -> CertDescriptor {
    let index = u8::try_from(items.len()).expect("fixture OOB item count is bounded");
    let length = u16::try_from(bytes.len()).expect("fixture evidence length fits U16");
    items.push(bytes.to_vec());
    CertDescriptor {
        index,
        length: U16::new(length),
    }
}

/// Append the root and leaf certificates to the OOB items in chain order
/// and return their descriptors.
fn push_chain(items: &mut Vec<Vec<u8>>, chain: &GeneratedChain) -> Vec<CertDescriptor> {
    vec![
        push_item(items, &chain.root_der),
        push_item(items, &chain.leaf_der),
    ]
}

/// Append manufacturer, owner, and POTA-rooted partition-owner chains for
/// the PID plus a key report. Return the chain descriptors, report descriptor,
/// and report's OOB index.
fn push_identity(
    items: &mut Vec<Vec<u8>>,
    pid_pub: &[u8; RAW_PUB_LEN],
    pota_key: &CaKey,
) -> (
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
    Vec<CertDescriptor>,
) {
    let mfgr = push_chain(items, &make_chain(&CaKey::generate(), pid_pub));
    let owner = push_chain(items, &make_chain(&CaKey::generate(), pid_pub));
    let part_owner = push_chain(items, &make_chain(pota_key, pid_pub));
    (mfgr, owner, part_owner)
}

/// Build source and destination evidence in a shared OOB item list, retaining
/// manufacturer leaf indices for targeted certificate mutations.
fn build_reseal_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    pota_key: &CaKey,
    dest_report: &[u8],
) -> ResealEvidence {
    let mut oob_items = common::sd_oob_items();
    let (src_mfgr, src_owner, src_part_owner) = push_identity(&mut oob_items, pid_pub, pota_key);
    let src_leaf_index = usize::from(src_mfgr[CHAIN_LEAF_INDEX].index);
    let (dest_mfgr, dest_owner, dest_part_owner) = push_identity(&mut oob_items, pid_pub, pota_key);
    let dest_leaf_index = usize::from(dest_mfgr[CHAIN_LEAF_INDEX].index);
    let report_item = push_item(&mut oob_items, dest_report);
    let dest_report = ReportDescriptor {
        index: report_item.index,
        length: report_item.length,
    };

    ResealEvidence {
        oob_items,
        src_mfgr,
        src_owner,
        src_part_owner,
        dest_mfgr,
        dest_owner,
        dest_part_owner,
        dest_report,
        src_leaf_index,
        dest_leaf_index,
    }
}

/// Convert a wire-LE P-384 public key into big-endian `x || y` bytes for
/// certificate generation.
fn public_key_from_wire(pub_key: &[u8]) -> [u8; RAW_PUB_LEN] {
    assert_eq!(pub_key.len(), RAW_PUB_LEN);

    let mut raw = [0u8; RAW_PUB_LEN];
    for (dst, src) in raw[..COORD_LEN]
        .iter_mut()
        .zip(pub_key[..COORD_LEN].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in raw[COORD_LEN..]
        .iter_mut()
        .zip(pub_key[COORD_LEN..].iter().rev())
    {
        *dst = *src;
    }
    raw
}

/// Generate a sealing key with the requested scope and attest it with
/// `KeyReport`. Return its masked key, report, and big-endian public key.
fn sealing_key_report_and_pub(
    ctx: &TestCtx,
    session_id: u16,
    key_scope: common::KeyScope,
) -> (Vec<u8>, Vec<u8>, [u8; RAW_PUB_LEN]) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: key_scope.to_tbor(),
            kem: TRANSFER_KEM_P384,
        })
        .expect("SdSealingKeyGen");
    let masked_key = seal.masked_key;
    let pub_key = public_key_from_wire(&seal.pub_key);
    let report = ctx
        .key_report(&TborKeyReportReq {
            session_id,
            masked_key: masked_key.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
            auth_envelope: Vec::new(),
        })
        .expect("KeyReport");
    (masked_key, report, pub_key)
}

/// Bind a policy to the partition's PID and supplied SATA and POTA keys, then
/// initialize and finalize the partition. Return the policy bytes and PID
/// public key.
fn build_policy_and_finalize(
    ctx: &TestCtx,
    session: &tsra_ddi_tbor_test_harness::SessionHandshake,
    sata_key: &CaKey,
    pota_key: &CaKey,
) -> (Vec<u8>, [u8; RAW_PUB_LEN]) {
    let part_info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let pid_pub: [u8; RAW_PUB_LEN] = part_info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("PartInfo public key is P-384");

    let policy_bytes =
        common::backup_test_policy(pota_key, sata_key, &part_info.pid, &pid_pub).encode();

    let init = ctx
        .part_init(session, &common::mach_seed(), &policy_bytes)
        .expect("PartInit");
    let pta_chain = make_pta_chain(pota_key, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal");

    (policy_bytes, pid_pub)
}

/// Create a real source remote backup and a reseal request with source and
/// destination evidence. Optionally generate an unrelated receiver key for
/// the wrong-key rejection case.
fn build_fixture(ctx: &TestCtx, wrong_receiver_key: bool, key_scope: common::KeyScope) -> Fixture {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let sata_key = CaKey::generate();
    let pota_key = CaKey::generate();
    let (policy, pid_pub) = build_policy_and_finalize(ctx, &session, &sata_key, &pota_key);

    let (masked_receiver, receiver_report, receiver_pub) =
        sealing_key_report_and_pub(ctx, session.session_id, key_scope);
    let (_masked_destination, destination_report, _) =
        sealing_key_report_and_pub(ctx, session.session_id, key_scope);
    let wrong_receiver_key = wrong_receiver_key
        .then(|| sealing_key_report_and_pub(ctx, session.session_id, key_scope).0);

    let mut oob_items = common::sd_oob_items();
    let receiver_chain = push_chain(&mut oob_items, &make_chain(&sata_key, &receiver_pub));
    let mfgr = push_chain(&mut oob_items, &make_chain(&CaKey::generate(), &pid_pub));
    let owner = push_chain(&mut oob_items, &make_chain(&CaKey::generate(), &pid_pub));
    let part_owner = push_chain(&mut oob_items, &make_chain(&sata_key, &pid_pub));
    let report_item = push_item(&mut oob_items, &receiver_report);
    let oob: Vec<&[u8]> = oob_items.iter().map(Vec::as_slice).collect();

    let request = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        receiver_cert_chain: receiver_chain,
        receiver_key_report: Vec::new(),
        receiver_mfgr_cert_chain: mfgr,
        receiver_owner_cert_chain: owner,
        receiver_part_owner_cert_chain: part_owner,
        receiver_report: ReportDescriptor {
            index: report_item.index,
            length: report_item.length,
        },
        policy: policy.clone(),
    };
    let (_created, src_remote_backup) = ctx
        .sd_oob_report(&request, &oob)
        .expect("create real source remote backup");

    let mut evidence = build_reseal_evidence(&pid_pub, &pota_key, &destination_report);
    let source = common::add_evidence_item(&mut evidence.oob_items, &src_remote_backup);
    let request = TborSdResealRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: masked_receiver,
        policy: policy.clone(),
        src_mfgr_cert_chain: evidence.src_mfgr.clone(),
        src_owner_cert_chain: evidence.src_owner.clone(),
        src_part_owner_cert_chain: evidence.src_part_owner.clone(),
        dest_mfgr_cert_chain: evidence.dest_mfgr.clone(),
        dest_owner_cert_chain: evidence.dest_owner.clone(),
        dest_part_owner_cert_chain: evidence.dest_part_owner.clone(),
        dest_report: evidence.dest_report,
        src_remote_backup: ReportDescriptor {
            index: source.index,
            length: source.length,
        },
    };

    Fixture {
        session_id: session.session_id,
        request,
        evidence,
        src_remote_backup,
        wrong_receiver_key,
    }
}

/// Submit the reseal request and check that the destination backup has the
/// schema length, is nonzero, and differs from the source. Return the backup
/// for freshness checks across repeated calls.
fn assert_success(ctx: &TestCtx, fixture: &Fixture) -> Vec<u8> {
    let oob = fixture.evidence.oob();
    let (_response, report) = ctx
        .sd_oob_report(&fixture.request, &oob)
        .expect("valid SdResealRemoteBackup fixture must succeed");
    assert_eq!(report.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        report.iter().any(|byte| *byte != 0),
        "resealed remote backup must not be all zero",
    );
    assert_ne!(
        report, fixture.src_remote_backup,
        "resealing must produce a fresh HPKE encapsulation",
    );
    report
}

/// Check that the reseal request is rejected with a firmware status rather
/// than a transport or host-side error.
fn assert_rejected(ctx: &TestCtx, fixture: &Fixture) {
    let oob = fixture.evidence.oob();
    let result = ctx.sd_oob(&fixture.request, &oob);
    assert!(
        matches!(&result, Err(tsra_ddi_interface::DdiError::TborStatus(_))),
        "invalid SdResealRemoteBackup fixture must be rejected by firmware",
    );
}

/// XOR the final byte of a nonempty buffer and return whether a nonzero
/// mask was applied.
fn flip_last_byte(bytes: &mut [u8], mask: u8) -> bool {
    if mask == 0 || bytes.is_empty() {
        return false;
    }
    let last = bytes.len() - 1;
    bytes[last] ^= mask;
    true
}

/// Exercise the selected reseal mutation, including repeated-call freshness
/// and zero-mask no-ops. Route non-partition key scopes through the shared
/// scope-validation helper and close the fixture's CO session afterward.
fn run_case(ctx: &TestCtx, mutation: Mutation, key_scope: common::KeyScope) {
    if !matches!(
        key_scope,
        common::KeyScope::Ephemeral | common::KeyScope::Local
    ) {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::exercise_non_partition_key_scope(ctx, &session, key_scope);
        ctx.session_close(session.session_id)
            .expect("close key-scope CO session");
        return;
    }

    let needs_wrong_receiver = matches!(mutation, Mutation::WrongReceiverKey);
    let mut fixture = build_fixture(ctx, needs_wrong_receiver, key_scope);

    match mutation {
        Mutation::Valid => {
            assert_success(ctx, &fixture);
        }
        Mutation::ResealTwice => {
            let first = assert_success(ctx, &fixture);
            let second = assert_success(ctx, &fixture);
            assert_ne!(
                first, second,
                "repeated reseals must use fresh HPKE encapsulations",
            );
        }
        Mutation::MissingOob => {
            ctx.expect_fw_reject(&fixture.request, TborStatus::InvalidArg);
        }
        Mutation::EmptySourceChain => {
            fixture.request.src_mfgr_cert_chain.clear();
            ctx.expect_sd_reject(
                &fixture.request,
                &fixture.evidence.oob(),
                TborStatus::InvalidArg,
            );
        }
        Mutation::EmptyDestinationChain => {
            fixture.request.dest_part_owner_cert_chain.clear();
            ctx.expect_sd_reject(
                &fixture.request,
                &fixture.evidence.oob(),
                TborStatus::InvalidArg,
            );
        }
        Mutation::PolicyHashMismatch => {
            common::mutate_policy_tail(&mut fixture.request.policy, POLICY_MUTATION_MASK);
            assert_rejected(ctx, &fixture);
        }
        Mutation::SourceCertificateOutOfRange => {
            fixture.request.src_mfgr_cert_chain[0].index = u8::MAX;
            assert_rejected(ctx, &fixture);
        }
        Mutation::DestinationReportOutOfRange => {
            fixture.request.dest_report.index = u8::MAX;
            assert_rejected(ctx, &fixture);
        }
        Mutation::TamperSourceEvidence { mask } => {
            let changed = flip_last_byte(
                &mut fixture.evidence.oob_items[fixture.evidence.src_leaf_index],
                mask,
            );
            if changed {
                assert_rejected(ctx, &fixture);
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::TamperDestinationEvidence { mask } => {
            let changed = flip_last_byte(
                &mut fixture.evidence.oob_items[fixture.evidence.dest_leaf_index],
                mask,
            );
            if changed {
                assert_rejected(ctx, &fixture);
            } else {
                assert_success(ctx, &fixture);
            }
        }
        Mutation::WrongReceiverKey => {
            fixture.request.masked_sealing_key = fixture
                .wrong_receiver_key
                .take()
                .expect("wrong receiver key generated for this case");
            assert_rejected(ctx, &fixture);
        }
        Mutation::TamperSourceBackup { offset, mask } => {
            if mask == 0 {
                assert_success(ctx, &fixture);
            } else {
                let artifact = &mut fixture.evidence.oob_items
                    [usize::from(fixture.request.src_remote_backup.index)];
                let index = usize::from(offset) % artifact.len();
                artifact[index] ^= mask;
                assert_rejected(ctx, &fixture);
            }
        }
    }

    ctx.session_close(fixture.session_id)
        .expect("close fuzz CO session");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        run_case(ctx, input.mutation, input.key_scope);
    });
});
