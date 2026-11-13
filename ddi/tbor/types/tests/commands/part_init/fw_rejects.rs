// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartInit` rejects that fire **before** any partition-state
//! mutation: default-PSK dispatcher gate, CU-role handler gate, and
//! malformed-policy decode gate.  Each test asserts the canonical
//! [`TborStatus`] surfaced by the FW and relies on
//! [`tsra_ddi_tbor_test_harness::bootstrap_rotated_co`] or
//! [`tsra_ddi_tbor_test_harness::bootstrap_rotated_cu`] (where needed) to clear the
//! default-PSK arm before reaching the path under test.

use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use tsra_ddi_tbor_test_harness::policy::CborWriter;
use tsra_ddi_tbor_test_harness::session_guard::SessionGuard;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::TestPolicy;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::CU_PSK_ID as CU;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::PolicyFlags;
use tsra_ddi_tbor_types::PolicyKey;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborPartInitReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::PART_POLICY_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::POLICY_INFO_MAX_LEN;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;
use tsra_ddi_tbor_types::POLICY_VERSION;

use super::known_good_part_policy;
use super::known_good_test_policy;
use super::mach_seed;
use super::FILLER_POTA_THUMBPRINT;
use super::FILLER_SATA_THUMBPRINT;

/// A structurally malformed policy (all zero bytes: a CBOR uint where
/// the top-level map is expected).
fn malformed_policy() -> Vec<u8> {
    vec![0u8; 64]
}

/// A policy of `0xFF` bytes (CBOR "break" where the map is expected).
fn all_ff_policy() -> Vec<u8> {
    vec![0xFFu8; 64]
}

/// The known-good policy with `version` set to zero.
fn zero_version_policy() -> Vec<u8> {
    let mut p = known_good_test_policy();
    p.version = 0;
    p.encode()
}

/// Default-PSK CO session: the TBOR dispatcher must reject `PartInit`
/// with [`TborStatus::DefaultPskMustRotate`] **before** the handler
/// runs.  Independent of partition state: the rejection lives in the
/// dispatcher gate, not in any setter.
#[test]
fn part_init_reject_default_psk_co() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy)
        .expect_err("PartInit under default CO PSK must be rejected");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// CU session under a rotated PSK: the handler's CO-only role gate
/// must surface [`TborStatus::InvalidPermissions`].
///
/// [`bootstrap_rotated_cu`] rotates the CU PSK first so the request
/// bypasses the default-PSK dispatcher gate and reaches the role check.
#[test]
fn part_init_reject_cu_session() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(&session, &seed, &policy)
        .expect_err("PartInit on CU session must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// A malformed partition policy must be rejected before firmware
/// applies any partition configuration.
///
/// The rotated CO session is wrapped in [`SessionGuard`] so the session
/// is closed automatically if an assertion or request unexpectedly
/// panics.
#[test]
fn part_init_reject_bad_policy() {
    let ctx = TestCtx::new();

    let session = SessionGuard::new(&ctx, bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK));

    let seed = mach_seed();
    let bad_policy = malformed_policy();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy)
        .expect_err("PartInit with malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// The dispatcher's default-PSK gate must run before policy decoding.
///
/// Even though the supplied policy is malformed, a CO session still using
/// the default PSK must receive `DefaultPskMustRotate`, not `InvalidArg`.
#[test]
fn part_init_default_psk_gate_precedes_policy_decode() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");
    let bad_policy = malformed_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(session.handshake(), &seed, &bad_policy)
        .expect_err("default-PSK gate must reject before policy decoding");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// The default-PSK dispatcher gate must run before the CU role-permission
/// gate.
///
/// The caller is a CU, which normally cannot execute `PartInit`, but the
/// CU session is still using its default PSK. Therefore, the dispatcher
/// must reject the request with `DefaultPskMustRotate` before the handler
/// can return `InvalidPermissions`.
#[test]
fn part_init_default_psk_gate_precedes_cu_role_gate() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open default-PSK CU session");
    let policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy)
        .expect_err("default-PSK CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// The handler's CO-only role gate must run before policy decoding.
///
/// Although the policy is malformed, the rotated CU session must be
/// rejected with `InvalidPermissions` before policy decoding occurs.
#[test]
fn part_init_cu_role_gate_precedes_policy_decode() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let bad_policy = malformed_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(&session, &seed, &bad_policy)
        .expect_err("CU role gate must reject before policy decoding");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// A policy containing only `0xFF` bytes must fail canonical policy
/// decoding with `InvalidArg`.
///
/// This complements the all-zero policy test and exercises a malformed
/// policy whose fields decode to their maximum encoded values.
#[test]
fn part_init_reject_all_ff_policy() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = all_ff_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(&session, &seed, &bad_policy)
        .expect_err("PartInit with all-0xFF PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A canonically encoded policy whose only defect is `version == 0`
/// must be rejected.
#[test]
fn part_init_reject_zero_policy_version() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = zero_version_policy();

    let seed = mach_seed();

    let err = ctx
        .part_init(&session, &seed, &bad_policy)
        .expect_err("PartInit with zero policy version must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Repeating the same malformed-policy request must return the same
/// canonical status each time.
///
/// This also helps detect accidental state mutation after the first
/// rejected request.
#[test]
fn part_init_bad_policy_rejection_is_repeatable() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = malformed_policy();
    let seed = mach_seed();

    for attempt in 1..=2 {
        let result = ctx.part_init(&session, &seed, &bad_policy);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded on attempt {}",
                attempt
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }
}

/// A malformed-policy rejection must occur before partition-state
/// mutation.
///
/// After the invalid request is rejected, a valid `PartInit` on the same
/// rotated CO session must still succeed. If the failed request partially
/// changed partition state, the valid retry would be rejected.
#[test]
fn part_init_bad_policy_does_not_mutate_partition_state() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = malformed_policy();
    let good_policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(&session, &seed, &bad_policy)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    ctx.part_init(&session, &seed, &good_policy)
        .expect("valid PartInit must succeed after malformed-policy rejection");
}

/// A valid PartInit request from an authenticated CO session using a
/// rotated PSK must succeed.
///
/// This is the basic positive-path test for PartInit. The other tests
/// depend on this combination representing a valid initialization request.
#[test]
fn part_init_valid_rotated_co_request_succeeds() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();

    ctx.part_init(&session, &seed, &policy)
        .expect("valid PartInit from rotated authenticated CO must succeed");
}

/// A rejection caused by the CU permission gate must not mutate partition state.
///
/// After the CU request is rejected with `InvalidPermissions`, a valid rotated-CO
/// `PartInit` request must still succeed.
#[test]
fn part_init_cu_rejection_does_not_mutate_partition_state() {
    let ctx = TestCtx::new();

    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(&cu_session, &seed, &policy)
        .expect_err("PartInit from a CU session must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    let co_ctx = TestCtx::new_with_path(ctx.path());
    let co_session = bootstrap_rotated_co(&co_ctx, &ROTATED_CO_PSK);

    co_ctx
        .part_init(&co_session, &seed, &policy)
        .expect("valid CO PartInit must succeed after CU rejection");
}

/// After successful partition initialization, a second `PartInit` request
/// must be rejected because the partition's PTA key has already been set.
///
/// The second request reuses the authenticated CO session that performed
/// the first initialization. Opening a new session with the pre-init
/// rotated CO PSK is not valid after `PartInit` changes partition
/// authentication state.
#[test]
fn part_init_rejects_second_initialization() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();

    ctx.part_init(&session, &seed, &policy)
        .expect("first valid PartInit must succeed");

    let err = ctx
        .part_init(&session, &seed, &policy)
        .expect_err("second PartInit on an initialized partition must be rejected");

    assert_fw_rejects(&err, TborStatus::PtaKeyAlreadySet);
}

/// Verify that several malformed policy representations are independently
/// rejected and that no rejection changes partition state.
///
/// A separate `TestCtx` is used for each case because the final valid request
/// initializes that case's partition.
#[test]
fn part_init_policy_rejection_matrix_does_not_mutate_state() {
    enum BadPolicyCase {
        AllZero,
        AllOnes,
        ZeroVersion,
    }

    for case in [
        BadPolicyCase::AllZero,
        BadPolicyCase::AllOnes,
        BadPolicyCase::ZeroVersion,
    ] {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        let bad_policy = match case {
            BadPolicyCase::AllZero => malformed_policy(),
            BadPolicyCase::AllOnes => all_ff_policy(),
            BadPolicyCase::ZeroVersion => zero_version_policy(),
        };

        let good_policy = known_good_part_policy();
        let seed = mach_seed();

        let err = ctx
            .part_init(&session, &seed, &bad_policy)
            .expect_err("malformed PartPolicy must be rejected");

        assert_fw_rejects(&err, TborStatus::InvalidArg);

        ctx.part_init(&session, &seed, &good_policy)
            .expect("valid PartInit must succeed after policy rejection");
    }
}

/// Policy rejection must not invalidate the authenticated CO session.
///
/// Submit multiple malformed policies through the same session, followed
/// by one valid request.
#[test]
fn part_init_session_remains_usable_after_policy_rejections() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();

    let bad_policies = [malformed_policy(), all_ff_policy(), zero_version_policy()];

    for (index, bad_policy) in bad_policies.iter().enumerate() {
        let result = ctx.part_init(&session, &seed, bad_policy);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded at index {}",
                index
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }

    let good_policy = known_good_part_policy();

    ctx.part_init(&session, &seed, &good_policy)
        .expect("session must remain usable after policy rejections");
}

/// A rejection caused by the default-PSK dispatcher gate must not mutate
/// partition state.
///
/// The first request uses the default CO PSK and must be rejected before
/// the `PartInit` handler performs any state mutation. After closing that
/// session and rotating the CO PSK, a valid `PartInit` request must still
/// succeed.
#[test]
fn part_init_default_psk_rejection_does_not_mutate_partition_state() {
    let ctx = TestCtx::new();

    let default_session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");

    let policy = known_good_part_policy();
    let seed = mach_seed();

    let err = ctx
        .part_init(default_session.handshake(), &seed, &policy)
        .expect_err("PartInit under default CO PSK must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

    default_session
        .close()
        .expect("close default-PSK CO session");

    let rotated_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(&rotated_session, &seed, &policy)
        .expect("valid PartInit must succeed after default-PSK rejection");
}

/// Multiple rejection classes must not collectively contaminate partition
/// state.
///
/// This test exercises three distinct rejection paths in order:
///
/// 1. Default CO PSK rejection.
/// 2. CU permission rejection.
/// 3. Malformed policy rejection.
///
/// A valid rotated-CO `PartInit` request must still succeed afterward.
#[test]
fn part_init_multiple_rejections_do_not_mutate_partition_state() {
    let ctx = TestCtx::new();

    let policy = known_good_part_policy();
    let bad_policy = malformed_policy();
    let seed = mach_seed();

    // First rejection: default CO PSK.
    let default_co = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open default-PSK CO session");
    let err = ctx
        .part_init(default_co.handshake(), &seed, &policy)
        .expect_err("PartInit under default CO PSK must be rejected");

    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

    default_co.close().expect("close default-PSK CO session");

    // Second rejection: CU role.
    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let err = ctx
        .part_init(&cu_session, &seed, &policy)
        .expect_err("PartInit from CU must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    // Open an authorized CO session on a separate handle: the CU session
    // remains live, and each hardware handle permits only one session.
    let co_ctx = TestCtx::new_with_path(ctx.path());
    let co_session = bootstrap_rotated_co(&co_ctx, &ROTATED_CO_PSK);

    // Third rejection: malformed policy.
    let err = co_ctx
        .part_init(&co_session, &seed, &bad_policy)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    // None of the preceding rejections may have initialized or otherwise
    // mutated the partition.
    co_ctx
        .part_init(&co_session, &seed, &policy)
        .expect("valid PartInit must succeed after multiple rejected requests");
}

/// A malformed-policy rejection must not modify any caller-owned input
/// buffer.
///
/// `PartInit` receives the seed and policy by shared
/// reference. This test confirms the harness and serialization path do
/// not unexpectedly alter those buffers when firmware rejects the
/// request.
#[test]
fn part_init_rejection_does_not_modify_input_buffers() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let bad_policy = malformed_policy();
    let seed = mach_seed();

    let expected_policy = bad_policy.clone();
    let expected_seed = seed;

    let err = ctx
        .part_init(&session, &seed, &bad_policy)
        .expect_err("malformed PartPolicy must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidArg);

    assert_eq!(
        bad_policy, expected_policy,
        "PartInit rejection modified the caller-owned policy buffer",
    );

    assert_eq!(
        seed, expected_seed,
        "PartInit rejection modified the caller-owned seed buffer",
    );
}

/// A policy rejection must remain deterministic across several requests,
/// and the same authenticated CO session must still be usable afterward.
///
/// Every malformed request must return the canonical
/// [`TborStatus::InvalidArg`] status. After the rejected requests, a valid
/// policy must still initialize the partition successfully.
#[test]
fn part_init_repeated_policy_rejections_preserve_session_and_state() {
    const ATTEMPTS: usize = 5;

    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = malformed_policy();
    let good_policy = known_good_part_policy();
    let seed = mach_seed();

    for attempt in 1..=ATTEMPTS {
        let result = ctx.part_init(&session, &seed, &bad_policy);

        let err = match result {
            Ok(_) => panic!(
                "malformed PartPolicy unexpectedly succeeded on attempt {}",
                attempt,
            ),
            Err(err) => err,
        };

        assert_fw_rejects(&err, TborStatus::InvalidArg);
    }

    ctx.part_init(&session, &seed, &good_policy)
        .expect("valid PartInit must succeed after repeated policy rejections");
}

/// A CO session cannot be opened with [`SessionType::PlainText`].
///
/// CO commands require an authenticated session, so the session-open
/// request must fail with [`TborStatus::InvalidSessionType`] before a
/// `PartInit` request can be submitted.
#[test]
fn part_init_co_plaintext_session_rejected() {
    let ctx = TestCtx::new();

    let err = ctx
        .session_open_init(0, SessionType::PlainText)
        .expect_err("CO PlainText session must be rejected");

    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

/// A value in a hand-built policy map entry.
#[derive(Clone, Copy)]
enum Val<'a> {
    U(u64),
    B(&'a [u8]),
}

const POTA_TP: [u8; POLICY_THUMBPRINT_LEN] = FILLER_POTA_THUMBPRINT;
const SATA_TP: [u8; POLICY_THUMBPRINT_LEN] = FILLER_SATA_THUMBPRINT;
const OTHER_TP: [u8; POLICY_THUMBPRINT_LEN] = [0x33; POLICY_THUMBPRINT_LEN];
const BACKUP_ID: [u8; POLICY_BACKUP_PART_ID_LEN] = [0xCD; POLICY_BACKUP_PART_ID_LEN];

/// Encode `entries` verbatim (in the given order) as a CBOR map with
/// shortest-form heads, so tests control key order, duplicates, and
/// value types independently of [`TestPolicy`]'s canonical encoder.
fn encode_map(entries: &[(u64, Val<'_>)]) -> Vec<u8> {
    let mut w = CborWriter::new();
    w.map(entries.len() as u64);
    for (k, v) in entries {
        w.uint(*k);
        match v {
            Val::U(u) => w.uint(*u),
            Val::B(b) => w.bstr(b),
        };
    }
    w.finish()
}

/// The minimal valid policy entries: version, POTA, SATA, flags.
fn minimal_entries() -> Vec<(u64, Val<'static>)> {
    vec![
        (PolicyKey::Version as u64, Val::U(POLICY_VERSION.into())),
        (PolicyKey::PotaSpkiThumbprint as u64, Val::B(&POTA_TP)),
        (PolicyKey::SataSpkiThumbprint as u64, Val::B(&SATA_TP)),
        (PolicyKey::Flags as u64, Val::U(0)),
    ]
}

/// [`minimal_entries`] with the entry for `key` replaced by `val`
/// (inserted in key order if absent).
fn with_entry(key: PolicyKey, val: Val<'static>) -> Vec<u8> {
    let mut e = minimal_entries();
    let k = key as u64;
    match e.iter().position(|(ek, _)| *ek >= k) {
        Some(i) if e[i].0 == k => e[i].1 = val,
        Some(i) => e.insert(i, (k, val)),
        None => e.push((k, val)),
    }
    encode_map(&e)
}

/// [`minimal_entries`] without the entry for `key`.
fn without_entry(key: PolicyKey) -> Vec<u8> {
    let mut e = minimal_entries();
    e.retain(|(k, _)| *k != key as u64);
    encode_map(&e)
}

/// Every non-canonical or schema-violating policy document must be
/// rejected by the firmware's strict CBOR decoder with
/// [`TborStatus::InvalidArg`] — the single status every `PolicyError`
/// maps to.  All cases share one rotated CO session; rejections never
/// mutate partition state, which the trailing valid `PartInit` confirms.
#[test]
fn part_init_rejects_malformed_cbor_policies() {
    let minimal = encode_map(&minimal_entries());

    let mut cases: Vec<(String, Vec<u8>)> = vec![
        ("empty document".into(), Vec::new()),
        ("all-zero bytes".into(), malformed_policy()),
        ("all-0xFF bytes".into(), all_ff_policy()),
        // Version.
        (
            "version 0".into(),
            with_entry(PolicyKey::Version, Val::U(0)),
        ),
        (
            "version 2".into(),
            with_entry(PolicyKey::Version, Val::U(2)),
        ),
        (
            "version as bstr".into(),
            with_entry(PolicyKey::Version, Val::B(&[1])),
        ),
        // Flags beyond the 8-bit field.
        (
            "flags 0x100".into(),
            with_entry(PolicyKey::Flags, Val::U(0x100)),
        ),
        // Missing required keys.
        ("missing version".into(), without_entry(PolicyKey::Version)),
        (
            "missing pota thumbprint".into(),
            without_entry(PolicyKey::PotaSpkiThumbprint),
        ),
        (
            "missing sata thumbprint".into(),
            without_entry(PolicyKey::SataSpkiThumbprint),
        ),
        ("missing flags".into(), without_entry(PolicyKey::Flags)),
        // Unknown keys.
        ("unknown key 10".into(), {
            let mut e = minimal_entries();
            e.push((10, Val::U(0)));
            encode_map(&e)
        }),
        ("unknown key 0".into(), {
            let mut e = minimal_entries();
            e.insert(0, (0, Val::U(0)));
            encode_map(&e)
        }),
        // Key ordering.
        ("keys out of order".into(), {
            let mut e = minimal_entries();
            e.swap(1, 2);
            encode_map(&e)
        }),
        ("duplicate key".into(), {
            let mut e = minimal_entries();
            e.insert(2, (PolicyKey::PotaSpkiThumbprint as u64, Val::B(&POTA_TP)));
            encode_map(&e)
        }),
        // Non-shortest / indefinite-length heads.
        ("non-shortest flags value".into(), {
            let mut b = minimal.clone();
            let last = b.len() - 1;
            b[last] = 0x18;
            b.push(0x00);
            b
        }),
        ("non-shortest map header".into(), {
            let mut b = vec![0xB8, 0x04];
            b.extend_from_slice(&minimal[1..]);
            b
        }),
        ("non-shortest bstr length".into(), {
            let mut w = CborWriter::new();
            w.map(4).uint(1).uint(1).uint(2);
            w.raw(&[0x59, 0x00, POLICY_THUMBPRINT_LEN as u8])
                .raw(&POTA_TP);
            w.uint(3).bstr(&SATA_TP).uint(7).uint(0);
            w.finish()
        }),
        ("indefinite-length map".into(), {
            let mut b = minimal.clone();
            b[0] = 0xBF;
            b.push(0xFF);
            b
        }),
        // Framing.
        ("trailing byte".into(), {
            let mut b = minimal.clone();
            b.push(0x00);
            b
        }),
        (
            "truncated document".into(),
            minimal[..minimal.len() - 1].to_vec(),
        ),
        ("map count exceeds entries".into(), {
            let mut b = minimal.clone();
            b[0] += 1;
            b
        }),
        // Backup-partition pairing.
        (
            "backup id without thumbprint".into(),
            with_entry(PolicyKey::BackupPartId, Val::B(&BACKUP_ID)),
        ),
        (
            "backup thumbprint without id".into(),
            with_entry(PolicyKey::BackupPartSpkiThumbprint, Val::B(&OTHER_TP)),
        ),
        // Info bounds.
        (
            "empty info".into(),
            with_entry(PolicyKey::Info, Val::B(&[])),
        ),
        (
            "info too long".into(),
            with_entry(PolicyKey::Info, Val::B(&[0xAB; POLICY_INFO_MAX_LEN + 1])),
        ),
    ];

    // Each reserved flag bit independently.
    for bit in 3..8 {
        cases.push((
            format!("reserved flag bit {bit}"),
            with_entry(PolicyKey::Flags, Val::U(1 << bit)),
        ));
    }

    // Wrong-length and wrong-type thumbprint / id fields.
    const TP_SHORT: [u8; POLICY_THUMBPRINT_LEN - 1] = [0x5A; POLICY_THUMBPRINT_LEN - 1];
    const TP_LONG: [u8; POLICY_THUMBPRINT_LEN + 1] = [0x5A; POLICY_THUMBPRINT_LEN + 1];
    for key in [
        PolicyKey::PotaSpkiThumbprint,
        PolicyKey::SataSpkiThumbprint,
        PolicyKey::SapotaSpkiThumbprint,
        PolicyKey::DataSpkiThumbprint,
    ] {
        cases.push((format!("{key:?} short"), with_entry(key, Val::B(&TP_SHORT))));
        cases.push((format!("{key:?} long"), with_entry(key, Val::B(&TP_LONG))));
        cases.push((format!("{key:?} as uint"), with_entry(key, Val::U(0))));
    }
    const ID_SHORT: [u8; POLICY_BACKUP_PART_ID_LEN - 1] = [0xCD; POLICY_BACKUP_PART_ID_LEN - 1];
    const ID_LONG: [u8; POLICY_BACKUP_PART_ID_LEN + 1] = [0xCD; POLICY_BACKUP_PART_ID_LEN + 1];
    for (name, id) in [("short", &ID_SHORT[..]), ("long", &ID_LONG[..])] {
        let mut e = minimal_entries();
        e.insert(3, (PolicyKey::BackupPartId as u64, Val::B(id)));
        e.insert(
            4,
            (
                PolicyKey::BackupPartSpkiThumbprint as u64,
                Val::B(&OTHER_TP),
            ),
        );
        cases.push((format!("backup id {name}"), encode_map(&e)));
    }
    {
        let mut e = minimal_entries();
        e.insert(3, (PolicyKey::BackupPartId as u64, Val::B(&BACKUP_ID)));
        e.insert(
            4,
            (
                PolicyKey::BackupPartSpkiThumbprint as u64,
                Val::B(&TP_SHORT),
            ),
        );
        cases.push(("backup thumbprint short".into(), encode_map(&e)));
    }

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let seed = mach_seed();

    for (name, bad_policy) in &cases {
        let err = ctx
            .part_init(&session, &seed, bad_policy)
            .expect_err(&format!("malformed policy ({name}) must be rejected"));
        match err {
            DdiError::TborStatus(status) => assert_eq!(
                status,
                TborStatus::InvalidArg,
                "malformed policy ({name}) rejected with wrong status",
            ),
            other => panic!("malformed policy ({name}): expected FW reject, got {other:?}"),
        }
    }

    ctx.part_init(&session, &seed, &minimal)
        .expect("minimal valid policy must be accepted after the rejections");
}

/// A policy populating every optional field (SAPOTA, backing partition,
/// all known flags, maximum-length info, DATA) must be accepted.
#[test]
fn part_init_accepts_policy_with_all_optional_fields() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let policy = TestPolicy::new(POTA_TP, SATA_TP)
        .with_sapota(OTHER_TP)
        .with_backup_part(BACKUP_ID, [0x44; POLICY_THUMBPRINT_LEN])
        .with_flags(PolicyFlags::KNOWN_MASK)
        .with_info(&[0xAB; POLICY_INFO_MAX_LEN])
        .with_data([0x55; POLICY_THUMBPRINT_LEN])
        .encode();
    assert!(policy.len() <= PART_POLICY_MAX_LEN);

    ctx.part_init(&session, &mach_seed(), &policy)
        .expect("policy with every optional field must be accepted");
}

/// The minimal policy (only the required keys, no `info`) and a
/// one-byte `info` must each be accepted.
#[test]
fn part_init_accepts_minimal_policy_boundaries() {
    for policy in [
        TestPolicy::new(POTA_TP, SATA_TP).encode(),
        TestPolicy::new(POTA_TP, SATA_TP)
            .with_info(&[0x01])
            .encode(),
    ] {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        ctx.part_init(&session, &mach_seed(), &policy)
            .expect("minimal-boundary policy must be accepted");
    }
}

/// A policy larger than [`PART_POLICY_MAX_LEN`] is refused: the harness
/// rejects it up front, and a raw request carrying it is rejected by the
/// firmware TBOR codec (schema `max_len`) with `TborInvalidFixedLength`.
#[test]
fn part_init_rejects_oversized_policy() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let oversized = vec![0u8; PART_POLICY_MAX_LEN + 1];

    let err = ctx
        .part_init(&session, &mach_seed(), &oversized)
        .expect_err("oversized policy must be refused by the harness");
    assert!(
        matches!(err, DdiError::InvalidParameter),
        "expected InvalidParameter, got {err:?}",
    );

    let req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: encrypt_mach_seed_envelope(&session, &mach_seed())
            .expect("seal mach_seed envelope"),
        part_policy: oversized,
    };
    // The host encoder does not enforce `max_len`; the firmware codec
    // rejects the over-long field before the handler runs.
    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);

    ctx.part_init(&session, &mach_seed(), &known_good_part_policy())
        .expect("valid PartInit must succeed after host-side rejects");
}
