// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PartInitWithObk` command.
//!
//! `PartInitWithObk` provisions an `Enabled` partition from the masked owner
//! backup key (MOBK) that UEFI sealed with the TPM, plus the partition
//! owner's (POTA) endorsement of the partition identity — inside a Crypto
//! Officer session, in place of the `PartInit` + `PartFinal` pair.  It
//! returns the `local_mk` backup the host keeps to restore the same local
//! masking key after a reset.
//!
//! The MOBK is minted by MBOR `InitBk3`, so every test returns early on a
//! Duo, which has no MBOR.  A device reset (`erase`) stands in for NSSR: the
//! host keeps only the BK3 plaintext, the POTA key and the `local_mk_backup`,
//! and mints a fresh MOBK (bound to the new `BK_BOOT`) and a fresh
//! endorsement (the identity key is regenerated) for each new incarnation.
//!
//! Coverage:
//! * Happy path — provisions the partition; the Ephemeral and Local masking
//!   keys then work.
//! * Restore — a replayed backup continues the Local masking key; fresh
//!   provisioning mints a different one; a restore is bound to the POTA and
//!   rejects a malformed or tampered backup.
//! * Rejects — bad POTA signature, tampered / foreign-bound / unmaskable
//!   MOBK envelope, Crypto-User session, default PSK, and the wrong lifecycle
//!   state.  A reject leaves the partition `Enabled`.
//! * Rotation — the session that rotated the CO PSK is rebound to it and
//!   provisions without being reopened.

use tsra_ddi_interface::DdiResult;
use tsra_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::build_psk_change_aad;
use tsra_ddi_tbor_test_harness::encrypt_mobk_envelope;
use tsra_ddi_tbor_test_harness::seal_mobk_envelope;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::PotaEndorsement;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::build_part_init_with_obk_aad;
use tsra_ddi_tbor_types::TborHmacGenerateKeyReq;
use tsra_ddi_tbor_types::TborHmacReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborPartInitWithObkReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;

use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_ENABLED;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;

/// The 48-byte owner backup key the tests seal.  Fixed, so every device
/// incarnation's MOBK wraps the same BK3, as it does across NSSR in the field.
const BK3: [u8; 48] = [0xB3; 48];

/// Message MACed to probe a masking key.
const PROBE_MSG: &[u8] = b"obk continuity probe";

/// A fresh test context, or `None` on a Duo, which has no MBOR `InitBk3` to
/// mint a MOBK with.
fn uno_ctx() -> Option<TestCtx> {
    let ctx = TestCtx::new();
    (!ctx.is_duo()).then_some(ctx)
}

/// `pota`'s endorsement of the partition identity `PartInfo` reports now.
fn endorse(ctx: &TestCtx, pota: &CaKey) -> PotaEndorsement {
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    PotaEndorsement::sign(pota, &info.pid_pub_key)
}

/// The OBK inputs of the current device incarnation: the MOBK from MBOR
/// `InitBk3` (one-shot per incarnation) and `pota`'s endorsement.
fn obk_inputs(ctx: &TestCtx, pota: &CaKey) -> (Vec<u8>, PotaEndorsement) {
    let mobk = ctx.init_bk3(&BK3).expect("InitBk3");
    (mobk, endorse(ctx, pota))
}

/// Provision with `PartInitWithObk`, asserting the pinned backup length, and
/// return the `local_mk_backup`.
fn provision(
    ctx: &TestCtx,
    session: &SessionHandshake,
    mobk: &[u8],
    endorsement: &PotaEndorsement,
    prev_backup: &[u8],
) -> Vec<u8> {
    let resp = ctx
        .part_init_with_obk(session, mobk, endorsement, prev_backup)
        .expect("PartInitWithObk");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "the backup must have the wire-pinned envelope length",
    );
    resp.local_mk_backup
}

/// A raw `PartInitWithObk` request carrying `envelope` as the MOBK envelope.
fn request(
    session: &SessionHandshake,
    envelope: Vec<u8>,
    endorsement: &PotaEndorsement,
) -> TborPartInitWithObkReq {
    TborPartInitWithObkReq {
        session_id: session.session_id,
        mobk_envelope: envelope,
        pota_pub_key: endorsement.pub_key.clone(),
        pota_sig: endorsement.sig.clone(),
        prev_local_mk_backup: Vec::new(),
    }
}

/// Generate a `scope`-scoped HMAC key on `session_id`; returns its masked form.
fn hmac_key(ctx: &TestCtx, session_id: u16, scope: u8) -> Vec<u8> {
    let req = TborHmacGenerateKeyReq {
        session_id,
        scope,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: b"obk-probe".to_vec(),
    };
    ctx.tbor(&req).expect("HmacGenerateKey").masked_key
}

/// MAC [`PROBE_MSG`] with `masked_key`.
fn mac(ctx: &TestCtx, session_id: u16, masked_key: &[u8]) -> DdiResult<Vec<u8>> {
    let req = TborHmacReq {
        session_id,
        masked_key: masked_key.to_vec(),
        msg: PROBE_MSG.to_vec(),
    };
    ctx.tbor(&req).map(|resp| resp.tag)
}

/// Happy path: the partition becomes `Initialized`, both persisted masking
/// keys exist, and the CO session survives the provisioning.
#[test]
fn part_init_with_obk_provisions_the_partition() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    assert_part_state(&ctx, PART_STATE_ENABLED, false);

    let backup = provision(&ctx, &session, &mobk, &endorsement, &[]);

    assert!(
        backup.iter().any(|&b| b != 0),
        "local_mk_backup must not be all-zero",
    );
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let key = hmac_key(&ctx, session.session_id, scope);
        let tag = mac(&ctx, session.session_id, &key).expect("MAC with a persisted-scope key");
        assert_eq!(tag.len(), 32);
    }
}

/// Restore: replaying the backup on a reset device continues the Local
/// masking key, so a key masked before the reset still unmasks.
#[test]
fn part_init_with_obk_restore_continues_the_local_key() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    let backup = provision(&ctx, &session, &mobk, &endorsement, &[]);
    let masked_key = hmac_key(&ctx, session.session_id, SCOPE_LOCAL);
    let tag = mac(&ctx, session.session_id, &masked_key).expect("MAC before the reset");

    ctx.session_close(session.session_id)
        .expect("close the CO session");
    ctx.erase().expect("erase stands in for NSSR");
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    provision(&ctx, &session, &mobk, &endorsement, &backup);

    let restored = mac(&ctx, session.session_id, &masked_key).expect("MAC after the restore");
    assert_eq!(restored, tag, "the restore must continue the Local key");
}

/// Provisioning without a backup mints a new Local masking key: a key masked
/// under the previous one no longer unmasks.
#[test]
fn part_init_with_obk_without_a_backup_mints_a_new_local_key() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    provision(&ctx, &session, &mobk, &endorsement, &[]);
    let masked_key = hmac_key(&ctx, session.session_id, SCOPE_LOCAL);

    ctx.session_close(session.session_id)
        .expect("close the CO session");
    ctx.erase().expect("erase stands in for NSSR");
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    provision(&ctx, &session, &mobk, &endorsement, &[]);

    let result = mac(&ctx, session.session_id, &masked_key);
    assert!(
        result.is_err(),
        "a key masked under the previous Local key must not unmask",
    );
}

/// A restore is bound to the backup and to the POTA: a malformed or tampered
/// backup, or one presented under another POTA, is rejected without changing
/// the partition, and the genuine inputs then still restore it.
#[test]
fn part_init_with_obk_restore_is_bound_to_the_backup_and_the_pota() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    let backup = provision(&ctx, &session, &mobk, &endorsement, &[]);

    ctx.session_close(session.session_id)
        .expect("close the CO session");
    ctx.erase().expect("erase stands in for NSSR");
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    let err = ctx
        .part_init_with_obk(&session, &mobk, &endorsement, &backup[1..])
        .expect_err("a backup of the wrong length must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);

    let mut tampered = backup.clone();
    *tampered.last_mut().expect("the backup is not empty") ^= 1;
    let err = ctx
        .part_init_with_obk(&session, &mobk, &endorsement, &tampered)
        .expect_err("a tampered backup must be rejected");
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);

    let other_pota = endorse(&ctx, &CaKey::generate());
    let err = ctx
        .part_init_with_obk(&session, &mobk, &other_pota, &backup)
        .expect_err("a backup must not restore under another POTA");
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
    provision(&ctx, &session, &mobk, &endorsement, &backup);
}

/// The POTA signature must verify over the partition identity under the
/// presented POTA key.
#[test]
fn part_init_with_obk_rejects_a_bad_pota_signature() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    let mut flipped = endorsement.clone();
    flipped.sig[0] ^= 1;
    let other = endorse(&ctx, &CaKey::generate());
    let mismatched = PotaEndorsement {
        pub_key: other.pub_key,
        sig: endorsement.sig.clone(),
    };
    for bad in [flipped, mismatched] {
        let err = ctx
            .part_init_with_obk(&session, &mobk, &bad, &[])
            .expect_err("an endorsement that does not verify must be rejected");
        assert_fw_rejects(&err, TborStatus::EccVerifyFailed);
    }

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
    provision(&ctx, &session, &mobk, &endorsement, &[]);
}

/// A tampered MOBK envelope fails its AEAD tag.
#[test]
fn part_init_with_obk_rejects_a_tampered_envelope() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    let mut envelope = encrypt_mobk_envelope(&session, &mobk).expect("seal the MOBK");
    *envelope.last_mut().expect("the envelope is not empty") ^= 1;
    ctx.expect_fw_reject(
        &request(&session, envelope, &endorsement),
        TborStatus::AeadEnvelopeAuthFailed,
    );

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
}

/// An envelope sealed under the right session key but bound to another
/// session or another command's AAD is rejected.
#[test]
fn part_init_with_obk_rejects_an_envelope_bound_elsewhere() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    let other_session = build_part_init_with_obk_aad(session.session_id ^ 1);
    let other_command = build_psk_change_aad(session.session_id);
    for aad in [other_session, other_command] {
        let envelope = seal_mobk_envelope(&session, &aad, &mobk).expect("seal the MOBK");
        ctx.expect_fw_reject(
            &request(&session, envelope, &endorsement),
            TborStatus::AeadEnvelopeAuthFailed,
        );
    }

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
}

/// A MOBK that the partition's `BK_BOOT` did not mask is rejected.
#[test]
fn part_init_with_obk_rejects_an_unmaskable_mobk() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let endorsement = endorse(&ctx, &pota);

    let envelope = encrypt_mobk_envelope(&session, &[0x5A; 80]).expect("seal the blob");
    ctx.expect_fw_reject(
        &request(&session, envelope, &endorsement),
        TborStatus::MaskedKeyDecodeFailed,
    );

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
}

/// `PartInitWithObk` is CO-only.
#[test]
fn part_init_with_obk_rejects_a_crypto_user_session() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    let err = ctx
        .part_init_with_obk(&cu, &mobk, &endorsement, &[])
        .expect_err("a Crypto User must not provision the partition");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);

    assert_part_state(&ctx, PART_STATE_ENABLED, false);
}

/// The default-PSK gate applies: a session under the unrotated CO PSK may
/// only rotate it or close.
#[test]
fn part_init_with_obk_requires_a_rotated_psk() {
    let Some(ctx) = uno_ctx() else { return };
    let session = ctx
        .open_session(CO_PSK_ID, SessionSuite::EcdhP384)
        .expect("default CO session");
    let endorsement = PotaEndorsement {
        pub_key: vec![0; 96],
        sig: vec![0; 96],
    };

    let err = ctx
        .part_init_with_obk(session.handshake(), &[0u8; 80], &endorsement, &[])
        .expect_err("a default-PSK session must be gated");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// `PskChange` rebinds the session that performs it to the new credential,
/// so the bootstrap session can provision without being reopened.  (The CO
/// role has a single session slot, so no other CO session can be left
/// holding the old credential.)
#[test]
fn part_init_with_obk_accepts_the_session_that_rotated_the_psk() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let bootstrap = ctx
        .open_session(CO_PSK_ID, SessionSuite::EcdhP384)
        .expect("default CO session");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CO_PSK)
        .expect("rotate the CO PSK");
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    provision(&ctx, bootstrap.handshake(), &mobk, &endorsement, &[]);

    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
}

/// The command is one-shot, and exclusive with the `PartInit` flow in both
/// orders.
#[test]
fn part_init_with_obk_is_exclusive_with_the_other_provisioning_flows() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);

    provision(&ctx, &session, &mobk, &endorsement, &[]);

    let err = ctx
        .part_init_with_obk(&session, &mobk, &endorsement, &[])
        .expect_err("a second provisioning must be rejected");
    assert_fw_rejects(&err, TborStatus::PartitionAlreadyProvisioned);
    let err = ctx
        .part_init(&session, &mach_seed(), &known_good_part_policy())
        .expect_err("PartInit must be rejected once the partition is provisioned");
    assert_fw_rejects(&err, TborStatus::PartitionAlreadyProvisioned);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
}

/// `PartInitWithObk` is rejected once `PartInit` has started provisioning.
#[test]
fn part_init_with_obk_rejects_a_partition_already_in_part_init() {
    let Some(ctx) = uno_ctx() else { return };
    let pota = CaKey::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mobk, endorsement) = obk_inputs(&ctx, &pota);
    ctx.part_init(&session, &mach_seed(), &known_good_part_policy())
        .expect("PartInit");

    let err = ctx
        .part_init_with_obk(&session, &mobk, &endorsement, &[])
        .expect_err("OBK provisioning must be rejected after PartInit");
    assert_fw_rejects(&err, TborStatus::PartitionAlreadyProvisioned);
}
