// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host regression tests for the persistent session lifecycle.

// Compile the real storage drivers together so both use part_store's existing
// cfg(test) heap-backed GSRAM. A normal dependency would use hardware addresses.
extern crate self as tsra_fw_uno_drivers_part_store;

#[allow(dead_code, unsafe_code)]
#[path = "../../part_store/src/part_store.rs"]
mod part_store;
#[path = "../src/reply_iv.rs"]
mod reply_iv;
#[allow(dead_code, unsafe_code)]
#[path = "../src/session_store.rs"]
mod session_store;

use part_store::HsmPartId;
use part_store::PartResetKind;
pub use part_store::PartStore;
pub use part_store::Partition;
use part_store::NUM_PARTITIONS;
use reply_iv::ReplyIvs;
use session_store::SessionStore;
use session_store::MAX_SESSIONS;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::HsmSessionState;

#[test]
fn migrate_retains_established_ids_and_releases_pending_handshakes() {
    let pid = HsmPartId::from(50u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let active = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(HsmSessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();
    table.try_consume_psk_change(active).unwrap();

    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Migrate);

    assert!(matches!(
        table.state(active),
        HsmSessionState::NeedsRenegotiation
    ));
    assert!(matches!(table.state(pending), HsmSessionState::Invalid));
    let retained = 1u8 << u16::from(active);
    assert_eq!(&part.session_table()[..2], &[retained, retained]);
    assert_eq!(&part.session_table()[2..], &[0u8; 16]);
    assert_eq!(part.session_meta(), &[0u8; 2]);
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));

    // A repeated reset must not release the established reservation.
    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Migrate);
    assert!(matches!(
        table.state(active),
        HsmSessionState::NeedsRenegotiation
    ));

    let new_key = HsmKeyId::from(2u16);
    assert_eq!(table.validate_recreation(active), Ok(()));
    assert_eq!(table.recreate(active, new_key).unwrap(), active);
    assert!(matches!(table.state(active), HsmSessionState::Active));
    assert_eq!(table.physical_id(active).unwrap(), new_key);
    table.try_consume_psk_change(active).unwrap();
    assert_eq!(table.create(HsmKeyId::from(3u16)).unwrap(), pending);
}

#[test]
fn recreate_rejects_non_renegotiating_slots_without_changing_the_table() {
    let pid = HsmPartId::from(51u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let active = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(HsmSessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();
    let before = *part.session_table();
    let meta_before = *part.session_meta();
    let replacement = HsmKeyId::from(2u16);

    assert_eq!(
        table.validate_recreation(active),
        Err(HsmError::ProcessedIoEventInInvalidState)
    );
    assert_eq!(
        table.recreate(active, replacement),
        Err(HsmError::ProcessedIoEventInInvalidState)
    );
    assert_eq!(
        table.validate_recreation(pending),
        Err(HsmError::ProcessedIoEventInInvalidState)
    );
    assert_eq!(
        table.recreate(pending, replacement),
        Err(HsmError::ProcessedIoEventInInvalidState)
    );
    assert_eq!(
        table.recreate(HsmSessId::from(7u16), replacement),
        Err(HsmError::SessionNotFound)
    );
    assert_eq!(
        table.validate_recreation(HsmSessId::from(7u16)),
        Err(HsmError::SessionNotFound)
    );
    for raw_id in [8u16, 9, u16::MAX] {
        let id = HsmSessId::from(raw_id);
        assert_eq!(
            table.validate_recreation(id),
            Err(HsmError::VaultSessionLimitReached)
        );
        assert_eq!(
            table.recreate(id, replacement),
            Err(HsmError::VaultSessionLimitReached)
        );
    }
    assert_eq!(part.session_table(), &before);
    assert_eq!(part.session_meta(), &meta_before);
}

#[test]
fn recreate_retained_sessions_when_the_table_is_full() {
    let pid = HsmPartId::from(55u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    for raw_id in 0..8u16 {
        assert_eq!(
            table.create(HsmKeyId::from(raw_id)).unwrap(),
            HsmSessId::from(raw_id)
        );
    }
    table.mark_all_needs_renego();
    assert!(table.limit_reached());

    for raw_id in 0..8u16 {
        let id = HsmSessId::from(raw_id);
        let replacement = HsmKeyId::from(raw_id + 8);
        let before = *part.session_table();
        assert_eq!(table.validate_recreation(id), Ok(()));
        assert_eq!(part.session_table(), &before);
        assert_eq!(table.recreate(id, replacement), Ok(id));
        assert!(matches!(table.state(id), HsmSessionState::Active));
        assert_eq!(table.physical_id(id).unwrap(), replacement);
    }
    assert!(table.limit_reached());
}

#[test]
fn reopen_rollback_preserves_the_reserved_id_for_retry() {
    let pid = HsmPartId::from(52u8);
    PartStore::partition(pid).unwrap().reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let id = table.create(HsmKeyId::from(0u16)).unwrap();
    table.mark_all_needs_renego();
    let migrated = *PartStore::partition(pid).unwrap().session_table();

    table.recreate(id, HsmKeyId::from(1u16)).unwrap();
    table.rollback_recreation(id).unwrap();
    assert!(matches!(
        table.state(id),
        HsmSessionState::NeedsRenegotiation
    ));
    assert_eq!(
        PartStore::partition(pid).unwrap().session_table(),
        &migrated
    );
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));
    assert_eq!(table.recreate(id, HsmKeyId::from(2u16)).unwrap(), id);
}

#[test]
fn disable_retains_ids_but_free_releases_them() {
    let pid = HsmPartId::from(53u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let id = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(HsmSessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();

    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Disable);
    assert!(matches!(
        table.state(id),
        HsmSessionState::NeedsRenegotiation
    ));
    assert!(matches!(table.state(pending), HsmSessionState::Invalid));
    let retained = 1u8 << u16::from(id);
    assert_eq!(&part.session_table()[..2], &[retained, retained]);
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));

    table.clear_all();
    assert!(matches!(table.state(id), HsmSessionState::Invalid));
    assert_eq!(part.session_table(), &[0u8; 18]);
    assert_eq!(table.create(HsmKeyId::from(2u16)).unwrap(), id);
}

#[test]
fn clear_all_releases_active_pending_and_renegotiating_slots() {
    let pid = HsmPartId::from(54u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let renegotiating = table.create(HsmKeyId::from(0u16)).unwrap();
    table.mark_all_needs_renego();
    let active = table.create(HsmKeyId::from(1u16)).unwrap();
    let (pending, _) = table
        .create_pending(HsmSessionRole::CryptoUser, HsmKeyId::from(2u16))
        .unwrap();
    table.try_consume_psk_change(active).unwrap();

    // Full teardown must clear both masks, even if some slots already
    // needed renegotiation before resources were removed.
    table.clear_all();

    assert_eq!(part.session_table(), &[0u8; 18]);
    assert_eq!(part.session_meta(), &[0u8; 2]);
    for id in [renegotiating, active, pending] {
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
        assert_eq!(
            table.recreate(id, HsmKeyId::from(3u16)),
            Err(HsmError::SessionNotFound)
        );
    }
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));
    assert_eq!(table.create(HsmKeyId::from(4u16)).unwrap(), renegotiating);
}

fn reply_iv(salt: [u8; 4], counter: u64) -> Option<[u8; 12]> {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(&salt);
    iv[4..].copy_from_slice(&counter.to_be_bytes());
    Some(iv)
}

#[test]
fn reply_ivs_count_under_the_salt_from_arming() {
    let ivs = ReplyIvs::new();
    let (pid, id) = (HsmPartId::from(3u8), HsmSessId::from(5u16));
    assert_eq!(ivs.next(pid, id), None);

    ivs.arm(pid, id, [1, 2, 3, 4]);
    assert_eq!(ivs.next(pid, id), reply_iv([1, 2, 3, 4], 1));
    assert_eq!(ivs.next(pid, id), reply_iv([1, 2, 3, 4], 2));
    assert_eq!(ivs.next(HsmPartId::from(4u8), id), None);
    assert_eq!(ivs.next(pid, HsmSessId::from(4u16)), None);

    // New transport keys: a new salt, and the count from 1 again.
    ivs.arm(pid, id, [5, 6, 7, 8]);
    assert_eq!(ivs.next(pid, id), reply_iv([5, 6, 7, 8], 1));

    ivs.disarm(pid, id);
    assert_eq!(ivs.next(pid, id), None);
}

#[test]
fn reply_ivs_ignore_slots_out_of_range() {
    let ivs = ReplyIvs::new();
    // Slot MAX_SESSIONS of one partition must not reach slot 0 of the next.
    ivs.arm(
        HsmPartId::from(3u8),
        HsmSessId::from(MAX_SESSIONS as u16),
        [1; 4],
    );
    assert_eq!(ivs.next(HsmPartId::from(4u8), HsmSessId::from(0u16)), None);

    let beyond = HsmPartId::from(NUM_PARTITIONS as u8);
    ivs.arm(beyond, HsmSessId::from(0u16), [1; 4]);
    assert_eq!(ivs.next(beyond, HsmSessId::from(0u16)), None);
}

#[test]
fn reply_iv_counter_carries_and_disarms_after_its_last_value() {
    let ivs = ReplyIvs::new();
    let (pid, id) = (HsmPartId::from(0u8), HsmSessId::from(0u16));
    ivs.arm(pid, id, [9; 4]);

    ivs.set_counter(pid, id, u64::from(u32::MAX));
    assert_eq!(ivs.next(pid, id), reply_iv([9; 4], u64::from(u32::MAX)));
    assert_eq!(ivs.next(pid, id), reply_iv([9; 4], 1 << 32));

    ivs.set_counter(pid, id, u64::MAX);
    assert_eq!(ivs.next(pid, id), reply_iv([9; 4], u64::MAX));
    assert_eq!(ivs.next(pid, id), None);
}
