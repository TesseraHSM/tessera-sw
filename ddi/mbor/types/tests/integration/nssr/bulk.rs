// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the AES bulk fast path (not `DdiOp`s).
//!
//! Firmware does not check session state for partition-scoped bulk keys, so
//! the socket server itself rejects a reset-invalidated session with
//! `SessionNeedsRenegotiation` (ddi/sock/server/src/lib.rs:294-315). These
//! rows therefore run on the socket transport only.

#![cfg(test)]

use test_with_tracing::test;

use super::*;

/// Short app id firmware assigns every MBOR session
/// (fw/core/lib/src/ddi/mbor/open_session.rs:64); `LMSetupResult` does not
/// keep the `OpenSession` response.
const SHORT_APP_ID: u8 = 0;

/// Checkpoint 2 on the fast path: the sock client surfaces only the CQE
/// status code (`FpError`), not which field was invalid
/// (ddi/sock/src/dev.rs:831-836).
#[track_caller]
fn assert_stale_bulk_key<T: Debug>(result: Result<T, DdiError>, sts: u32) {
    assert!(
        matches!(result, Err(DdiError::FpError(status)) if status == sts),
        "checkpoint 2 (stale key): expected FpError({sts}), got {result:?}"
    );
}

#[test]
fn nssr_bulk_aes_gcm() {
    if !sock_selected() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let key = generate_aes_bulk_256_key(dev, &sid, DdiAesKeySize::AesGcmBulk256Unapproved)
                .expect("GCM bulk key")
                .data;
            // The unapproved kind encrypts under the host IV: deterministic.
            let gcm = |dev: &Dev,
                       app: u8,
                       key_id: u16,
                       op: DdiAesOp,
                       tag: Option<[u8; 16]>,
                       data: &[u8]| {
                let params = DdiAesGcmParams {
                    key_id: u32::from(key_id),
                    iv: [0x3C; 12],
                    aad: Some(vec![0xAA; 32]),
                    tag,
                    session_id: sid,
                    short_app_id: app,
                };
                dev.exec_op_fp_gcm(op, params, data.to_vec())
            };
            let bulk_id = key.bulk_key_id.expect("bulk key id");
            let sealed =
                gcm(dev, SHORT_APP_ID, bulk_id, DdiAesOp::Encrypt, None, &MSG).expect("encrypt");

            nssr(dev);
            assert_stale_session(gcm(
                dev,
                SHORT_APP_ID,
                bulk_id,
                DdiAesOp::Encrypt,
                None,
                &MSG,
            ));
            let app = lm.recover_session(dev).short_app_id;
            assert_stale_bulk_key(gcm(dev, app, bulk_id, DdiAesOp::Encrypt, None, &MSG), 2);
            let bulk_id = lm
                .unmask(dev, key.masked_key)
                .bulk_key_id
                .expect("restored bulk key id");
            let opened = gcm(
                dev,
                app,
                bulk_id,
                DdiAesOp::Decrypt,
                sealed.tag,
                &sealed.data,
            )
            .expect("checkpoint 3");
            assert_eq!(opened.data, MSG);
            let resealed = gcm(dev, app, bulk_id, DdiAesOp::Encrypt, None, &MSG).expect("encrypt");
            assert_eq!((resealed.data, resealed.tag), (sealed.data, sealed.tag));
        },
    );
}

#[test]
fn nssr_bulk_aes_xts() {
    if !sock_selected() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sid = lm.sid();
            let keys = [(); 2].map(|()| {
                generate_aes_bulk_256_key(dev, &sid, DdiAesKeySize::AesXtsBulk256)
                    .expect("XTS bulk key")
                    .data
            });
            let xts =
                |dev: &Dev, app: u8, (key_id1, key_id2): (u16, u16), op: DdiAesOp, data: &[u8]| {
                    let params = DdiAesXtsParams {
                        data_unit_len: data.len(),
                        key_id1: u32::from(key_id1),
                        key_id2: u32::from(key_id2),
                        tweak: [0x4; 16],
                        session_id: sid,
                        short_app_id: app,
                    };
                    dev.exec_op_fp_xts(op, params, data.to_vec())
                };
            let bulk_ids = |ids: [Option<u16>; 2]| {
                (ids[0].expect("bulk key id"), ids[1].expect("bulk key id"))
            };
            let old = bulk_ids([keys[0].bulk_key_id, keys[1].bulk_key_id]);
            let ciphertext = xts(dev, SHORT_APP_ID, old, DdiAesOp::Encrypt, &MSG)
                .expect("encrypt")
                .data;

            nssr(dev);
            assert_stale_session(xts(dev, SHORT_APP_ID, old, DdiAesOp::Encrypt, &MSG));
            let app = lm.recover_session(dev).short_app_id;
            assert_stale_bulk_key(xts(dev, app, old, DdiAesOp::Encrypt, &MSG), 1);
            let new = bulk_ids(keys.map(|key| lm.unmask(dev, key.masked_key).bulk_key_id));
            let plaintext = xts(dev, app, new, DdiAesOp::Decrypt, &ciphertext)
                .expect("checkpoint 3")
                .data;
            assert_eq!(plaintext, MSG);
            let again = xts(dev, app, new, DdiAesOp::Encrypt, &MSG).expect("encrypt");
            assert_eq!(again.data, ciphertext);
        },
    );
}
