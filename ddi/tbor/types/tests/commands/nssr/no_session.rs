// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the no-session opcodes. They answer straight after the
//! reset, without recovery, and describe the reset partition: back in
//! `Enabled` with a regenerated identity key and a re-issued leaf
//! certificate.

use tsra_ddi_tbor_types::TborGetCertChainInfoReq;
use tsra_ddi_tbor_types::TborGetCertReq;
use tsra_ddi_tbor_types::TborPartInfoReq;

use super::World;
use crate::commands::part_info::PART_STATE_ENABLED;
use crate::commands::part_info::PART_STATE_INITIALIZED;

const SLOT: u8 = 0;

#[test]
pub(super) fn nssr_api_rev() {
    let w = World::new();
    let before = w.ctx.api_rev().expect("ApiRev");
    w.nssr();
    let after = w.ctx.api_rev().expect("ApiRev after NSSR");
    assert_eq!(after.min_ver, before.min_ver);
    assert_eq!(after.max_ver, before.max_ver);
}

#[test]
pub(super) fn nssr_part_info() {
    let mut w = World::new();
    let before = w.ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    assert_eq!(before.part_state, PART_STATE_INITIALIZED);

    w.nssr();
    let after = w
        .ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after NSSR");
    assert_eq!(after.part_state, PART_STATE_ENABLED);
    assert_eq!(after.sd_initialized, 0);
    assert_ne!(
        after.pid_pub_key, before.pid_pub_key,
        "NSSR must regenerate the identity key"
    );
    assert_eq!(after.owner_svn, before.owner_svn);
    assert_eq!(after.mfgr_svn, before.mfgr_svn);
    assert!(after.generation >= before.generation);

    w.recover();
    let recovered = w
        .ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after recovery");
    assert_eq!(recovered.part_state, PART_STATE_INITIALIZED);
    assert_eq!(
        recovered.pid_pub_key, after.pid_pub_key,
        "re-provisioning keeps the post-reset identity key"
    );
}

#[test]
pub(super) fn nssr_get_cert_chain_info() {
    let w = World::new();
    let before = w
        .ctx
        .tbor(&TborGetCertChainInfoReq::new(SLOT))
        .expect("GetCertChainInfo");
    w.nssr();
    let after = w
        .ctx
        .tbor(&TborGetCertChainInfoReq::new(SLOT))
        .expect("GetCertChainInfo after NSSR");
    assert_eq!(after.num_certs, before.num_certs);
    assert_ne!(
        after.thumbprint, before.thumbprint,
        "the chain must reflect the regenerated identity key"
    );
}

/// Also covers an NSSR between `GetCertChainInfo` and `GetCertificate`:
/// certificates fetched after the reset belong to the new chain.
#[test]
pub(super) fn nssr_get_certificate() {
    let w = World::new();
    let chain = |w: &World| -> Vec<Vec<u8>> {
        let count = w
            .ctx
            .tbor(&TborGetCertChainInfoReq::new(SLOT))
            .expect("GetCertChainInfo")
            .num_certs;
        (0..count)
            .map(|id| {
                w.ctx
                    .tbor(&TborGetCertReq::new(SLOT, id))
                    .expect("GetCertificate")
                    .certificate
            })
            .collect()
    };
    let before = chain(&w);
    let leaf = before.len() - 1;
    w.nssr();
    let after: Vec<_> = (0..before.len() as u8)
        .map(|id| {
            w.ctx
                .tbor(&TborGetCertReq::new(SLOT, id))
                .expect("GetCertificate after NSSR")
                .certificate
        })
        .collect();
    assert_eq!(
        after[..leaf],
        before[..leaf],
        "issuer certificates survive the NSSR"
    );
    assert_ne!(after[leaf], before[leaf], "the leaf must be re-issued");
    assert_eq!(after, chain(&w), "the chain is stable after the reset");
}
