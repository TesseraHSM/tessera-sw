// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks that the host-side entry codecs in `tsra_ddi_sock_proto` agree
//! with the firmware's. The client no longer depends on firmware crates,
//! so this is where the two layouts meet.

use tsra_ddi_sock_proto::bulk as host_bulk;
use tsra_ddi_sock_proto::cmd as host_cmd;
use tsra_ddi_sock_proto::duo as host_duo;
use tsra_fw_hsm_bulk as fw_bulk;
use tsra_fw_hsm_io as fw_io;
use tsra_fw_hsm_io::duo as fw_duo;

#[test]
fn cmd_sqe_matches_firmware() {
    let raw = host_cmd::SqeBuilder::new()
        .cmd(
            host_cmd::CmdDword::new()
                .with_op(host_cmd::OP_TBOR)
                .with_id(0xBEEF),
        )
        .buf_lens(5, 6)
        .session_flags(
            host_cmd::SessionFlags::new()
                .with_ctrl(2)
                .with_id_valid(true),
        )
        .session_id(7)
        .oob_len(32)
        .build();
    let sqe = fw_io::Sqe::from(&raw);
    assert_eq!(sqe.op(), fw_io::OP_TBOR);
    assert_eq!(host_cmd::OP_MBOR, fw_io::OP_MBOR);
    assert_eq!(sqe.cmd_id(), 0xBEEF);
    assert_eq!(host_cmd::CmdDword::from_bits(raw[0]).id(), 0xBEEF);
    assert_eq!((sqe.src_len(), sqe.dst_len()), (5, 6));
    assert_eq!(sqe.session_flags().ctrl(), 2);
    assert!(sqe.session_flags().id_valid());
    assert_eq!(sqe.session_id(), 7);
    assert_eq!(sqe.oob_len(), 32);
}

#[test]
fn cmd_cqe_matches_firmware() {
    let mut raw = [0u32; fw_io::CQE_DWORDS];
    let mut cqe = fw_io::Cqe::from(&mut raw);
    cqe.set_dst_len(0x40);
    cqe.set_session_id_valid(true);
    cqe.set_cmd_id(0x55);
    cqe.set_phase(true);
    cqe.set_status(0x123);
    assert_eq!(
        host_cmd::Cqe::decode(&raw),
        host_cmd::Cqe {
            dst_len: 0x40,
            status: 0x123,
            cmd_id: 0x55,
        }
    );
}

#[test]
fn duo_sqe_matches_firmware() {
    let tag: [u8; host_duo::DUO_TAG_LEN] = core::array::from_fn(|i| i as u8);
    let iv: [u8; host_duo::DUO_IV_LEN] = core::array::from_fn(|i| 0x80 | i as u8);
    for (op, fw_op) in [
        (host_duo::DuoOp::Tbor, fw_duo::DuoOp::Tbor),
        (host_duo::DuoOp::TborSecure, fw_duo::DuoOp::TborSecure),
        (host_duo::DuoOp::FlushSession, fw_duo::DuoOp::FlushSession),
    ] {
        let raw = host_duo::DuoSqeBuilder::new()
            .cmd(op, 0x1234)
            .session_id(9)
            .oob_len(48)
            .buf_lens(3, 4)
            .gcm_tag(&tag)
            .iv(&iv)
            .build();
        let sqe = fw_duo::DuoSqe::from(&raw);
        assert_eq!(sqe.op(), Ok(fw_op));
        assert_eq!(sqe.cmd_id(), 0x1234);
        assert_eq!(sqe.session_id(), 9);
        assert_eq!(sqe.oob_len(), 48);
        assert_eq!((sqe.src_len(), sqe.dst_len()), (3, 4));
        assert_eq!(sqe.gcm_tag(), tag);
        assert_eq!(sqe.iv(), iv);
    }
}

#[test]
fn duo_cqe_matches_firmware() {
    let tag: [u8; fw_duo::DUO_TAG_LEN] = core::array::from_fn(|i| i as u8);
    let iv: [u8; fw_duo::DUO_IV_LEN] = core::array::from_fn(|i| 0x80 | i as u8);
    let mut raw = [0u32; fw_duo::DUO_CQE_DWORDS];
    let mut cqe = fw_duo::DuoCqe::from(&mut raw);
    cqe.set_cmd(fw_duo::DuoCmdDword::new().with_op(1).with_id(0xAA));
    cqe.set_tag(&tag);
    cqe.set_iv(&iv);
    cqe.set_dst_len(77);
    cqe.set_error(0x0BAD);
    cqe.set_phase(true);
    cqe.set_status(0x5A);
    assert_eq!(
        host_duo::DuoCqe::decode(&raw),
        host_duo::DuoCqe {
            cmd_id: 0xAA,
            tag,
            iv,
            dst_len: 77,
            error: 0x0BAD,
            status: 0x5A,
        }
    );
}

#[test]
fn bulk_gcm_sqe_matches_firmware() {
    let host = host_bulk::BulkSqe {
        dir: host_bulk::BulkDir::Decrypt,
        cid: 0x1234,
        session_id: 0x5678,
        short_app_id: 0x9A,
        src_len: 64,
        src_addr: 0x1111_2222_3333_4444,
        dst_len: 64,
        dst_addr: 0x5555_6666_7777_8888,
        params: host_bulk::BulkParams::Gcm(host_bulk::GcmParams {
            key_id: 0xDEAD_BEEF,
            aad_len: 20,
            aligned_aad_len: 32,
            tag: core::array::from_fn(|i| i as u8),
            iv: core::array::from_fn(|i| 0x40 | i as u8),
            tail: Some(host_bulk::GcmTail {
                len: 7,
                src: 0xAAAA_0000,
                dst: 0xBBBB_0000,
            }),
        }),
    };
    let fw = fw_bulk::BulkSqe::parse(&host.encode()).expect("parse GCM SQE");
    assert_eq!(fw.dir, fw_bulk::BulkDir::Decrypt);
    assert_eq!(
        (fw.cid, fw.session_id, fw.short_app_id),
        (0x1234, 0x5678, 0x9A)
    );
    assert_eq!((fw.src_len, fw.src_addr), (64, host.src_addr));
    assert_eq!((fw.dst_len, fw.dst_addr), (64, host.dst_addr));
    let fw_bulk::BulkParams::Gcm(gcm) = fw.params else {
        panic!("expected GCM params");
    };
    let host_bulk::BulkParams::Gcm(want) = host.params else {
        unreachable!();
    };
    assert_eq!(gcm.key_id, want.key_id);
    assert_eq!((gcm.aad_len, gcm.aligned_aad_len), (20, 32));
    assert_eq!((gcm.tag, gcm.iv), (want.tag, want.iv));
    assert_eq!(
        gcm.tail,
        Some(fw_bulk::GcmTail {
            len: 7,
            src: 0xAAAA_0000,
            dst: 0xBBBB_0000,
        })
    );
    assert_eq!(host_bulk::BLOCK_LEN, fw_bulk::BLOCK_LEN);
    assert_eq!(host_bulk::GCM_AAD_ALIGN, fw_bulk::GCM_AAD_ALIGN);
}

#[test]
fn bulk_xts_sqe_matches_firmware() {
    for (dul, fw_dul) in [
        (host_bulk::XtsDul::Full, fw_bulk::XtsDul::Full),
        (host_bulk::XtsDul::B512, fw_bulk::XtsDul::B512),
        (host_bulk::XtsDul::B4096, fw_bulk::XtsDul::B4096),
        (host_bulk::XtsDul::B8192, fw_bulk::XtsDul::B8192),
    ] {
        let host = host_bulk::BulkSqe {
            dir: host_bulk::BulkDir::Encrypt,
            cid: 3,
            session_id: 4,
            short_app_id: 5,
            src_len: 8192,
            src_addr: 0x1000,
            dst_len: 8192,
            dst_addr: 0x2000,
            params: host_bulk::BulkParams::Xts(host_bulk::XtsParams {
                dul,
                key_id1: 11,
                key_id2: 22,
                tweak: core::array::from_fn(|i| 0xC0 | i as u8),
            }),
        };
        let fw = fw_bulk::BulkSqe::parse(&host.encode()).expect("parse XTS SQE");
        assert_eq!(fw.dir, fw_bulk::BulkDir::Encrypt);
        let fw_bulk::BulkParams::Xts(xts) = fw.params else {
            panic!("expected XTS params");
        };
        assert_eq!(xts.dul, fw_dul);
        assert_eq!((xts.key_id1, xts.key_id2), (11, 22));
        assert_eq!(xts.tweak, core::array::from_fn(|i| 0xC0 | i as u8));
    }
}

#[test]
fn bulk_cqe_matches_firmware() {
    let fw = fw_bulk::BulkCqe {
        attr: 0x28,
        cid: 9,
        tag: core::array::from_fn(|i| i as u8),
        iv: core::array::from_fn(|i| 0x40 | i as u8),
        tail_len: 7,
        fips_approved: true,
        data_len: 64,
        sq_head: 1,
        sq_id: 2,
        status: fw_bulk::BulkStatus {
            sts: 0x1234,
            err: 0x5678,
        },
        phase: true,
    };
    assert_eq!(
        host_bulk::BulkCqe::decode(&fw.encode()),
        host_bulk::BulkCqe {
            tag: fw.tag,
            iv: fw.iv,
            tail_len: 7,
            fips_approved: true,
            data_len: 64,
            sts: 0x1234,
            err: 0x5678,
        }
    );
}
