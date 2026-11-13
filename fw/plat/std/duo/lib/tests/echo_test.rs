// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the Duo `StdHsm`: TBOR exchanged over 32-dword
//! Duo SQEs and 16-dword Duo CQEs.
//!
//! Due to the global HSM OnceLock, only one StdHsm can be active per
//! process. All tests share a single instance via LazyLock.

use std::sync::Arc;

use tsra_fw_ddi_tbor_types::tbor_int::U16;
use tsra_fw_ddi_tbor_types::DeviceKind;
use tsra_fw_ddi_tbor_types::ResponseView;
use tsra_fw_ddi_tbor_types::SessionId;
use tsra_fw_ddi_tbor_types::TborApiRevReq;
use tsra_fw_ddi_tbor_types::TborApiRevResp;
use tsra_fw_ddi_tbor_types::TborGetCertChainInfoReq;
use tsra_fw_ddi_tbor_types::TborGetCertChainInfoResp;
use tsra_fw_ddi_tbor_types::TborGetCertReq;
use tsra_fw_ddi_tbor_types::TborGetCertResp;
use tsra_fw_ddi_tbor_types::TborPartInfoReq;
use tsra_fw_ddi_tbor_types::TborPartInfoResp;
use tsra_fw_ddi_tbor_types::TborSessionCloseReq;
use tsra_fw_ddi_tbor_types::PID_LEN;
use tsra_fw_ddi_tbor_types::PID_PUB_KEY_LEN;
use tsra_fw_hsm_io::duo::DuoCmdDword;
use tsra_fw_hsm_io::duo::DuoCqeDw14;
use tsra_fw_hsm_io::duo::DuoCqeDw15;
use tsra_fw_hsm_io::duo::DuoOp;
use tsra_fw_hsm_io::duo::DuoRawCqe;
use tsra_fw_hsm_io::duo::DuoRawSqe;
use tsra_fw_hsm_io::duo::DuoSqeBuilder;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_std_duo::StdHsm;

/// A 4K-aligned buffer for DMA testing.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: AlignedBuf owns its allocation exclusively.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        Self { ptr, len }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    #[allow(dead_code)]
    fn fill(&mut self, val: u8) {
        self.as_mut_slice().fill(val);
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.len, 4096).unwrap();
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

/// Duo CQE host status codes (CQE DW15 `status`), mirroring the core's
/// `HostStatus` constants narrowed to 8 bits.
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_INVALID_COMMAND_OPCODE: u8 = 0x01;
const STATUS_INVALID_FIELD_IN_COMMAND: u8 = 0x02;
const STATUS_INVALID_SRC_LEN: u8 = 0xC1;
const STATUS_INVALID_DST_LEN: u8 = 0xC2;
const STATUS_SESSION_TRANSPORT_ERR: u8 = 0xCC;

/// Build a Duo command dword.
fn cmd(op: u8, cmd_id: u16) -> DuoCmdDword {
    DuoCmdDword::new().with_op(op).with_id(cmd_id)
}

/// Build a minimal plain-TBOR Duo SQE with `cmd_id` and no DMA.
fn sqe(cmd_id: u16) -> DuoRawSqe {
    DuoSqeBuilder::new()
        .cmd(cmd(DuoOp::Tbor as u8, cmd_id))
        .build()
}

/// Build a Duo SQE whose source/destination PRPs point to `src` / `dst`.
fn sqe_with_dma(op: DuoOp, cmd_id: u16, session_id: u16, src: &[u8], dst: &mut [u8]) -> DuoRawSqe {
    DuoSqeBuilder::new()
        .cmd(cmd(op as u8, cmd_id))
        .session_id(session_id)
        .buf_lens(src.len() as u32, dst.len() as u32)
        .src_prp1(src.as_ptr() as u64)
        .dst_prp1(dst.as_mut_ptr() as u64)
        .build()
}

fn cqe_cmd(cqe: &DuoRawCqe) -> DuoCmdDword {
    DuoCmdDword::from(cqe[0])
}

fn cqe_dst_len(cqe: &DuoRawCqe) -> usize {
    cqe[11] as usize
}

fn cqe_sq_id(cqe: &DuoRawCqe) -> u16 {
    DuoCqeDw14::from(cqe[14]).sq_id()
}

fn cqe_status(cqe: &DuoRawCqe) -> u8 {
    DuoCqeDw15::from(cqe[15]).status()
}

/// Views host bytes as a [`HsmDmaBuf`] for the TBOR decoders.
fn dma(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: host tests only read the slice through ordinary accesses;
    // no DMA engine touches it.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

/// Submit one TBOR exchange over `op`, encoding the request with
/// `encode` into a 4K-aligned buffer. Returns the CQE and the response
/// bytes (as reported by the CQE destination length).
async fn tbor_io(
    pid: u8,
    op: DuoOp,
    cmd_id: u16,
    session_id: u16,
    qid: u16,
    encode: impl FnOnce(&mut [u8]) -> usize,
) -> (DuoRawCqe, Vec<u8>) {
    let mut src = AlignedBuf::new(4096);
    let mut dst = AlignedBuf::new(4096);
    let req_len = encode(src.as_mut_slice());
    let c = HSM
        .io(
            sqe_with_dma(
                op,
                cmd_id,
                session_id,
                &src.as_slice()[..req_len],
                dst.as_mut_slice(),
            ),
            pid,
            qid,
            0,
        )
        .await
        .expect("io");
    let resp = dst.as_slice()[..cqe_dst_len(&c)].to_vec();
    (c, resp)
}

fn encode_api_rev(buf: &mut [u8]) -> usize {
    TborApiRevReq::encode(buf)
        .expect("encode")
        .finish()
        .as_bytes()
        .len()
}

static HSM: std::sync::LazyLock<Arc<StdHsm>> = std::sync::LazyLock::new(|| Arc::new(StdHsm::new()));

/// Partition used by all IO tests. Allocated once via [`ensure_io_part`].
const IO_PID: u8 = 10;

/// Ensure the IO test partition is allocated and enabled. Safe to call multiple times.
async fn ensure_io_part() {
    // Ignore errors — means another test already set it up.
    let _ = HSM.part_alloc(IO_PID, 1u128 << IO_PID).await;
    let _ = HSM.part_enable(IO_PID).await;
}

#[tokio::test]
async fn single_io() {
    ensure_io_part().await;
    let c = HSM.io(sqe(42), IO_PID, 0, 0).await.expect("io");
    assert_eq!(cqe_cmd(&c).id(), 42);
}

#[tokio::test]
async fn cqe_echoes_sqe_cmd_dword() {
    ensure_io_part().await;
    let dword = DuoCmdDword::new()
        .with_op(DuoOp::FlushSession as u8)
        .with_hint(0x5A)
        .with_id(0xBEEF);
    let sqe = DuoSqeBuilder::new().cmd(dword).build();
    let c = HSM.io(sqe, IO_PID, 0, 0).await.expect("io");
    assert_eq!(
        c[0],
        u32::from(dword),
        "CQE DW0 must echo the SQE cmd dword"
    );
}

#[tokio::test]
async fn multiple_sequential_ios() {
    ensure_io_part().await;
    for i in 0..10u16 {
        let c = HSM.io(sqe(i), IO_PID, 0, 0).await.expect("io");
        assert_eq!(cqe_cmd(&c).id(), i);
    }
}

#[tokio::test]
async fn concurrent_ios() {
    ensure_io_part().await;
    let mut handles = Vec::new();
    for i in 100..110u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.io(sqe(i), IO_PID, i, 0).await.expect("io");
            assert_eq!(cqe_cmd(&c).id(), i);
            assert_eq!(cqe_sq_id(&c), i);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn fifty_concurrent_ios() {
    ensure_io_part().await;
    let mut handles = Vec::new();
    for i in 200..250u16 {
        let hsm = Arc::clone(&HSM);
        handles.push(tokio::spawn(async move {
            let c = hsm.io(sqe(i), IO_PID, 0, 0).await.expect("io");
            assert_eq!(cqe_cmd(&c).id(), i);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn tbor_get_api_rev() {
    ensure_io_part().await;

    let queue_id = 0x1234;
    let (c, resp) = tbor_io(IO_PID, DuoOp::Tbor, 1002, 0, queue_id, encode_api_rev).await;
    assert_eq!(cqe_cmd(&c).id(), 1002, "cmd_id mismatch");
    assert_eq!(cqe_sq_id(&c), queue_id);
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);
    assert!(!resp.is_empty(), "response length is zero");
    // A plain TBOR completion carries no transport tag or IV.
    assert!(c[1..8].iter().all(|&w| w == 0), "unexpected tag/IV");

    let view = TborApiRevResp::decode(dma(&resp)).expect("decode resp");
    let rev = |major: U16, minor: U16| (major.get(), minor.get());
    assert_eq!(rev(view.min_major(), view.min_minor()), (2, 0));
    assert_eq!(rev(view.max_major(), view.max_minor()), (2, 0));
}

#[tokio::test]
async fn tbor_part_info() {
    ensure_io_part().await;

    let (c, resp) = tbor_io(IO_PID, DuoOp::Tbor, 800, 0, 0, |buf| {
        TborPartInfoReq::encode(buf)
            .expect("encode")
            .finish()
            .as_bytes()
            .len()
    })
    .await;
    assert_eq!(cqe_cmd(&c).id(), 800, "cmd_id");
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);

    let view = TborPartInfoResp::decode(dma(&resp)).expect("decode resp");
    assert_eq!(view.device_kind(), DeviceKind::Physical);
    assert_eq!(view.pid().len(), PID_LEN);
    assert_eq!(view.pid_pub_key().len(), PID_PUB_KEY_LEN);
    assert!(!ResponseView::parse(dma(&resp))
        .expect("parse")
        .fips_approved());
}

#[tokio::test]
async fn cqe_status_on_invalid_src_len() {
    ensure_io_part().await;
    // SQE with src_len=0 → invalid source length.
    let queue_id = u16::MAX;
    let c = HSM.io(sqe(500), IO_PID, queue_id, 0).await.expect("io");
    assert_eq!(cqe_cmd(&c).id(), 500, "cmd_id");
    assert_eq!(cqe_sq_id(&c), queue_id);
    assert_eq!(cqe_status(&c), STATUS_INVALID_SRC_LEN);
    assert_eq!(cqe_dst_len(&c), 0);
}

#[tokio::test]
async fn cqe_status_on_invalid_dst_len() {
    ensure_io_part().await;
    let sqe = DuoSqeBuilder::new()
        .cmd(cmd(DuoOp::Tbor as u8, 503))
        .buf_lens(64, 0)
        .build();
    let c = HSM.io(sqe, IO_PID, 0, 0).await.expect("io");
    assert_eq!(cqe_status(&c), STATUS_INVALID_DST_LEN);
}

#[tokio::test]
async fn cqe_status_on_oob_len_without_pointer() {
    ensure_io_part().await;
    // A non-zero OOB length with a null OOB pointer is an invalid field.
    let sqe = DuoSqeBuilder::new()
        .cmd(cmd(DuoOp::Tbor as u8, 501))
        .buf_lens(64, 64)
        .oob_len(16)
        .build();
    let c = HSM.io(sqe, IO_PID, 0, 0).await.expect("io");
    assert_eq!(cqe_cmd(&c).id(), 501, "cmd_id");
    assert_eq!(cqe_status(&c), STATUS_INVALID_FIELD_IN_COMMAND);
}

#[tokio::test]
async fn cqe_status_on_unknown_op() {
    ensure_io_part().await;
    let sqe = DuoSqeBuilder::new().cmd(cmd(0xFF, 504)).build();
    let c = HSM.io(sqe, IO_PID, 7, 0).await.expect("io");
    assert_eq!(cqe_cmd(&c).op(), 0xFF, "cmd dword echoed");
    assert_eq!(cqe_cmd(&c).id(), 504, "cmd_id");
    assert_eq!(cqe_sq_id(&c), 7);
    assert_eq!(cqe_status(&c), STATUS_INVALID_COMMAND_OPCODE);
}

#[tokio::test]
async fn in_session_command_on_plain_tbor_is_rejected() {
    ensure_io_part().await;

    let (c, resp) = tbor_io(IO_PID, DuoOp::Tbor, 701, 1, 0, |buf| {
        TborSessionCloseReq::encode(buf)
            .expect("encode")
            .session_id(SessionId(1))
            .expect("session_id")
            .finish()
            .as_bytes()
            .len()
    })
    .await;

    // Post-decode error → CQE Success, TBOR error in body.
    assert_eq!(cqe_cmd(&c).id(), 701, "cmd_id");
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);
    let view = ResponseView::parse(dma(&resp)).expect("parse resp");
    assert_eq!(view.status(), HsmError::InvalidSessionControlOpcode.0);
}

#[tokio::test]
async fn flush_absent_session_completes() {
    ensure_io_part().await;
    let sqe = DuoSqeBuilder::new()
        .cmd(cmd(DuoOp::FlushSession as u8, 702))
        .session_id(0x7FFF)
        .build();
    let c = HSM.io(sqe, IO_PID, 0, 0).await.expect("io");
    assert_eq!(cqe_cmd(&c).id(), 702, "cmd_id");
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);
    assert_eq!(cqe_dst_len(&c), 0);
}

#[tokio::test]
async fn secure_tbor_without_session_fails_transport() {
    ensure_io_part().await;

    let (c, resp) = tbor_io(IO_PID, DuoOp::TborSecure, 703, 0x7FFF, 0, encode_api_rev).await;
    assert_eq!(cqe_cmd(&c).id(), 703, "cmd_id");
    assert_eq!(cqe_status(&c), STATUS_SESSION_TRANSPORT_ERR);
    assert!(resp.is_empty(), "no response on transport failure");
}

#[tokio::test]
async fn io_dropped_on_disabled_partition() {
    // Partition 63 is never allocated — IO should be dropped.
    let result = HSM.io(sqe(900), 63, 0, 0).await;
    assert!(
        result.is_err(),
        "IO on disabled partition should be dropped"
    );
}

// ---------------------------------------------------------------------------
// Partition sideband tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn part_alloc_single() {
    let result = HSM.part_alloc(0, 1u128 << 0).await;
    assert!(result.is_ok(), "part_alloc(0, mask) failed: {result:?}");
    // Free so subsequent tests see a clean partition 0.
    let _ = HSM.part_free(0).await;
}

#[tokio::test]
async fn part_alloc_free_lifecycle() {
    let pid = 1;
    // Allocate with 2 resources (bits 10,11)
    HSM.part_alloc(pid, 0b11 << 10).await.expect("alloc");
    // Free
    HSM.part_free(pid).await.expect("free");
    // Should be able to re-allocate after free with different mask
    HSM.part_alloc(pid, 0b111 << 10).await.expect("re-alloc");
    HSM.part_free(pid).await.expect("re-free");
}

#[tokio::test]
async fn part_alloc_invalid_pid() {
    let result = HSM.part_alloc(65, 1).await;
    assert!(result.is_err(), "pid=65 should fail");

    let result = HSM.part_alloc(255, 1).await;
    assert!(result.is_err(), "pid=255 should fail");
}

#[tokio::test]
async fn part_free_invalid_pid() {
    let result = HSM.part_free(65).await;
    assert!(result.is_err(), "free pid=65 should fail");
}

#[tokio::test]
async fn part_free_disabled() {
    // Partition 60 was never allocated — freeing should fail.
    let result = HSM.part_free(60).await;
    assert!(result.is_err(), "free of disabled partition should fail");
}

#[tokio::test]
async fn part_double_alloc() {
    let pid = 2;
    HSM.part_alloc(pid, 1u128 << 20).await.expect("first alloc");
    let result = HSM.part_alloc(pid, 1u128 << 21).await;
    assert!(result.is_err(), "double alloc should fail");
    HSM.part_free(pid).await.expect("cleanup");
}

#[tokio::test]
async fn part_resource_exhaustion() {
    // Allocate partitions using up to 65 total resources via bitmasks.
    // pid 50: bits 0..12 (13 bits), pid 51: bits 13..25, etc.
    for (i, pid) in (50..55u8).enumerate() {
        let shift = i * 13;
        let mask = ((1u128 << 13) - 1) << shift;
        HSM.part_alloc(pid, mask).await.expect("alloc");
    }

    // All 65 resources allocated (5×13). Next should overlap.
    let result = HSM.part_alloc(55, 1u128 << 0).await;
    assert!(result.is_err(), "should fail when resources overlap");

    // Cleanup
    for pid in 50..55u8 {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

#[tokio::test]
async fn part_resource_accounting_after_free() {
    // Allocate 3 partitions with non-overlapping masks: 20 bits each.
    // pid 40: bits 0..19, pid 41: bits 20..39, pid 42: bits 40..59
    for (i, pid) in (40..43u8).enumerate() {
        let shift = i * 20;
        let mask = ((1u128 << 20) - 1) << shift;
        HSM.part_alloc(pid, mask).await.expect("alloc");
    }

    // Can't alloc overlapping bit (bit 0 already taken by pid 40)
    let result = HSM.part_alloc(43, 1u128 << 0).await;
    assert!(result.is_err(), "overlapping resource should fail");

    // Free pid 41 (releases bits 20..39)
    HSM.part_free(41).await.expect("free middle");

    // Now can alloc bits 20..39 + bits 60..64 = 25 resources
    let mask = ((1u128 << 20) - 1) << 20 | ((1u128 << 5) - 1) << 60;
    HSM.part_alloc(43, mask).await.expect("alloc after free");

    // Cleanup
    for pid in [40u8, 42, 43] {
        HSM.part_free(pid).await.expect("cleanup");
    }
}

// ---------------------------------------------------------------------------
// Certificate chain tests
// ---------------------------------------------------------------------------

/// Submit `GetCertChainInfo` for `slot_id` on partition `pid`.
async fn get_cert_chain_info(pid: u8, slot_id: u8) -> (DuoRawCqe, Vec<u8>) {
    tbor_io(pid, DuoOp::Tbor, 1108, 0, 0, |buf| {
        TborGetCertChainInfoReq::encode(buf)
            .expect("encode")
            .slot_id(slot_id)
            .expect("slot_id")
            .finish()
            .as_bytes()
            .len()
    })
    .await
}

/// Submit `GetCertificate` for slot 0, `cert_id`.
async fn get_cert(cert_id: u8) -> (DuoRawCqe, Vec<u8>) {
    tbor_io(IO_PID, DuoOp::Tbor, 1109, 0, 0, |buf| {
        TborGetCertReq::encode(buf)
            .expect("encode")
            .slot_id(0)
            .expect("slot_id")
            .cert_id(cert_id)
            .expect("cert_id")
            .finish()
            .as_bytes()
            .len()
    })
    .await
}

/// Asserts `resp` is a TBOR error response.
fn assert_tbor_error(resp: &[u8]) {
    let view = ResponseView::parse(dma(resp)).expect("parse resp");
    assert_ne!(view.status(), 0, "expected error status");
}

#[tokio::test]
async fn get_cert_chain_info_slot0() {
    ensure_io_part().await;
    let (c, resp) = get_cert_chain_info(IO_PID, 0).await;
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);

    let data = TborGetCertChainInfoResp::decode(dma(&resp)).expect("decode");
    assert_eq!(data.num_certs(), 4, "slot 0 should have 4 certs");
    assert_eq!(data.thumbprint().len(), 32, "thumbprint should be 32 bytes");
    assert!(
        data.thumbprint().iter().any(|&b| b != 0),
        "thumbprint must not be all zeros"
    );
}

#[tokio::test]
async fn get_cert_chain_info_invalid_slot() {
    ensure_io_part().await;
    let (c, resp) = get_cert_chain_info(IO_PID, 1).await;
    // TBOR errors are returned inside the response body.
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);
    assert_tbor_error(&resp);
}

/// Helper to retrieve a single certificate by index.
async fn get_cert_der(idx: u8) -> Vec<u8> {
    let (c, resp) = get_cert(idx).await;
    assert_eq!(
        cqe_status(&c),
        STATUS_SUCCESS,
        "cert idx {idx}: expected Success"
    );
    let data = TborGetCertResp::decode(dma(&resp)).expect("decode");
    data.certificate().to_vec()
}

#[tokio::test]
async fn get_certificate_all_indices() {
    ensure_io_part().await;

    for idx in 0..4u8 {
        let cert = get_cert_der(idx).await;
        assert!(
            cert.len() > 100,
            "cert idx {idx}: cert too short ({})",
            cert.len()
        );
    }
}

#[tokio::test]
async fn get_certificate_invalid_index() {
    ensure_io_part().await;
    let (c, resp) = get_cert(4).await;
    assert_eq!(cqe_status(&c), STATUS_SUCCESS);
    assert_tbor_error(&resp);
}

#[tokio::test]
async fn get_certificate_chain_validation() {
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    ensure_io_part().await;

    // Retrieve all 4 certs
    let root_der = get_cert_der(0).await;
    let deviceid_der = get_cert_der(1).await;
    let alias_der = get_cert_der(2).await;
    let leaf_der = get_cert_der(3).await;

    // Parse all certs
    let root = X509Certificate::from_der(&root_der).expect("parse root");
    let deviceid = X509Certificate::from_der(&deviceid_der).expect("parse deviceid");
    let alias = X509Certificate::from_der(&alias_der).expect("parse alias");
    let leaf = X509Certificate::from_der(&leaf_der).expect("parse leaf");

    // Validate chain: leaf → alias → deviceid → root
    assert!(
        leaf.validate_chain(&[alias, deviceid, root])
            .expect("validate chain"),
        "cert chain validation failed"
    );
}

#[tokio::test]
async fn get_cert_thumbprint_consistency() {
    ensure_io_part().await;

    let get_thumbprint = |pid| async move {
        let (c, resp) = get_cert_chain_info(pid, 0).await;
        assert_eq!(cqe_status(&c), STATUS_SUCCESS);
        let data = TborGetCertChainInfoResp::decode(dma(&resp)).expect("decode");
        data.thumbprint().to_vec()
    };

    let tp1 = get_thumbprint(IO_PID).await;
    let tp2 = get_thumbprint(IO_PID).await;
    assert_eq!(tp1, tp2, "thumbprint must be stable across calls");

    let other_pid = 11;
    HSM.part_alloc(other_pid, 1u128 << other_pid)
        .await
        .expect("allocate second partition");
    HSM.part_enable(other_pid)
        .await
        .expect("enable second partition");
    let other_tp = get_thumbprint(other_pid).await;
    assert_ne!(tp1, other_tp, "thumbprint must follow the IO's partition");
    assert_eq!(
        tp1,
        get_thumbprint(IO_PID).await,
        "querying another partition must not change the original chain"
    );
    HSM.part_disable(other_pid)
        .await
        .expect("disable second partition");
    HSM.part_free(other_pid)
        .await
        .expect("free second partition");
}
