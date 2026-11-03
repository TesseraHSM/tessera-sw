// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exercise `PartInfo` framing, session independence, and partition posture.
//!
//! `TborPartInfoReq` is a unit struct: there are no semantic request fields
//! to fuzz. Instead, structured mutations cover its header/TOC/data while
//! valid lifecycle operations vary the state observed by the handler.
//! The dispatcher only performs structural decoding for this opcode; it
//! does not require the typed schema's single `None` placeholder.

#![no_main]

#[path = "../../common.rs"]
mod common;

use arbitrary::Arbitrary;
use libfuzzer_sys::*;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_codec::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// `HostStatus::REQ_HDR_DECODE_ERR` from `fw/core/lib/src/error.rs`.
///
/// `handle_tbor_op` maps every structural parse failure to this CQE
/// status before dispatch; the emu transport returns `DdiError::DdiError`.
const REQUEST_DECODE_STATUS: u32 = 0xC8;
const DEVICE_KIND_PHYSICAL: u8 = 2;
const PART_STATE_ENABLED: u8 = 2;
const PART_STATE_INITIALIZING: u8 = 4;
const PART_STATE_INITIALIZED: u8 = 5;
const MAX_REPEAT_CALLS: u8 = 4;
/// Even the largest constructed frame is far below the 4-KiB transport limit.
const WIRE_CAPACITY: usize = REQ_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + 32;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Posture {
    /// Enabled, without opening any session.
    Enabled,
    /// Probe both Pending and Active, then close and probe again.
    SessionLifecycle,
    /// Bind a policy using `PartInit`, without finalizing.
    Initializing,
    /// Finalize the partition without creating a security domain.
    Initialized,
    /// Finalize and create the security domain using the shared fixture.
    SecurityDomain,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FrameCase {
    /// Use the real typed encoder, without mutation.
    Canonical,
    /// Change only header bits that structural decoding ignores.
    ReservedHeader,
    /// Add structurally valid TOC entries.
    AdditionalToc,
    /// Replace the placeholder with a valid inline or offset/length entry.
    AlternativeToc,
    /// Add unused data after the placeholder.
    TrailingData,
    /// Replace the placeholder with a forward-compatible unknown type.
    UnknownToc,
    /// Force a version different from the supported protocol version.
    UnsupportedVersion,
    /// Remove part of the header or mandatory TOC, retaining at least one byte.
    Truncated,
    /// Claim more TOC entries than the frame contains.
    MissingToc,
    /// Set at least one of the `None` entry's reserved payload bits.
    NonePayload,
    /// Make a buffer reference extend past the data section.
    OutOfBounds,
    /// Use an in-bounds Uint32/Uint64 reference with the wrong length.
    InvalidFixedLength,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    posture: Posture,
    frame: FrameCase,
    /// Inline values, offset/length choices, and reserved bits.
    value: u32,
    /// Mutation position, entry kind, TOC count, or trailing-data length.
    selector: u8,
    /// Number of identical requests, bounded to preserve throughput.
    repeats: u8,
    /// Bounded arbitrary data for accepted and rejected offset/length entries.
    data: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum Expected {
    Success,
    /// Parse failures precede dispatch and have no TBOR response body.
    CqeReject,
}

struct WireRequest(Vec<u8>);

impl TborOpReq for WireRequest {
    const OPCODE: u8 = TBOR_OP_PART_INFO;
    type OpResp = TborPartInfoResp;

    /// Copy the bounded frame unchanged, retaining the trait's NoSession defaults.
    ///
    /// Invalid frames must reach firmware, not be rejected by a host encoder.
    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], EncodeError> {
        let out = buf
            .get_mut(..self.0.len())
            .ok_or(EncodeError::BufferTooSmall)?;
        out.copy_from_slice(&self.0);
        Ok(out)
    }
}

/// Replace the first TOC entry using its big-endian wire representation.
fn set_entry(bytes: &mut [u8], kind: u8, payload: u32) {
    let word = (u32::from(kind) << 26) | (payload & 0x03FF_FFFF);
    bytes[REQ_HEADER_LEN..REQ_HEADER_LEN + TOC_ENTRY_LEN].copy_from_slice(&word.to_be_bytes());
}

/// Build one bounded frame and its independent, construction-based oracle.
///
/// Each rejection introduces exactly one structural defect. In particular,
/// fixed-length faults remain in bounds, and truncation retains a nonzero
/// source length so SQE validation does not mask the framing rejection.
fn build_request(input: &FuzzInput) -> (WireRequest, Expected) {
    let mut storage = [0; WIRE_CAPACITY];
    let mut bytes = TborPartInfoReq::new()
        .encode_request(&mut storage)
        .expect("canonical PartInfo must encode")
        .to_vec();
    let mut expected = Expected::Success;

    match input.frame {
        FrameCase::Canonical => {}
        FrameCase::ReservedHeader => {
            bytes[1] = input.selector | 1;
            bytes[2] |= (input.data[0] & 0xE0) | 0x20;
            bytes[4..REQ_HEADER_LEN].copy_from_slice(&input.value.to_le_bytes());
        }
        FrameCase::AdditionalToc => {
            let count = 2 + usize::from(input.selector) % (MAX_TOC_ENTRIES - 1);
            bytes[2] = (count - 1) as u8;
            for i in 1..count {
                let word = ((TocType::Uint16 as u32) << 26)
                    | u32::from(u16::from_be_bytes([
                        input.data[i % input.data.len()],
                        input.data[(i + 1) % input.data.len()],
                    ]));
                bytes.extend_from_slice(&word.to_be_bytes());
            }
        }
        FrameCase::AlternativeToc => {
            let kinds = [
                TocType::SessionId,
                TocType::KeyId,
                TocType::Uint8,
                TocType::Uint16,
                TocType::Buffer,
                TocType::SealedKey,
                TocType::Padding,
                TocType::Uint32,
                TocType::Uint64,
            ];
            let kind = kinds[usize::from(input.selector) % kinds.len()];
            let payload = match kind {
                TocType::Uint32 | TocType::Uint64 => {
                    let length = if kind == TocType::Uint32 { 4 } else { 8 };
                    bytes.extend_from_slice(&input.data);
                    let offset = input.value as usize % (input.data.len() - length + 1);
                    ((length as u32) << 13) | offset as u32
                }
                TocType::Buffer | TocType::SealedKey | TocType::Padding => {
                    bytes.extend_from_slice(&input.data);
                    let offset = input.value as usize % (input.data.len() + 1);
                    let length = usize::from(input.data[0]) % (input.data.len() - offset + 1);
                    ((length as u32) << 13) | offset as u32
                }
                _ => input.value,
            };
            set_entry(&mut bytes, kind as u8, payload);
        }
        FrameCase::TrailingData => {
            let length = 1 + usize::from(input.selector) % input.data.len();
            bytes.extend_from_slice(&input.data[..length]);
        }
        FrameCase::UnknownToc => {
            let first_unknown = TocType::Padding as u8 + 1;
            let kind = first_unknown + input.selector % (64 - first_unknown);
            set_entry(&mut bytes, kind, input.value);
        }
        FrameCase::UnsupportedVersion => {
            // A nonzero XOR cannot accidentally produce the original version.
            bytes[0] = PROTOCOL_VERSION ^ (input.selector | 1);
            expected = Expected::CqeReject;
        }
        FrameCase::Truncated => {
            let length = 1 + usize::from(input.selector) % (bytes.len() - 1);
            bytes.truncate(length);
            expected = Expected::CqeReject;
        }
        FrameCase::MissingToc => {
            bytes[2] = 1 + input.selector % (MAX_TOC_ENTRIES as u8 - 1);
            expected = Expected::CqeReject;
        }
        FrameCase::NonePayload => {
            set_entry(
                &mut bytes,
                TocType::None as u8,
                input.value | (1 << (input.selector % 26)),
            );
            expected = Expected::CqeReject;
        }
        FrameCase::OutOfBounds => {
            bytes.extend_from_slice(&input.data);
            let offset = input.value % (input.data.len() as u32 + 1);
            let length = input.data.len() as u32 - offset + 1 + u32::from(input.selector);
            set_entry(&mut bytes, TocType::Buffer as u8, (length << 13) | offset);
            expected = Expected::CqeReject;
        }
        FrameCase::InvalidFixedLength => {
            bytes.extend_from_slice(&input.data);
            let (kind, required) = if input.selector & 1 == 0 {
                (TocType::Uint32, 4)
            } else {
                (TocType::Uint64, 8)
            };
            let mut length = input.value % (input.data.len() as u32 + 1);
            if length == required {
                length -= 1;
            }
            let offset = u32::from(input.selector) % (input.data.len() as u32 - length + 1);
            set_entry(&mut bytes, kind as u8, (length << 13) | offset);
            expected = Expected::CqeReject;
        }
    }
    (WireRequest(bytes), expected)
}

/// Read a canonical response and verify the fixture's current lifecycle posture.
fn read_info(ctx: &TestCtx, state: u8, sd_initialized: bool) -> TborPartInfoResp {
    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("canonical PartInfo must succeed");
    assert_eq!(info.device_kind, DEVICE_KIND_PHYSICAL);
    assert_eq!(info.part_state, state);
    assert_eq!(info.sd_initialized, u8::from(sd_initialized));
    assert!(
        info.pid_pub_key.iter().any(|&byte| byte != 0),
        "partition identity public key must be materialized"
    );
    info
}

/// Assert that provisioning changes posture, not partition identity or lineage.
///
/// Generation changes on allocation/free, neither of which these scenarios run.
fn assert_identity(before: &TborPartInfoResp, after: &TborPartInfoResp) {
    assert_eq!(after.device_kind, before.device_kind);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.owner_svn, before.owner_svn);
    assert_eq!(after.mfgr_svn, before.mfgr_svn);
    assert_eq!(after.pid, before.pid);
    assert_eq!(after.pid_pub_key, before.pid_pub_key);
}

/// Submit repeated frames and verify their predicted outcome and lack of effects.
///
/// The real response decoder is used for every successful request. Only the
/// specific pre-dispatch CQE decode status is accepted for malformed frames;
/// driver faults, encode/decode failures, and command errors remain failures.
fn exercise(ctx: &TestCtx, input: &FuzzInput, baseline: &TborPartInfoResp) {
    let (request, expected) = build_request(input);
    for _ in 0..1 + input.repeats % MAX_REPEAT_CALLS {
        let result = ctx.tbor(&request);
        match expected {
            Expected::Success => assert_eq!(
                result.expect("structurally valid PartInfo frame must succeed"),
                *baseline,
                "accepted framing must not change PartInfo"
            ),
            Expected::CqeReject => assert!(
                matches!(result, Err(DdiError::DdiError(status)) if status == REQUEST_DECODE_STATUS),
                "unexpected CQE request-decode status"
            ),
        }
        assert_eq!(
            ctx.tbor(&TborPartInfoReq::new())
                .expect("canonical PartInfo must remain responsive after each probe"),
            *baseline,
            "PartInfo probe must not mutate partition state"
        );
    }
}

/// Exercise the selected posture without hiding setup failures or leaking sessions.
fn run(ctx: &TestCtx, input: &FuzzInput) {
    let before = read_info(ctx, PART_STATE_ENABLED, false);
    match input.posture {
        Posture::Enabled => exercise(ctx, input, &before),
        Posture::SessionLifecycle => {
            let role = if input.selector & 1 == 0 {
                common::FuzzRole::Co
            } else {
                common::FuzzRole::Cu
            };
            let pending = ctx
                .session_open_init(role.psk_id(), role.session_type())
                .expect("pending handshake setup must succeed");
            assert_eq!(read_info(ctx, PART_STATE_ENABLED, false), before);
            exercise(ctx, input, &before);
            let session = ctx
                .session_open_finish(pending)
                .expect("finishing the pending handshake must succeed");
            assert_eq!(read_info(ctx, PART_STATE_ENABLED, false), before);
            exercise(ctx, input, &before);
            ctx.session_close(session.session_id)
                .expect("probe session must close");
            assert_eq!(read_info(ctx, PART_STATE_ENABLED, false), before);
            exercise(ctx, input, &before);
        }
        Posture::Initializing | Posture::Initialized | Posture::SecurityDomain => {
            let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
            assert_eq!(read_info(ctx, PART_STATE_ENABLED, false), before);
            let (state, sd_initialized) = match input.posture {
                Posture::Initializing => {
                    let policy = common::known_good_part_policy(
                        common::fill_ecc384_pubkey_pattern(input.selector),
                    );
                    ctx.part_init(
                        &session,
                        &common::mach_seed(),
                        &policy,
                        &common::pota_thumbprint(),
                    )
                    .expect("valid PartInit must succeed");
                    (PART_STATE_INITIALIZING, false)
                }
                Posture::Initialized => {
                    common::finalize_partition(ctx, &session);
                    (PART_STATE_INITIALIZED, false)
                }
                Posture::SecurityDomain => {
                    common::create_test_security_domain(ctx, &session);
                    (PART_STATE_INITIALIZED, true)
                }
                _ => unreachable!("only provisioning postures enter this branch"),
            };
            let after = read_info(ctx, state, sd_initialized);
            assert_identity(&before, &after);
            exercise(ctx, input, &after);
            ctx.session_close(session.session_id)
                .expect("provisioning session must close");
            assert_eq!(read_info(ctx, state, sd_initialized), after);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| run(ctx, &input));
});
