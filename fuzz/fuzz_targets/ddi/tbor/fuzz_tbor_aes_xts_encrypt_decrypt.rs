// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured AES-XTS requests: valid operations, isolated faults, and
//! combinations. A pristine generated key keeps authentication from hiding
//! the crypto paths; malformed blobs additionally exercise unmasking.
//! Generated XTS keys permit both directions, so authenticated restricted-
//! permission keys are not constructed by this target.

#![no_main]

#[path = "../../common.rs"]
mod common;

use arbitrary::*;
use libfuzzer_sys::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Maximum number of owned OOB items, including optional padding items.
const OOB_ITEMS: usize = 4;
/// Bound malformed lengths without requiring large corpus entries.
const EXTRA_BYTES: usize = 16;
/// AES-XTS only supports complete 16-byte blocks in this command.
const BLOCK_LEN: usize = 16;

/// Scalar controls precede bounded vectors so small inputs reach the handler.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: u8,
    role: common::FuzzRole,
    op: u8,
    session_id: u16,
    data_len: u16,
    dul: u16,
    in_index: u8,
    out_index: u8,
    tweak: u64,
    length: u16,
    offset: u16,
    mask: u8,
    layout: u8,
    pattern: [u8; BLOCK_LEN],
    raw_tweak: BoundedBytes<{ XTS_TWEAK_LEN * 2 }>,
    raw_key: BoundedBytes<{ MASKED_AES_XTS_KEY_LEN + EXTRA_BYTES }>,
}

/// Bounded bytes with an accurate size hint: derive's `with` callbacks use
/// `size_of::<Vec<u8>>()` instead, unnecessarily rejecting short corpus entries.
#[derive(Debug)]
struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<'a, const MAX: usize> Arbitrary<'a> for BoundedBytes<MAX> {
    /// Read a bounded length and allocate only bytes available in the input.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = (usize::from(u16::arbitrary(u)?) % (MAX + 1)).min(u.len());
        Ok(Self(u.bytes(len)?.to_vec()))
    }

    /// Account for the length prefix rather than the in-memory vector size.
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (size_of::<u16>(), Some(size_of::<u16>() + MAX))
    }
}

/// Outcome predicted before submission, independently of the observed result.
#[derive(Debug)]
enum Expected {
    Success,
    Status(TborStatus),
    /// Altered or arbitrary authenticated envelopes have negligible forgery
    /// probability. Only framing, scope, or authentication rejects are allowed.
    BadKey,
}

/// Construct compatible lengths, including arbitrary block-aligned units.
fn valid_lengths(input: &FuzzInput) -> (usize, usize) {
    let dul = match input.dul % 8 {
        0 => BLOCK_LEN,
        1 => BLOCK_LEN * 2,
        2 => 512,
        3 => 4096,
        4 => XTS_DATA_MAX_LEN,
        _ => BLOCK_LEN * (1 + usize::from(input.dul / 8) % (XTS_DATA_MAX_LEN / BLOCK_LEN)),
    };
    let max_units = XTS_DATA_MAX_LEN / dul;
    let units = if input.scenario % 32 == 0 {
        // Frequent small multi-unit cases enable the per-unit oracle.
        1 + usize::from(input.data_len) % max_units.min(4)
    } else {
        1 + usize::from(input.data_len) % max_units
    };
    (dul * units, dul)
}

/// Finalize only persisted-scope cases, using CO before optionally opening CU.
fn session<'ctx>(ctx: &'ctx TestCtx, input: &FuzzInput, finalized: bool) -> SessionGuard<'ctx> {
    if finalized {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        common::finalize_partition(ctx, co.handshake());
        if matches!(input.role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close partition-setup session");
    }
    let handshake = match input.role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Expand fuzzed bytes into a bounded payload without a large corpus entry.
fn payload(input: &FuzzInput, len: usize, item: usize) -> Vec<u8> {
    (0..len)
        .map(|i| input.pattern[i % BLOCK_LEN] ^ item as u8)
        .collect()
}

/// Predict validation in transport/handler order; schema limits are enforced
/// by firmware, not the host encoder. Key equality accounts for mutation no-ops.
fn expected(
    req: &TborAesXtsEncryptDecryptReq,
    sid: u16,
    pristine: &[u8],
    wrong_kind: bool,
    tag_only: bool,
    buffers: &[Vec<u8>],
) -> Expected {
    let reject = Expected::Status;
    if req.session_id != sid {
        return reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if buffers.is_empty() {
        return reject(TborStatus::InvalidArg);
    }
    if req.tweak.len() != XTS_TWEAK_LEN || req.masked_key.len() != MASKED_AES_XTS_KEY_LEN {
        return reject(TborStatus::TborInvalidFixedLength);
    }
    let len = usize::from(req.data_len);
    if ![AES_OP_ENCRYPT, AES_OP_DECRYPT].contains(&req.op) || len > XTS_DATA_MAX_LEN {
        return reject(TborStatus::InvalidArg);
    }
    let (Some(src), Some(dst)) = (
        buffers.get(usize::from(req.in_index)),
        buffers.get(usize::from(req.out_index)),
    ) else {
        return reject(TborStatus::InvalidArg);
    };
    if wrong_kind {
        return reject(TborStatus::InvalidKeyType);
    }
    // The last four stored IV bytes are ignored when unmasking.
    if req.masked_key[..20] != pristine[..20]
        || req.masked_key[24..] != pristine[24..]
    {
        return if tag_only {
            reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
        } else {
            Expected::BadKey
        };
    }
    let dul = usize::from(req.dul);
    if dul < BLOCK_LEN || !dul.is_multiple_of(BLOCK_LEN) || len == 0 || !len.is_multiple_of(dul) {
        return reject(TborStatus::AesXtsInvalidBufferSize);
    }
    let tweak = u64::from_le_bytes(
        req.tweak
            .as_slice()
            .try_into()
            .expect("validated tweak size"),
    );
    if tweak.checked_add((len / dul) as u64).is_none() {
        return reject(TborStatus::AesXtsInvalidBufferSize);
    }
    if src.len() != len || dst.len() != len {
        return reject(TborStatus::InvalidArg);
    }
    Expected::Success
}

/// Submit owned descriptors; an aliased source/destination stays writable and
/// observable, while a distinct source uses the harness's read-only item.
fn submit(
    ctx: &TestCtx,
    req: &TborAesXtsEncryptDecryptReq,
    buffers: &mut [Vec<u8>],
) -> DdiResult<TborAesXtsEncryptDecryptResp> {
    let mut items: Vec<_> = buffers
        .iter_mut()
        .enumerate()
        .map(|(i, buf)| {
            if i == usize::from(req.in_index) && i != usize::from(req.out_index) {
                TborOobItem::In(buf)
            } else {
                TborOobItem::Out(buf)
            }
        })
        .collect();
    ctx.tbor_oob_io(req, &mut items)
}

/// Execute a canonical follow-up with the same key and unit size.
fn crypt(
    ctx: &TestCtx,
    original: &TborAesXtsEncryptDecryptReq,
    op: u8,
    tweak: u64,
    data: &[u8],
) -> Vec<u8> {
    let req = TborAesXtsEncryptDecryptReq {
        op,
        data_len: data.len() as u16,
        in_index: 0,
        out_index: 1,
        tweak: tweak.to_le_bytes().to_vec(),
        ..original.clone()
    };
    let mut out = vec![0; data.len()];
    ctx.tbor_oob_io(
        &req,
        &mut [TborOobItem::In(data), TborOobItem::Out(&mut out)],
    )
    .expect("valid AES-XTS follow-up");
    out
}

/// Check both inverse directions and, for bounded runs, data-unit advancement.
fn check_output(ctx: &TestCtx, req: &TborAesXtsEncryptDecryptReq, input: &[u8], output: &[u8]) {
    let tweak = u64::from_le_bytes(req.tweak.as_slice().try_into().expect("successful tweak"));
    let inverse = if req.op == AES_OP_ENCRYPT {
        AES_OP_DECRYPT
    } else {
        AES_OP_ENCRYPT
    };
    assert_eq!(
        crypt(ctx, req, inverse, tweak, output),
        input,
        "AES-XTS inverse must reproduce the input"
    );
    let dul = usize::from(req.dul);
    let units = input.len() / dul;
    if (2..=4).contains(&units) {
        for (i, (src, dst)) in input
            .chunks_exact(dul)
            .zip(output.chunks_exact(dul))
            .enumerate()
        {
            assert_eq!(
                crypt(ctx, req, req.op, tweak + i as u64, src),
                dst,
                "multi-unit AES-XTS must match independent unit {i}"
            );
        }
    }
}

/// Construct one scenario, predict its outcome, and check the actual command.
fn exercise(ctx: &TestCtx, input: &FuzzInput) {
    let scenario = input.scenario % 32;
    let persisted_scope = matches!(scenario, 25 | 26);
    let session = session(ctx, input, persisted_scope);
    let sid = session.session_id();
    let scope = match scenario {
        25 => common::KEY_SCOPE_LOCAL,
        26 => common::KEY_SCOPE_EPHEMERAL,
        _ => common::KEY_SCOPE_SESSION,
    };
    let pristine = ctx
        .tbor(&TborAesXtsGenerateKeyReq {
            session_id: sid,
            scope,
            key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            key_label: Vec::new(),
        })
        .expect("generate fixture AES-XTS key")
        .masked_key;
    let (len, dul) = valid_lengths(input);
    let in_index = usize::from(input.layout) % OOB_ITEMS;
    let out_index =
        (in_index + 1 + usize::from(input.layout / OOB_ITEMS as u8) % (OOB_ITEMS - 1)) % OOB_ITEMS;
    let mut buffers: Vec<_> = (0..=in_index.max(out_index))
        .map(|i| payload(input, len, i))
        .collect();
    let mut req = TborAesXtsEncryptDecryptReq {
        session_id: sid,
        op: if input.op.is_multiple_of(2) {
            AES_OP_ENCRYPT
        } else {
            AES_OP_DECRYPT
        },
        data_len: len as u16,
        dul: dul as u16,
        in_index: in_index as u8,
        out_index: out_index as u8,
        tweak: input
            .tweak
            .min(u64::MAX - (len / dul) as u64)
            .to_le_bytes()
            .to_vec(),
        masked_key: pristine.clone(),
    };
    match scenario {
        0..=7 | 25 | 26 => {}
        8 => req.op = input.op,
        9 => req.session_id = input.session_id,
        10 => req.session_id = sid.wrapping_add(1 + input.session_id % u16::MAX),
        11 => req.data_len = input.data_len,
        12 => req.dul = input.dul,
        13 => req.in_index = input.in_index,
        14 => req.out_index = input.out_index,
        15 => req.tweak = input.raw_tweak.0.clone(),
        16 => req.masked_key = input.raw_key.0.clone(),
        17 => {
            req.masked_key[usize::from(input.offset) % MASKED_AES_XTS_KEY_LEN] ^= input.mask;
        }
        18 => req
            .masked_key
            .truncate(usize::from(input.length) % (MASKED_AES_XTS_KEY_LEN + 1)),
        19 => req.masked_key.extend_from_slice(&input.raw_key.0),
        20 => req.masked_key[MASKED_AES_XTS_KEY_LEN - 1] ^= input.mask | 1,
        21 => buffers.clear(),
        22 => {
            buffers[in_index] = payload(
                input,
                usize::from(input.length) % (XTS_DATA_MAX_LEN + EXTRA_BYTES + 1),
                in_index,
            )
        }
        23 => buffers[out_index].resize(
            usize::from(input.length) % (XTS_DATA_MAX_LEN + EXTRA_BYTES + 1),
            input.mask,
        ),
        24 => {
            req.tweak = (u64::MAX - input.tweak % ((len / dul) as u64 + 2))
                .to_le_bytes()
                .to_vec()
        }
        27 => {
            req.masked_key = ctx
                .tbor(&TborHmacGenerateKeyReq {
                    session_id: sid,
                    scope,
                    hash_algo: HMAC_HASH_SHA512,
                    key_length: AES_XTS_KEY_LEN as u8,
                    key_label: Vec::new(),
                })
                .expect("generate same-sized authenticated non-XTS key")
                .masked_key;
            assert_eq!(req.masked_key.len(), MASKED_AES_XTS_KEY_LEN);
        }
        28 => {
            // Independent switches retain useful late-validation combinations.
            if input.mask & 1 != 0 {
                req.op = input.op;
            }
            if input.mask & 2 != 0 {
                req.session_id = input.session_id;
            }
            if input.mask & 4 != 0 {
                req.data_len = input.data_len;
            }
            if input.mask & 8 != 0 {
                req.dul = input.dul;
            }
            if input.mask & 16 != 0 {
                req.in_index = input.in_index;
            }
            if input.mask & 32 != 0 {
                req.out_index = input.out_index;
            }
            if input.mask & 64 != 0 {
                req.tweak = input.raw_tweak.0.clone();
            }
            if input.mask & 128 != 0 {
                req.masked_key = input.raw_key.0.clone();
            }
        }
        29 => {
            // Equal indices are a valid in-place operation, not a reject.
            req.out_index = req.in_index;
        }
        30 => req.tweak = input.tweak.to_le_bytes().to_vec(),
        31 => {
            let lengths = [
                0,
                1,
                15,
                16,
                XTS_DATA_MAX_LEN,
                XTS_DATA_MAX_LEN + 1,
                u16::MAX as usize,
            ];
            req.data_len = lengths[usize::from(input.data_len) % lengths.len()] as u16;
            let units = [
                0,
                1,
                15,
                16,
                24,
                32,
                XTS_DATA_MAX_LEN + BLOCK_LEN,
                u16::MAX as usize,
            ];
            req.dul = units[usize::from(input.dul) % units.len()] as u16;
        }
        _ => unreachable!("scenario reduced modulo 32"),
    }
    let expected = expected(
        &req,
        sid,
        &pristine,
        scenario == 27,
        scenario == 20,
        &buffers,
    );
    let before = buffers
        .get(usize::from(req.in_index))
        .cloned()
        .unwrap_or_default();
    let result = submit(ctx, &req, &mut buffers);
    match expected {
        Expected::Success => {
            result.unwrap_or_else(|err| panic!("valid AES-XTS scenario {scenario} failed: {err}"));
            check_output(ctx, &req, &before, &buffers[usize::from(req.out_index)]);
        }
        Expected::Status(status) => {
            let err = result.expect_err("invalid AES-XTS request unexpectedly succeeded");
            if req.session_id != sid {
                assertions::assert_session_rejects(&err, status);
            } else {
                assertions::assert_fw_rejects(&err, status);
            }
        }
        Expected::BadKey => {
            let err = result.expect_err("altered/arbitrary masked key unexpectedly authenticated");
            assert!(
                matches!(err, DdiError::TborStatus(status) if [
                    TborStatus::InvalidArg,
                    TborStatus::MaskedKeyDecodeFailed,
                    TborStatus::UnsupportedKeyScope,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ].contains(&status)),
                "unexpected masked-key rejection in scenario {scenario}: {err}"
            );
        }
    }
    session.close().expect("close actual fixture session");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| exercise(ctx, &input));
});
