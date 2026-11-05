// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured AES-256-GCM requests with authenticated decrypt fixtures and
//! isolated faults. The first byte selects one of 41 scenarios; absent
//! controls default to zero, so even one-byte seeds execute the command.
//!
//! Canonical typed requests cannot exercise noncanonical TOC placement.
//! Permission rejects are unreachable through current AES generation/import:
//! both require ENCRYPT | DECRYPT together. Wrong-kind keys are authenticated,
//! rather than simulating either check by corrupting masked metadata.

#![cfg_attr(not(test), no_main)]

#[path = "../../common.rs"]
mod common;

use arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Bound the descriptor plan while allowing reordered and aliased indices.
const OOB_ITEMS: usize = 4;
/// Bound corpus-derived bytes independently of requested OOB lengths.
const PATTERN_MAX_LEN: usize = 512;
/// Number of individually reproducible success and fault scenarios.
const SCENARIOS: u8 = 41;

/// Scalar controls default to zero; the input also seeds bounded crypto data.
#[derive(Debug)]
struct FuzzInput {
    scenario: u8,
    role: common::FuzzRole,
    op: u8,
    iv_source: u8,
    session_id: u16,
    aad_len: u16,
    data_len: u16,
    in_index: u8,
    out_index: u8,
    length: u16,
    offset: u16,
    mask: u8,
    pattern: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode controls without rejecting short seeds. Reuse the bounded input
    /// prefix as data so even single-byte mutations change crypto buffers.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let pattern = u
            .peek_bytes(u.len().min(PATTERN_MAX_LEN))
            .expect("bounded prefix is available")
            .to_vec();
        Ok(Self {
            scenario: u.arbitrary::<u8>().unwrap_or_default() % SCENARIOS,
            role: if u.arbitrary::<bool>().unwrap_or_default() {
                common::FuzzRole::Cu
            } else {
                common::FuzzRole::Co
            },
            op: u.arbitrary().unwrap_or_default(),
            iv_source: u.arbitrary().unwrap_or_default(),
            session_id: u.arbitrary().unwrap_or_default(),
            aad_len: u.arbitrary().unwrap_or_default(),
            data_len: u.arbitrary().unwrap_or_default(),
            in_index: u.arbitrary().unwrap_or_default(),
            out_index: u.arbitrary().unwrap_or_default(),
            length: u.arbitrary().unwrap_or_default(),
            offset: u.arbitrary().unwrap_or_default(),
            mask: u.arbitrary().unwrap_or_default(),
            pattern,
        })
    }
}

/// Outcome predicted from the request and fixture before submission.
#[derive(Debug)]
enum Expected {
    Success,
    Status(TborStatus),
    /// Arbitrary envelopes may fail framing, scope selection or authentication,
    /// but must never mask transport, driver or response-decoding failures.
    BadKey,
}

/// Round up the u16-derived AAD length without narrow-integer overflow.
fn padded_aad_len(aad_len: usize) -> usize {
    aad_len.next_multiple_of(32)
}

/// Locate the actual AAD, excluding padding that GCM does not authenticate.
fn aad_offset(aad_len: usize) -> usize {
    if (1..=16).contains(&(aad_len % 32)) {
        16
    } else {
        0
    }
}

/// Expand bounded fuzz bytes so maximum-size cases need only short seeds.
fn payload(input: &FuzzInput, len: usize, offset: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            if input.pattern.is_empty() {
                0
            } else {
                input.pattern[(i + offset) % input.pattern.len()]
            }
        })
        .collect()
}

/// Bias toward padding/block boundaries, reserving explicit maximum cases.
fn valid_lengths(input: &FuzzInput) -> (usize, usize) {
    let aad_lengths = [0, 1, 15, 16, 17, 31, 32, 33, 48, 64];
    let text_lengths = [16, 0, 1, 15, 17, 32, 100, 1024];
    let mut aad = aad_lengths[usize::from(input.aad_len) % aad_lengths.len()];
    let mut text = match input.data_len % 16 {
        0..=7 => text_lengths[usize::from(input.data_len) % text_lengths.len()],
        _ => usize::from(input.data_len) % 2049,
    };
    match input.scenario {
        3 | 4 => (0, 0),
        5 => (aad.max(1), 0),
        6 => (0, GCM_DATA_MAX_LEN),
        7 => {
            aad = aad.max(1);
            (aad, GCM_DATA_MAX_LEN - padded_aad_len(aad))
        }
        28 | 37 => (aad.max(1), text),
        29 => {
            text = text.max(1);
            (aad, text)
        }
        _ => (aad, text),
    }
}

/// Finalize Local cases under CO, then open the requested role without nesting
/// primary contexts or leaving the setup session live.
fn open_session<'a>(ctx: &'a TestCtx, input: &FuzzInput) -> SessionGuard<'a> {
    if matches!(input.scenario, 31 | 32) {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        common::finalize_partition(ctx, co.handshake());
        if matches!(input.role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close Local-scope setup session");
    }
    let handshake = match input.role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Submit owned writable descriptors so arbitrary indices, including equal
/// indices, cannot make firmware write through an immutable Rust reference.
fn submit(
    ctx: &TestCtx,
    req: &TborAesGcmEncryptDecryptReq,
    buffers: &mut [Vec<u8>],
) -> DdiResult<TborAesGcmEncryptDecryptResp> {
    if req.data_len == 0 {
        return ctx.tbor_oob_io(req, &mut []);
    }
    let mut items: Vec<_> = buffers
        .iter_mut()
        .map(|buf| TborOobItem::Out(buf))
        .collect();
    ctx.tbor_oob_io(req, &mut items)
}

/// Execute a canonical follow-up over the same padded layout, using host IVs
/// for decrypt even when the preceding encrypt generated its IV on-device.
fn crypt(
    ctx: &TestCtx,
    original: &TborAesGcmEncryptDecryptReq,
    op: u8,
    iv_source: u8,
    data: &[u8],
) -> (TborAesGcmEncryptDecryptResp, Vec<u8>) {
    let req = TborAesGcmEncryptDecryptReq {
        op,
        iv_source,
        data_len: data.len() as u16,
        in_index: 0,
        out_index: 1,
        ..original.clone()
    };
    let mut out = vec![0; data.len()];
    let result = if data.is_empty() {
        ctx.tbor_oob_io(&req, &mut [])
    } else {
        ctx.tbor_oob_io(
            &req,
            &mut [TborOobItem::In(data), TborOobItem::Out(&mut out)],
        )
    };
    (result.expect("valid AES-GCM follow-up"), out)
}

/// Import the all-zero AES-256 known-answer key using the existing RSA-OAEP /
/// AES-KWP test convention, without treating an AEAD envelope as a masked key.
fn import_zero_key(ctx: &TestCtx, sid: u16) -> Vec<u8> {
    let timeout = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let wire = loop {
        match ctx.tbor(&TborGetUnwrappingKeyReq { session_id: sid }) {
            Ok(resp) => break resp.pub_key,
            Err(DdiError::TborStatus(status))
                if status == TborStatus::PendingKeyGeneration && start.elapsed() < timeout =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("GetUnwrappingKey for known answer failed: {err:?}"),
        }
    };
    assert_eq!(wire.len(), UNWRAPPING_PUB_KEY_LEN);
    let modulus_len = wire.len() - 4;
    let be: Vec<_> = wire[..modulus_len]
        .iter()
        .rev()
        .chain(wire[modulus_len..].iter().rev())
        .copied()
        .collect();
    let pub_key = RsaPublicKey::from_hsm_bytes(&be).expect("unwrapping public key");
    let kek_bytes = [0xA7; 32];
    let kek = AesKey::from_bytes(&kek_bytes).expect("AES wrapping key");
    let mut wrapped = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &pub_key,
        &kek_bytes,
    )
    .expect("RSA-OAEP wrap KEK");
    wrapped.reverse();
    wrapped.extend(
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &[0; 32])
            .expect("AES-KWP wrap known key"),
    );
    ctx.tbor(&TborUnwrapKeyReq {
        session_id: sid,
        scope: common::KEY_SCOPE_SESSION,
        key_class: KEY_CLASS_AES,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob: wrapped,
        key_label: Vec::new(),
    })
    .expect("import known-answer key")
    .masked_key
}

/// Predict schema, semantic, descriptor, key and authentication rejects in
/// handler order. Length mutations in this bounded target still encode on
/// the host; fixed-length enforcement happens during firmware decoding.
fn expected(
    req: &TborAesGcmEncryptDecryptReq,
    active_sid: Option<u16>,
    pristine: &[u8],
    buffers: &[Vec<u8>],
    scenario: u8,
    authentic: bool,
) -> Expected {
    let reject = Expected::Status;
    if active_sid.is_none() {
        return reject(TborStatus::SessionNotFound);
    }
    if active_sid != Some(req.session_id) {
        return reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if req.iv.len() != GCM_IV_LEN
        || req.tag.len() != GCM_TAG_LEN
        || req.masked_key.len() != MASKED_AES_KEY_MAX_LEN
    {
        return reject(TborStatus::TborInvalidFixedLength);
    }
    let len = usize::from(req.data_len);
    if ![AES_OP_ENCRYPT, AES_OP_DECRYPT].contains(&req.op)
        || !(req.iv_source == GCM_IV_SOURCE_HOST
            || (req.iv_source == GCM_IV_SOURCE_DEVICE && req.op == AES_OP_ENCRYPT))
        || len > GCM_DATA_MAX_LEN
        || padded_aad_len(usize::from(req.aad_len)) > len
    {
        return reject(TborStatus::InvalidArg);
    }
    if len != 0
        && (usize::from(req.in_index) >= buffers.len()
            || usize::from(req.out_index) >= buffers.len())
    {
        return reject(TborStatus::InvalidArg);
    }
    if scenario == 30 {
        return reject(TborStatus::InvalidKeyType);
    }
    if scenario == 40 {
        return reject(TborStatus::AesGcmDecryptTagDoesNotMatch);
    }
    if req.masked_key != pristine {
        return if matches!(scenario, 24 | 35) {
            reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
        } else {
            Expected::BadKey
        };
    }
    if len != 0
        && (buffers[usize::from(req.in_index)].len() != len
            || buffers[usize::from(req.out_index)].len() != len)
    {
        return reject(TborStatus::InvalidArg);
    }
    if req.op == AES_OP_DECRYPT && !authentic {
        return reject(TborStatus::AesGcmDecryptTagDoesNotMatch);
    }
    Expected::Success
}

/// Check output shape, echoed fields, AAD preservation and plaintext recovery;
/// known-answer cases additionally check fixed AES-256-GCM ciphertext/tags.
fn check_output(
    ctx: &TestCtx,
    req: &TborAesGcmEncryptDecryptReq,
    resp: &TborAesGcmEncryptDecryptResp,
    source: &[u8],
    output: &[u8],
    plaintext: &[u8],
    scenario: u8,
) {
    assert_eq!(resp.iv.len(), GCM_IV_LEN);
    assert_eq!(resp.tag.len(), GCM_TAG_LEN);
    if req.iv_source == GCM_IV_SOURCE_HOST {
        assert_eq!(resp.iv, req.iv, "host IV must be echoed");
    }
    let padded = padded_aad_len(usize::from(req.aad_len));
    assert_eq!(output.len(), usize::from(req.data_len));
    assert_eq!(&output[..padded], &source[..padded], "preserve AAD layout");
    if req.op == AES_OP_DECRYPT {
        assert_eq!(resp.tag, req.tag, "verified tag must be echoed");
        assert_eq!(&output[padded..], &plaintext[padded..]);
    } else {
        let followup = TborAesGcmEncryptDecryptReq {
            iv: resp.iv.clone(),
            tag: resp.tag.clone(),
            ..req.clone()
        };
        let (decrypted, recovered) =
            crypt(ctx, &followup, AES_OP_DECRYPT, GCM_IV_SOURCE_HOST, output);
        assert_eq!(decrypted.iv, resp.iv);
        assert_eq!(decrypted.tag, resp.tag);
        assert_eq!(recovered, source, "authenticated round trip");
    }
    if scenario == 36 {
        if output.is_empty() {
            assert_eq!(
                resp.tag,
                [
                    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4,
                    0xcb, 0x73, 0x8b
                ]
            );
        } else {
            assert_eq!(
                output,
                [
                    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba,
                    0xf3, 0x9d, 0x18
                ]
            );
            assert_eq!(
                resp.tag,
                [
                    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4,
                    0x8a, 0xb9, 0x19
                ]
            );
        }
    }
}

/// Build one valid fixture, apply a controlled mutation, predict the outcome,
/// then submit and check it. Expensive Local/import setup is scenario-specific.
fn exercise(ctx: &TestCtx, input: &FuzzInput) {
    let scenario = input.scenario;
    let session = open_session(ctx, input);
    let sid = session.session_id();
    let mut session = Some(session);
    let scope = if matches!(scenario, 31 | 32) {
        common::KEY_SCOPE_LOCAL
    } else {
        common::KEY_SCOPE_SESSION
    };
    let pristine = if scenario == 36 {
        import_zero_key(ctx, sid)
    } else {
        ctx.tbor(&TborAesGenerateKeyReq {
            session_id: sid,
            scope,
            key_size: AES_KEY_SIZE_256,
            key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            key_label: Vec::new(),
        })
        .expect("generate fixture AES-256 key")
        .masked_key
    };
    let (mut aad, mut text) = valid_lengths(input);
    if scenario == 36 {
        aad = 0;
        text = if input.op & 1 == 0 { 0 } else { 16 };
    }
    let padded = padded_aad_len(aad);
    let len = padded + text;
    let src = usize::from(input.in_index) % OOB_ITEMS;
    let dst = (src + 1 + usize::from(input.out_index) % (OOB_ITEMS - 1)) % OOB_ITEMS;
    let mut block = vec![0; len];
    block[aad_offset(aad)..aad_offset(aad) + aad].copy_from_slice(&payload(input, aad, 0));
    block[padded..].copy_from_slice(&payload(input, text, aad));
    let plaintext = if scenario == 36 { vec![0; len] } else { block };
    let mut buffers = vec![plaintext.clone(); src.max(dst) + 1];
    let decrypt = matches!(scenario, 1 | 4 | 26..=29 | 32 | 33 | 37)
        || (scenario == 8 && input.op == AES_OP_DECRYPT)
        || (scenario == 9 && input.op & 1 != 0);
    let mut req = TborAesGcmEncryptDecryptReq {
        session_id: sid,
        op: if decrypt {
            AES_OP_DECRYPT
        } else {
            AES_OP_ENCRYPT
        },
        iv_source: if scenario == 2 {
            GCM_IV_SOURCE_DEVICE
        } else {
            GCM_IV_SOURCE_HOST
        },
        aad_len: aad as u16,
        data_len: len as u16,
        in_index: src as u8,
        out_index: dst as u8,
        iv: if scenario == 36 {
            vec![0; GCM_IV_LEN]
        } else {
            payload(input, GCM_IV_LEN, 7)
        },
        tag: payload(input, GCM_TAG_LEN, 19),
        masked_key: pristine.clone(),
    };
    if decrypt {
        let (resp, ciphertext) = crypt(
            ctx,
            &req,
            AES_OP_ENCRYPT,
            if scenario == 33 {
                GCM_IV_SOURCE_DEVICE
            } else {
                GCM_IV_SOURCE_HOST
            },
            &plaintext,
        );
        req.iv = resp.iv;
        req.tag = resp.tag;
        buffers[src] = ciphertext;
    }
    let mut authentic = true;
    match scenario {
        0..=2 | 5..=7 | 31..=33 | 36 => {}
        3 | 4 => {
            req.in_index = input.in_index;
            req.out_index = input.out_index;
        }
        8 => req.op = input.op,
        9 => req.iv_source = input.iv_source,
        10 => {
            req.op = AES_OP_DECRYPT;
            req.iv_source = GCM_IV_SOURCE_DEVICE;
        }
        11 => req.session_id = input.session_id,
        12 => session
            .take()
            .expect("live fixture session")
            .close()
            .expect("close tested session"),
        13 => req.aad_len = input.aad_len,
        14 => req.data_len = input.data_len,
        15 => buffers.clear(),
        16 => {
            buffers.pop();
        }
        17 => req.in_index = input.in_index,
        18 => req.out_index = input.out_index,
        19 => buffers[src].resize(1 + usize::from(input.length) % GCM_DATA_MAX_LEN, input.mask),
        20 => buffers[dst].resize(1 + usize::from(input.length) % GCM_DATA_MAX_LEN, input.mask),
        21 => req
            .iv
            .resize(usize::from(input.length) % (GCM_IV_LEN * 2 + 1), input.mask),
        22 => req.tag.resize(
            usize::from(input.length) % (GCM_TAG_LEN * 2 + 1),
            input.mask,
        ),
        23 => req.masked_key.resize(
            usize::from(input.length) % (MASKED_AES_KEY_MAX_LEN + 17),
            input.mask,
        ),
        24 => {
            let at = MASKED_AES_KEY_MAX_LEN - GCM_TAG_LEN + usize::from(input.offset) % GCM_TAG_LEN;
            req.masked_key[at] ^= input.mask;
        }
        25 => {
            req.masked_key = payload(
                input,
                usize::from(input.length) % (MASKED_AES_KEY_MAX_LEN + 17),
                0,
            )
        }
        26 => {
            req.tag[usize::from(input.offset) % GCM_TAG_LEN] ^= input.mask;
            authentic = input.mask == 0;
        }
        27 => {
            req.iv[usize::from(input.offset) % GCM_IV_LEN] ^= input.mask | 1;
            authentic = false;
        }
        28 => {
            buffers[src][aad_offset(aad) + usize::from(input.offset) % aad] ^= input.mask | 1;
            authentic = false;
        }
        29 => {
            buffers[src][padded + usize::from(input.offset) % text] ^= input.mask | 1;
            authentic = false;
        }
        30 => {
            req.masked_key = ctx
                .tbor(&TborAesGenerateKeyReq {
                    session_id: sid,
                    scope,
                    key_size: common::AesKeySize::Aes192.to_tbor(),
                    key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                    key_label: Vec::new(),
                })
                .expect("generate authenticated wrong-kind key")
                .masked_key;
            assert_eq!(req.masked_key.len(), MASKED_AES_KEY_MAX_LEN);
        }
        34 => req.out_index = req.in_index,
        35 => {
            // Mutate only encrypted key material, preserving envelope framing
            // and scope so the request reaches key authentication.
            let at = MASKED_AES_KEY_MAX_LEN - GCM_TAG_LEN - 32 + usize::from(input.offset) % 32;
            req.masked_key[at] ^= input.mask | 1;
        }
        37 => {
            // The chosen byte is padding, not authenticated AAD.
            let at = if aad_offset(aad) == 16 { 0 } else { aad };
            if at < padded {
                buffers[src][at] ^= input.mask | 1;
            }
        }
        38 => {
            let lengths = [
                0,
                1,
                GCM_DATA_MAX_LEN,
                GCM_DATA_MAX_LEN + 1,
                u16::MAX as usize,
            ];
            req.data_len = lengths[usize::from(input.data_len) % lengths.len()] as u16;
        }
        39 => {
            let lengths = [1, 17, GCM_DATA_MAX_LEN + 1, u16::MAX as usize];
            req.aad_len = lengths[usize::from(input.aad_len) % lengths.len()] as u16;
            req.data_len = 0;
        }
        40 => {
            session
                .take()
                .expect("key's original session")
                .close()
                .expect("close key's original session");
            let psk = match input.role {
                common::FuzzRole::Co => &ROTATED_CO_PSK,
                common::FuzzRole::Cu => &ROTATED_CU_PSK,
            };
            let options =
                SessionOpenInitOptions::new(input.role.psk_id(), input.role.session_type())
                    .with_psk(psk);
            let pending = ctx
                .session_open_init_with_options(options)
                .expect("open independent session under rotated PSK");
            let fresh = ctx
                .session_open_finish(pending)
                .expect("finish independent session");
            req.session_id = fresh.session_id;
            session = Some(SessionGuard::new(ctx, fresh));
        }
        _ => unreachable!("scenario reduced modulo SCENARIOS"),
    }
    let active_sid = session.as_ref().map(SessionGuard::session_id);
    let prediction = expected(&req, active_sid, &pristine, &buffers, scenario, authentic);
    let source = if req.data_len == 0 {
        Vec::new()
    } else {
        buffers
            .get(usize::from(req.in_index))
            .cloned()
            .unwrap_or_default()
    };
    let result = submit(ctx, &req, &mut buffers);
    match prediction {
        Expected::Success => {
            let resp =
                result.unwrap_or_else(|err| panic!("valid GCM scenario {scenario} failed: {err}"));
            let output = if req.data_len == 0 {
                &[][..]
            } else {
                buffers[usize::from(req.out_index)].as_slice()
            };
            check_output(ctx, &req, &resp, &source, output, &plaintext, scenario);
        }
        Expected::Status(status) => {
            let err = result.expect_err("invalid GCM request unexpectedly succeeded");
            if active_sid != Some(req.session_id) {
                assertions::assert_session_rejects(&err, status);
            } else {
                assertions::assert_fw_rejects(&err, status);
            }
        }
        Expected::BadKey => {
            let err = result.expect_err("arbitrary masked key unexpectedly authenticated");
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
    if let Some(session) = session {
        session.close().expect("close actual fixture session");
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| exercise(ctx, &input));
});

#[cfg(all(test, feature = "emu"))]
mod tests {
    use super::*;

    /// Replay short seeds and boundary controls in one test: the shared fuzz
    /// fixture's device-display state is not safe for parallel entry.
    #[test]
    fn structured_scenarios() {
        for scenario in 0..SCENARIOS {
            let seed = [scenario];
            let input = FuzzInput::arbitrary(&mut Unstructured::new(&seed)).expect("short seed");
            common::common_fuzz_test(&|ctx, _| exercise(ctx, &input));
        }
        boundary_scenarios();
    }

    /// Exercise effective/no-op mutations, alternate roles, known answers,
    /// padding boundaries and descriptor aliases with reproducible controls.
    fn boundary_scenarios() {
        for scenario in [
            0, 1, 2, 4, 5, 7, 17, 18, 21, 22, 23, 24, 26, 28, 29, 34, 36, 37, 38, 39,
        ] {
            for value in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 264, u16::MAX] {
                let mut input =
                    FuzzInput::arbitrary(&mut Unstructured::new(&[scenario])).expect("seed");
                input.role = common::FuzzRole::Cu;
                input.op = 1;
                input.aad_len = value;
                input.data_len = value;
                input.in_index = 3;
                input.out_index = 2;
                input.length = value;
                input.offset = value;
                input.mask = value as u8;
                input.pattern = vec![0xA5, value as u8, 0x5A];
                common::common_fuzz_test(&|ctx, _| exercise(ctx, &input));
            }
        }
    }
}
