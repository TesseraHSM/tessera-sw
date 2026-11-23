// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ML-DSA signing: valid keys, isolated faults, and combinations.
//!
//! Successful signatures are verified independently over the submitted external
//! mu. Generated keys always allow signing, so authenticated permission and
//! private-key-length failures are not constructed by this target.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_codec::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Bound malformed blobs while keeping every request inside transport capacity.
const EXTRA_BYTES: usize = 16;
/// Stored GCM IV suffix is not part of the 96-bit nonce.
const IGNORED_IV: std::ops::Range<usize> = 20..24;
/// Metadata label bytes are authenticated without changing scope selection.
const LABEL_START: usize = 24 + 26;
/// Scalars occupy thirteen bytes; payload bytes consume the remaining input.
const CONTROL_LEN: usize = 13;

const MASKED_KEY_ENVELOPE_LEN: usize = 232;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    ArbitraryHedge,
    InvalidHedge,
    ArbitrarySession,
    MismatchedSession,
    MuBoundary,
    MuLength,
    RawMu,
    RawKey,
    FlipKey,
    TruncateKey,
    AppendKey,
    CorruptTag,
    IgnoredIv,
    WrongKeyType,
    OversizedKey,
    KeyBoundary,
    ShiftedLayout,
    Local,
    Ephemeral,
    Combined,
    ClosedSession,
    CorruptNonce,
    CorruptLabel,
    ExtendKey,
}

impl Scenario {
    fn from_byte(byte: u8) -> Self {
        use Scenario::*;
        // Preserve the compact corpus format and success-biased distribution.
        let scenarios = [
            Valid,
            Valid,
            Valid,
            Valid,
            Valid,
            Valid,
            Valid,
            Valid,
            ArbitraryHedge,
            InvalidHedge,
            ArbitrarySession,
            MismatchedSession,
            MuBoundary,
            MuLength,
            RawMu,
            RawKey,
            FlipKey,
            TruncateKey,
            AppendKey,
            CorruptTag,
            IgnoredIv,
            WrongKeyType,
            OversizedKey,
            KeyBoundary,
            ShiftedLayout,
            Local,
            Ephemeral,
            Combined,
            ClosedSession,
            CorruptNonce,
            CorruptLabel,
            ExtendKey,
        ];
        scenarios[usize::from(byte) % scenarios.len()]
    }
}

/// Scalar controls stay ahead of optional bytes so small inputs execute commands.
#[derive(Debug)]
struct FuzzInput {
    scenario: Scenario,
    role: common::FuzzRole,
    params: u8,
    hedge: u8,
    session_id: u16,
    length: u16,
    offset: u16,
    mask: u8,
    switches: u8,
    fill: u8,
    bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode scalar selectors followed by a bounded, possibly empty payload.
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            scenario: Scenario::from_byte(u.arbitrary()?),
            role: if u.arbitrary::<u8>()? & 1 == 0 {
                common::FuzzRole::Co
            } else {
                common::FuzzRole::Cu
            },
            params: u.arbitrary()?,
            hedge: u.arbitrary()?,
            session_id: u.arbitrary()?,
            length: u.arbitrary()?,
            offset: u.arbitrary()?,
            mask: u.arbitrary()?,
            switches: u.arbitrary()?,
            fill: u.arbitrary()?,
            bytes: u
                .bytes(u.len().min(MASKED_MLDSA_KEY_MAX_LEN + EXTRA_BYTES))?
                .to_vec(),
        })
    }

    /// Account for wire controls rather than an in-memory vector allocation.
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (
            CONTROL_LEN,
            Some(CONTROL_LEN + MASKED_MLDSA_KEY_MAX_LEN + EXTRA_BYTES),
        )
    }
}

/// Predicted outcome, computed without inspecting the command's actual result.
#[derive(Debug)]
enum Expected {
    Success,
    Reject(TborStatus),
    /// Header, metadata framing, scope, or authentication rejection only.
    BadEnvelope,
}

/// Preserve session routing while optionally inserting a gap before the key.
struct SignRequest<'a> {
    req: &'a TborMlDsaSignReq,
    shifted: bool,
}

impl TborOpReq for SignRequest<'_> {
    const OPCODE: u8 = TBOR_OP_MLDSA_SIGN;
    type OpResp = TborMlDsaSignResp;

    /// Route the wrapper through the same session gate as the typed request.
    fn get_session_id(&self) -> Option<u16> {
        self.req.get_session_id()
    }

    /// Keep the command in-session even for the noncanonical data layout.
    fn session_ctrl(&self) -> SessionControlKind {
        self.req.session_ctrl()
    }

    /// Keep offsets monotonic but displace both buffers by one unused data byte.
    fn encode_request<'b>(
        &self,
        buf: &'b mut [u8],
        api_rev: (u16, u16),
    ) -> Result<&'b [u8], EncodeError> {
        let len = self.req.encode_request(buf, api_rev)?.len();
        if !self.shifted {
            return Ok(&buf[..len]);
        }
        if buf.len() <= len {
            return Err(EncodeError::BufferTooSmall);
        }
        let data_start = REQ_HEADER_LEN + 4 * TOC_ENTRY_LEN;
        buf.copy_within(data_start..len, data_start + 1);
        buf[data_start] = 0;
        for index in [1, 2] {
            let start = REQ_HEADER_LEN + index * TOC_ENTRY_LEN;
            let entry = &mut buf[start..start + TOC_ENTRY_LEN];
            let word = u32::from_be_bytes(entry.try_into().expect("four-byte TOC entry"));
            entry.copy_from_slice(&(word + 1).to_be_bytes());
        }
        Ok(&buf[..len + 1])
    }
}

/// Expand fuzzed contents to a bounded length without requiring a large corpus.
fn payload(input: &FuzzInput, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            input.fill
                ^ if input.bytes.is_empty() {
                    0
                } else {
                    input.bytes[i % input.bytes.len()]
                }
        })
        .collect()
}

/// Finalize persisted scopes under CO before optionally switching to CU.
fn session<'ctx>(ctx: &'ctx TestCtx, input: &FuzzInput, persisted: bool) -> SessionGuard<'ctx> {
    if persisted {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        common::finalize_partition(ctx, co.handshake());
        if matches!(input.role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close partition setup session");
    }
    let handshake = match input.role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Compare authenticated bytes and the nonce, ignoring only the stored IV suffix.
fn equivalent_key(key: &[u8], pristine: &[u8]) -> bool {
    key.len() == pristine.len()
        && key[..IGNORED_IV.start] == pristine[..IGNORED_IV.start]
        && key[IGNORED_IV.end..] == pristine[IGNORED_IV.end..]
}

/// Predict transport and handler validation in their actual rejection order.
fn expected(
    request: &SignRequest<'_>,
    sid: u16,
    active: bool,
    pristine: &[u8],
    wrong_kind: bool,
    auth_only: bool,
) -> Expected {
    let req = request.req;
    if !active {
        return Expected::Reject(TborStatus::SessionNotFound);
    }
    if req.session_id != sid {
        return Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if req.masked_key.len() > MASKED_MLDSA_KEY_MAX_LEN
        || req.mu.len() != tsra_ddi_tbor_types::MLDSA_MU_LEN
    {
        return Expected::Reject(TborStatus::TborInvalidFixedLength);
    }
    if ![
        MLDSA_HEDGE_PREFERRED,
        MLDSA_HEDGE_REQUIRED,
        MLDSA_HEDGE_DETERMINISTIC,
    ]
    .contains(&req.hedge)
        || request.shifted
    {
        return Expected::Reject(TborStatus::InvalidArg);
    }
    if wrong_kind {
        return Expected::Reject(TborStatus::InvalidKeyType);
    }
    if equivalent_key(&req.masked_key, pristine) {
        Expected::Success
    } else if auth_only {
        Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
    } else {
        Expected::BadEnvelope
    }
}

/// Check signature size, DMA completeness, and independent external-mu validity.
fn check_signature(p: &MlDsaParams, pk: &MlDsaPublicKey, mu: &[u8], signature: &[u8]) {
    assert_eq!(signature.len(), p.sig_len, "{} signature length", p.name);
    assert_not_truncated_at_page(signature, p.name);
    assert!(
        Verifier::verify(&mut MlDsaAlgo::external_mu(), pk, mu, signature)
            .expect("host external-mu verification must run"),
        "{} signature must authenticate the submitted mu",
        p.name,
    );
}

/// Verify output, repeat deterministic/selected hedged signs, and change mu.
fn check_success(
    ctx: &TestCtx,
    input: &FuzzInput,
    p: &MlDsaParams,
    pub_key: &[u8],
    req: &TborMlDsaSignReq,
    resp: &TborMlDsaSignResp,
) {
    let pk = MlDsaPublicKey::from_bytes(pub_key).expect("import generated public key");
    check_signature(p, &pk, &req.mu, &resp.signature);
    let mut bad_mu = req.mu.clone();
    bad_mu[usize::from(input.offset) % req.mu.len()] ^= input.mask | 1;
    assert!(
        !Verifier::verify(&mut MlDsaAlgo::external_mu(), &pk, &bad_mu, &resp.signature)
            .expect("host negative verification must run"),
        "signature must not authenticate modified mu",
    );
    if req.hedge == MLDSA_HEDGE_DETERMINISTIC || input.switches & 1 != 0 {
        let repeat = ctx.tbor(req).expect("repeat valid sign");
        check_signature(p, &pk, &req.mu, &repeat.signature);
        if req.hedge == MLDSA_HEDGE_DETERMINISTIC {
            assert_eq!(resp.signature, repeat.signature, "deterministic sign");
        } else {
            assert_ne!(resp.signature, repeat.signature, "hedged sign");
        }
    }
}

/// Construct one bounded scenario and assert its independently predicted result.
fn exercise(ctx: &TestCtx, input: &FuzzInput) {
    let scenario = input.scenario;
    let p = [&ML_DSA_44, &ML_DSA_65, &ML_DSA_87][usize::from(input.params) % 3];
    let session = session(
        ctx,
        input,
        matches!(scenario, Scenario::Local | Scenario::Ephemeral),
    );
    let sid = session.session_id();
    let scope = match scenario {
        Scenario::Local => common::KEY_SCOPE_LOCAL,
        Scenario::Ephemeral => common::KEY_SCOPE_EPHEMERAL,
        _ => common::KEY_SCOPE_SESSION,
    };
    let key = ctx
        .tbor(&TborMlDsaGenerateKeyReq {
            session_id: sid,
            scope,
            key_kind: p.key_kind,
        })
        .expect("generate genuine ML-DSA signing key");
    assert_eq!(key.masked_key.len(), p.masked_key_len);
    assert_eq!(key.pub_key.len(), p.pub_key_len);
    assert_not_truncated_at_page(&key.masked_key, p.name);
    let mut req = TborMlDsaSignReq {
        session_id: sid,
        masked_key: key.masked_key.clone(),
        mu: payload(input, tsra_ddi_tbor_types::MLDSA_MU_LEN),
        hedge: [
            MLDSA_HEDGE_PREFERRED,
            MLDSA_HEDGE_REQUIRED,
            MLDSA_HEDGE_DETERMINISTIC,
        ][usize::from(input.hedge) % 3],
    };
    match scenario {
        Scenario::Valid
        | Scenario::ShiftedLayout
        | Scenario::Local
        | Scenario::Ephemeral
        | Scenario::ClosedSession => {}
        Scenario::ArbitraryHedge => req.hedge = input.hedge,
        Scenario::InvalidHedge => req.hedge = [3, 4, 0x80, 0xFF][usize::from(input.hedge) % 4],
        Scenario::ArbitrarySession => req.session_id = input.session_id,
        Scenario::MismatchedSession => {
            req.session_id = sid.wrapping_add(1 + input.session_id % u16::MAX)
        }
        Scenario::MuBoundary => {
            let mu_len = tsra_ddi_tbor_types::MLDSA_MU_LEN;
            let lengths = [0, 1, mu_len - 1, mu_len, mu_len + 1, mu_len * 2];
            req.mu = payload(input, lengths[usize::from(input.length) % lengths.len()]);
        }
        Scenario::MuLength => {
            req.mu = payload(
                input,
                usize::from(input.length) % (2 * tsra_ddi_tbor_types::MLDSA_MU_LEN + 1),
            )
        }
        Scenario::RawMu => {
            req.mu =
                input.bytes[..input.bytes.len().min(2 * tsra_ddi_tbor_types::MLDSA_MU_LEN)].to_vec()
        }
        Scenario::RawKey => req.masked_key = input.bytes.clone(),
        Scenario::FlipKey => common::EnvelopeMutation::FlipByte {
            offset: input.offset,
            mask: input.mask,
        }
        .apply(&mut req.masked_key),
        Scenario::TruncateKey => {
            common::EnvelopeMutation::Truncate { len: input.length }.apply(&mut req.masked_key)
        }
        Scenario::AppendKey => common::EnvelopeMutation::Append(
            input.bytes[..input.bytes.len().min(EXTRA_BYTES)].to_vec(),
        )
        .apply(&mut req.masked_key),
        Scenario::CorruptTag => {
            let last = req.masked_key.len() - 1;
            req.masked_key[last] ^= input.mask | 1;
        }
        Scenario::IgnoredIv => {
            req.masked_key[IGNORED_IV.start + usize::from(input.offset) % IGNORED_IV.len()] ^=
                input.mask | 1;
        }
        Scenario::WrongKeyType => {
            req.masked_key = ctx
                .tbor(&TborMlKemGenerateKeyReq {
                    session_id: sid,
                    scope,
                    key_kind: ML_KEM_512.key_kind,
                })
                .expect("generate authenticated wrong-class key")
                .masked_key;
        }
        Scenario::OversizedKey => req
            .masked_key
            .resize(MASKED_MLDSA_KEY_MAX_LEN + 1, input.fill),
        Scenario::KeyBoundary => {
            let lengths = [
                0,
                1,
                aead_envelope::HEADER_LEN - 1,
                aead_envelope::HEADER_LEN,
                aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len() - 1,
                aead_envelope::HEADER_LEN + aead_envelope::AeadAlg::AesGcm256.iv_len(),
                MASKED_KEY_ENVELOPE_LEN - 1,
                MASKED_KEY_ENVELOPE_LEN,
                p.masked_key_len - 1,
                p.masked_key_len,
                MASKED_MLDSA_KEY_MAX_LEN,
                MASKED_MLDSA_KEY_MAX_LEN + 1,
            ];
            req.masked_key.resize(
                lengths[usize::from(input.length) % lengths.len()],
                input.fill,
            );
        }
        Scenario::Combined => {
            if input.switches & 1 != 0 {
                req.hedge = input.hedge;
            }
            if input.switches & 2 != 0 {
                req.session_id = input.session_id;
            }
            if input.switches & 4 != 0 {
                req.mu = payload(
                    input,
                    usize::from(input.length) % (2 * tsra_ddi_tbor_types::MLDSA_MU_LEN + 1),
                );
            }
            if input.switches & 8 != 0 {
                common::EnvelopeMutation::FlipByte {
                    offset: input.offset,
                    mask: input.mask,
                }
                .apply(&mut req.masked_key);
            }
        }
        Scenario::CorruptNonce => {
            req.masked_key[8 + usize::from(input.offset) % 12] ^= input.mask | 1
        }
        Scenario::CorruptLabel => {
            req.masked_key[LABEL_START + usize::from(input.offset) % 128] ^= input.mask | 1
        }
        Scenario::ExtendKey => req
            .masked_key
            .extend_from_slice(&payload(input, EXTRA_BYTES)),
    }
    let active = scenario != Scenario::ClosedSession;
    let live_session = if active {
        Some(session)
    } else {
        session.close().expect("close fixture before stale-id sign");
        None
    };
    let request = SignRequest {
        req: &req,
        shifted: scenario == Scenario::ShiftedLayout,
    };
    let predicted = expected(
        &request,
        sid,
        active,
        &key.masked_key,
        scenario == Scenario::WrongKeyType,
        matches!(
            scenario,
            Scenario::CorruptTag | Scenario::CorruptNonce | Scenario::CorruptLabel
        ),
    );
    let result = ctx.tbor(&request);
    match predicted {
        Expected::Success => {
            let resp = result
                .unwrap_or_else(|err| panic!("valid ML-DSA scenario {scenario:?} failed: {err}"));
            check_success(ctx, input, p, &key.pub_key, &req, &resp);
        }
        Expected::Reject(status) => {
            let err = result.expect_err("invalid ML-DSA sign unexpectedly succeeded");
            if !active || req.session_id != sid {
                assertions::assert_session_rejects(&err, status);
            } else {
                assertions::assert_fw_rejects(&err, status);
            }
        }
        Expected::BadEnvelope => {
            let err = result.expect_err("malformed ML-DSA envelope unexpectedly accepted");
            assert!(
                matches!(err, DdiError::TborStatus(status) if [
                    TborStatus::InvalidArg,
                    TborStatus::MaskedKeyDecodeFailed,
                    TborStatus::UnsupportedKeyScope,
                    TborStatus::AesGcmDecryptTagDoesNotMatch,
                ].contains(&status)),
                "unexpected envelope rejection in ML-DSA scenario {scenario:?}: {err}",
            );
        }
    }
    if let Some(session) = live_session {
        session.close().expect("close actual fixture session");
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| exercise(ctx, &input));
});
