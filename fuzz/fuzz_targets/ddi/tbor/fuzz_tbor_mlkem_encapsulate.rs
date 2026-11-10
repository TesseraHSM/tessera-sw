// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured ML-KEM encapsulation with a state-aware, bidirectional oracle.
//!
//! Frequent seeded-key successes reach encapsulation and masking for every
//! parameter set. Other scenarios isolate session, scope, length, canonical-key,
//! and in-place layout rejects, or combine arbitrary request fields to check
//! precedence. Key validity is predicted independently from FIPS 203's packed
//! coefficients and cross-checked against the host importer. This does not
//! independently verify ciphertext mathematics or inject PAL allocation faults.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary::*;
use libfuzzer_sys::*;
use tsra_crypto as crypto;
use tsra_ddi_tbor_codec::*;
use tsra_ddi_tbor_test_harness::pqc::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// Independent FIPS 203 coefficient modulus and trailing public seed length.
const MODULUS: u16 = 3329;
const RHO_LEN: usize = 32;

/// Harness-owned parameter sizes, also used to classify final request bytes.
const PARAMS: [&MlKemParams; 3] = [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024];

/// Partition/session state established independently of the fuzzed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Unfinalized,
    Finalized,
    SecurityDomain,
    Closed,
    DefaultPsk,
}

/// Twelve little-endian control bytes followed by a bounded binary payload.
///
/// Controls are scenario, role, parameter set, session ID (u16), scope, key mode,
/// length (u16), offset (u16), and XOR mask. Missing controls default to zero,
/// so even an empty corpus entry exercises a successful encapsulation.
#[derive(Debug)]
struct FuzzInput {
    scenario: u8,
    role: u8,
    params: u8,
    session_id: u16,
    scope: u8,
    key_mode: u8,
    length: u16,
    offset: u16,
    mask: u8,
    bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    /// Decode compact controls and retain at most one oversized public key.
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Self {
            scenario: u.arbitrary().unwrap_or_default(),
            role: u.arbitrary().unwrap_or_default(),
            params: u.arbitrary().unwrap_or_default(),
            session_id: u.arbitrary().unwrap_or_default(),
            scope: u.arbitrary().unwrap_or_default(),
            key_mode: u.arbitrary().unwrap_or_default(),
            length: u.arbitrary().unwrap_or_default(),
            offset: u.arbitrary().unwrap_or_default(),
            mask: u.arbitrary().unwrap_or_default(),
            bytes: u.bytes(u.len().min(MLKEM_PUB_KEY_MAX_LEN + 1))?.to_vec(),
        })
    }
}

impl FuzzInput {
    /// Keep costly provisioning uncommon while retaining each lifecycle.
    fn lifecycle(&self) -> Lifecycle {
        match self.scenario % 32 {
            8 | 25 => Lifecycle::Finalized,
            9 | 26 => Lifecycle::SecurityDomain,
            11 | 27 => Lifecycle::DefaultPsk,
            12 | 28 => Lifecycle::Closed,
            _ => Lifecycle::Unfinalized,
        }
    }

    /// Repeat fuzzed bytes to make exact-size inputs reachable from short seeds.
    fn repeated_bytes(&self, len: usize) -> Vec<u8> {
        if self.bytes.is_empty() {
            vec![0; len]
        } else {
            self.bytes.iter().copied().cycle().take(len).collect()
        }
    }

    /// Choose isolated key mutations or combine them with arbitrary scalars.
    fn key_mode(&self) -> u8 {
        match self.scenario % 32 {
            4 | 19 => 1,
            5 | 17 => 2,
            6 => 3,
            18 => 4,
            16 => 5,
            20 => 6,
            15 => 7,
            21 => 8,
            22 => 9,
            24 | 27..=29 | 31 => self.key_mode % 10,
            _ => 0,
        }
    }
}

/// Open the selected role only after CO has provisioned administrative state.
///
/// Default-PSK scenarios deliberately bypass both PSK-rotation helpers.
fn open_session<'a>(ctx: &'a TestCtx, input: &FuzzInput) -> SessionGuard<'a> {
    let lifecycle = input.lifecycle();
    let role = if input.role & 1 == 0 {
        common::FuzzRole::Co
    } else {
        common::FuzzRole::Cu
    };
    if lifecycle == Lifecycle::DefaultPsk {
        return ctx
            .open_session(role.psk_id(), role.session_type())
            .expect("open default-PSK session");
    }
    if matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain) {
        let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
        if lifecycle == Lifecycle::SecurityDomain {
            common::create_test_security_domain(ctx, co.handshake());
        } else {
            common::finalize_partition(ctx, co.handshake());
        }
        if matches!(role, common::FuzzRole::Co) {
            return co;
        }
        co.close().expect("close administrative CO session");
    }
    let handshake = match role {
        common::FuzzRole::Co => bootstrap_rotated_co(ctx, &ROTATED_CO_PSK),
        common::FuzzRole::Cu => bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK),
    };
    SessionGuard::new(ctx, handshake)
}

/// Derive a genuine public key from a fuzz-controlled, bounded host seed.
fn seeded_public_key(input: &FuzzInput, p: &MlKemParams) -> Vec<u8> {
    let variant = match p.key_kind {
        MLKEM_KEY_KIND_512_SEED => crypto::MlKemVariant::MlKem512,
        MLKEM_KEY_KIND_768_SEED => crypto::MlKemVariant::MlKem768,
        MLKEM_KEY_KIND_1024_SEED => crypto::MlKemVariant::MlKem1024,
        _ => unreachable!("harness ML-KEM parameter set"),
    };
    let seed = input.repeated_bytes(crypto::MLKEM_SEED_LEN);
    let private = crypto::MlKemPrivateKey::from_seed(variant, &seed).expect("host ML-KEM keygen");
    let public = crypto::PrivateKey::public_key(&private).expect("derive host ML-KEM public key");
    let bytes = crypto::ExportableKey::to_vec(&public).expect("export host ML-KEM public key");
    assert_eq!(bytes.len(), p.pub_key_len);
    bytes
}

/// Decode the two little-endian 12-bit coefficients packed into three bytes.
fn coefficients(bytes: &[u8]) -> (u16, u16) {
    (
        u16::from(bytes[0]) | (u16::from(bytes[1] & 0x0f) << 8),
        u16::from(bytes[1] >> 4) | (u16::from(bytes[2]) << 4),
    )
}

/// Encode two coefficients that fit in the 12-bit FIPS 203 representation.
fn write_coefficients(bytes: &mut [u8], first: u16, second: u16) {
    bytes[0] = first as u8;
    bytes[1] = ((first >> 8) | (second << 4)) as u8;
    bytes[2] = (second >> 4) as u8;
}

/// Check canonical polynomial coefficients without constraining the rho seed.
///
/// Call only after identifying a supported public-key length.
fn canonical_public_key(bytes: &[u8]) -> bool {
    bytes[..bytes.len() - RHO_LEN].chunks_exact(3).all(|chunk| {
        let (first, second) = coefficients(chunk);
        first < MODULUS && second < MODULUS
    })
}

/// Construct generated, canonical, mutated, malformed, or arbitrary key bytes.
fn public_key(ctx: &TestCtx, input: &FuzzInput, p: &MlKemParams, session_id: u16) -> Vec<u8> {
    if matches!(input.scenario % 32, 7 | 30) {
        let key = ctx
            .tbor(&TborMlKemGenerateKeyReq {
                session_id,
                scope: common::KEY_SCOPE_SESSION,
                key_kind: p.key_kind,
            })
            .expect("independent session-scoped device key generation");
        assert_eq!(key.pub_key.len(), p.pub_key_len);
        assert!(canonical_public_key(&key.pub_key));
        return key.pub_key;
    }

    let mut key = seeded_public_key(input, p);
    let polynomial_len = p.pub_key_len - RHO_LEN;
    let pair_offset = (usize::from(input.offset) % (polynomial_len / 3)) * 3;
    match input.key_mode() {
        1 => {
            key = input.repeated_bytes(p.pub_key_len);
            for chunk in key[..polynomial_len].chunks_exact_mut(3) {
                let (first, second) = coefficients(chunk);
                write_coefficients(chunk, first % MODULUS, second % MODULUS);
            }
        }
        2 => {
            key[polynomial_len + usize::from(input.offset) % RHO_LEN] ^= input.mask;
        }
        3 => {
            write_coefficients(
                &mut key[pair_offset..pair_offset + 3],
                MODULUS - 1,
                u16::from(input.mask) % 2,
            );
        }
        4 => {
            key[usize::from(input.offset) % polynomial_len] ^= input.mask;
        }
        5 => {
            let (_, second) = coefficients(&key[pair_offset..pair_offset + 3]);
            let invalid = MODULUS + input.length % (4096 - MODULUS);
            write_coefficients(&mut key[pair_offset..pair_offset + 3], invalid, second);
        }
        6 => key = input.repeated_bytes(p.pub_key_len),
        7 => {
            let lengths = [
                0,
                1,
                p.pub_key_len - 1,
                p.pub_key_len,
                p.pub_key_len + 1,
                MLKEM_PUB_KEY_MAX_LEN,
                MLKEM_PUB_KEY_MAX_LEN + 1,
            ];
            key.resize(lengths[usize::from(input.length) % lengths.len()], 0);
        }
        8 => key.resize(MLKEM_PUB_KEY_MAX_LEN + 1, 0),
        9 => {
            key = input.repeated_bytes(usize::from(input.length) % (MLKEM_PUB_KEY_MAX_LEN + 2));
        }
        _ => {}
    }
    key
}

/// A local adapter that moves key data without changing the three-field schema.
struct EncapsulateRequest {
    req: TborMlKemEncapsulateReq,
    gap: usize,
}

impl TborOpReq for EncapsulateRequest {
    const OPCODE: u8 = TborMlKemEncapsulateReq::OPCODE;
    type OpResp = TborMlKemEncapsulateResp;

    /// Preserve the actual request's handle/session ownership checks.
    fn get_session_id(&self) -> Option<u16> {
        self.req.get_session_id()
    }

    /// Keep the command in-session even for the relocated-data scenario.
    fn session_ctrl(&self) -> SessionControlKind {
        self.req.session_ctrl()
    }

    /// Encode a padding region, then remove only its TOC slot and backpatch.
    ///
    /// The remaining key offset still points past the unreferenced gap. The
    /// ordinary codec accepts this frame, but the handler must reject its
    /// noncanonical in-place location before invoking encapsulation.
    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> core::result::Result<&'b [u8], EncodeError> {
        if self.gap == 0 {
            return self.req.encode_request(buf);
        }
        let len = RequestEncoder::new(buf, PROTOCOL_VERSION, Self::OPCODE)
            .with_toc_slots(4)?
            .session_id(self.req.session_id)?
            .uint8(self.req.scope)?
            .padding(self.gap)?
            .buffer(&self.req.pub_key)?
            .finish()?
            .len();
        let padding_toc = REQ_HEADER_LEN + 2 * TOC_ENTRY_LEN;
        buf.copy_within(padding_toc + TOC_ENTRY_LEN..len, padding_toc);
        Request::write_header(buf, &Request::new(Self::OPCODE), 3);
        let frame = &buf[..len - TOC_ENTRY_LEN];
        let view = RequestView::parse(frame).expect("relocated request must be structurally valid");
        assert_eq!(view.toc_count(), 3);
        assert_eq!(view.toc_entry(0), TocEntry::SessionId(self.req.session_id));
        assert_eq!(view.toc_entry(1), TocEntry::Uint8(self.req.scope));
        let TocEntry::Buffer(key) = view.toc_entry(2) else {
            panic!("relocated key must retain its buffer TOC type");
        };
        assert_eq!(key, self.req.pub_key);
        assert_eq!(
            key.as_ptr() as usize - frame.as_ptr() as usize,
            REQ_HEADER_LEN + view.toc_count() * TOC_ENTRY_LEN + self.gap,
        );
        Ok(frame)
    }
}

/// Construct valid baselines, single-field rejects, or combined-invalid cases.
fn request(ctx: &TestCtx, input: &FuzzInput, session_id: u16) -> EncapsulateRequest {
    let scenario = input.scenario % 32;
    let p = PARAMS[usize::from(input.params % 3)];
    let pub_key = public_key(ctx, input, p, session_id);
    let scope = match scenario {
        8 => [
            common::KEY_SCOPE_SESSION,
            common::KEY_SCOPE_EPHEMERAL,
            common::KEY_SCOPE_LOCAL,
        ][usize::from(input.scope % 3)],
        9 => common::KEY_SCOPE_SECURITY_DOMAIN,
        10 | 24..=29 | 31 => input.scope,
        _ => common::KEY_SCOPE_SESSION,
    };
    let session_id = match scenario {
        13 | 29 => session_id ^ (1u16 << (input.session_id % 16)),
        14 | 24 => input.session_id,
        _ => session_id,
    };
    let gap = if scenario == 23 || (scenario == 24 && input.key_mode & 0x80 != 0) {
        (usize::from(input.offset) % 16 + 1) * TOC_ENTRY_LEN
    } else {
        0
    };
    EncapsulateRequest {
        req: TborMlKemEncapsulateReq {
            session_id,
            scope,
            pub_key,
        },
        gap,
    }
}

/// Predict the first rejection from the final bytes and actual fixture state.
///
/// Transport binding precedes dispatch's PSK gate, schema maximum length,
/// handler length/layout checks, PAL key import, and finally masking scope.
/// The host encoder does not enforce this schema's max_len; max+1 reaches FW.
fn expected_rejection(
    request: &EncapsulateRequest,
    bound_session: Option<u16>,
    lifecycle: Lifecycle,
) -> Option<TborStatus> {
    let req = &request.req;
    let Some(bound_session) = bound_session else {
        return Some(TborStatus::SessionNotFound);
    };
    if req.session_id != bound_session {
        return Some(TborStatus::FileHandleSessionIdDoesNotMatch);
    }
    if lifecycle == Lifecycle::DefaultPsk {
        return Some(TborStatus::DefaultPskMustRotate);
    }
    if req.pub_key.len() > MLKEM_PUB_KEY_MAX_LEN {
        return Some(TborStatus::TborInvalidFixedLength);
    }
    if !PARAMS.iter().any(|p| p.pub_key_len == req.pub_key.len()) {
        return Some(TborStatus::InvalidArg);
    }
    if request.gap != 0 {
        return Some(TborStatus::InvalidArg);
    }
    let canonical = canonical_public_key(&req.pub_key);
    assert_eq!(
        <crypto::MlKemPublicKey as crypto::ImportableKey>::from_bytes(&req.pub_key).is_ok(),
        canonical,
        "independent coefficient predicate disagrees with host ML-KEM import",
    );
    if !canonical {
        return Some(TborStatus::InvalidArg);
    }
    let available = match req.scope {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            matches!(lifecycle, Lifecycle::Finalized | Lifecycle::SecurityDomain)
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => lifecycle == Lifecycle::SecurityDomain,
        _ => false,
    };
    if available {
        None
    } else {
        Some(TborStatus::UnsupportedKeyScope)
    }
}

/// Enforce exact rejection statuses or validate every successful response.
fn check_request(
    ctx: &TestCtx,
    request: &EncapsulateRequest,
    bound_session: Option<u16>,
    lifecycle: Lifecycle,
) {
    let expected = expected_rejection(request, bound_session, lifecycle);
    if let Some(status) = expected {
        if bound_session != Some(request.req.session_id) {
            ctx.expect_session_reject(request, status);
        } else {
            ctx.expect_fw_reject(request, status);
        }
        return;
    }
    let p = PARAMS
        .iter()
        .find(|p| p.pub_key_len == request.req.pub_key.len())
        .expect("successful request must identify a supported parameter set");
    let response = ctx
        .tbor(request)
        .expect("valid ML-KEM encapsulation must succeed");
    assert_eq!(response.ciphertext.len(), p.ciphertext_len);
    assert_eq!(
        response.masked_shared_secret.len(),
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
    );
    assert!(response.ciphertext.iter().any(|&byte| byte != 0));
    assert!(response.masked_shared_secret.iter().any(|&byte| byte != 0));
    assert_not_truncated_at_page(&response.ciphertext, p.name);
    assert_not_truncated_at_page(&response.masked_shared_secret, p.name);
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx, _path| {
        let lifecycle = input.lifecycle();
        let session = open_session(ctx, &input);
        let session_id = session.session_id();
        let request = request(ctx, &input, session_id);
        let session = if lifecycle == Lifecycle::Closed {
            session
                .close()
                .expect("close session before negative request");
            None
        } else {
            Some(session)
        };
        check_request(
            ctx,
            &request,
            session.as_ref().map(SessionGuard::session_id),
            lifecycle,
        );
        if let Some(session) = session {
            session.close().expect("close fuzz session");
        }
    });
});
