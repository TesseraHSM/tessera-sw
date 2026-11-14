// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured public-key recovery with authenticated fixtures, exact rejection
//! oracles, independent imported public keys, and post-rejection recovery probes.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::OnceLock;

use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;
use tsra_fw_core_crypto_key_masking::aead::MaskedKeyMetadata;
use zerocopy::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    Imported,
    Symmetric,
    Header,
    Iv,
    Metadata,
    Ciphertext,
    Tag,
    Truncate,
    Append,
    Raw,
    Session,
    DifferentSession,
    ClosedSession,
    ReplacementSession,
    DefaultPsk,
    Scope,
    Length,
}

/// Byte-oriented controls allow even an empty corpus entry to reach the handler.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    /// Read a control byte, defaulting missing controls to a valid ECC baseline.
    fn byte(&self, index: usize) -> u8 {
        self.0.get(index).copied().unwrap_or(0)
    }

    /// Read a full-width little-endian selector without rejecting short inputs.
    fn word(&self, index: usize) -> u16 {
        u16::from_le_bytes([self.byte(index), self.byte(index + 1)])
    }

    /// Reserve nearly half the selector space for unmodified asymmetric blobs.
    fn scenario(&self) -> Scenario {
        match self.byte(0) % 32 {
            10 | 27 => Scenario::Imported,
            11 => Scenario::Symmetric,
            12 => Scenario::Header,
            13 => Scenario::Iv,
            14 => Scenario::Metadata,
            15 => Scenario::Ciphertext,
            16 => Scenario::Tag,
            17 => Scenario::Truncate,
            18 => Scenario::Append,
            19 => Scenario::Raw,
            20 => Scenario::Session,
            21 => Scenario::DifferentSession,
            22 => Scenario::ClosedSession,
            23 => Scenario::ReplacementSession,
            24 => Scenario::DefaultPsk,
            25 => Scenario::Scope,
            26 => Scenario::Length,
            _ => Scenario::Valid,
        }
    }

    /// Favor cheap session-scoped fixtures while retaining every supported scope.
    fn scope(&self) -> common::KeyScope {
        match self.byte(3) % 32 {
            1 => common::KeyScope::Ephemeral,
            2 => common::KeyScope::Local,
            3 => common::KeyScope::SecurityDomain,
            _ => common::KeyScope::Session,
        }
    }

    /// Select both supported role/session profiles using the shared role model.
    fn role(&self) -> common::FuzzRole {
        if self.byte(2) & 1 == 0 {
            common::FuzzRole::Co
        } else {
            common::FuzzRole::Cu
        }
    }

    /// Select a supported curve and its wire-format sizing helpers.
    fn curve(&self) -> common::EccCurve {
        [
            common::EccCurve::P256,
            common::EccCurve::P384,
            common::EccCurve::P521,
        ][usize::from(self.byte(1) % 3)]
    }

    /// Expand a bounded fuzz tail, using a fuzzed fill when the tail is absent.
    fn bytes(&self, len: usize) -> Vec<u8> {
        let tail = self.0.get(16..).unwrap_or_default();
        (0..len)
            .map(|index| {
                if tail.is_empty() {
                    self.byte(10)
                } else {
                    tail[index % tail.len()]
                }
            })
            .collect()
    }

    /// Vary authenticated labels, including the empty and maximum-length cases.
    fn label(&self) -> Vec<u8> {
        self.bytes(usize::from(self.byte(6)) % (TBOR_KEY_LABEL_MAX_LEN + 1))
    }
}

struct Material {
    der: Vec<u8>,
    public: Vec<u8>,
}

/// Cache immutable host DER and independently serialized public bytes only.
fn imported_material(class: u8, size: usize) -> &'static Material {
    static RSA: [OnceLock<Material>; 3] = [const { OnceLock::new() }; 3];
    static ECC: [OnceLock<Material>; 3] = [const { OnceLock::new() }; 3];
    if class == KEY_CLASS_ECC {
        ECC[size].get_or_init(|| {
            let curve = [
                tsra_crypto::EccCurve::P256,
                tsra_crypto::EccCurve::P384,
                tsra_crypto::EccCurve::P521,
            ][size];
            let key = EccPrivateKey::from_curve(curve).expect("host ECC fixture");
            let (x, y) = key.coord_vec().expect("host ECC coordinates");
            let width = [
                common::EccCurve::P256,
                common::EccCurve::P384,
                common::EccCurve::P521,
            ][size]
                .wire_coord_len();
            let mut public = vec![0; width * 2];
            for (dest, source) in public.chunks_mut(width).zip([x, y]) {
                assert!(source.len() <= width);
                for (dst, src) in dest.iter_mut().zip(source.iter().rev()) {
                    *dst = *src;
                }
            }
            Material {
                der: key.to_vec().expect("host ECC DER"),
                public,
            }
        })
    } else {
        RSA[size].get_or_init(|| {
            let key = RsaPrivateKey::generate([256, 384, 512][size]).expect("host RSA fixture");
            let public_key = key.public_key().expect("host RSA public key");
            let mut public = public_key.n_vec().expect("host RSA modulus");
            public.reverse();
            let mut exponent = public_key.e_vec().expect("host RSA exponent");
            assert!(exponent.len() <= 4);
            exponent.reverse();
            exponent.resize(4, 0);
            public.extend(exponent);
            Material {
                der: key.to_vec().expect("host RSA DER"),
                public,
            }
        })
    }
}

struct KeyBlob {
    masked: Vec<u8>,
    public: Vec<u8>,
}

/// Import fresh device-bound ciphertext; never reuse it across fixture resets.
fn import_key(ctx: &TestCtx, session_id: u16, input: &Input<'_>, scope: u8) -> KeyBlob {
    let class = [KEY_CLASS_ECC, KEY_CLASS_RSA, KEY_CLASS_RSA_CRT][usize::from(input.byte(4) % 3)];
    let size = usize::from(input.byte(1) % 3);
    let material = imported_material(class, size);
    let wire = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("GetUnwrappingKey")
        .pub_key;
    assert_eq!(wire.len(), UNWRAPPING_PUB_KEY_LEN);
    let modulus_len = UNWRAPPING_PUB_KEY_LEN - 4;
    let public_be: Vec<_> = wire[..modulus_len]
        .iter()
        .rev()
        .chain(wire[modulus_len..].iter().rev())
        .copied()
        .collect();
    let public = RsaPublicKey::from_hsm_bytes(&public_be).expect("unwrapping public key");
    let kek_bytes = input.bytes(32);
    let kek = AesKey::from_bytes(&kek_bytes).expect("host KEK");
    let mut wrapped = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public,
        &kek_bytes,
    )
    .expect("RSA-OAEP fixture");
    assert_eq!(wrapped.len(), modulus_len);
    wrapped.reverse();
    wrapped.extend(
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &material.der)
            .expect("AES-KWP fixture"),
    );
    let resp = ctx
        .tbor(&TborUnwrapKeyReq {
            session_id,
            scope,
            key_class: class,
            key_usage: if input.byte(5) & 1 == 0 {
                KEY_USAGE_SIGN | KEY_USAGE_VERIFY
            } else if class == KEY_CLASS_ECC {
                KEY_USAGE_DERIVE
            } else {
                KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT
            },
            oaep_hash_algo: HASH_ALGO_SHA256,
            wrapped_blob: wrapped,
            key_label: input.label(),
        })
        .expect("valid asymmetric UnwrapKey");
    let expected_len = if class == KEY_CLASS_ECC {
        input.curve().wire_pub_key_len()
    } else {
        [256, 384, 512][size] + 4
    };
    assert_eq!(resp.pub_key.len(), expected_len);
    assert_eq!(resp.pub_key, material.public, "independent host public key");
    KeyBlob {
        masked: resp.masked_key,
        public: resp.pub_key,
    }
}

/// Generate authenticated asymmetric or symmetric blobs under a provisioned scope.
fn make_key(ctx: &TestCtx, session_id: u16, input: &Input<'_>, scope: u8) -> KeyBlob {
    if input.scenario() == Scenario::Imported {
        return import_key(ctx, session_id, input, scope);
    }
    if input.scenario() == Scenario::Symmetric {
        let masked = if input.byte(4) & 1 == 0 {
            ctx.tbor(&TborAesGenerateKeyReq {
                session_id,
                scope,
                key_size: [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256]
                    [usize::from(input.byte(1) % 3)],
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: input.label(),
            })
            .expect("valid AES fixture")
            .masked_key
        } else {
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id,
                scope,
                hash_algo: [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512]
                    [usize::from(input.byte(1) % 3)],
                key_length: 64,
                key_label: input.label(),
            })
            .expect("valid HMAC fixture")
            .masked_key
        };
        return KeyBlob {
            masked,
            public: Vec::new(),
        };
    }
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
            curve: input.curve().to_tbor(),
            key_usage: if input.byte(5) & 1 == 0 {
                KEY_USAGE_SIGN
            } else {
                KEY_USAGE_DERIVE
            },
            key_label: input.label(),
        })
        .expect("valid ECC fixture");
    assert_eq!(resp.pub_key.len(), input.curve().wire_pub_key_len());
    KeyBlob {
        masked: resp.masked_key,
        public: resp.pub_key,
    }
}

/// Provision administrative scopes through CO before switching to the chosen role.
fn setup<'ctx>(
    ctx: &'ctx TestCtx,
    input: &Input<'_>,
    scope: common::KeyScope,
) -> SessionGuard<'ctx> {
    let role = input.role();
    if scope == common::KeyScope::Session && matches!(role, common::FuzzRole::Cu) {
        return SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK));
    }
    let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
    match scope {
        common::KeyScope::Ephemeral | common::KeyScope::Local => {
            common::finalize_partition(ctx, co.handshake());
        }
        common::KeyScope::SecurityDomain => {
            common::create_test_security_domain(ctx, co.handshake());
        }
        _ => {}
    }
    match role {
        common::FuzzRole::Co => co,
        common::FuzzRole::Cu => {
            co.close().expect("close provisioning CO session");
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        }
    }
}

/// Select lengths around framing, payload alignment, schema, and transport limits.
fn boundary_len(input: &Input<'_>, original: usize) -> usize {
    let alg = aead_envelope::AeadAlg::AesGcm256;
    let aad_at = aead_envelope::HEADER_LEN + alg.iv_len();
    let payload_at = aad_at + core::mem::size_of::<MaskedKeyMetadata>();
    let minimum = payload_at + alg.tag_len();
    let lengths = [
        0,
        1,
        aead_envelope::HEADER_LEN - 1,
        aead_envelope::HEADER_LEN,
        aad_at - 1,
        aad_at,
        payload_at - 1,
        payload_at,
        minimum - 1,
        minimum,
        minimum + 1,
        minimum + 15,
        minimum + 16,
        original - 1,
        original,
        original + 1,
        original + 16,
        GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN - 1,
        GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN,
        GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN + 1,
        tsra_ddi_tbor_codec::MAX_DATA_SIZE + 1,
    ];
    lengths[usize::from(input.byte(7)) % lengths.len()]
}

/// Apply bounded mutations; absent masks flip a bit, while explicit zero is a no-op.
fn mutate(input: &Input<'_>, original: &[u8]) -> Vec<u8> {
    let env = aead_envelope::inspect(original).expect("fixture envelope framing");
    let aad_at = aead_envelope::HEADER_LEN + env.iv.len();
    let payload_at = aad_at + env.aad.len();
    let tag_at = original.len() - env.tag.len();
    let offset = usize::from(input.word(8));
    let flip_at = match input.scenario() {
        Scenario::Header => Some(offset % aead_envelope::HEADER_LEN),
        Scenario::Iv => Some(aead_envelope::HEADER_LEN + offset % env.iv.len()),
        Scenario::Metadata => Some(aad_at + offset % env.aad.len()),
        Scenario::Ciphertext => Some(payload_at + offset % env.payload.len()),
        Scenario::Tag => Some(tag_at + offset % env.tag.len()),
        _ => None,
    };
    let mutation = if let Some(offset) = flip_at {
        common::EnvelopeMutation::FlipByte {
            offset: offset as u16,
            mask: input.0.get(10).copied().unwrap_or(1),
        }
    } else {
        match input.scenario() {
            Scenario::Truncate => common::EnvelopeMutation::Truncate {
                len: boundary_len(input, original.len()).min(original.len()) as u16,
            },
            Scenario::Append => {
                common::EnvelopeMutation::Append(input.bytes(usize::from(input.word(11)) % 33))
            }
            _ => common::EnvelopeMutation::None,
        }
    };
    let noop = mutation.is_noop(original);
    let mut blob = original.to_vec();
    mutation.apply(&mut blob);
    assert_eq!(noop, blob == original, "shared mutation no-op contract");
    match input.scenario() {
        Scenario::Scope => {
            let metadata = MaskedKeyMetadata::read_from_bytes(env.aad).expect("fixture metadata");
            let mut scope = metadata.usage_flags().scope();
            scope.0 = input.byte(7) % 8;
            let flags = metadata.usage_flags().with_scope(scope).into_bits();
            let at = aad_at + core::mem::offset_of!(MaskedKeyMetadata, usage_flags);
            blob[at..at + 8].copy_from_slice(&flags.to_le_bytes());
        }
        Scenario::Length => {
            blob.resize(boundary_len(input, original.len()), input.byte(10));
        }
        Scenario::Raw => {
            blob = input.bytes(boundary_len(input, original.len()));
            if let Some(first) = blob.first_mut() {
                *first = !aead_envelope::FORMAT_TAG[0];
            }
        }
        _ => {}
    }
    blob
}

#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Success,
    Reject(TborStatus),
    HostEncode,
}

/// Predict framing, masking-key availability, and authentication from provenance.
fn expected_blob(blob: &[u8], original: &KeyBlob, provisioned: common::KeyScope) -> Expected {
    let env = match aead_envelope::inspect(blob) {
        Ok(env) => env,
        Err(_) => return Expected::Reject(TborStatus::InvalidArg),
    };
    if env.aad.len() != core::mem::size_of::<MaskedKeyMetadata>()
        || !env.payload.len().is_multiple_of(16)
    {
        return Expected::Reject(TborStatus::MaskedKeyDecodeFailed);
    }
    let metadata = MaskedKeyMetadata::read_from_bytes(env.aad).expect("metadata size checked");
    let available = match metadata.usage_flags().scope().0 {
        common::KEY_SCOPE_SESSION => true,
        common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL => {
            provisioned != common::KeyScope::Session
        }
        common::KEY_SCOPE_SECURITY_DOMAIN => provisioned == common::KeyScope::SecurityDomain,
        _ => false,
    };
    if !available {
        return Expected::Reject(TborStatus::UnsupportedKeyScope);
    }
    // The stored IV's final four bytes are neither nonce nor authenticated data.
    let nonce_end = aead_envelope::HEADER_LEN + 12;
    let iv_end = aead_envelope::HEADER_LEN + env.iv.len();
    let unchanged = blob.len() == original.masked.len()
        && blob[..nonce_end] == original.masked[..nonce_end]
        && blob[iv_end..] == original.masked[iv_end..];
    if !unchanged {
        Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch)
    } else if original.public.is_empty() {
        Expected::Reject(TborStatus::InvalidKeyType)
    } else {
        Expected::Success
    }
}

/// Assert exact response bytes, wire size, and repeatability of a caller-held blob.
fn assert_success(ctx: &TestCtx, req: &TborGetPublicKeyReq, public: &[u8]) {
    assert!(!public.is_empty());
    assert!(public.len() <= GET_PUBLIC_KEY_PUB_KEY_MAX_LEN);
    for _ in 0..2 {
        let resp = ctx.tbor(req).expect("oracle-valid GetPublicKey");
        assert_eq!(resp.pub_key.len(), public.len(), "public wire length");
        assert_eq!(resp.pub_key, public, "public wire bytes");
    }
}

/// Execute one isolated scenario with a precomputed oracle and a recovery probe.
fn run(input: &Input<'_>) {
    common::common_fuzz_test(&|ctx, _path| {
        if input.scenario() == Scenario::DefaultPsk {
            let role = input.role();
            let session = ctx
                .open_session(role.psk_id(), role.session_type())
                .expect("default-PSK session");
            ctx.expect_fw_reject(
                &TborGetPublicKeyReq {
                    session_id: session.session_id(),
                    masked_key: input.bytes(usize::from(input.word(11)) % 65),
                },
                TborStatus::DefaultPskMustRotate,
            );
            session.close().expect("close default-PSK session");
            return;
        }

        let scope = if input.scenario() == Scenario::ReplacementSession {
            common::KeyScope::Session
        } else {
            input.scope()
        };
        let session = setup(ctx, input, scope);
        let original = make_key(ctx, session.session_id(), input, scope.to_tbor());
        let mut req = TborGetPublicKeyReq {
            session_id: session.session_id(),
            masked_key: mutate(input, &original.masked),
        };
        let mut expected = expected_blob(&req.masked_key, &original, scope);
        let session = match input.scenario() {
            Scenario::ClosedSession => {
                session.close().expect("close before stale-session request");
                expected = Expected::Reject(TborStatus::SessionNotFound);
                None
            }
            Scenario::ReplacementSession => {
                session.close().expect("close originating session");
                let role = input.role();
                let psk = match role {
                    common::FuzzRole::Co => &ROTATED_CO_PSK,
                    common::FuzzRole::Cu => &ROTATED_CU_PSK,
                };
                let pending = ctx
                    .session_open_init_with_options(
                        SessionOpenInitOptions::new(role.psk_id(), role.session_type())
                            .with_psk(psk),
                    )
                    .expect("replacement session init");
                let replacement = SessionGuard::new(
                    ctx,
                    ctx.session_open_finish(pending)
                        .expect("replacement session finish"),
                );
                req.session_id = replacement.session_id();
                expected = Expected::Reject(TborStatus::AesGcmDecryptTagDoesNotMatch);
                Some(replacement)
            }
            Scenario::Session | Scenario::DifferentSession => {
                req.session_id = input.word(11);
                if input.scenario() == Scenario::DifferentSession
                    && req.session_id == session.session_id()
                {
                    req.session_id = req.session_id.wrapping_add(1);
                }
                if req.session_id != session.session_id() {
                    expected = Expected::Reject(TborStatus::FileHandleSessionIdDoesNotMatch);
                }
                Some(session)
            }
            _ => Some(session),
        };

        if session
            .as_ref()
            .is_some_and(|s| s.session_id() == req.session_id)
        {
            let mut buf = [0; common::FUZZ_REQ_BUF_SIZE];
            if req.encode_request(&mut buf).is_err() {
                expected = Expected::HostEncode;
            } else if req.masked_key.len() > GET_PUBLIC_KEY_MASKED_KEY_MAX_LEN {
                expected = Expected::Reject(TborStatus::TborInvalidFixedLength);
            }
        }

        match expected {
            Expected::Success => assert_success(ctx, &req, &original.public),
            Expected::Reject(status) => {
                ctx.expect_session_reject(&req, status);
            }
            Expected::HostEncode => {
                assert!(
                    matches!(ctx.tbor(&req), Err(DdiError::TborEncodeError)),
                    "oversized transport request must fail host encoding",
                );
            }
        }
        if let Some(session) = session {
            if expected != Expected::Success {
                let probe = if input.scenario() == Scenario::ReplacementSession
                    || original.public.is_empty()
                {
                    make_key(
                        ctx,
                        session.session_id(),
                        &Input(&[]),
                        common::KEY_SCOPE_SESSION,
                    )
                } else {
                    original
                };
                assert_success(
                    ctx,
                    &TborGetPublicKeyReq {
                        session_id: session.session_id(),
                        masked_key: probe.masked,
                    },
                    &probe.public,
                );
            }
            session.close().expect("close caller session");
        }
    });
}

fuzz_target!(|data: &[u8]| {
    run(&Input(data));
});
