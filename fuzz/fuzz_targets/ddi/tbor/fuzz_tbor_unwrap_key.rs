// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured RSA-AES import scenarios with exact rejection oracles,
//! independently derived public keys, and unmask-on-use checks.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::OnceLock;

use libfuzzer_sys::*;
use tsra_crypto::*;
use tsra_ddi_interface::*;
use tsra_ddi_tbor_test_harness::*;
use tsra_ddi_tbor_types::*;

/// RSA-2048 ciphertext width, independent of the imported key's size.
const RSA_SEGMENT_LEN: usize = UNWRAPPING_PUB_KEY_LEN - 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    Valid,
    Scope,
    Class,
    Usage,
    Hash,
    HashMismatch,
    Label,
    Session,
    ClosedSession,
    Material,
    RsaCiphertext,
    KwpCiphertext,
    Truncate,
    Append,
    RawBlob,
    Kek,
    Cleanup,
}

/// Byte-oriented controls keep even an empty corpus entry executable.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    /// Read a control byte, defaulting absent controls to the valid baseline.
    fn byte(&self, index: usize) -> u8 {
        self.0.get(index).copied().unwrap_or(0)
    }

    /// Select a scenario with a quarter of selector values reserved for success.
    fn scenario(&self) -> Scenario {
        match self.byte(0) % 24 {
            0..=5 => Scenario::Valid,
            6 => Scenario::Scope,
            7 => Scenario::Class,
            8 | 22 => Scenario::Usage,
            9 => Scenario::Hash,
            10 => Scenario::HashMismatch,
            11 | 23 => Scenario::Label,
            12 => Scenario::Session,
            13 => Scenario::ClosedSession,
            14 => Scenario::Material,
            15 => Scenario::RsaCiphertext,
            16 => Scenario::KwpCiphertext,
            17 => Scenario::Truncate,
            18 => Scenario::Append,
            19 => Scenario::RawBlob,
            20 => Scenario::Kek,
            _ => Scenario::Cleanup,
        }
    }

    /// Expand bounded fuzz bytes without a PRNG; empty tails use a fuzzed fill.
    fn bytes(&self, len: usize) -> Vec<u8> {
        let tail = self.0.get(24..).unwrap_or_default();
        (0..len)
            .map(|index| {
                if tail.is_empty() {
                    self.byte(19)
                } else {
                    tail[index % tail.len()]
                }
            })
            .collect()
    }

    /// Decode a full-width usage value without requiring a long corpus entry.
    fn usage(&self) -> u64 {
        u64::from_le_bytes(core::array::from_fn(|index| self.byte(8 + index)))
    }
}

#[derive(Clone)]
struct Material {
    bytes: Vec<u8>,
    kind: u8,
    public: Vec<u8>,
}

/// Map a known wire selector to the host OAEP implementation.
fn host_hash(hash: u8) -> HashAlgo {
    match hash {
        HASH_ALGO_SHA1 => HashAlgo::sha1(),
        HASH_ALGO_SHA256 => HashAlgo::sha256(),
        HASH_ALGO_SHA384 => HashAlgo::sha384(),
        HASH_ALGO_SHA512 => HashAlgo::sha512(),
        _ => panic!("host hash must be a supported selector"),
    }
}

/// Cache immutable DER and independently serialized public bytes, never ciphertext.
fn asymmetric_material(class: u8, size: usize) -> Material {
    static RSA: [OnceLock<Material>; 3] = [const { OnceLock::new() }; 3];
    static ECC: [OnceLock<Material>; 3] = [const { OnceLock::new() }; 3];
    if class == KEY_CLASS_ECC {
        ECC[size]
            .get_or_init(|| {
                let curve = [
                    common::EccCurve::P256,
                    common::EccCurve::P384,
                    common::EccCurve::P521,
                ][size];
                let host_curve = match curve {
                    common::EccCurve::P256 => tsra_crypto::EccCurve::P256,
                    common::EccCurve::P384 => tsra_crypto::EccCurve::P384,
                    common::EccCurve::P521 => tsra_crypto::EccCurve::P521,
                };
                let key = EccPrivateKey::from_curve(host_curve).expect("ECC fixture");
                let (x, y) = key.coord_vec().expect("fixture public coordinates");
                let width = curve.wire_pub_key_len() / 2;
                let mut public = vec![0; width * 2];
                for (dest, source) in public.chunks_mut(width).zip([x, y]) {
                    assert!(source.len() <= width);
                    for (dst, src) in dest.iter_mut().zip(source.iter().rev()) {
                        *dst = *src;
                    }
                }
                Material {
                    bytes: key.to_vec().expect("ECC fixture DER"),
                    kind: [
                        KEY_KIND_ECC256_PRIVATE,
                        KEY_KIND_ECC384_PRIVATE,
                        KEY_KIND_ECC521_PRIVATE,
                    ][size],
                    public,
                }
            })
            .clone()
    } else {
        let mut material = RSA[size]
            .get_or_init(|| {
                let key = RsaPrivateKey::generate([256, 384, 512][size]).expect("RSA fixture");
                let public_key = key.public_key().expect("fixture RSA public key");
                let mut public = public_key.n_vec().expect("fixture modulus");
                public.reverse();
                let mut exponent = public_key.e_vec().expect("fixture exponent");
                assert!(exponent.len() <= 4);
                exponent.reverse();
                exponent.resize(4, 0);
                public.extend_from_slice(&exponent);
                Material {
                    bytes: key.to_vec().expect("RSA fixture DER"),
                    kind: [
                        KEY_KIND_RSA2K_PRIVATE,
                        KEY_KIND_RSA3K_PRIVATE,
                        KEY_KIND_RSA4K_PRIVATE,
                    ][size],
                    public,
                }
            })
            .clone();
        if class == KEY_CLASS_RSA_CRT {
            material.kind = [
                KEY_KIND_RSA2K_PRIVATE_CRT,
                KEY_KIND_RSA3K_PRIVATE_CRT,
                KEY_KIND_RSA4K_PRIVATE_CRT,
            ][size];
        }
        material
    }
}

/// Build valid imported plaintext, varying every supported class and key size.
fn valid_material(input: &Input<'_>, class: u8) -> Material {
    let size = usize::from(input.byte(2) % 3);
    let (len, kind) = match class {
        KEY_CLASS_RSA | KEY_CLASS_RSA_CRT | KEY_CLASS_ECC => {
            return asymmetric_material(class, size);
        }
        KEY_CLASS_AES_XTS512 => (64, KEY_KIND_AES_XTS512),
        KEY_CLASS_HMAC_SHA256 | KEY_CLASS_HMAC_SHA384 | KEY_CLASS_HMAC_SHA512 => (
            [1, 16, 31, 32, 48, 64, 65, 128, 129, 256][usize::from(input.byte(2) % 10)],
            [
                KEY_KIND_VAR_LEN_HMAC_SHA256,
                KEY_KIND_VAR_LEN_HMAC_SHA384,
                KEY_KIND_VAR_LEN_HMAC_SHA512,
            ][usize::from(class - KEY_CLASS_HMAC_SHA256)],
        ),
        _ => (
            [16, 24, 32][size],
            [KEY_KIND_AES128, KEY_KIND_AES192, KEY_KIND_AES256][size],
        ),
    };
    let mut bytes = input.bytes(len);
    if class == KEY_CLASS_AES_XTS512 && bytes[..32] == bytes[32..] {
        bytes[32] ^= 1;
    }
    Material {
        bytes,
        kind,
        public: Vec::new(),
    }
}

/// Select both permitted usage groups for RSA/ECC, and optional unknown high bits.
fn valid_usage(class: u8, selector: u8) -> u64 {
    let usage = match class {
        KEY_CLASS_AES | KEY_CLASS_AES_XTS512 => KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        KEY_CLASS_RSA | KEY_CLASS_RSA_CRT if selector & 1 != 0 => {
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT
        }
        KEY_CLASS_ECC if selector & 1 != 0 => KEY_USAGE_DERIVE,
        _ => KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    };
    usage | if selector & 2 != 0 { 1 << 63 } else { 0 }
}

/// Independently recognize exact allowed groups; undefined usage bits are ignored.
fn accepts_usage(class: u8, usage: u64) -> bool {
    let known = usage
        & (KEY_USAGE_ENCRYPT
            | KEY_USAGE_DECRYPT
            | KEY_USAGE_SIGN
            | KEY_USAGE_VERIFY
            | KEY_USAGE_DERIVE
            | KEY_USAGE_WRAP
            | KEY_USAGE_UNWRAP);
    let cipher = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;
    let signature = KEY_USAGE_SIGN | KEY_USAGE_VERIFY;
    match class {
        KEY_CLASS_AES | KEY_CLASS_AES_XTS512 => known == cipher,
        KEY_CLASS_RSA | KEY_CLASS_RSA_CRT => known == cipher || known == signature,
        KEY_CLASS_ECC => known == signature || known == KEY_USAGE_DERIVE,
        KEY_CLASS_HMAC_SHA256 | KEY_CLASS_HMAC_SHA384 | KEY_CLASS_HMAC_SHA512 => known == signature,
        _ => false,
    }
}

/// Convert each LE public component independently before importing the host key.
fn unwrapping_public(wire: &[u8]) -> RsaPublicKey {
    assert_eq!(wire.len(), UNWRAPPING_PUB_KEY_LEN);
    let bytes: Vec<_> = wire[..RSA_SEGMENT_LEN]
        .iter()
        .rev()
        .chain(wire[RSA_SEGMENT_LEN..].iter().rev())
        .copied()
        .collect();
    RsaPublicKey::from_hsm_bytes(&bytes).expect("unwrapping public key")
}

/// Wrap with a separately selectable OAEP plaintext to reach invalid-KEK checks.
fn wrap(
    public: &RsaPublicKey,
    hash: u8,
    oaep_plaintext: &[u8],
    kek: &AesKey,
    material: &[u8],
) -> Vec<u8> {
    let mut blob = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(host_hash(hash), None),
        public,
        oaep_plaintext,
    )
    .expect("OAEP fixture encryption");
    assert_eq!(blob.len(), RSA_SEGMENT_LEN);
    blob.reverse();
    blob.extend(
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), kek, material)
            .expect("KWP fixture encryption"),
    );
    blob
}

/// Predict a modified KWP segment using the known host KEK, not the device result.
///
/// Mutation scenarios use AES plaintext, making any authenticated replacement's
/// classification depend only on its recovered length.
fn kwp_outcome(blob: &[u8], kek: &AesKey, material: &mut Material) -> Result<(), TborStatus> {
    if blob.len() <= RSA_SEGMENT_LEN {
        return Err(TborStatus::RsaUnwrapInvalidRequest);
    }
    let payload = &blob[RSA_SEGMENT_LEN..];
    if payload.len() < 16 || !payload.len().is_multiple_of(8) {
        return Err(TborStatus::InvalidArg);
    }
    match Decrypter::decrypt_vec(&mut AesKeyWrapPadAlgo::default(), kek, payload) {
        Ok(bytes) => {
            material.kind = match bytes.len() {
                16 => KEY_KIND_AES128,
                24 => KEY_KIND_AES192,
                32 => KEY_KIND_AES256,
                _ => return Err(TborStatus::InvalidArg),
            };
            material.bytes = bytes;
            Ok(())
        }
        Err(_) => Err(TborStatus::RsaUnwrapAesUnwrapFailed),
    }
}

/// Scenario construction records crypto expectations before command submission.
struct Case {
    req: TborUnwrapKeyReq,
    material: Material,
    crypto: Result<(), TborStatus>,
}

/// Build one valid baseline and apply one bounded, attributable fault.
fn build_case(input: &Input<'_>, session_id: u16, public: &RsaPublicKey) -> Case {
    let scenario = input.scenario();
    let mut class = if scenario == Scenario::Class {
        input.byte(22)
    } else {
        input.byte(1) % (KEY_CLASS_AES_XTS512 + 1)
    };
    if matches!(
        scenario,
        Scenario::RsaCiphertext
            | Scenario::KwpCiphertext
            | Scenario::Truncate
            | Scenario::Append
            | Scenario::RawBlob
    ) {
        class = KEY_CLASS_AES;
    }
    let mut material = valid_material(input, class);
    let mut crypto = Ok(());
    if scenario == Scenario::Material {
        match class {
            KEY_CLASS_AES => {
                material.bytes =
                    input.bytes([1, 15, 17, 23, 25, 31, 33, 64][usize::from(input.byte(21) % 8)]);
                crypto = Err(TborStatus::InvalidArg);
            }
            KEY_CLASS_AES_XTS512 => {
                let len = [32, 48, 64, 72][usize::from(input.byte(21) % 4)];
                material.bytes = input.bytes(len);
                if len == 64 {
                    material.bytes.copy_within(..32, 32);
                }
                crypto = Err(TborStatus::InvalidArg);
            }
            KEY_CLASS_RSA | KEY_CLASS_RSA_CRT | KEY_CLASS_ECC => {
                material.bytes = input.bytes(1 + usize::from(input.byte(21)));
                // A zero tag cannot start a DER private-key SEQUENCE.
                material.bytes[0] = 0;
                crypto = Err(TborStatus::InvalidArg);
            }
            _ => {}
        }
    }
    let hash = input.byte(3) % 4;
    let mut kek_bytes = input.bytes([16, 24, 32][usize::from(input.byte(20) % 3)]);
    let kek = AesKey::from_bytes(&kek_bytes).expect("valid host KEK");
    if scenario == Scenario::Kek {
        let len = [0, 1, 15, 17, 24, 31, 32, 33][usize::from(input.byte(20) % 8)];
        kek_bytes = input.bytes(len);
        crypto = if len == 0 || len > 32 {
            Err(TborStatus::RsaUnwrapInvalidKek)
        } else if !matches!(len, 16 | 24 | 32) {
            Err(TborStatus::AesInvalidKeyLength)
        } else {
            Ok(())
        };
    }
    let payload_kek = if matches!(kek_bytes.len(), 16 | 24 | 32) {
        AesKey::from_bytes(&kek_bytes).expect("valid selected KEK")
    } else {
        kek
    };
    let mut blob = wrap(public, hash, &kek_bytes, &payload_kek, &material.bytes);
    match scenario {
        Scenario::RsaCiphertext if input.byte(19) != 0 => {
            // Ciphertext zero decrypts to zero, which is not an OAEP encoding.
            blob[..RSA_SEGMENT_LEN].fill(0);
            crypto = Err(TborStatus::RsaDecryptFailed);
        }
        Scenario::KwpCiphertext => {
            let index =
                RSA_SEGMENT_LEN + usize::from(input.byte(18)) % (blob.len() - RSA_SEGMENT_LEN);
            blob[index] ^= input.byte(19);
            crypto = kwp_outcome(&blob, &payload_kek, &mut material);
        }
        Scenario::Truncate => {
            let len = [0, 1, 255, 256, 257, 263, 264, 271, 272, blob.len()]
                [usize::from(input.byte(18) % 10)];
            blob.truncate(len);
            crypto = kwp_outcome(&blob, &payload_kek, &mut material);
        }
        Scenario::Append => {
            blob.extend(input.bytes(usize::from(input.byte(18) % 17)));
            crypto = kwp_outcome(&blob, &payload_kek, &mut material);
        }
        Scenario::RawBlob => {
            let len = [
                0,
                1,
                255,
                256,
                257,
                271,
                272,
                3071,
                3072,
                3073,
                4096,
                tsra_ddi_tbor_codec::MAX_DATA_SIZE + 1,
            ][usize::from(input.byte(18) % 12)];
            blob = input.bytes(len);
            // Long arbitrary payloads retain a provably invalid RSA segment.
            if len > RSA_SEGMENT_LEN {
                blob[..RSA_SEGMENT_LEN].fill(0);
            }
            crypto = Err(if len <= RSA_SEGMENT_LEN {
                TborStatus::RsaUnwrapInvalidRequest
            } else {
                TborStatus::RsaDecryptFailed
            });
        }
        _ => {}
    }
    let partition = input.byte(5) % 3;
    let scope = match scenario {
        Scenario::Scope => {
            if input.byte(23) & 1 == 0 {
                common::derive_valid_key_scope(input.byte(6))
            } else {
                input.byte(6)
            }
        }
        Scenario::Cleanup => [0, 5, 6, u8::MAX][usize::from(input.byte(6) % 4)],
        _ => match partition {
            0 => common::KEY_SCOPE_SESSION,
            1 => [
                common::KEY_SCOPE_SESSION,
                common::KEY_SCOPE_EPHEMERAL,
                common::KEY_SCOPE_LOCAL,
            ][usize::from(input.byte(6) % 3)],
            _ => [
                common::KEY_SCOPE_SESSION,
                common::KEY_SCOPE_EPHEMERAL,
                common::KEY_SCOPE_LOCAL,
                common::KEY_SCOPE_SECURITY_DOMAIN,
            ][usize::from(input.byte(6) % 4)],
        },
    };
    let label_len = [0, 1, 127, 128, 129][usize::from(input.byte(7) % 5)];
    let label_len = if scenario == Scenario::Label {
        label_len
    } else {
        label_len.min(TBOR_KEY_LABEL_MAX_LEN)
    };
    let usage = if scenario == Scenario::Usage {
        if input.byte(23) & 1 == 0 {
            [
                0,
                KEY_USAGE_ENCRYPT,
                KEY_USAGE_DECRYPT,
                KEY_USAGE_SIGN,
                KEY_USAGE_VERIFY,
                KEY_USAGE_DERIVE,
                KEY_USAGE_WRAP,
                KEY_USAGE_UNWRAP,
                KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
                KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                KEY_USAGE_SIGN | KEY_USAGE_VERIFY | KEY_USAGE_DERIVE,
                u64::MAX,
            ][usize::from(input.byte(8) % 12)]
        } else {
            input.usage()
        }
    } else {
        valid_usage(class, input.byte(8))
    };
    let wire_hash = match scenario {
        Scenario::Hash => input.byte(22),
        Scenario::HashMismatch => (hash + 1 + input.byte(22) % 3) % 4,
        _ => hash,
    };
    if wire_hash < 4 && wire_hash != hash {
        crypto = Err(TborStatus::RsaDecryptFailed);
    }
    Case {
        req: TborUnwrapKeyReq {
            session_id: if scenario == Scenario::Session {
                u16::from_le_bytes([input.byte(16), input.byte(17)])
            } else {
                session_id
            },
            scope,
            key_class: class,
            key_usage: usage,
            oaep_hash_algo: wire_hash,
            wrapped_blob: blob,
            key_label: input.bytes(label_len),
        },
        material,
        crypto,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Success,
    Reject(TborStatus),
    HostEncode,
}

/// Predict transport, schema, handler, crypto, then late masking-key failures.
fn expected(case: &Case, input: &Input<'_>, active: u16) -> Expected {
    let req = &case.req;
    let status = if input.scenario() == Scenario::ClosedSession {
        Some(TborStatus::SessionNotFound)
    } else if req.session_id != active {
        Some(TborStatus::FileHandleSessionIdDoesNotMatch)
    } else {
        None
    };
    if let Some(status) = status {
        return Expected::Reject(status);
    }
    let mut buf = [0; common::FUZZ_REQ_BUF_SIZE];
    if req.encode_request(&mut buf).is_err() {
        return Expected::HostEncode;
    }
    let status = if req.key_label.len() > TBOR_KEY_LABEL_MAX_LEN
        || req.wrapped_blob.len() > UNWRAP_WRAPPED_BLOB_MAX_LEN
    {
        Some(TborStatus::TborInvalidFixedLength)
    } else if req.oaep_hash_algo > HASH_ALGO_SHA512 {
        Some(TborStatus::InvalidArg)
    } else if req.key_class > KEY_CLASS_AES_XTS512 {
        Some(TborStatus::UnsupportedCmd)
    } else if !accepts_usage(req.key_class, req.key_usage) {
        Some(TborStatus::InvalidPermissions)
    } else if let Err(status) = case.crypto {
        Some(status)
    } else {
        match req.scope {
            common::KEY_SCOPE_SESSION => None,
            common::KEY_SCOPE_EPHEMERAL | common::KEY_SCOPE_LOCAL if input.byte(5) % 3 != 0 => None,
            common::KEY_SCOPE_SECURITY_DOMAIN if input.byte(5) % 3 == 2 => None,
            _ => Some(TborStatus::UnsupportedKeyScope),
        }
    };
    status.map_or(Expected::Success, Expected::Reject)
}

/// Check response semantics and authenticate the masked key using an existing consumer.
fn assert_success(ctx: &TestCtx, case: &Case) {
    let req = &case.req;
    let resp = ctx.tbor(req).expect("oracle-valid UnwrapKey must succeed");
    assert_eq!(resp.key_kind, case.material.kind, "recovered key kind");
    assert_eq!(
        resp.pub_key, case.material.public,
        "recovered wire public key"
    );
    assert!(!resp.masked_key.is_empty());
    assert!(resp.masked_key.len() <= UNWRAP_MASKED_KEY_MAX_LEN);
    let envelope = aead_envelope::inspect(&resp.masked_key).expect("masked envelope framing");
    assert_eq!(envelope.alg, aead_envelope::AeadAlg::AesGcm256);
    if case.material.public.is_empty() {
        assert_eq!(
            envelope.payload.len(),
            case.material.bytes.len().next_multiple_of(16),
            "symmetric key material length"
        );
    }
    ctx.tbor(&TborVerifyKeyReq {
        session_id: req.session_id,
        masked_key: resp.masked_key.clone(),
    })
    .expect("imported key must authenticate and unmask");
    if matches!(
        req.key_class,
        KEY_CLASS_HMAC_SHA256 | KEY_CLASS_HMAC_SHA384 | KEY_CLASS_HMAC_SHA512
    ) {
        let hash = match req.key_class {
            KEY_CLASS_HMAC_SHA256 => HASH_ALGO_SHA256,
            KEY_CLASS_HMAC_SHA384 => HASH_ALGO_SHA384,
            _ => HASH_ALGO_SHA512,
        };
        let key = HmacKey::from_bytes(&case.material.bytes).expect("host HMAC key");
        let tag = Signer::sign_vec(&mut HmacAlgo::new(host_hash(hash)), &key, &req.key_label)
            .expect("host HMAC oracle");
        let mac_req = TborHmacReq {
            session_id: req.session_id,
            masked_key: resp.masked_key,
            msg: req.key_label.clone(),
        };
        // Unwrap accepts nonempty HMAC material beyond Hmac's envelope bounds.
        if !(MASKED_HMAC_KEY_MIN_LEN..=MASKED_HMAC_KEY_MAX_LEN).contains(&mac_req.masked_key.len())
        {
            ctx.expect_fw_reject(&mac_req, TborStatus::TborInvalidFixedLength);
            return;
        }
        let actual = ctx
            .tbor(&mac_req)
            .expect("imported HMAC key must be usable");
        assert_eq!(actual.tag, tag, "unwrapped plaintext must match host key");
    }
}

/// Provision through CO, then switch roles on the same handle when requested.
fn setup<'ctx>(ctx: &'ctx TestCtx, input: &Input<'_>) -> SessionGuard<'ctx> {
    let co = SessionGuard::new(ctx, bootstrap_rotated_co(ctx, &ROTATED_CO_PSK));
    match input.byte(5) % 3 {
        1 => common::finalize_partition(ctx, co.handshake()),
        2 => common::create_test_security_domain(ctx, co.handshake()),
        _ => {}
    }
    let role = if input.byte(4) & 1 == 0 {
        common::FuzzRole::Co
    } else {
        common::FuzzRole::Cu
    };
    match role {
        common::FuzzRole::Co => co,
        common::FuzzRole::Cu => {
            co.close().expect("close provisioning CO session");
            SessionGuard::new(ctx, bootstrap_rotated_cu(ctx, &ROTATED_CU_PSK))
        }
    }
}

/// Execute one isolated case; late failures are repeated before a valid recovery probe.
fn run(input: &Input<'_>) {
    common::common_fuzz_test(&|ctx, _path| {
        let session = setup(ctx, input);
        let active = session.session_id();
        let public = ctx
            .tbor(&TborGetUnwrappingKeyReq { session_id: active })
            .expect("unwrapping key must be ready")
            .pub_key;
        let public = unwrapping_public(&public);
        let case = build_case(input, active, &public);
        let outcome = expected(&case, input, active);
        let session = if input.scenario() == Scenario::ClosedSession {
            session.close().expect("close before stale-session request");
            None
        } else {
            Some(session)
        };
        match outcome {
            Expected::Success => assert_success(ctx, &case),
            Expected::Reject(status) => {
                let repeats = if status == TborStatus::UnsupportedKeyScope {
                    2 + usize::from(input.byte(23) % 3)
                } else {
                    1
                };
                for _ in 0..repeats {
                    ctx.expect_fw_reject(&case.req, status);
                }
                if session.is_some() {
                    let mut probe = build_case(&Input(&[]), active, &public);
                    probe.req.scope = common::KEY_SCOPE_SESSION;
                    assert_success(ctx, &probe);
                }
            }
            Expected::HostEncode => {
                let result = ctx.tbor(&case.req);
                assert!(
                    matches!(result, Err(DdiError::TborEncodeError)),
                    "oversized transport request must fail host encoding"
                );
            }
        }
        if let Some(session) = session {
            session.close().expect("close caller session");
        }
    });
}

fuzz_target!(|data: &[u8]| {
    run(&Input(data));
});
