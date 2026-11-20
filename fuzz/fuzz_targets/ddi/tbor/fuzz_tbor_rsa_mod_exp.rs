// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::KeyScope;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::Encrypter;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaKeyOp;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_ddi_interface::DdiError;
use tsra_ddi_mbor_types::DdiStatus;
use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_types::codec::REQ_HEADER_LEN;
use tsra_ddi_tbor_types::codec::TOC_ENTRY_LEN;
use tsra_ddi_tbor_types::*;

/// MBOR key availability. TBOR key-import responses are masked blobs, not
/// persistent key IDs, so only session-scoped valid keys are generated
/// (mirrors `fuzz_tbor_ecc_sign`'s treatment of the same legacy field).
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

struct RawRsaModExpReq {
    session_id: u16,
    frame: Vec<u8>,
}

impl TborOpReq for RawRsaModExpReq {
    const OPCODE: u8 = TBOR_OP_RSA_MOD_EXP;
    type OpResp = TborRsaModExpResp;

    fn get_session_id(&self) -> Option<u16> {
        Some(self.session_id)
    }

    fn session_ctrl(&self) -> SessionControlKind {
        SessionControlKind::InSession
    }

    fn encode_request<'b>(
        &self,
        buf: &'b mut [u8],
        _api_rev: (u16, u16),
    ) -> Result<&'b [u8], tsra_ddi_tbor_types::codec::EncodeError> {
        let out = buf
            .get_mut(..self.frame.len())
            .ok_or(tsra_ddi_tbor_types::codec::EncodeError::BufferTooSmall)?;
        out.copy_from_slice(&self.frame);
        Ok(out)
    }
}

/// RSA modulus size for host-generated keys, mirroring the MBOR
/// `RsaKeySize` selector used to pick the modulus length (2048 / 3072 /
/// 4096 bits == 256 / 384 / 512 bytes).
#[derive(Arbitrary, Debug, Clone, Copy)]
enum RsaKeySize {
    Rsa2k,
    Rsa3k,
    Rsa4k,
}

impl RsaKeySize {
    fn modulus_bytes(self) -> usize {
        match self {
            Self::Rsa2k => 256,
            Self::Rsa3k => 384,
            Self::Rsa4k => 512,
        }
    }
}

/// TBOR `RsaModExp` `op_type` discriminant. `Unknown` carries a raw byte so
/// out-of-range discriminants are exercised too.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum RsaOpType {
    Sign,
    Decrypt,
    Encrypt,
    Verify,
    Unknown(u8),
}

impl RsaOpType {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Sign => RSA_OP_SIGN,
            Self::Decrypt => RSA_OP_DECRYPT,
            Self::Encrypt => RSA_OP_ENCRYPT,
            Self::Verify => RSA_OP_VERIFY,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Representative {
    Random,
    Zero,
    One,
    Two,
    NMinus2,
    NMinus1,
    N,
    NPlus1,
    Maximum,
}

/// Fuzzed fields corresponding to the MBOR `DdiRsaModExpReq` structure
/// (key id + op type); TBOR carries the masked key itself instead of a key
/// id, so `masked_key` substitutes for the legacy `key_id` field when a
/// valid key is not generated.
#[derive(Arbitrary, Debug)]
struct FuzzRsaModExpReq {
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
    /// The private-key operation requested of `RsaModExp`.
    op_type: RsaOpType,
}

/// Fuzz input corresponding to the MBOR `RsaModExp` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Seed for deterministic generation of the `y` operand.
    rand_seed: u64,
    /// If `true`, the fuzz test will generate a valid RSA key for modular
    /// exponentiation.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent, so only `Session` generates a valid key.
    key_availability: KeyAvailability,
    /// Size of the RSA key to generate.
    key_size: RsaKeySize,
    /// Scope requested for the imported RSA key.
    key_scope: KeyScope,
    /// Usage permissions requested for the imported RSA key.
    key_usage: u64,
    /// When set, import with the usage group required by the encoded selector.
    matching_usage: bool,
    /// Selects a public-operation representative, including modulus edges.
    representative: Representative,
    /// Also submit a raw frame with `y` shifted beyond the canonical data start.
    exercise_noncanonical_y: bool,
    /// Submit the operation with a session id that is not active.
    invalid_session: bool,
    /// Caller-supplied label for the imported RSA key.
    key_label: Vec<u8>,
    /// Selects the CRT vs non-CRT `KeyClass` used to import the generated
    /// key through `UnwrapKey`.
    crt: bool,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzRsaModExpReq,
}

/// `KeyScope::Session` discriminant — masked keys generated here only need
/// to outlive the fuzzed `RsaModExp` call.
/// `HashAlgo::Sha256` discriminant used to OAEP-wrap the KEK in `UnwrapKey`.
const RSA_OAEP_SHA256: u8 = 1;

/// Deterministic xorshift64* fill used to materialize the fuzzed `y`
/// operand from `rand_seed`, avoiding a dependency on the `rand` crate.
fn fill_rand(seed: u64, buf: &mut [u8]) {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn usage_for_operation(op_type: u8) -> Option<u64> {
    match op_type {
        RSA_OP_DECRYPT | RSA_OP_ENCRYPT => Some(KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT),
        RSA_OP_SIGN | RSA_OP_VERIFY => Some(KEY_USAGE_SIGN | KEY_USAGE_VERIFY),
        _ => None,
    }
}

fn is_expected_validation_error(error: &DdiError) -> bool {
    matches!(
        error,
        DdiError::TborStatus(status)
            if matches!(
                *status,
                TborStatus::InvalidArg
                    | TborStatus::InvalidPermissions
                    | TborStatus::InvalidKeyType
                    | TborStatus::UnsupportedKeyScope
                    | TborStatus::SessionNotFound
                    | TborStatus::FileHandleSessionIdDoesNotMatch
                    | TborStatus::InvalidSessionControlOpcode
                    | TborStatus::TborInvalidFixedLength
                    | TborStatus::MaskedKeyDecodeFailed
                    | TborStatus::AesGcmDecryptTagDoesNotMatch
            )
    ) || matches!(
        error,
        DdiError::DdiStatus(
            DdiStatus::SessionNotFound | DdiStatus::FileHandleSessionIdDoesNotMatch
        )
    ) || matches!(
        error,
        DdiError::TborEncodeError | DdiError::InvalidParameter
    )
}

fn representative_operand(
    public_key: &RsaPublicKey,
    modulus_len: usize,
    representative: Representative,
    seed: u64,
    public_operation: bool,
) -> (Vec<u8>, bool) {
    let mut n = vec![0u8; modulus_len];
    public_key
        .n(Some(&mut n))
        .expect("read generated RSA modulus");
    let mut value = vec![0u8; modulus_len];
    match representative {
        Representative::Random => {
            fill_rand(seed, &mut value);
            value[0] = 1;
        }
        Representative::Zero => {}
        Representative::One => value[modulus_len - 1] = 1,
        Representative::Two => value[modulus_len - 1] = 2,
        Representative::NMinus2 => {
            value.copy_from_slice(&n);
            subtract_one(&mut value);
            subtract_one(&mut value);
        }
        Representative::NMinus1 => {
            value.copy_from_slice(&n);
            subtract_one(&mut value);
        }
        Representative::N => value.copy_from_slice(&n),
        Representative::NPlus1 => {
            value.copy_from_slice(&n);
            add_one(&mut value);
        }
        Representative::Maximum => value.fill(0xFF),
    }
    let less_than_modulus = value.as_slice() < n.as_slice();
    let valid = if public_operation {
        less_than_modulus
    } else {
        let greater_than_one =
            value[..modulus_len - 1].iter().any(|&byte| byte != 0) || value[modulus_len - 1] > 1;
        let mut private_upper_bound = n.clone();
        subtract_one(&mut private_upper_bound);
        greater_than_one && value.as_slice() < private_upper_bound.as_slice()
    };
    (dev_rev(&value), valid)
}

fn subtract_one(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xFF;
        } else {
            *byte -= 1;
            break;
        }
    }
}

fn add_one(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn shift_y_past_canonical_data(req: &TborRsaModExpReq, api_rev: (u16, u16)) -> Vec<u8> {
    let mut storage = [0u8; 4096];
    let mut frame = req
        .encode_request(&mut storage, api_rev)
        .expect("valid RSA request must encode")
        .to_vec();
    let data_start = RequestView::parse(&frame)
        .expect("encoded RSA request must parse")
        .data_start();

    for toc_index in [1, 2, 3] {
        let entry_start = REQ_HEADER_LEN + toc_index * TOC_ENTRY_LEN;
        let word = u32::from_be_bytes(
            frame[entry_start..entry_start + TOC_ENTRY_LEN]
                .try_into()
                .expect("TOC entry is four bytes"),
        );
        let kind = word & 0xFC00_0000;
        let payload = word & 0x03FF_FFFF;
        let length = payload >> 13;
        let offset = payload & 0x1FFF;
        let shifted = kind | (length << 13) | (offset + 4);
        frame[entry_start..entry_start + TOC_ENTRY_LEN].copy_from_slice(&shifted.to_be_bytes());
    }

    frame.splice(data_start..data_start, [0; 4]);
    frame
}

/// Generate a host RSA private key of `modulus_bytes`, import it on-device
/// via `UnwrapKey` under the given CRT / non-CRT class and usage, and
/// return the resulting masked key and public key. Mirrors `import_rsa_key` in
/// `fuzz_tbor_attest_key`, generalized over modulus size, key class, and
/// key usage.
fn import_rsa_key(
    ctx: &TestCtx,
    session_id: u16,
    modulus_bytes: usize,
    crt: bool,
    scope: u8,
    key_usage: u64,
    key_label: &[u8],
) -> Result<(Vec<u8>, RsaPublicKey), DdiError> {
    let key = RsaPrivateKey::generate(modulus_bytes).expect("generate host RSA key");
    let imported_public_key = key.public_key().expect("derive host RSA public key");
    let private_der = key.to_vec().expect("export host RSA private key");
    let unwrapping_key = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("get built-in unwrapping public key")
        .pub_key;

    // Convert each device-order integer to big-endian; the built-in
    // unwrapping key is fixed at RSA-2048 regardless of the imported size.
    assert_eq!(
        unwrapping_key.len(),
        260,
        "built-in unwrapping key is a fixed-size RSA-2048 (n(256) ‖ e(4))",
    );
    let mut public_key_be = Vec::with_capacity(unwrapping_key.len());
    public_key_be.extend(dev_rev(&unwrapping_key[..256]));
    public_key_be.extend(dev_rev(&unwrapping_key[256..]));
    let unwrapping_public_key =
        RsaPublicKey::from_hsm_bytes(&public_key_be).expect("parse unwrapping public key");

    let kek = [0xA7u8; 32];
    let mut encrypted_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &unwrapping_public_key,
        &kek,
    )
    .expect("RSA-OAEP wrap AES key");
    encrypted_kek = dev_rev(&encrypted_kek);

    let kek = AesKey::from_bytes(&kek).expect("construct AES key-encryption key");
    let encrypted_private_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &private_der)
            .expect("AES-KWP wrap RSA private key");
    let mut wrapped_blob = encrypted_kek;
    wrapped_blob.extend(encrypted_private_key);

    let key_class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };

    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope,
        key_class,
        key_usage,
        oaep_hash_algo: RSA_OAEP_SHA256,
        wrapped_blob,
        key_label: key_label.to_vec(),
    })
    .map(|resp| (resp.masked_key, imported_public_key))
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let op_type = input.cmdreq_data.op_type.to_tbor();
        let request_session_id = if input.invalid_session {
            u16::MAX
        } else {
            session.session_id
        };
        let requested_usage = if input.matching_usage {
            usage_for_operation(op_type).unwrap_or(input.key_usage)
        } else {
            input.key_usage
        };
        let public_operation = matches!(op_type, RSA_OP_ENCRYPT | RSA_OP_VERIFY);
        let scope = input.key_scope.to_tbor();
        let mut import_succeeded = false;
        let mut host_public_key = None;
        let (masked_key, modulus_len) = if generate_valid_key {
            match input.key_scope {
                KeyScope::SecurityDomain => common::create_test_security_domain(ctx, &session),
                _ => common::finalize_partition(ctx, &session),
            }
            let modulus_len = input.key_size.modulus_bytes();
            match import_rsa_key(
                ctx,
                session.session_id,
                modulus_len,
                input.crt,
                scope,
                requested_usage,
                &input.key_label,
            ) {
                Ok((masked_key, public_key)) => {
                    import_succeeded = true;
                    host_public_key = Some(public_key);
                    (masked_key, Some(modulus_len))
                }
                Err(err @ DdiError::DriverError(_)) => panic!("Crash Detected: {err}"),
                Err(err) if !is_expected_validation_error(&err) => {
                    panic!("unexpected RSA key-import failure: {err}")
                }
                Err(_) => (input.cmdreq_data.masked_key.clone(), None),
            }
        } else {
            (input.cmdreq_data.masked_key.clone(), None)
        };

        let mut y = vec![0u8; modulus_len.unwrap_or(RSA_MOD_EXP_MAX_LEN)];
        fill_rand(input.rand_seed, &mut y);
        let mut representative_valid = true;
        if let (Some(k), Some(public_key)) = (modulus_len, host_public_key.as_ref()) {
            let (operand, valid) = representative_operand(
                public_key,
                k,
                input.representative,
                input.rand_seed,
                public_operation,
            );
            y = operand;
            representative_valid = valid;
        }

        // Classify by encoded selector so Unknown(3) / Unknown(4) aliases
        // follow the newly supported operations.
        let known_usage = requested_usage
            & (KEY_USAGE_ENCRYPT
                | KEY_USAGE_DECRYPT
                | KEY_USAGE_SIGN
                | KEY_USAGE_VERIFY
                | KEY_USAGE_DERIVE
                | KEY_USAGE_WRAP
                | KEY_USAGE_UNWRAP);
        let valid_rsa_usage = known_usage == (KEY_USAGE_SIGN | KEY_USAGE_VERIFY)
            || known_usage == (KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT);
        let import_expected_success = matches!(
            input.key_scope,
            KeyScope::Session | KeyScope::Ephemeral | KeyScope::Local | KeyScope::SecurityDomain
        ) && valid_rsa_usage
            && input.key_label.len() <= TBOR_KEY_LABEL_MAX_LEN;
        if generate_valid_key && import_succeeded != import_expected_success {
            panic!(
                "UnwrapKey import success mismatch: expected {import_expected_success}, got {import_succeeded}"
            );
        }

        let op_usage_matches =
            usage_for_operation(op_type).is_some_and(|required| known_usage == required);
        let expect_success = generate_valid_key
            && import_succeeded
            && op_usage_matches
            && modulus_len == Some(y.len())
            && !input.invalid_session
            && representative_valid;

        let req = TborRsaModExpReq {
            session_id: request_session_id,
            masked_key,
            op_type,
            y,
        };

        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                let k = modulus_len.expect("a successful request has a known modulus length");
                assert_eq!(
                    resp.x.len(),
                    k,
                    "result length must match the key's modulus length",
                );
                if public_operation {
                    let input_be = dev_rev(&req.y);
                    let expected_be = Encrypter::encrypt_vec(
                        &mut RsaEncryptAlgo::with_no_padding(),
                        host_public_key
                            .as_ref()
                            .expect("successful public operation has host key"),
                        &input_be,
                    )
                    .expect("host raw RSA public-operation oracle");
                    assert_eq!(resp.x, dev_rev(&expected_be));
                }
            }
            (Ok(_), false) => panic!("invalid RsaModExp request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid RsaModExp request failed: {err}"),
            // Host encoding failures never reach the device's session policy.
            (Err(DdiError::TborEncodeError), false) => {}
            (Err(err), false) if input.invalid_session => {
                ctx.assert_unknown_session_rejects(err, TborStatus::SessionNotFound);
            }
            (Err(err), false) if is_expected_validation_error(err) => {}
            (Err(err), false) => panic!("unexpected RsaModExp failure: {err:?}"),
        }

        if input.exercise_noncanonical_y
            && generate_valid_key
            && import_succeeded
            && op_usage_matches
            && !input.invalid_session
            && modulus_len == Some(req.y.len())
        {
            let raw = RawRsaModExpReq {
                session_id: request_session_id,
                frame: shift_y_past_canonical_data(
                    &req,
                    if ctx.is_duo() { (2, 0) } else { (1, 1) },
                ),
            };
            match ctx.tbor(&raw) {
                Err(DdiError::TborStatus(TborStatus::TborNonCanonicalLayout)) => {}
                Err(err) => panic!("unexpected noncanonical-layout result: {err}"),
                Ok(_) => panic!("RsaModExp accepted noncanonical y placement"),
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
