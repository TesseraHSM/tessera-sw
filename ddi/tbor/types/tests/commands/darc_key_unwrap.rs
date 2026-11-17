// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcKeyUnwrap` command.
//!
//! `DarcKeyUnwrap` imports an externally-generated EC private key —
//! encoded as an EC2 `COSE_Key` and AES-KWP-wrapped under a DARC Transfer
//! Masking Key (TMK) — and returns it re-masked under a caller-chosen
//! partition scope (`Ephemeral` / `Local`).  The TMK is supplied as the
//! masked envelope produced by `DarcTmkImport`.
//!
//! The **round-trip** test mirrors the real flow end to end: it finalizes
//! a partition, initializes its security domain, and imports a known TMK
//! (`DarcTmkImport`); then — entirely on the host with `tsra_crypto` —
//! it mints an EC private key, encodes it as an EC2 `COSE_Key`,
//! AES-KWP-wraps it under that same TMK, and imports it.
//!
//! Coverage:
//! * Round-trip (`Local` and `Ephemeral` scope) — the imported key comes
//!   back as a non-zero masked envelope plus the wire public key that the
//!   device re-derived and consistency-checked against the COSE `x`/`y`.
//! * Tampered `wrapped_key` (AES-KWP AIV/tag fails) → `AesUnwrapFailed`.
//! * A `key_usage` the COSE `key_ops` does not grant → `InvalidPermissions`.
//! * An unsupported output scope (`SecurityDomain`) → `UnsupportedKeyScope`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).
//! * Extra Ephemeral P-384/P-521 success cases and single-operation rejection cases.
//! * Mismatched `y` and `d`, wrong wrapping TMK, ciphertext corruption at
//!   multiple offsets, and two distinct keys sharing one imported TMK.

use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::Encrypter;
use tsra_crypto::ImportableKey;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::wire_coord_len;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcKeyUnwrapReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::DARC_UNWRAP_MASKED_KEY_MAX_LEN;
use tsra_ddi_tbor_types::KEY_SCOPE_EPHEMERAL;
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;
use tsra_ddi_tbor_types::KEY_USAGE_DERIVE;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;

use crate::commands::common::assert_masked_key_layout_rejected;
use crate::commands::darc_tmk_import::build_valid_import;
use crate::commands::darc_tmk_import::sd_initialized_session;
use crate::commands::darc_tmk_import::SdReady;

/// The raw TMK imported by the harness `DarcTmkImport` — the same key
/// material the host uses to AES-KWP-wrap the `COSE_Key`.
const TMK: [u8; TMK_LEN] = [0x5Au8; TMK_LEN];

/// COSE `key_ops` value: create a signature.
const KEY_OP_CREATE_SIGNATURE: u8 = 1;
/// COSE `key_ops` value: verify a signature.
const KEY_OP_VERIFY_SIGNATURE: u8 = 2;
/// COSE `key_ops` value: derive a key.
const KEY_OP_DERIVE_KEY: u8 = 7;

/// COSE per-curve parameters: `(crv id, alg id, raw field width, wire
/// coordinate width)`.  `alg` is any non-deprecated identifier (the ESP*
/// codes); the handler only rejects the deprecated ES* ones.
fn curve_params(curve: EccCurve) -> (i32, i32, usize, usize) {
    match curve {
        EccCurve::P256 => (1, -9, 32, 32),
        EccCurve::P384 => (2, -51, 48, 48),
        EccCurve::P521 => (3, -52, 66, wire_coord_len(66)),
    }
}

/// A masked TMK envelope (from a real `DarcTmkImport`) plus the raw TMK
/// bytes the host wrapped the `COSE_Key` under.
fn masked_tmk(ready: &SdReady) -> [u8; MASKED_TMK_LEN] {
    let (req, chain) = build_valid_import(ready, &ready.pota, &TMK);
    let resp = ready
        .ctx
        .tbor_oob(&req, &chain.der_items())
        .expect("DarcTmkImport");
    resp.masked_tmk
        .as_slice()
        .try_into()
        .expect("masked TMK length")
}

/// A freshly generated EC key on `curve` with a fixed small private
/// scalar, plus its big-endian `x`/`y`/`d` field elements (each the
/// curve's raw field width).
struct HostEcKey {
    curve: EccCurve,
    d: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

/// Mint an EC key from a fixed, valid scalar and export its big-endian
/// coordinates — the material the `COSE_Key` carries and the device
/// re-derives to enforce private/public consistency.
fn host_ec_key(curve: EccCurve) -> HostEcKey {
    let (_, _, field, _) = curve_params(curve);
    // A small, unambiguously-in-range scalar valid on every curve.
    let mut d = vec![0u8; field];
    d[field - 2] = 0x12;
    d[field - 1] = 0x34;
    let sk = EccPrivateKey::from_scalar(curve, &d).expect("valid scalar");
    let (x, y) = sk.coord_vec().expect("public coords");
    HostEcKey { curve, d, x, y }
}

/// Encode an EC2 **private** `COSE_Key` for `key` with the given
/// `key_ops`, matching the firmware `cose-key` wire shape.
#[allow(clippy::unwrap_used)]
fn encode_cose(key: &HostEcKey, key_ops: &[u8]) -> Vec<u8> {
    let (crv, alg, _, _) = curve_params(key.curve);
    let mut buf = [0u8; 512];
    let cap = buf.len();
    let mut enc = minicbor::Encoder::new(&mut buf[..]);
    enc.map(8).unwrap();
    enc.i32(1).unwrap().u8(2).unwrap(); // kty: EC2
    enc.i32(2).unwrap().bytes(b"kid-1").unwrap(); // kid
    enc.i32(3).unwrap().i32(alg).unwrap(); // alg (non-deprecated)
    enc.i32(4).unwrap().array(key_ops.len() as u64).unwrap(); // key_ops
    for &op in key_ops {
        enc.u8(op).unwrap();
    }
    enc.i32(-1).unwrap().i32(crv).unwrap(); // crv
    enc.i32(-2).unwrap().bytes(&key.x).unwrap();
    enc.i32(-3).unwrap().bytes(&key.y).unwrap();
    enc.i32(-4).unwrap().bytes(&key.d).unwrap();
    let used = cap - enc.writer().len();
    buf[..used].to_vec()
}

/// AES-KWP-wrap `plaintext` under the raw `tmk`.
fn kwp_wrap(tmk: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let kek = AesKey::from_bytes(tmk).expect("import TMK as AES key");
    let mut kwp = AesKeyWrapPadAlgo::default();
    Encrypter::encrypt_vec(&mut kwp, &kek, plaintext).expect("AES-KWP wrap")
}

/// Assemble a `DarcKeyUnwrap` request from `ready`, an imported TMK, and a
/// (possibly tampered) `COSE_Key`.
fn unwrap_req(
    ready: &SdReady,
    scope: u8,
    key_usage: u64,
    key: &HostEcKey,
    key_ops: &[u8],
) -> TborDarcKeyUnwrapReq {
    let tmk = masked_tmk(ready);
    let cose = encode_cose(key, key_ops);
    let wrapped_key = kwp_wrap(&TMK, &cose);
    TborDarcKeyUnwrapReq {
        session_id: ready.session.session_id,
        scope,
        key_usage,
        masked_tmk: tmk,
        wrapped_key,
    }
}

/// Build a fully valid `DarcKeyUnwrap` request on `curve`: import a TMK,
/// mint + COSE-encode an EC key, and wrap it under that TMK.
fn build_valid_unwrap(
    ready: &SdReady,
    scope: u8,
    key_usage: u64,
    key_ops: &[u8],
    curve: EccCurve,
) -> (TborDarcKeyUnwrapReq, HostEcKey) {
    let key = host_ec_key(curve);
    let req = unwrap_req(ready, scope, key_usage, &key, key_ops);
    (req, key)
}

/// The expected wire public key (`x ‖ y` in device byte order, each
/// zero-padded to the curve's wire coordinate width) the device returns.
fn expected_wire_pub(key: &HostEcKey) -> Vec<u8> {
    let (_, _, _, wire) = curve_params(key.curve);
    let mut out = Vec::with_capacity(2 * wire);
    for coord in [&key.x, &key.y] {
        let mut dev = dev_rev(coord);
        dev.resize(wire, 0);
        out.extend_from_slice(&dev);
    }
    out
}

/// Imports a P-256 key into Local scope and verifies its public key and fresh masking.
#[test]
fn darc_key_unwrap_roundtrip_local() {
    let ready = sd_initialized_session();
    let (req, key) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    let resp = ready.ctx.tbor(&req).expect("DarcKeyUnwrap roundtrip");

    // A P-256 private key comes back masked and non-empty, with its
    // device-re-derived wire public key matching the COSE coordinates.
    assert_ne!(
        resp.key_kind, 0,
        "key_kind must identify an ECC private key"
    );
    assert!(
        !resp.masked_key.is_empty() && resp.masked_key.len() <= DARC_UNWRAP_MASKED_KEY_MAX_LEN,
        "masked_key must be a non-empty envelope within the wire max",
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    assert_eq!(resp.pub_key, expected_wire_pub(&key));

    // A second import yields a fresh masked envelope (new masking IV).
    let resp2 = ready.ctx.tbor(&req).expect("second DarcKeyUnwrap");
    assert_ne!(
        resp.masked_key, resp2.masked_key,
        "each import must yield a fresh masked envelope",
    );
}

/// Imports a P-256 key into Ephemeral scope and verifies the returned key material.
#[test]
fn darc_key_unwrap_roundtrip_ephemeral() {
    let ready = sd_initialized_session();
    let (req, key) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_EPHEMERAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    let resp = ready
        .ctx
        .tbor(&req)
        .expect("DarcKeyUnwrap ephemeral roundtrip");
    assert_eq!(resp.pub_key, expected_wire_pub(&key));
    assert!(resp.masked_key.iter().any(|&b| b != 0));
}

/// Round-trip an EC key on `curve` and assert the device returns a
/// non-empty masked envelope plus the expected wire public key.
fn assert_roundtrip_on(curve: EccCurve) {
    let ready = sd_initialized_session();
    let (req, key) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        curve,
    );

    let resp = ready.ctx.tbor(&req).expect("DarcKeyUnwrap roundtrip");
    assert_ne!(
        resp.key_kind, 0,
        "key_kind must identify an ECC private key"
    );
    assert!(
        !resp.masked_key.is_empty() && resp.masked_key.len() <= DARC_UNWRAP_MASKED_KEY_MAX_LEN,
        "masked_key must be a non-empty envelope within the wire max",
    );
    assert!(resp.masked_key.iter().any(|&b| b != 0));
    // Exercises the curve's wire padding (P-521: 66-byte coords padded to 68).
    assert_eq!(resp.pub_key, expected_wire_pub(&key));
}

/// Imports a P-384 key and checks its re-derived public coordinates.
#[test]
fn darc_key_unwrap_roundtrip_p384() {
    assert_roundtrip_on(EccCurve::P384);
}

/// Imports a P-521 key and validates padded wire-format public coordinates.
#[test]
fn darc_key_unwrap_roundtrip_p521() {
    assert_roundtrip_on(EccCurve::P521);
}

/// Imports a derive-only P-256 private key with matching COSE permissions.
#[test]
fn darc_key_unwrap_roundtrip_derive_usage() {
    let ready = sd_initialized_session();
    // A derive-only key: the COSE `key_ops` grants derivation and the
    // request asks for `derive`, so the effective usage is non-empty and
    // the key imports as a derive-capable ECC private key.
    let (req, key) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_DERIVE,
        &[KEY_OP_DERIVE_KEY],
        EccCurve::P256,
    );

    let resp = ready
        .ctx
        .tbor(&req)
        .expect("DarcKeyUnwrap derive-usage roundtrip");
    assert_ne!(resp.key_kind, 0);
    assert!(resp.masked_key.iter().any(|&b| b != 0));
    assert_eq!(resp.pub_key, expected_wire_pub(&key));
}

/// Rejects a COSE key whose x coordinate disagrees with its private scalar.
#[test]
fn darc_key_unwrap_rejects_mismatched_public_key() {
    let ready = sd_initialized_session();
    // A COSE key whose `x` coordinate does not correspond to `d·G`. The
    // parser only checks field widths, so the tampered key decodes; the
    // handler re-derives the public key from `d` and rejects the mismatch.
    let mut key = host_ec_key(EccCurve::P256);
    key.x[0] ^= 0x01;
    let req = unwrap_req(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &key,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
    );

    ready.ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects AES-KWP ciphertext corrupted at the final byte.
#[test]
fn darc_key_unwrap_rejects_tampered_wrapped_key() {
    let ready = sd_initialized_session();
    let (mut req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    // Flip a ciphertext byte: AES-KWP's AIV / pad check fails on unwrap.
    let last = req.wrapped_key.len() - 1;
    req.wrapped_key[last] ^= 0xFF;

    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::AesUnwrapFailed);
}

/// Rejects requested derivation when COSE permissions grant signing only.
#[test]
fn darc_key_unwrap_rejects_usage_not_granted() {
    let ready = sd_initialized_session();
    // Request `derive` but the COSE key only grants signing → the
    // intersection is empty and the handler rejects it.
    let (req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_DERIVE,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

/// Rejects SecurityDomain as an unsupported destination scope.
#[test]
fn darc_key_unwrap_rejects_unsupported_scope() {
    let ready = sd_initialized_session();
    // `SecurityDomain` (0b100) is not a permitted output scope for an
    // imported key.
    let (req, _) = build_valid_unwrap(
        &ready,
        0b100,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
}

/// A dummy well-formed request whose crypto inputs never get exercised —
/// used by gating tests that must fail at the session/lifecycle gate
/// before any crypto work.
fn dummy_req(session_id: u16) -> TborDarcKeyUnwrapReq {
    TborDarcKeyUnwrapReq {
        session_id,
        scope: KEY_SCOPE_LOCAL,
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        masked_tmk: [0u8; MASKED_TMK_LEN],
        wrapped_key: alloc_wrapped_stub(),
    }
}

/// A minimal (well-formed-length) wrapped-key placeholder — one AES block
/// past the AES-KWP minimum so the request decodes past the FW schema's
/// length checks; these tests fail earlier, at the session gate.
fn alloc_wrapped_stub() -> Vec<u8> {
    vec![0u8; 24]
}

/// Rejects key unwrapping before partition finalization.
#[test]
fn darc_key_unwrap_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not Initialized, so the command is rejected at the lifecycle gate
    // before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

/// Rejects a Crypto-User session for this Crypto-Officer-only command.
#[test]
fn darc_key_unwrap_rejected_on_cu_session() {
    // DarcKeyUnwrap is Crypto-Officer-only: a CU session is rejected at
    // the role gate before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

/// Rejects unwrapping while the default CO PSK is still in use.
#[test]
fn darc_key_unwrap_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the
    // dispatcher's default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let mut req = dummy_req(session.session_id());
    req.session_id = session.session_id();
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Rejects a misaligned masked TMK and one without its padding entry.
#[test]
fn darc_key_unwrap_rejects_bad_masked_key_layout() {
    let ready = sd_initialized_session();
    let (req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    assert_masked_key_layout_rejected(&ready.ctx, &req);
}

// -----------------------------------------------------------------------------
// Additional coverage: scope/curve combinations, permission subsets, independent
// key material, and authenticated-wrapping / EC consistency failures.
// -----------------------------------------------------------------------------

/// Keep the same response checks across the additional supported combinations.
fn assert_unwrap_roundtrip_for_scope(curve: EccCurve, scope: u8) {
    let ready = sd_initialized_session();
    let (req, key) = build_valid_unwrap(
        &ready,
        scope,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        curve,
    );
    let resp = ready
        .ctx
        .tbor(&req)
        .expect("DarcKeyUnwrap scope/curve roundtrip");
    assert_ne!(resp.key_kind, 0);
    assert!(!resp.masked_key.is_empty());
    assert!(resp.masked_key.len() <= DARC_UNWRAP_MASKED_KEY_MAX_LEN);
    assert!(resp.masked_key.iter().any(|&b| b != 0));
    assert_eq!(resp.pub_key, expected_wire_pub(&key));
}

/// Imports P-384 into Ephemeral scope and verifies the returned public key.
#[test]
fn darc_key_unwrap_roundtrip_ephemeral_p384() {
    assert_unwrap_roundtrip_for_scope(EccCurve::P384, KEY_SCOPE_EPHEMERAL);
}

/// Imports P-521 into Ephemeral scope and checks padded public coordinates.
#[test]
fn darc_key_unwrap_roundtrip_ephemeral_p521() {
    // Also checks the 66-byte P-521 coordinates in the 68-byte wire slots.
    assert_unwrap_roundtrip_for_scope(EccCurve::P521, KEY_SCOPE_EPHEMERAL);
}

/// Rejects a COSE key whose y coordinate disagrees with its private scalar.
#[test]
fn darc_key_unwrap_rejects_mismatched_y_coordinate() {
    let ready = sd_initialized_session();
    let mut key = host_ec_key(EccCurve::P256);
    // A valid-length COSE key still has to agree with d * G in BOTH axes.
    key.y[0] ^= 0x01;
    let req = unwrap_req(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &key,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
    );
    ready.ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects a valid private scalar inconsistent with the supplied public point.
#[test]
fn darc_key_unwrap_rejects_mismatched_private_scalar() {
    let ready = sd_initialized_session();
    let mut key = host_ec_key(EccCurve::P256);
    // d=0x1235 is valid, but x/y still describe d=0x1234.
    // This distinguishes a key-consistency failure from an invalid scalar.
    let last = key.d.len() - 1;
    key.d[last] ^= 0x01;
    let req = unwrap_req(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &key,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
    );
    ready.ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects a COSE key wrapped under a different TMK.
#[test]
fn darc_key_unwrap_rejects_wrong_wrapping_tmk() {
    let ready = sd_initialized_session();
    let (mut req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    // The masked TMK is valid, but the COSE key was wrapped under another
    // same-length AES key; the device must reject AES-KWP authentication.
    let key = host_ec_key(EccCurve::P256);
    let wrong_tmk = [0xA5u8; TMK_LEN];
    req.wrapped_key = kwp_wrap(
        &wrong_tmk,
        &encode_cose(&key, &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE]),
    );
    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::AesUnwrapFailed);
}

/// Rejects AES-KWP ciphertext corrupted at the first byte.
#[test]
fn darc_key_unwrap_rejects_tampered_wrapped_key_first_byte() {
    let ready = sd_initialized_session();
    let (mut req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    req.wrapped_key[0] ^= 0x80;
    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::AesUnwrapFailed);
}

/// Rejects AES-KWP ciphertext corrupted in the middle.
#[test]
fn darc_key_unwrap_rejects_tampered_wrapped_key_middle() {
    let ready = sd_initialized_session();
    let (mut req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    let middle = req.wrapped_key.len() / 2;
    req.wrapped_key[middle] ^= 0x40;
    ready
        .ctx
        .expect_fw_reject(&req, TborStatus::AesUnwrapFailed);
}

/// Imports two distinct EC keys using the same masked TMK envelope.
#[test]
fn darc_key_unwrap_two_distinct_keys_same_tmk() {
    let ready = sd_initialized_session();
    let (req1, key1) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );

    // Reuse the same imported TMK envelope, but wrap a second valid key.
    let mut d2 = key1.d.clone();
    let last = d2.len() - 1;
    d2[last] ^= 0x01; // 0x1235, still valid on P-256
    let sk2 = EccPrivateKey::from_scalar(EccCurve::P256, &d2).expect("second valid scalar");
    let (x2, y2) = sk2.coord_vec().expect("second public coordinates");
    let key2 = HostEcKey {
        curve: EccCurve::P256,
        d: d2,
        x: x2,
        y: y2,
    };
    let req2 = TborDarcKeyUnwrapReq {
        session_id: req1.session_id,
        scope: req1.scope,
        key_usage: req1.key_usage,
        masked_tmk: req1.masked_tmk,
        wrapped_key: kwp_wrap(
            &TMK,
            &encode_cose(&key2, &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE]),
        ),
    };
    let resp1 = ready.ctx.tbor(&req1).expect("first import");
    let resp2 = ready.ctx.tbor(&req2).expect("second import using same TMK");
    assert_eq!(resp1.pub_key, expected_wire_pub(&key1));
    assert_eq!(resp2.pub_key, expected_wire_pub(&key2));
    assert_ne!(resp1.pub_key, resp2.pub_key);
    assert_ne!(resp1.masked_key, resp2.masked_key);
}

// -----------------------------------------------------------------------------
// Additional coverage: independent operations and TMK reuse across scopes.
// -----------------------------------------------------------------------------

/// Rejects importing a signing-only P-256 private key under current firmware rules.
#[test]
fn darc_key_unwrap_rejects_sign_only() {
    let ready = sd_initialized_session();
    let (req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN,
        &[KEY_OP_CREATE_SIGNATURE],
        EccCurve::P256,
    );
    assert!(
        ready.ctx.tbor(&req).is_err(),
        "sign-only import must be rejected"
    );
}

/// Rejects importing a verification-only P-256 private key under current firmware rules.
#[test]
fn darc_key_unwrap_rejects_verify_only() {
    let ready = sd_initialized_session();
    let (req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_VERIFY,
        &[KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    assert!(
        ready.ctx.tbor(&req).is_err(),
        "verify-only import must be rejected"
    );
}

/// Rejects signing-only requested usage even when COSE grants signing and verification.
#[test]
fn darc_key_unwrap_rejects_requested_usage_subset() {
    let ready = sd_initialized_session();
    let (req, _) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    assert!(
        ready.ctx.tbor(&req).is_err(),
        "subset-permission import must be rejected"
    );
}

/// Reuses one imported TMK to unwrap the same EC key into both permitted scopes.
#[test]
fn darc_key_unwrap_same_tmk_local_and_ephemeral() {
    let ready = sd_initialized_session();
    let (local_req, key) = build_valid_unwrap(
        &ready,
        KEY_SCOPE_LOCAL,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &[KEY_OP_CREATE_SIGNATURE, KEY_OP_VERIFY_SIGNATURE],
        EccCurve::P256,
    );
    let mut ephemeral_req = local_req.clone();
    ephemeral_req.scope = KEY_SCOPE_EPHEMERAL;

    let local = ready.ctx.tbor(&local_req).expect("Local key import");
    let ephemeral = ready
        .ctx
        .tbor(&ephemeral_req)
        .expect("Ephemeral key import");
    let expected = expected_wire_pub(&key);
    assert_eq!(local.pub_key, expected);
    assert_eq!(ephemeral.pub_key, expected);
    assert!(!local.masked_key.is_empty());
    assert!(!ephemeral.masked_key.is_empty());
    assert_ne!(local.masked_key, ephemeral.masked_key);
}
