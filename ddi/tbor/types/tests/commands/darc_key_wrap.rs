// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `DarcKeyWrap` command.
//!
//! `DarcKeyWrap` is the source-side mirror of `DarcKeyUnwrap`: it exports
//! a local masked EC private key by re-encoding it as an EC2 `COSE_Key`
//! and AES-KWP-wrapping it under a DARC Transfer Masking Key (TMK).  The
//! resulting `wrapped_key` is byte-compatible with what `DarcKeyUnwrap`
//! consumes.
//!
//! Coverage:
//! * Wrap → unwrap round-trip on every curve (P-256/384/521) under a
//!   single generated TMK: the key the device re-derives on unwrap matches
//!   the original public key, and the recovered key signs (host-verified).
//! * Grand end-to-end: `DarcTmkGen` → `EccGenerateKey` → `DarcKeyWrap`
//!   (under the generated TMK) → `DarcTmkExport` → `DarcTmkImport` →
//!   `DarcKeyUnwrap` (under the round-tripped TMK) → `EccSign` — proving a
//!   key wrapped on a source device can be unwrapped and used on a target
//!   that received the TMK over the DARC export/import hand-off.
//! * Wrong masked-TMK kind (an EC key) → `UnsupportedKeyType`.
//! * Wrong masked-key kind (a TMK) → `UnsupportedKeyType`.
//! * Before SD init → `InvalidArg`; before finalize → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

#![cfg(feature = "emu")]

use tsra_crypto::EccAlgo;
use tsra_crypto::EccPublicKey;
use tsra_crypto::Verifier;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborDarcKeyUnwrapReq;
use tsra_ddi_tbor_types::TborDarcKeyWrapReq;
use tsra_ddi_tbor_types::TborDarcTmkGenReq;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::KEY_SCOPE_LOCAL;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_ddi_tbor_types::TMK_LEN;

use crate::commands::darc_tmk_export::build_valid_export;
use crate::commands::darc_tmk_export::gen_masked_tmk;
use crate::commands::darc_tmk_export::mint_kex;
use crate::commands::darc_tmk_export::reimport;
use crate::commands::darc_tmk_export::sd_initialized_session_with_data;
use crate::commands::darc_tmk_import::build_valid_import;
use crate::commands::darc_tmk_import::sd_initialized_session;

/// `KeyScope::Local` discriminant for `EccGenerateKey`.
const SCOPE_LOCAL: u8 = 0b011;

/// A raw TMK imported by `DarcTmkImport` for the wrong-kind negatives.
const TMK: [u8; TMK_LEN] = [0x5Au8; TMK_LEN];

/// Per-curve wire sizes: `(wire_coord_len, raw_coord_len)`.
fn coord_sizes(pub_len: usize) -> (usize, usize) {
    match pub_len {
        64 => (32, 32),
        96 => (48, 48),
        136 => (68, 66),
        _ => panic!("unexpected public-key length {pub_len}"),
    }
}

/// Reverse the low `len` bytes of `src` into a fresh big-endian vec.
fn rev(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].iter().rev().copied().collect()
}

/// Verify a wire-LE ECDSA signature on the host against a wire-LE public
/// key (mirrors the helper in the `ecc_sign` tests).
fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let (wire_coord, raw_coord) = coord_sizes(pub_le.len());
    assert_eq!(sig_le.len(), wire_coord * 2, "signature length mismatch");

    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le, wire_coord);
    pub_be.extend(rev(y_le, wire_coord));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(r_le, raw_coord);
    sig_be.extend(rev(s_le, raw_coord));

    let digest_be = rev(digest_le, digest_le.len());
    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

/// A deterministic, non-trivial digest of `len` bytes.
fn digest(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
        .collect()
}

/// The SHA-2 digest length matched to a curve's public-key length.
fn digest_len_for(pub_len: usize) -> usize {
    match pub_len {
        64 => 32,
        96 => 48,
        136 => 64,
        _ => panic!("unexpected public-key length {pub_len}"),
    }
}

/// Coerce a masked-TMK slice into the fixed wire array.
fn tmk_array(masked_tmk: &[u8]) -> [u8; MASKED_TMK_LEN] {
    masked_tmk.try_into().expect("masked TMK length")
}

/// Wrap `masked_ec` under `masked_tmk`, then unwrap it back under the same
/// TMK, sign a digest with the recovered key, and assert the recovered
/// public key and signature match the original `pub_ec`.
fn assert_wrap_unwrap_sign(
    ctx: &TestCtx,
    session_id: u16,
    masked_tmk: [u8; MASKED_TMK_LEN],
    masked_ec: Vec<u8>,
    pub_ec: &[u8],
) {
    // Wrap the local EC key under the TMK.
    let wrapped = ctx
        .tbor(&TborDarcKeyWrapReq {
            session_id,
            masked_tmk,
            masked_key: masked_ec,
        })
        .expect("DarcKeyWrap");
    assert!(
        !wrapped.wrapped_key.is_empty() && wrapped.wrapped_key.len() <= 512,
        "wrapped_key must be a non-empty envelope within the wire max",
    );

    // Unwrap it back under the same TMK, asking for signing usage.
    let unwrapped = ctx
        .tbor(&TborDarcKeyUnwrapReq {
            session_id,
            scope: KEY_SCOPE_LOCAL,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            masked_tmk,
            wrapped_key: wrapped.wrapped_key,
        })
        .expect("DarcKeyUnwrap of wrapped key");

    // The device re-derived the public key from the recovered scalar; it
    // must match the key we originally wrapped — the end-to-end proof that
    // the vault-scalar → COSE `d` conversion is correct.
    assert_eq!(
        unwrapped.pub_key, pub_ec,
        "unwrapped public key must match the wrapped key",
    );

    // The recovered key must sign, and the signature must verify against
    // the original public key.
    let dgst = digest(digest_len_for(pub_ec.len()));
    let sign = ctx
        .tbor(&TborEccSignReq {
            session_id,
            masked_key: unwrapped.masked_key,
            digest: dgst.clone(),
        })
        .expect("EccSign with the unwrapped key");
    assert!(
        verify_wire_ecdsa(pub_ec, &sign.signature, &dgst),
        "signature from the unwrapped key must verify against the original public key",
    );
}

/// Round-trip an on-device EC key on `curve` through wrap → unwrap → sign
/// under a freshly generated TMK.
fn assert_roundtrip_on(curve: u8) {
    let ready = sd_initialized_session();

    // A fresh TMK, masked under the SDMK.
    let tmk = ready
        .ctx
        .tbor(&TborDarcTmkGenReq {
            session_id: ready.session.session_id,
        })
        .expect("DarcTmkGen");
    let masked_tmk = tmk_array(&tmk.masked_tmk);

    // A local EC key to export.
    let ec = ready
        .ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    assert_wrap_unwrap_sign(
        &ready.ctx,
        ready.session.session_id,
        masked_tmk,
        ec.masked_key,
        &ec.pub_key,
    );
}

#[test]
fn darc_key_wrap_roundtrip_p256() {
    assert_roundtrip_on(ECC_CURVE_P256);
}

#[test]
fn darc_key_wrap_roundtrip_p384() {
    assert_roundtrip_on(ECC_CURVE_P384);
}

#[test]
fn darc_key_wrap_roundtrip_p521() {
    assert_roundtrip_on(ECC_CURVE_P521);
}

#[test]
fn darc_key_wrap_e2e_create_export_import_sign() {
    // The full DARC hand-off on a single device: create a TMK, wrap a
    // local EC key under it, ship the TMK to a "target" via
    // export → import, then unwrap the key under the round-tripped TMK and
    // use it to sign.
    let ready = sd_initialized_session_with_data();
    let sid = ready.session.session_id;

    // (1) Originate a TMK (masked under the SDMK).
    let masked_tmk = gen_masked_tmk(&ready);

    // (2) Generate the local EC key to be exported.
    let ec = ready
        .ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: sid,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    // (3) Wrap the EC key under the generated TMK.
    let wrapped = ready
        .ctx
        .tbor(&TborDarcKeyWrapReq {
            session_id: sid,
            masked_tmk,
            masked_key: ec.masked_key,
        })
        .expect("DarcKeyWrap");

    // (4) Ship the TMK to the target: source + target key-exchange keys,
    // export (DATA-anchored target chain), then import (POTA-anchored
    // sender chain).  Import re-masks the *same* 32-byte TMK under the
    // SDMK, so a key wrapped under the generated TMK unwraps under it.
    let source_kex = mint_kex(&ready);
    let target_kex = mint_kex(&ready);
    let (export_req, export_chain) = build_valid_export(
        &ready,
        &ready.data,
        &target_kex.pub_raw,
        source_kex.masked,
        masked_tmk,
    );
    let export = ready
        .ctx
        .tbor_oob(&export_req, &export_chain.der_items())
        .expect("DarcTmkExport");
    let imported_tmk = reimport(
        &ready,
        target_kex.masked,
        &source_kex.pub_raw,
        export.sealed_tmk.as_slice().try_into().expect("sealed TMK"),
    );
    let imported_tmk = tmk_array(&imported_tmk);

    // (5) Unwrap the key under the round-tripped TMK, asking for signing.
    let unwrapped = ready
        .ctx
        .tbor(&TborDarcKeyUnwrapReq {
            session_id: sid,
            scope: KEY_SCOPE_LOCAL,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            masked_tmk: imported_tmk,
            wrapped_key: wrapped.wrapped_key,
        })
        .expect("DarcKeyUnwrap under the imported TMK");
    assert_eq!(
        unwrapped.pub_key, ec.pub_key,
        "the key unwrapped on the target must match the source key",
    );

    // (6) Sign with the recovered key and verify against the original key.
    let dgst = digest(32);
    let sign = ready
        .ctx
        .tbor(&TborEccSignReq {
            session_id: sid,
            masked_key: unwrapped.masked_key,
            digest: dgst.clone(),
        })
        .expect("EccSign");
    assert!(
        verify_wire_ecdsa(&ec.pub_key, &sign.signature, &dgst),
        "the end-to-end recovered key must produce a verifiable signature",
    );
}

#[test]
fn darc_key_wrap_rejects_wrong_masked_tmk_kind() {
    // Feed a masked EC key where the masked TMK is expected: it unmasks
    // fine but its kind is not `DarcTmk`.
    let ready = sd_initialized_session();
    let ec = ready
        .ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: ready.session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    let mut wrong_tmk = [0u8; MASKED_TMK_LEN];
    // The EC masked envelope (264 B for P-256) is the same length as a
    // masked TMK, so it decodes past the fixed-length wire check.
    wrong_tmk.copy_from_slice(&ec.masked_key);

    ready.ctx.expect_fw_reject(
        &TborDarcKeyWrapReq {
            session_id: ready.session.session_id,
            masked_tmk: wrong_tmk,
            masked_key: ec.masked_key,
        },
        TborStatus::UnsupportedKeyType,
    );
}

#[test]
fn darc_key_wrap_rejects_wrong_masked_key_kind() {
    // Feed a masked TMK where the masked EC key is expected: it unmasks
    // fine but its kind is `DarcTmk`, not an EC private key.
    let ready = sd_initialized_session();
    let (import_req, chain) = build_valid_import(&ready, &ready.pota, &TMK);
    let tmk_resp = ready
        .ctx
        .tbor_oob(&import_req, &chain.der_items())
        .expect("DarcTmkImport");
    let masked_tmk = tmk_array(&tmk_resp.masked_tmk);

    ready.ctx.expect_fw_reject(
        &TborDarcKeyWrapReq {
            session_id: ready.session.session_id,
            masked_tmk,
            masked_key: masked_tmk.to_vec(),
        },
        TborStatus::UnsupportedKeyType,
    );
}

/// A well-formed request whose crypto inputs never get exercised — used by
/// gating tests that must fail at the session/lifecycle gate before any
/// unmask work.
fn dummy_req(session_id: u16) -> TborDarcKeyWrapReq {
    TborDarcKeyWrapReq {
        session_id,
        masked_tmk: [0u8; MASKED_TMK_LEN],
        // One AES block past the masking metadata minimum so the request
        // decodes; these tests fail earlier, at the session gate.
        masked_key: vec![0u8; 132 + 32],
    }
}

#[test]
fn darc_key_wrap_rejects_before_sd_init() {
    // Finalized but no security domain: the SDMK the TMK is masked under
    // does not exist → rejected before any crypto work.
    let ctx = TestCtx::new();
    let session = crate::commands::sd_sealing_key_gen::finalized_co_session(&ctx);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_key_wrap_rejects_before_finalize() {
    // A rotated CO session but no PartInit/PartFinal → the partition is
    // not Initialized, so the command is rejected at the lifecycle gate.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(&dummy_req(session.session_id), TborStatus::InvalidArg);
}

#[test]
fn darc_key_wrap_rejected_on_cu_session() {
    // DarcKeyWrap is Crypto-Officer-only: a CU session is rejected at the
    // role gate before any crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.expect_fw_reject(
        &dummy_req(session.session_id),
        TborStatus::InvalidPermissions,
    );
}

#[test]
fn darc_key_wrap_rejected_on_default_psk() {
    // A CO session on the still-default PSK is rejected by the dispatcher's
    // default-PSK gate before the handler runs.
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    let mut req = dummy_req(session.session_id());
    req.session_id = session.session_id();
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
