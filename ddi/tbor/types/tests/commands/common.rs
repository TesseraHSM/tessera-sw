// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common constants and helpers for TBOR command tests.
//!
//! Unlike most command modules, this one also builds without `emu`, so the
//! hardware-eligible tests share these helpers too.

use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::EccAlgo;
use tsra_crypto::EccPublicKey;
use tsra_crypto::Encrypter;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaPublicKey;
use tsra_crypto::RsaSignAlgo;
use tsra_crypto::Verifier;
use tsra_ddi_tbor_codec::EncodeError;
use tsra_ddi_tbor_codec::RequestView;
use tsra_ddi_tbor_codec::TocType;
use tsra_ddi_tbor_codec::REQ_HEADER_LEN;
use tsra_ddi_tbor_codec::TOC_ENTRY_LEN;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::coord_sizes;
use tsra_ddi_tbor_test_harness::dev_coord_to_host_be;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::dev_rev_in_place;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::SessionControlKind;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborEcdhDeriveReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborRsaModExpReq;
use tsra_ddi_tbor_types::TborUnwrapKeyReq;
use tsra_ddi_tbor_types::TborUnwrapKeyResp;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::RSA_OP_DECRYPT;
use tsra_ddi_tbor_types::RSA_OP_SIGN;

/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// `SessionType` role identifier for Crypto-Officer sessions.
pub(crate) const CO: u8 = 0;

/// `SessionType` role identifier for Crypto-User sessions.
pub(crate) const CU: u8 = 1;

/// AEAD envelope component lengths.
pub(crate) const ENVELOPE_HEADER_LEN: usize = tsra_crypto::aead_envelope::HEADER_LEN;

/// Length in bytes of the masked-key envelope IV.
pub(crate) const ENVELOPE_IV_LEN: usize = 16;

/// Length in bytes of the masked-key envelope AAD.
pub(crate) const ENVELOPE_AAD_LEN: usize = 192;

/// Length in bytes of the masked-key envelope authentication tag.
pub(crate) const ENVELOPE_TAG_LEN: usize = 16;

/// Creates a Crypto-Officer session, generates a session-scoped ECC signing key,
/// and keeps the session alive while `test` runs.
pub(crate) fn with_generated_ecc_key(
    curve: u8,
    test: impl FnOnce(&TestCtx, u16, Vec<u8>, Vec<u8>),
) {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    test(&ctx, session.session_id, resp.masked_key, resp.pub_key);
}

/// RSA-AES-wrap `data` against the HSM-format unwrapping public key
/// (`n ‖ e`, device byte order): RSA-OAEP an ephemeral 32-byte KEK with
/// `oaep_hash`, then AES-KWP the data under it, and concatenate.
pub(crate) fn rsa_aes_wrap(hsm_pub: &[u8], data: &[u8], oaep_hash: HashAlgo) -> Vec<u8> {
    // `GetUnwrappingKey` returns the modulus / exponent in device byte
    // order (`n(256) ‖ e(4)`), but `RsaPublicKey::from_hsm_bytes` parses
    // each component big-endian — convert them per-component.
    assert_eq!(hsm_pub.len(), 260, "RSA-2048 HSM pubkey is 260 bytes");
    let mut be = rev(&hsm_pub[..256]);
    be.extend(rev(&hsm_pub[256..260]));

    let ephemeral_kek = [0xA7u8; 32];
    let pub_key = RsaPublicKey::from_hsm_bytes(&be).expect("from_hsm_bytes");
    let mut enc_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(oaep_hash, None),
        &pub_key,
        &ephemeral_kek,
    )
    .expect("RSA-OAEP wrap KEK");
    // The device expects the OAEP ciphertext in device byte order; OpenSSL
    // emits big-endian.
    dev_rev_in_place(&mut enc_kek);

    let kek = AesKey::from_bytes(&ephemeral_kek).expect("AES KEK");
    let mut enc_data = Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, data)
        .expect("AES-KWP wrap data");

    let mut wrapped = Vec::with_capacity(enc_kek.len() + enc_data.len());
    wrapped.append(&mut enc_kek);
    wrapped.append(&mut enc_data);
    wrapped
}

/// Builds an `UnwrapKey` request that imports `key` under the `Local` scope,
/// RSA-AES-wrapped against `hsm_pub` with SHA-256 OAEP.
pub(crate) fn unwrap_req(
    session_id: u16,
    hsm_pub: &[u8],
    class: u8,
    usage: u64,
    key: &[u8],
) -> TborUnwrapKeyReq {
    TborUnwrapKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_class: class,
        key_usage: usage,
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob: rsa_aes_wrap(hsm_pub, key, HashAlgo::sha256()),
        key_label: b"imported-key".to_vec(),
    }
}

/// Imports `key` with [`unwrap_req`], expecting success.
pub(crate) fn import_ok(
    ctx: &TestCtx,
    session_id: u16,
    hsm_pub: &[u8],
    class: u8,
    usage: u64,
    key: &[u8],
) -> TborUnwrapKeyResp {
    ctx.tbor(&unwrap_req(session_id, hsm_pub, class, usage, key))
        .expect("UnwrapKey")
}

/// Convert `bytes` between device byte order and OpenSSL big-endian (see
/// [`dev_rev`]). Operand names suffixed `_le` in these tests hold device
/// byte order, which is big-endian on Duo.
pub(crate) fn rev(bytes: &[u8]) -> Vec<u8> {
    dev_rev(bytes)
}

/// A non-palindrome big-endian integer of `modulus_len` bytes that stays
/// below the modulus (leading byte `0x01`, so `m < n`).  The non-symmetry
/// exercises the wire little-endian operand handling.
pub(crate) fn test_integer(modulus_len: usize) -> Vec<u8> {
    let mut m = vec![0x02u8; modulus_len];
    m[0] = 0x01;
    m
}

/// Run `RsaModExp` and return the wire-LE `x` result.
pub(crate) fn mod_exp(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    op_type: u8,
    y_le: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborRsaModExpReq {
        session_id,
        masked_key,
        op_type,
        y: y_le,
    })
    .expect("RsaModExp")
    .x
}

/// Raw-signs a test integer with `masked_key` through `RsaModExp`, and
/// verifies the signature on the host with `pubkey`.
pub(crate) fn assert_rsa_signs(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pubkey: &RsaPublicKey,
    modulus_len: usize,
) {
    let m = test_integer(modulus_len);

    // Device consumes wire-LE `y`, returns wire-LE `x`.
    let x_le = mod_exp(ctx, session_id, masked_key, RSA_OP_SIGN, rev(&m));
    assert_eq!(
        x_le.len(),
        modulus_len,
        "result length equals the modulus length"
    );
    let verified = Verifier::verify(&mut RsaSignAlgo::with_no_padding(), pubkey, &m, &rev(&x_le))
        .expect("raw RSA verify");
    assert!(
        verified,
        "RsaModExp Sign must produce a signature verifying over the message (k={modulus_len})",
    );
}

/// Raw-encrypts a test integer on the host with `pubkey`, and checks that
/// `RsaModExp` decrypts it with `masked_key`.
pub(crate) fn assert_rsa_decrypts(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pubkey: &RsaPublicKey,
    modulus_len: usize,
) {
    let m = test_integer(modulus_len);

    // c = m^e mod n (big-endian), then fed to the device as wire-LE `y`.
    let ciphertext = Encrypter::encrypt_vec(&mut RsaEncryptAlgo::with_no_padding(), pubkey, &m)
        .expect("raw RSA encrypt");
    let x_le = mod_exp(
        ctx,
        session_id,
        masked_key,
        RSA_OP_DECRYPT,
        rev(&ciphertext),
    );
    assert_eq!(
        rev(&x_le),
        m,
        "RsaModExp Decrypt must recover the original message (k={modulus_len})"
    );
}

/// Sign `digest` with a caller-held masked key.
pub(crate) fn sign(ctx: &TestCtx, session_id: u16, masked_key: Vec<u8>, digest: &[u8]) -> Vec<u8> {
    ctx.tbor(&TborEccSignReq {
        session_id,
        masked_key,
        digest: digest.to_vec(),
    })
    .expect("EccSign")
    .signature
}

/// Verify a wire-LE ECDSA signature on the host with `tsra_crypto`.
///
/// * `pub_le` — `x_le ‖ y_le`, each `wire_coord_len` bytes.
/// * `sig_le` — `r_le ‖ s_le`, each `wire_coord_len` bytes.
/// * `digest_le` — the wire-LE digest that was handed to `EccSign`.
pub(crate) fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let (wire_coord, raw_coord) = coord_sizes(pub_le.len());
    assert_eq!(sig_le.len(), wire_coord * 2, "signature length mismatch");

    // Public key: convert each wire coordinate → big-endian
    // `hsm_point_size` coordinates (P-521 is left-padded to 68 bytes).
    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = dev_coord_to_host_be(x_le);
    pub_be.extend(dev_coord_to_host_be(y_le));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    // Signature: reverse the meaningful `raw_coord` bytes of each component
    // → big-endian `r ‖ s`.
    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(&r_le[..raw_coord]);
    sig_be.extend(rev(&s_le[..raw_coord]));

    // Verify the full big-endian digest; host ECDSA applies the same
    // most-significant-bit truncation as the firmware.
    let digest_be = rev(digest_le);

    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

/// Signs a `digest_len`-byte test digest with `masked_key` on the device, and
/// verifies the signature on the host against `pub_le`.
pub(crate) fn assert_ecc_signs(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pub_le: &[u8],
    digest_len: usize,
) {
    let digest: Vec<u8> = (0..digest_len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
        .collect();
    let signature = sign(ctx, session_id, masked_key, &digest);
    assert_eq!(
        signature.len(),
        pub_le.len(),
        "wire signature length equals wire public-key length ({}-byte public key)",
        pub_le.len(),
    );
    assert!(
        verify_wire_ecdsa(pub_le, &signature, &digest),
        "ECDSA signature must verify against the public key ({}-byte public key)",
        pub_le.len(),
    );
}

/// Derive a shared secret from local key `masked_key` against `peer_pub`
/// under `scope`.
pub(crate) fn derive(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    masked_key: Vec<u8>,
    peer_pub: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborEcdhDeriveReq {
        session_id,
        scope,
        masked_key,
        peer_pub_key: peer_pub,
        key_label: Vec::new(),
    })
    .expect("EcdhDerive")
    .masked_secret
}

/// Wraps a request so its encoding carries a 4-byte zero gap at the start of
/// the payload data area, with every offset/length TOC entry rebased past it.
///
/// The result still parses as a structurally valid TBOR request, but its
/// payload layout is non-canonical, which firmware must reject.
pub(crate) struct PayloadGapReq<R>(pub(crate) R);

/// Size of the zero gap [`PayloadGapReq`] inserts.
const PAYLOAD_GAP: usize = 4;

impl<R: TborOpReq> TborOpReq for PayloadGapReq<R> {
    const OPCODE: u8 = R::OPCODE;
    type OpResp = R::OpResp;

    fn get_session_id(&self) -> Option<u16> {
        self.0.get_session_id()
    }

    fn session_ctrl(&self) -> SessionControlKind {
        self.0.session_ctrl()
    }

    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], EncodeError> {
        let len = self.0.encode_request(buf)?.len();
        let toc_count = RequestView::parse(&buf[..len])
            .expect("parse canonical request")
            .toc_count();
        let data_start = REQ_HEADER_LEN + toc_count * TOC_ENTRY_LEN;
        if buf.len() < len + PAYLOAD_GAP {
            return Err(EncodeError::BufferTooSmall);
        }
        buf.copy_within(data_start..len, data_start + PAYLOAD_GAP);
        buf[data_start..data_start + PAYLOAD_GAP].fill(0);
        for index in 0..toc_count {
            let at = REQ_HEADER_LEN + index * TOC_ENTRY_LEN;
            let word = u32::from_be_bytes(
                buf[at..at + TOC_ENTRY_LEN]
                    .try_into()
                    .expect("TOC entry is 4 bytes"),
            );
            let entry_type = TocType::from_raw((word >> 26) as u8);
            if matches!(
                entry_type,
                Some(
                    TocType::SealedKey
                        | TocType::Uint32
                        | TocType::Uint64
                        | TocType::Buffer
                        | TocType::Padding
                )
            ) {
                // The offset occupies the low 13 bits of the TOC word.
                assert!((word & 0x1FFF) as usize + PAYLOAD_GAP <= 0x1FFF);
                let word = word + PAYLOAD_GAP as u32;
                buf[at..at + TOC_ENTRY_LEN].copy_from_slice(&word.to_be_bytes());
            }
        }
        let shifted = &buf[..len + PAYLOAD_GAP];
        RequestView::parse(shifted).expect("gapped request stays structurally valid");
        Ok(shifted)
    }
}
