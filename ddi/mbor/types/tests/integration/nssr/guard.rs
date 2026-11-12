// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage guard: every MBOR `DdiOp` variant needs a row in [`ROWS`].

#![cfg(test)]

use test_with_tracing::test;

enum Row {
    Test(&'static str),
    Excluded(&'static str),
}

/// Every `DdiOp` variant → its NSSR test, or why it has none.
///
/// The AES bulk fast path is not a `DdiOp`; its rows are in [`BULK_ROWS`]
/// (`nssr_bulk_aes_gcm`, `nssr_bulk_aes_xts`).
const ROWS: &[(&str, Row)] = &[
    ("Invalid", Row::Excluded("sentinel value, not a command")),
    ("GetApiRev", Row::Test("nssr_get_api_rev")),
    ("GetDeviceInfo", Row::Test("nssr_get_device_info")),
    ("DeleteKey", Row::Test("nssr_delete_key")),
    ("OpenKey", Row::Test("nssr_open_key")),
    ("AttestKey", Row::Test("nssr_attest_key")),
    ("RsaModExp", Row::Test("nssr_rsa_mod_exp")),
    ("RsaUnwrap", Row::Test("nssr_rsa_unwrap")),
    ("GetUnwrappingKey", Row::Test("nssr_get_unwrapping_key")),
    (
        "EccGenerateKeyPair",
        Row::Test("nssr_ecc_generate_key_pair"),
    ),
    ("EccSign", Row::Test("nssr_ecc_sign")),
    ("AesGenerateKey", Row::Test("nssr_aes_generate_key")),
    ("AesEncryptDecrypt", Row::Test("nssr_aes_encrypt_decrypt")),
    ("EcdhKeyExchange", Row::Test("nssr_ecdh_key_exchange")),
    ("HkdfDerive", Row::Test("nssr_hkdf_derive")),
    (
        "KbkdfCounterHmacDerive",
        Row::Test("nssr_kbkdf_counter_hmac_derive"),
    ),
    ("Hmac", Row::Test("nssr_hmac")),
    (
        "GetEstablishCredEncryptionKey",
        Row::Test("nssr_get_establish_cred_encryption_key"),
    ),
    (
        "EstablishCredential",
        Row::Test("nssr_establish_credential"),
    ),
    (
        "GetSessionEncryptionKey",
        Row::Test("nssr_get_session_encryption_key"),
    ),
    ("OpenSession", Row::Test("nssr_open_session")),
    ("CloseSession", Row::Test("nssr_close_session")),
    ("ChangePin", Row::Test("nssr_change_pin")),
    ("UnmaskKey", Row::Test("nssr_unmask_key")),
    ("GetCertChainInfo", Row::Test("nssr_get_cert_chain_info")),
    ("GetCertificate", Row::Test("nssr_get_certificate")),
    ("ReopenSession", Row::Test("nssr_reopen_session")),
    ("InitBk3", Row::Test("nssr_init_bk3")),
    ("GetSealedBk3", Row::Test("nssr_get_sealed_bk3")),
    ("SetSealedBk3", Row::Test("nssr_set_sealed_bk3")),
    ("SetInitBk3Pin", Row::Test("nssr_set_init_bk3_pin")),
    ("SecureInitBk3", Row::Test("nssr_secure_init_bk3")),
    ("ShaDigest", Row::Test("nssr_sha_digest")),
];

/// Fast-path rows that are not `DdiOp`s.
const BULK_ROWS: &[(&str, Row)] = &[
    ("AES-GCM bulk", Row::Test("nssr_bulk_aes_gcm")),
    ("AES-XTS bulk", Row::Test("nssr_bulk_aes_xts")),
];

/// Sources that define the tests the rows name.
const SOURCES: &[&str] = &[
    include_str!("bk3.rs"),
    include_str!("bulk.rs"),
    include_str!("keyed.rs"),
    include_str!("keyless.rs"),
    include_str!("lifecycle.rs"),
    include_str!("no_session.rs"),
];

/// Variant names of the `pub enum DdiOp { ... }` block in `src`.
fn ddi_op_variants(src: &str) -> Vec<String> {
    src.lines()
        .skip_while(|line| !line.contains("pub enum DdiOp {"))
        .skip(1)
        .take_while(|line| line.trim() != "}")
        .filter_map(|line| line.trim().split_once('='))
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.starts_with("//"))
        .collect()
}

#[test]
fn nssr_every_mbor_opcode_has_a_row() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
    let src = std::fs::read_to_string(path).expect("read DdiOp source");
    let variants = ddi_op_variants(&src);
    assert!(
        !variants.is_empty(),
        "no `pub enum DdiOp` variants in {path}"
    );

    let missing: Vec<&String> = variants
        .iter()
        .filter(|variant| !ROWS.iter().any(|(op, _)| op == variant))
        .collect();
    let stale: Vec<&str> = ROWS
        .iter()
        .map(|(op, _)| *op)
        .filter(|op| !variants.iter().any(|variant| variant == op))
        .collect();
    let mut undefined = Vec::new();
    let mut unexplained = Vec::new();
    for (op, row) in ROWS.iter().chain(BULK_ROWS) {
        match row {
            Row::Test(test)
                if !SOURCES
                    .iter()
                    .any(|src| src.contains(&format!("fn {test}()"))) =>
            {
                undefined.push(*test)
            }
            Row::Excluded(reason) if reason.trim().is_empty() => unexplained.push(*op),
            _ => {}
        }
    }

    assert!(
        missing.is_empty() && stale.is_empty() && undefined.is_empty() && unexplained.is_empty(),
        "NSSR coverage table is out of date:\n  \
         missing rows (DdiOp variants without a row): {missing:?}\n  \
         stale rows (not a DdiOp variant): {stale:?}\n  \
         rows naming an undefined test: {undefined:?}\n  \
         exclusions without a reason: {unexplained:?}"
    );
}
