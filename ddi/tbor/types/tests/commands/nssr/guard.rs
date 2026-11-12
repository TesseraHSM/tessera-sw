// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage guard: every opcode declared with `#[tbor(opcode = …)]` in
//! `src/` needs a row in [`ROWS`]. Rows point at their test functions, so
//! renaming or removing a row's test fails to compile.

use super::keys;
use super::lifecycle;
use super::no_session;
use super::sd_darc;

const ROWS: &[(&str, fn())] = &[
    ("TBOR_OP_API_REV", no_session::nssr_api_rev),
    ("TBOR_OP_PART_INFO", no_session::nssr_part_info),
    (
        "TBOR_OP_GET_CERT_CHAIN_INFO",
        no_session::nssr_get_cert_chain_info,
    ),
    ("TBOR_OP_GET_CERTIFICATE", no_session::nssr_get_certificate),
    (
        "TBOR_OP_SESSION_OPEN_INIT",
        lifecycle::nssr_session_open_init,
    ),
    (
        "TBOR_OP_SESSION_OPEN_FINISH",
        lifecycle::nssr_session_open_finish,
    ),
    (
        "TBOR_OP_SESSION_REOPEN_INIT",
        lifecycle::nssr_session_reopen_init,
    ),
    (
        "TBOR_OP_SESSION_REOPEN_FINISH",
        lifecycle::nssr_session_reopen_finish,
    ),
    ("TBOR_OP_SESSION_CLOSE", lifecycle::nssr_session_close),
    ("TBOR_OP_PSK_CHANGE", lifecycle::nssr_psk_change),
    ("TBOR_OP_PART_INIT", lifecycle::nssr_part_init),
    ("TBOR_OP_PART_FINAL", lifecycle::nssr_part_final),
    ("TBOR_OP_AES_GENERATE_KEY", keys::nssr_aes_generate_key),
    (
        "TBOR_OP_AES_ENCRYPT_DECRYPT",
        keys::nssr_aes_encrypt_decrypt,
    ),
    (
        "TBOR_OP_AES_GCM_ENCRYPT_DECRYPT",
        keys::nssr_aes_gcm_encrypt_decrypt,
    ),
    (
        "TBOR_OP_AES_XTS_GENERATE_KEY",
        keys::nssr_aes_xts_generate_key,
    ),
    (
        "TBOR_OP_AES_XTS_ENCRYPT_DECRYPT",
        keys::nssr_aes_xts_encrypt_decrypt,
    ),
    ("TBOR_OP_ECC_GENERATE_KEY", keys::nssr_ecc_generate_key),
    ("TBOR_OP_ECC_SIGN", keys::nssr_ecc_sign),
    ("TBOR_OP_ECDH_DERIVE", keys::nssr_ecdh_derive),
    ("TBOR_OP_HKDF_DERIVE", keys::nssr_hkdf_derive),
    ("TBOR_OP_CONCAT_KDF_DERIVE", keys::nssr_concat_kdf_derive),
    ("TBOR_OP_HASH", keys::nssr_hash),
    ("TBOR_OP_HMAC_GENERATE_KEY", keys::nssr_hmac_generate_key),
    ("TBOR_OP_HMAC", keys::nssr_hmac),
    ("TBOR_OP_GET_PUBLIC_KEY", keys::nssr_get_public_key),
    ("TBOR_OP_GET_UNWRAPPING_KEY", keys::nssr_get_unwrapping_key),
    ("TBOR_OP_UNWRAP_KEY", keys::nssr_unwrap_key),
    ("TBOR_OP_RSA_MOD_EXP", keys::nssr_rsa_mod_exp),
    ("TBOR_OP_VERIFY_KEY", keys::nssr_verify_key),
    ("TBOR_OP_KEY_REPORT", keys::nssr_key_report),
    ("TBOR_OP_MLDSA_GENERATE_KEY", keys::nssr_mldsa_generate_key),
    ("TBOR_OP_MLDSA_SIGN", keys::nssr_mldsa_sign),
    ("TBOR_OP_MLDSA_VERIFY", keys::nssr_mldsa_verify),
    ("TBOR_OP_MLKEM_GENERATE_KEY", keys::nssr_mlkem_generate_key),
    ("TBOR_OP_MLKEM_ENCAPSULATE", keys::nssr_mlkem_encapsulate),
    ("TBOR_OP_MLKEM_DECAPSULATE", keys::nssr_mlkem_decapsulate),
    (
        "TBOR_OP_SD_SEALING_KEY_GEN",
        sd_darc::nssr_sd_sealing_key_gen,
    ),
    (
        "TBOR_OP_SD_CREATE_REMOTE_BACKUP",
        sd_darc::nssr_sd_create_remote_backup,
    ),
    (
        "TBOR_OP_SD_RESEAL_REMOTE_BACKUP",
        sd_darc::nssr_sd_reseal_remote_backup,
    ),
    (
        "TBOR_OP_SD_RESTORE_REMOTE_BACKUP",
        sd_darc::nssr_sd_restore_remote_backup,
    ),
    (
        "TBOR_OP_SD_RESTORE_LOCAL_BACKUP",
        sd_darc::nssr_sd_restore_local_backup,
    ),
    (
        "TBOR_OP_SD_CREATE_PEER_BACKUP",
        sd_darc::nssr_sd_create_peer_backup,
    ),
    (
        "TBOR_OP_SD_RESTORE_PEER_BACKUP",
        sd_darc::nssr_sd_restore_peer_backup,
    ),
    ("TBOR_OP_DARC_KEX_KEY_GEN", sd_darc::nssr_darc_kex_key_gen),
    ("TBOR_OP_DARC_TMK_IMPORT", sd_darc::nssr_darc_tmk_import),
    ("TBOR_OP_DARC_KEY_UNWRAP", sd_darc::nssr_darc_key_unwrap),
    ("TBOR_OP_DARC_TMK_GEN", sd_darc::nssr_darc_tmk_gen),
    ("TBOR_OP_DARC_TMK_EXPORT", sd_darc::nssr_darc_tmk_export),
    ("TBOR_OP_DARC_KEY_WRAP", sd_darc::nssr_darc_key_wrap),
];

/// Opcode constants named by the `#[tbor(opcode = …)]` attributes in `src/`.
fn declared_opcodes() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut opcodes = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read src/") {
        let path = entry.expect("src/ entry").path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            let src = std::fs::read_to_string(&path).expect("read source");
            opcodes.extend(src.lines().filter_map(|line| {
                let rest = line.trim().strip_prefix("#[tbor(opcode = ")?;
                rest.split([',', ')']).next().map(str::to_owned)
            }));
        }
    }
    opcodes
}

#[test]
fn nssr_every_tbor_opcode_has_a_row() {
    let declared = declared_opcodes();
    assert!(!declared.is_empty(), "no `#[tbor(opcode = …)]` in src/");
    let missing: Vec<_> = declared
        .iter()
        .filter(|op| !ROWS.iter().any(|(row, _)| row == op))
        .collect();
    let stale: Vec<_> = ROWS
        .iter()
        .map(|(row, _)| *row)
        .filter(|row| !declared.iter().any(|op| op == row))
        .collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "NSSR coverage table is out of date:\n  \
         missing rows (declared opcodes without a row): {missing:?}\n  \
         stale rows (not a declared opcode): {stale:?}"
    );
}
