// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-command compliance test modules. Each file is gated on the
//! backend feature(s) that can satisfy it (e.g., TBOR commands require
//! `emu` for a real round-trip).

pub mod aes_ctr_block_alignment;
pub mod aes_encrypt_decrypt;
pub mod aes_generate_key;
pub mod api_rev;
pub mod common;
pub mod concat_kdf_derive;
pub mod darc_kex_key_gen;
pub mod darc_key_unwrap;
pub mod darc_key_wrap;
pub mod darc_tmk_export;
pub mod darc_tmk_gen;
pub mod darc_tmk_import;
pub mod default_psk_gate;
pub mod ecc_generate_key;
pub mod ecc_sign;
pub mod ecc_sign_hw;
pub mod ecdh_derive;
pub mod forward_compat;
pub mod fw_error_decode;
pub mod get_cert;
pub mod get_cert_chain_info;
pub mod get_unwrapping_key;
pub mod hash;
pub mod hkdf_derive;
pub mod hmac;
pub mod hmac_generate_key;
pub mod key_report;
pub mod mldsa_generate_key;
pub mod mldsa_kat;
pub mod mldsa_sign;
pub mod mldsa_verify;
pub mod mlkem_decapsulate;
pub mod mlkem_encapsulate;
pub mod mlkem_generate_key;
pub mod mlkem_kat;
pub mod open_session;
pub mod part_final;
pub mod part_info;
pub mod part_init;
pub mod psk_change;
pub mod rsa_mod_exp;
pub mod sd_create_peer_backup;
pub mod sd_create_remote_backup;
pub mod sd_reseal_remote_backup;
pub mod sd_restore_local_backup;
pub mod sd_restore_peer_backup;
pub mod sd_restore_remote_backup;
pub mod sd_sealing_key_gen;
pub mod session_close;
pub mod unexpected_toc_type;
pub mod unwrap_key;
