// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hybrid Public Key Encryption (HPKE — RFC 9180), single-shot API.
//!
//! Sync port of `fw/core/crypto/hpke` for host use. Eight ciphersuites:
//!
//! * Three RFC 9180 DHKEM(P-256/P-384/P-521) + HKDF + AES-256-GCM
//!   suites, and three that substitute AES-256-CBC + HMAC for AES-GCM
//!   under a private-use AEAD identifier (`0xFFFF`). All four HPKE
//!   modes (Base / PSK / Auth / AuthPSK) are supported.
//! * Two post-quantum suites (draft-ietf-hpke-pq) with the one-stage
//!   SHAKE256 KDF and AES-256-GCM: HPKE-10 (MLKEM1024-P384) and HPKE-13
//!   (ML-KEM-1024). Base and PSK modes only.
//!
//! Recipient keys are passed as [`HpkePublicKey`] / [`HpkePrivateKey`];
//! [`HpkeSuite::generate_keypair`] and [`HpkeSuite::derive_keypair`]
//! produce an [`HpkeKeyPair`] for any suite. The encapsulated key
//! `enc` is exchanged as bytes.
//!
//! # Public surface
//!
//! Four operations, each with a `_vec` convenience sibling:
//!
//! | Operation       | Buffer form | Owned-output form     |
//! |-----------------|-------------|-----------------------|
//! | [`seal`]        | slice       | [`seal_vec`]          |
//! | [`open`]        | slice       | [`open_vec`]          |
//! | [`send_export`] | slice       | [`send_export_vec`]   |
//! | [`receive_export`] | slice    | [`receive_export_vec`] |
//!
//! Mode is selected via a config-struct constructor — for example
//! [`HpkeSealConfig::base`] / `psk` / `auth` / `auth_psk` — mirroring
//! the established [`crate::AesGcmAlgo::for_encrypt`] pattern.
//!
//! See [`suite`] for ciphersuite constants and wire-format conventions
//! (host uses SEC1 uncompressed public keys and raw scalar private keys
//! for DHKEM).

mod aead;
mod kdf;
mod kem;
mod keys;
mod ops;
mod schedule;
mod suite;

pub use keys::HpkeKeyPair;
pub use keys::HpkePrivateKey;
pub use keys::HpkePublicKey;
pub use ops::HpkeExportSent;
pub use ops::HpkeOpenConfig;
pub use ops::HpkeReceiveExportConfig;
pub use ops::HpkeSealConfig;
pub use ops::HpkeSealed;
pub use ops::HpkeSendExportConfig;
pub use ops::PskParams;
pub use ops::open;
pub use ops::open_vec;
pub use ops::receive_export;
pub use ops::receive_export_vec;
pub use ops::seal;
pub use ops::seal_vec;
pub use ops::send_export;
pub use ops::send_export_vec;
pub use suite::HpkeSuite;

#[cfg(test)]
mod tests;
