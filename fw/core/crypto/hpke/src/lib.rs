// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::too_many_arguments)]

//! Hybrid Public Key Encryption (HPKE — RFC 9180, draft-ietf-hpke-hpke
//! and draft-ietf-hpke-pq), single-shot API.
//!
//! Supports all four HPKE modes (Base / PSK / Auth / AuthPSK) across
//! eight ciphersuites built from five KEMs, two KDF families and two
//! AEAD primitives:
//!
//! | KEM            | KDF          | AEAD                     | Modes      |
//! |----------------|--------------|--------------------------|------------|
//! | DHKEM(P-256)   | HKDF-SHA-256 | AES-256-GCM              | all        |
//! | DHKEM(P-256)   | HKDF-SHA-256 | AES-256-CBC-HMAC-SHA-256 | all        |
//! | DHKEM(P-384)   | HKDF-SHA-384 | AES-256-GCM              | all        |
//! | DHKEM(P-384)   | HKDF-SHA-384 | AES-256-CBC-HMAC-SHA-384 | all        |
//! | DHKEM(P-521)   | HKDF-SHA-512 | AES-256-GCM              | all        |
//! | DHKEM(P-521)   | HKDF-SHA-512 | AES-256-CBC-HMAC-SHA-512 | all        |
//! | MLKEM1024-P384 | SHAKE256     | AES-256-GCM (HPKE-10)    | Base / PSK |
//! | ML-KEM-1024    | SHAKE256     | AES-256-GCM (HPKE-13)    | Base / PSK |
//!
//! See [`HpkeSuite`] for the full enum and per-suite size constants.
//!
//! ## API surface
//!
//! Four operations, each takes a per-operation configuration struct
//! whose mode is selected by a constructor:
//!
//! | Operation        | Config                          |
//! |------------------|---------------------------------|
//! | [`seal`]         | [`HpkeSealConfig`]              |
//! | [`open`]         | [`HpkeOpenConfig`]              |
//! | [`send_export`]  | [`HpkeSendExportConfig`]        |
//! | [`receive_export`] | [`HpkeReceiveExportConfig`]   |
//!
//! Each config has four constructors that bake the HPKE mode into
//! the value and enforce the corresponding auth / PSK invariants at
//! construction time:
//!
//! | Mode    | Constructor                       |
//! |---------|-----------------------------------|
//! | Base    | `HpkeSealConfig::base(...)`       |
//! | PSK     | `HpkeSealConfig::psk(...)`        |
//! | Auth    | `HpkeSealConfig::auth(...)`       |
//! | AuthPSK | `HpkeSealConfig::auth_psk(...)`   |
//!
//! The other three configs follow the same shape.
//!
//! ## Scoped-allocation contract
//!
//! Every entry point takes an [`tsra_fw_hsm_pal_traits::HsmScopedAlloc`]
//! and allocates its intermediate buffers from that alloc. Internal
//! helpers request only the slices they need, and the PAL frees them
//! automatically when the outer alloc returns.
//!
//! ## Internal modules
//!
//! * `aead` — AES-GCM / AES-CBC-HMAC seal & open dispatch.
//! * `kdf` — LabeledExtract / LabeledExpand (two-stage) and
//!   LabeledDerive (one-stage).
//! * `kem` — DHKEM, ML-KEM and hybrid Encap / Decap, plus the DHKEM
//!   Auth variants.
//! * `ops` — public seal / open / export entry points.
//! * `schedule` — one- and two-stage key schedule.
//! * `suite` — [`HpkeSuite`] enum and per-suite constants.
//! * `error` — placeholder; HPKE currently surfaces
//!   [`tsra_fw_hsm_pal_traits::HsmError`] directly.

mod aead;
mod error;
mod helpers;
mod kdf;
mod kem;
mod ops;
mod schedule;
mod suite;

pub use kem::generate_key_pair;
pub use kem::public_key;
pub use kem::validate_mlkem1024_public_key;
pub use ops::open;
pub use ops::receive_export;
pub use ops::seal;
pub use ops::send_export;
pub use ops::AuthParams;
pub use ops::ExportSizes;
pub use ops::HpkeOpenConfig;
pub use ops::HpkeReceiveExportConfig;
pub use ops::HpkeSealConfig;
pub use ops::HpkeSendExportConfig;
pub use ops::PskParams;
pub use ops::SealSizes;
pub use suite::HpkeSuite;
