// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format constants and the `KeyFlags` bitfield for COSE_Sign1
//! key-attestation reports.
//!
//! The wire format matches the host report codec
//! (`ddi/mbor/test_helpers/src/report.rs`). Encoded lengths are computed at
//! runtime by `minicbor::len` on the [`codec`](crate::codec) structs, so
//! this module holds only the fixed wire facts — not any derived
//! byte-counting arithmetic.

use bitfield_struct::bitfield;

// ─── COSE_Sign1 envelope ────────────────────────────────────────────────────

/// COSE_Sign1 CBOR tag byte (tag 18): major type 6 (`0b110`) | 18.
pub const COSE_SIGN1_TAG: u8 = 0xD2;

/// Size of the COSE_Sign1 tag prefix.
pub const COSE_SIGN1_TAG_SIZE: usize = 1;

/// Encoded protected header `{ 1: -35 (ES384), 3: "application/cbor" }`,
/// emitted as a 22-byte bstr in both the COSE_Sign1 object and the
/// COSE `Sig_structure`.
pub const PROTECTED_HEADER: [u8; 22] = [
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];

/// Encoded protected header `{ 1: -50 (ML-DSA-87), 3: "application/cbor" }`
/// (draft-ietf-cose-dilithium). Same 22-byte shape as [`PROTECTED_HEADER`].
pub const PROTECTED_HEADER_MLDSA87: [u8; 22] = [
    0xa2, 0x01, 0x38, 0x31, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];

// ─── Payload fields ─────────────────────────────────────────────────────────

/// Report format version for a v1 report (no `policy_hash`).
pub const REPORT_VERSION: u16 = 1;

/// Report format version for a v2 report (carries a `policy_hash`).
pub const REPORT_VERSION_V2: u16 = 2;

/// Report format version with an explicit signed [`crate::ReportKind`].
pub const REPORT_VERSION_V3: u16 = 3;

/// Length of the app-UUID field (RFC 4122 binary form).
pub const APP_UUID_LEN: usize = 16;

/// Length of the report-data field.
pub const REPORT_DATA_LEN: usize = 128;

/// Length of the VM launch-ID field.
pub const VM_LAUNCH_ID_LEN: usize = 16;

/// Fixed size of the `public_key` bstr that wraps the inner COSE_Key.
///
/// Sized for a 4096-bit RSA public key (512-byte modulus + 4-byte
/// exponent + 9 CBOR framing bytes = 525). An ECC P-384 COSE_Key
/// occupies ~107 bytes; the remainder is zero-padded and the real
/// length is carried in the `public_key_size` field.
pub const PUBLIC_KEY_MAX_SIZE: usize = 525;

/// Maximum RSA modulus length (4096-bit) carried in an attested key's
/// COSE_Key.
pub const RSA_MODULUS_MAX_LEN: usize = 512;

/// Maximum RSA public-exponent length carried in an attested key's
/// COSE_Key.
pub const RSA_EXPONENT_MAX_LEN: usize = 4;

/// CBOR framing overhead of a maximal RSA COSE_Key map — the map
/// header, the `kty` pair, and the two bstr length headers for `n`
/// (3 bytes at 512) and `e` (1 byte at 4).
pub const RSA_COSE_KEY_FRAMING: usize = 9;

// The fixed `public_key` field must exactly fit a maximal RSA COSE_Key
// (keep the modulus/exponent bounds and the 525-byte field in sync).
const _: () = assert!(
    RSA_MODULUS_MAX_LEN + RSA_EXPONENT_MAX_LEN + RSA_COSE_KEY_FRAMING == PUBLIC_KEY_MAX_SIZE
);

/// Upper bound on the encoded size of a key-attestation report.
///
/// The report is built entirely from fixed-size fields (the 525-byte
/// `public_key`, 128-byte `report_data`, 96-byte signature, etc.), so
/// its length is effectively constant; this bound additionally allows
/// every CBOR integer field (`version`, `public_key_size`, `flags`) to
/// encode at its maximum width, and leaves headroom for the optional
/// 48-byte v2 [`policy_hash`](crate::KeyReportView::policy_hash) map entry.
/// The `report_fits_max_len` test pins the **v1** bound against the
/// byte-identical host encoder (which has no `policy_hash`); the
/// `parse_decodes_v2_policy_hash` wire test checks that a worst-case **v2**
/// report still fits. Consumers (e.g. the PartInit handler) `const`-assert
/// their response caps against it.
pub const KEY_REPORT_MAX_LEN: usize = 896;

/// Upper bound on the encoded size of any report, including an ML-DSA-87
/// signature over a payload attesting an ML-DSA-87 public key.
pub const REPORT_MAX_LEN: usize = 8192;

// ─── Signing (ES384 / ECDSA-P384) ──────────────────────────────────────────

/// ECDSA-P384 raw signature length (`r || s`, 48 + 48).
pub const SIGNATURE_LEN: usize = 96;

/// ML-DSA-87 signature length.
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;

/// ML-DSA-87 encoded public-key length.
pub const MLDSA87_PUB_KEY_LEN: usize = 2592;

/// ML-DSA private-key seed (`ξ`) length.
pub const MLDSA_SEED_LEN: usize = 32;

/// Size of an ML-DSA-87 AKP COSE_Key `{ 1: 7, 3: -50, -1: pub }`: the map
/// header, `kty` and `alg` pairs (2 + 3 bytes), the `pub` label and its
/// 3-byte bstr header, and the public key. It exceeds
/// [`PUBLIC_KEY_MAX_SIZE`], so such a key's `public_key` field is exactly
/// this long rather than padded.
pub const MLDSA87_COSE_KEY_LEN: usize = 1 + 2 + 3 + 1 + 3 + MLDSA87_PUB_KEY_LEN;

/// ML-KEM-1024 encapsulation-key length (FIPS 203).
pub const MLKEM1024_PUB_KEY_LEN: usize = 1568;

/// MLKEM1024-P384 hybrid public-key length: `ek_PQ ‖ SEC1(ek_T)`
/// (draft-ietf-hpke-pq).
pub const MLKEM1024P384_PUB_KEY_LEN: usize = MLKEM1024_PUB_KEY_LEN + 97;

/// Size of an ML-KEM-1024 AKP COSE_Key `{ 1: 7, 3: alg, -1: pub }`: the
/// map header, the `kty` pair (2 bytes), the `alg` pair with a 5-byte
/// private-use algorithm (6 bytes), the `pub` label and its 3-byte bstr
/// header, and the key. Like ML-DSA-87 it exceeds [`PUBLIC_KEY_MAX_SIZE`].
pub const MLKEM1024_COSE_KEY_LEN: usize = 1 + 2 + 6 + 1 + 3 + MLKEM1024_PUB_KEY_LEN;

/// Size of an MLKEM1024-P384 AKP COSE_Key (see [`MLKEM1024_COSE_KEY_LEN`]).
pub const MLKEM1024P384_COSE_KEY_LEN: usize = 1 + 2 + 6 + 1 + 3 + MLKEM1024P384_PUB_KEY_LEN;

/// Upper bound on an ES384-signed key-attestation report whose attested key
/// is an ML-KEM-1024 or MLKEM1024-P384 key: [`KEY_REPORT_MAX_LEN`] with the
/// padded `public_key` field replaced by the largest KEM COSE_Key.
pub const KEM_KEY_REPORT_MAX_LEN: usize =
    KEY_REPORT_MAX_LEN - PUBLIC_KEY_MAX_SIZE + MLKEM1024P384_COSE_KEY_LEN;

/// P-384 attestation private-key (raw scalar) length.
pub const PRIV_KEY_LEN: usize = 48;

/// SHA-384 digest length.
pub const SHA384_LEN: usize = 48;

/// Length of the optional `policy_hash` field carried by v2 reports: the
/// SHA-384 digest of the PartPolicy blob.
pub const POLICY_HASH_LEN: usize = SHA384_LEN;

// ─── KeyFlags ───────────────────────────────────────────────────────────────

/// Capability / attribute flags packed into the report's `flags: u32`
/// field. Wire layout matches the host report codec.
#[bitfield(u32)]
pub struct KeyFlags {
    /// Whether the key was imported (vs generated on-device).
    pub is_imported: bool,
    /// Whether the key is available for the current session only.
    pub is_session_key: bool,
    /// Whether the key was generated inside the device.
    pub is_generated: bool,
    /// Whether the key can encrypt.
    pub can_encrypt: bool,
    /// Whether the key can decrypt.
    pub can_decrypt: bool,
    /// Whether the key can sign.
    pub can_sign: bool,
    /// Whether the key can verify.
    pub can_verify: bool,
    /// Whether the key can wrap other keys.
    pub can_wrap: bool,
    /// Whether the key can unwrap other keys.
    pub can_unwrap: bool,
    /// Whether the key can derive other keys.
    pub can_derive: bool,
    /// The authenticated key kind is an HSM-generated SD sealing key.
    pub is_sd_sealing: bool,
    /// The authenticated key kind is an HSM-generated DARC key-exchange key.
    pub is_darc_kex: bool,
    #[bits(20)]
    _reserved: u32,
}
