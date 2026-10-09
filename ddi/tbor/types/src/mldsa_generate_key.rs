// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlDsaGenerateKey` command.
//!
//! `MlDsaGenerateKey` is (temporarily) an **out-of-session** command that generates a fresh ML-DSA keypair and returns the
//! secret key as a **masked** blob plus the wire public key.  The private
//! key is not stored on-device; the caller holds the masked blob and
//! passes it back to [`MlDsaSign`](crate::mldsa_sign).
//!
//!
//! `key_kind` is a raw 1-byte `MlDsaKeyKind` discriminant (the firmware
//! types it as an open enum) byte-identical to the PQC subset of
//! `HsmVaultKeyKind`. It selects the ML-DSA parameter set.  The TBOR wire
//! ships **seed-only** private keys today, so the returned masked blob
//! always carries the compact 32-byte `xi` seed.
//!
//! # TEMPORARY: out-of-session bring-up
//!
//! **This command is wired as `no_session` purely to unblock hardware
//! bring-up and MUST be reverted to `in_session` before any PR.**  TBOR
//! session establishment currently fails on real silicon
//! (`SessionOpenInit` -> `TborDecodeError`), which blocks every
//! in-session command, while the `no_session` path is proven working
//! there by `ApiRev`.  Running out of session means the request carries
//! no `session_id` and the private key is masked under a hardcoded
//! development key rather than a partition masking key, so there is
//! **no authentication, no authorization and no key protection**.
//! Not fit to ship.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `MlDsaGenerateKey`.
pub const TBOR_OP_MLDSA_GENERATE_KEY: u8 = 0x26;

/// Maximum masked ML-DSA private-key envelope length.
///
/// The masked plaintext is the 32-byte `xi` seed **concatenated with the
/// expanded secret key**, seed first: `32 + 4896 + 228 = 5156` B at
/// ML-DSA-87, where 228 is the AEAD-GCM-256 masked-envelope overhead
/// `header(8) + iv(12) + aad(96) + tag(16)`.
///
/// Carrying both is what makes signing cheap. The seed alone would be
/// smaller on the wire, but every signature would have to re-derive the
/// key pair from it first — a full key generation per signature, measured
/// at 8.51 ms of ML-DSA-87's 24.5 ms floor. Carrying the expanded key too
/// removes that, while keeping the seed so the public key can still be
/// regenerated from the blob alone.
///
/// One AEAD tag covers the pair, so the two halves cannot disagree without
/// failing to unmask — the device does not need to re-derive to check them.
///
/// Note this makes the masked length **parameter-set dependent** (2724 /
/// 4196 / 5156 for ML-DSA-44 / 65 / 87), where the seed-only form was a
/// constant 164 regardless. The `key_kind` in the AAD is therefore no
/// longer the only thing distinguishing parameter sets.
pub const MASKED_MLDSA_KEY_MAX_LEN: usize = 8 + 12 + 192 + 32 + 4896 + 16;
/// Maximum ML-DSA public-key length: 2592 B for ML-DSA-87.
pub const MLDSA_PUB_KEY_MAX_LEN: usize = 2592;
/// Maximum ML-DSA signature length: 4627 B for ML-DSA-87.
pub const MLDSA_SIGNATURE_MAX_LEN: usize = 4627;
/// Maximum ML-DSA context-string length: 255 B.
///
/// FIPS 204 defines `ML-DSA.Sign(sk, M, ctx)` and
/// `ML-DSA.Verify(pk, M, sigma, ctx)` over a caller-chosen context string
/// with `0 <= |ctx| <= 255`.  The bound is a hard specification limit, not
/// a wire-budget choice: the signed message representative embeds `|ctx|`
/// as a single byte of the domain separator, so a longer context string
/// is not representable.  An empty `ctx` is the FIPS 204 default.
pub const MLDSA_CTX_MAX_LEN: usize = 255;
/// Maximum message length accepted by the TBOR ML-DSA sign and verify
/// schemas.
///
/// The binding constraint is the worst-case `MlDsaVerify` request — the
/// largest PQC frame — and the limit is the **host encoder's staging
/// budget**, not TBOR's 8191-byte `MAX_DATA_SIZE`.  The encoder stages
/// the data section at offset 132 (`header(4) + 32 TOC entries * 4`; see
/// `stage_base()` in `ddi/tbor/codec/src/encode.rs`) inside an 8192-byte
/// transport buffer (`REQ_BUF_LEN` in `ddi/nix/src/dev.rs` and
/// `ddi/win/src/dev.rs`):
///
/// ```text
///   transport buffer  =  8192
///   stage offset      =  -132   header(4) + 32 * 4 TOC bytes
///   pub_key           = -2592   ML-DSA-87
///   signature         = -4627   ML-DSA-87
///   ctx               =  -255   MLDSA_CTX_MAX_LEN
///   message budget    =   586
/// ```
///
/// `MlDsaSign` shares the same cap: sign and verify are inverse
/// operations over pure ML-DSA, so a message that can be signed must also
/// be verifiable.  `MlDsaSign` on its own would allow
/// `8192 - 132 - 164 - 255 = 7641` bytes.
///
/// The cap is therefore dictated entirely by `MlDsaVerify`.  If
/// `MlDsaVerify` is ever removed as a command, raising the cap is a
/// deliberate **one-constant change**: nothing else in the schema derives
/// from it, and the `max_len` literals on the `message` fields are
/// mechanically pinned to this constant by `const _: () = assert!(...)`
/// checks that fail the build if they drift.
pub const MLDSA_MESSAGE_MAX_LEN: usize = 586;

/// `MlDsaKeyKind` discriminant for an ML-DSA-44 compact seed (`xi`, 32 B).
pub const MLDSA_KEY_KIND_44_SEED: u8 = 46;
/// `MlDsaKeyKind` discriminant for an ML-DSA-65 compact seed (`xi`, 32 B).
pub const MLDSA_KEY_KIND_65_SEED: u8 = 47;
/// `MlDsaKeyKind` discriminant for an ML-DSA-87 compact seed (`xi`, 32 B).
pub const MLDSA_KEY_KIND_87_SEED: u8 = 48;

/// Host-facing TBOR `MlDsaGenerateKey` request.
#[tbor(opcode = TBOR_OP_MLDSA_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborMlDsaGenerateKeyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// Requested ML-DSA private key kind as the 1-byte `MlDsaKeyKind`
    /// discriminant.  The kind encodes the parameter set; the wire is
    /// seed-only today (see [`MLDSA_KEY_KIND_44_SEED`] /
    /// [`MLDSA_KEY_KIND_65_SEED`] / [`MLDSA_KEY_KIND_87_SEED`]).
    pub key_kind: u8,
}

/// Host-facing TBOR `MlDsaGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlDsaGenerateKeyResp {
    /// The generated ML-DSA private key, masked under the scope's masking
    /// key.  Always 164 B: the wire is seed-only, so the plaintext is the
    /// 32-byte `xi` seed.  See [`MASKED_MLDSA_KEY_MAX_LEN`].
    #[tbor(max_len = 5156)]
    pub masked_key: Vec<u8>,

    /// The ML-DSA public key bytes.
    #[tbor(max_len = 2592)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::MLDSA_KEY_KIND_44_SEED;
    use crate::MLDSA_KEY_KIND_65_SEED;
    use crate::MLDSA_KEY_KIND_87_SEED;

    #[test]
    fn request_encodes_seed_kind() {
        let req = TborMlDsaGenerateKeyReq {
            session_id: 7,
            scope: 0b011,
            key_kind: MLDSA_KEY_KIND_65_SEED,
        };
        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&MLDSA_KEY_KIND_65_SEED),
            "encoded frame must carry the key-kind discriminant",
        );
    }

    #[test]
    fn request_encodes_every_seed_kind() {
        for kind in [
            MLDSA_KEY_KIND_44_SEED,
            MLDSA_KEY_KIND_65_SEED,
            MLDSA_KEY_KIND_87_SEED,
        ] {
            let req = TborMlDsaGenerateKeyReq {
                session_id: 7,
                scope: 0b011,
                key_kind: kind,
            };
            let mut buf = [0u8; 256];
            let frame = req.encode_request(&mut buf).expect("encode");
            assert!(
                frame.contains(&kind),
                "encoded frame must carry the key-kind discriminant",
            );
        }
    }

    #[test]
    fn seed_kind_discriminants_are_contiguous_from_46() {
        assert_eq!(MLDSA_KEY_KIND_44_SEED, 46);
        assert_eq!(MLDSA_KEY_KIND_65_SEED, 47);
        assert_eq!(MLDSA_KEY_KIND_87_SEED, 48);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(5156 == MASKED_MLDSA_KEY_MAX_LEN);
        const _: () = assert!(2592 == MLDSA_PUB_KEY_MAX_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
        const _: () = assert!(255 == MLDSA_CTX_MAX_LEN);
        const _: () = assert!(586 == MLDSA_MESSAGE_MAX_LEN);
        assert_eq!(MASKED_MLDSA_KEY_MAX_LEN, 5156);
    }

    /// The message cap is the residue of the worst-case `MlDsaVerify`
    /// request against the host encoder's 8192-byte staging budget.
    #[test]
    fn message_cap_is_the_mldsa_verify_staging_residue() {
        const TRANSPORT_BUF_LEN: usize = 8192;
        const STAGE_OFFSET: usize = 132;

        assert_eq!(
            TRANSPORT_BUF_LEN
                - STAGE_OFFSET
                - MLDSA_PUB_KEY_MAX_LEN
                - MLDSA_SIGNATURE_MAX_LEN
                - MLDSA_CTX_MAX_LEN,
            MLDSA_MESSAGE_MAX_LEN,
        );
    }
}
