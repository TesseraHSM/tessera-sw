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
/// expanded secret key**, seed first: `32 + 4896 + 232 = 5160` B at
/// ML-DSA-87, where 232 is the AEAD-GCM-256 masked-envelope overhead
/// `header(8) + iv(16) + aad(192) + tag(16)`. The payload is padded to 16 B.
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
/// Note this makes the masked length **parameter-set dependent** (2824 /
/// 4296 / 5160 for ML-DSA-44 / 65 / 87), where the seed-only form is a
/// constant 264 regardless. The `key_kind` in the AAD is therefore no
/// longer the only thing distinguishing parameter sets.
pub const MASKED_MLDSA_KEY_MAX_LEN: usize = 8 + 16 + 192 + 32 + 4896 + 16;
/// Maximum ML-DSA public-key length: 2592 B for ML-DSA-87.
pub const MLDSA_PUB_KEY_MAX_LEN: usize = 2592;
/// Maximum ML-DSA signature length: 4627 B for ML-DSA-87.
pub const MLDSA_SIGNATURE_MAX_LEN: usize = 4627;
/// Length of the ML-DSA message representative `μ`, the input of `MlDsaSign`
/// and `MlDsaVerify`.
///
/// `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`, with
/// `tr = SHAKE256(pk, 64)`, is what pure ML-DSA signs for a message `M` under
/// the FIPS 204 context string `ctx`.  The commands take `μ`, as `EccSign`
/// takes a digest, rather than the message: compute it on the host, or on
/// the device with `Hash` (SHAKE256).
pub const MLDSA_MU_LEN: usize = 64;

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
    #[tbor(max_len = 5160)]
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
        const _: () = assert!(5160 == MASKED_MLDSA_KEY_MAX_LEN);
        const _: () = assert!(2592 == MLDSA_PUB_KEY_MAX_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
        const _: () = assert!(64 == MLDSA_MU_LEN);
        assert_eq!(MASKED_MLDSA_KEY_MAX_LEN, 5160);
    }
}
