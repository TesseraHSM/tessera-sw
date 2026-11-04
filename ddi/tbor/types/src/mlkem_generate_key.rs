// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlKemGenerateKey` command.
//!
//! `MlKemGenerateKey` is (temporarily) an **out-of-session** command that generates a fresh ML-KEM keypair and returns the
//! decapsulation key as a **masked** blob plus the public encapsulation
//! key.  The private key is not stored on-device; the caller holds the
//! masked blob and passes it back to [`MlKemDecapsulate`](crate::mlkem_decapsulate).
//! `key_kind` is a raw 1-byte `MlKemKeyKind` discriminant (the firmware
//! types it as an open enum) byte-identical to the PQC subset of
//! `HsmVaultKeyKind`. It selects the ML-KEM parameter set.  The TBOR wire
//! ships **seed-only** decapsulation keys today, so the returned masked
//! blob always carries the compact 64-byte `(d ‖ z)` seed material.
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

/// TBOR opcode for `MlKemGenerateKey`.
pub const TBOR_OP_MLKEM_GENERATE_KEY: u8 = 0x29;

/// Maximum masked ML-KEM decapsulation-key envelope length.
///
/// The payload carries the 64-byte `(d ‖ z)` seed material followed by
/// the expanded decapsulation key (3168 B for ML-KEM-1024). Both lengths
/// are multiples of 16. The masked-envelope overhead is 232 B:
/// `header(8) + iv(16) + aad(192) + tag(16)`.
pub const MASKED_MLKEM_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 3168 + 16;
/// Maximum ML-KEM public-key / encapsulation-key length: 1568 B for ML-KEM-1024.
pub const MLKEM_PUB_KEY_MAX_LEN: usize = 1568;
/// Maximum ML-KEM ciphertext length: 1568 B for ML-KEM-1024.
pub const MLKEM_CIPHERTEXT_MAX_LEN: usize = 1568;
/// Maximum masked shared-secret length: 32-byte shared secret plus 232 B
/// of masked-envelope overhead.
pub const MASKED_MLKEM_SHARED_SECRET_MAX_LEN: usize = 8 + 16 + 192 + 32 + 16;

/// `MlKemKeyKind` discriminant for an ML-KEM-512 compact `(d, z)` seed (64 B).
pub const MLKEM_KEY_KIND_512_SEED: u8 = 55;
/// `MlKemKeyKind` discriminant for an ML-KEM-768 compact `(d, z)` seed (64 B).
pub const MLKEM_KEY_KIND_768_SEED: u8 = 56;
/// `MlKemKeyKind` discriminant for an ML-KEM-1024 compact `(d, z)` seed (64 B).
pub const MLKEM_KEY_KIND_1024_SEED: u8 = 57;

/// Host-facing TBOR `MlKemGenerateKey` request.
#[tbor(opcode = TBOR_OP_MLKEM_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborMlKemGenerateKeyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// Requested ML-KEM private key kind as the 1-byte `MlKemKeyKind`
    /// discriminant.  The kind encodes the parameter set; the wire is
    /// seed-only today (see [`MLKEM_KEY_KIND_512_SEED`] /
    /// [`MLKEM_KEY_KIND_768_SEED`] / [`MLKEM_KEY_KIND_1024_SEED`]).
    pub key_kind: u8,
}

/// Host-facing TBOR `MlKemGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlKemGenerateKeyResp {
    /// The generated ML-KEM decapsulation key, masked under the scope's
    /// masking key. The plaintext contains the 64-byte `(d ‖ z)` seed
    /// followed by the expanded decapsulation key. See
    /// [`MASKED_MLKEM_KEY_MAX_LEN`].
    #[tbor(max_len = 3464)]
    pub masked_key: Vec<u8>,

    /// The ML-KEM public / encapsulation key bytes.
    #[tbor(max_len = 1568)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::MLKEM_KEY_KIND_1024_SEED;
    use crate::MLKEM_KEY_KIND_512_SEED;
    use crate::MLKEM_KEY_KIND_768_SEED;

    #[test]
    fn request_encodes_seed_kind() {
        let req = TborMlKemGenerateKeyReq {
            session_id: 7,
            scope: 0b011,
            key_kind: MLKEM_KEY_KIND_768_SEED,
        };
        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&MLKEM_KEY_KIND_768_SEED),
            "encoded frame must carry the key-kind discriminant",
        );
    }

    #[test]
    fn request_encodes_every_seed_kind() {
        for kind in [
            MLKEM_KEY_KIND_512_SEED,
            MLKEM_KEY_KIND_768_SEED,
            MLKEM_KEY_KIND_1024_SEED,
        ] {
            let req = TborMlKemGenerateKeyReq {
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
    fn seed_kind_discriminants_are_contiguous_from_55() {
        assert_eq!(MLKEM_KEY_KIND_512_SEED, 55);
        assert_eq!(MLKEM_KEY_KIND_768_SEED, 56);
        assert_eq!(MLKEM_KEY_KIND_1024_SEED, 57);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(3464 == MASKED_MLKEM_KEY_MAX_LEN);
        const _: () = assert!(1568 == MLKEM_PUB_KEY_MAX_LEN);
        const _: () = assert!(1568 == MLKEM_CIPHERTEXT_MAX_LEN);
        const _: () = assert!(264 == MASKED_MLKEM_SHARED_SECRET_MAX_LEN);
        assert_eq!(MASKED_MLKEM_KEY_MAX_LEN, 3464);
    }
}
