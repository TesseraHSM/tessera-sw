// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemGenerateKey` wire schema.
//!
//! `MlKemGenerateKey` is an in-session command that generates a fresh
//! ML-KEM (FIPS 203) keypair for the requested PQC key kind and returns
//! the decapsulation key as a **masked** blob plus the encapsulation
//! public key.  The private key is **not** stored on the device: the
//! caller holds the masked blob and passes it back to
//! [`MlKemDecapsulate`](crate::mlkem_decapsulate) (unmask-on-use).  This
//! is the TBOR analogue of MBOR `MlkemGenerateKey`, but without a vault
//! `private_key_id`.
//!
//! Requests are bound to an active session.

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;

/// TBOR opcode for `MlKemGenerateKey`.
pub const TBOR_OP_MLKEM_GENERATE_KEY: u8 = 0x29;

/// Maximum masked ML-KEM decapsulation-key envelope length.
///
/// The plaintext is the 64-byte `(d, z)` seed pair followed by the
/// expanded decapsulation key. ML-KEM-1024 needs
/// `64 + 3168 + 232 = 3464` bytes including the AEAD-GCM-256 envelope:
/// header 8 + IV 16 + AAD 192 + tag 16. Masked lengths are
/// 1928 / 2696 / 3464 bytes for ML-KEM-512 / -768 / -1024.
///
/// Pinned into the `#[tbor(buffer, max_len = 3464)]` literal on
/// [`TborMlKemGenerateKeyResp::masked_key`].
pub const MASKED_MLKEM_KEY_MAX_LEN: usize = 8 + 16 + 192 + 64 + 3168 + 16;

/// Maximum ML-KEM public-key / encapsulation-key length: 1568 bytes for
/// ML-KEM-1024.  Pinned into the `#[tbor(buffer, max_len = 1568)]` literal
/// on [`TborMlKemGenerateKeyResp::pub_key`].
pub const MLKEM_PUB_KEY_MAX_LEN: usize = 1568;

/// Maximum ML-KEM ciphertext length: 1568 bytes for ML-KEM-1024.  Shared
/// by `MlKemEncapsulate` / `MlKemDecapsulate`.
pub const MLKEM_CIPHERTEXT_MAX_LEN: usize = 1568;

/// Maximum masked shared-secret length.  ML-KEM shared secrets are 32
/// bytes for all parameter sets, carried as `header(8) ‖ iv(16) ‖ aad(192)
/// ‖ pt(32) ‖ tag(16)`.
pub const MASKED_MLKEM_SHARED_SECRET_MAX_LEN: usize = 8 + 16 + 192 + 32 + 16;

/// ML-KEM key-kind selector on the TBOR wire — a wire-side mirror of the
/// ML-KEM subset of the firmware
/// [`HsmVaultKeyKind`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind) enum.
///
/// The 1-byte discriminants MUST stay byte-identical to `HsmVaultKeyKind`
/// so the two convert losslessly.  A kind encodes both the parameter set
/// and the decapsulation-key representation, following the existing vault
/// taxonomy where each algorithm/variant/format pair is its own kind (the
/// same way fixed- and variable-length HMAC keys are distinct kinds).
///
/// Only the three `Seed` kinds (55-57) are accepted. Their masked blobs
/// contain the 64-byte `(d, z)` seed pair followed by the expanded
/// decapsulation key. The seeds support public-key regeneration;
/// decapsulation uses the expanded key directly. Separate `Private`
/// kinds are not exposed by this wire enum.
///
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips as
/// `MlKemKeyKind(x)` and is rejected on-device rather than failing to
/// decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemKeyKind {
    /// ML-KEM-512 compact `(d, z)` seed material (64 B).
    MlKem512Seed = 55,
    /// ML-KEM-768 compact `(d, z)` seed material (64 B).
    MlKem768Seed = 56,
    /// ML-KEM-1024 compact `(d, z)` seed material (64 B).
    MlKem1024Seed = 57,
}

/// `MlKemGenerateKey` request schema.
#[tbor(opcode = 0x29, pair = TborMlKemGenerateKeyResp)]
pub struct TborMlKemGenerateKeyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the decapsulation key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Requested ML-KEM private key kind, 1-byte [`MlKemKeyKind`].  The kind
    /// encodes the parameter set; the wire is seed-only today.
    #[tbor(U8)]
    pub key_kind: MlKemKeyKind,
}

/// `MlKemGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the decapsulation key straight into it (`decode_mut`).
#[tbor(response, pair = TborMlKemGenerateKeyReq)]
pub struct TborMlKemGenerateKeyResp<'a> {
    /// The generated ML-KEM decapsulation key, masked (AEAD-GCM-256)
    /// under the scope's masking key. The plaintext is the 64-byte seed
    /// pair followed by the expanded decapsulation key. See
    /// [`MASKED_MLKEM_KEY_MAX_LEN`].
    #[tbor(align = 4, buffer, max_len = 3464, mutable)]
    pub masked_key: &'a [u8],

    /// The ML-KEM public / encapsulation key.  Up to 1568 B for ML-KEM-1024.
    #[tbor(buffer, max_len = 1568, mutable)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_seed_kind() {
        let mut buf = [0u8; 256];
        let frame = TborMlKemGenerateKeyReq::encode(&mut buf, (1, 1))
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_kind(MlKemKeyKind::MlKem768Seed)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.key_kind(), MlKemKeyKind::MlKem768Seed);
    }

    #[test]
    fn request_round_trips_every_seed_kind() {
        for kind in [
            MlKemKeyKind::MlKem512Seed,
            MlKemKeyKind::MlKem768Seed,
            MlKemKeyKind::MlKem1024Seed,
        ] {
            let mut buf = [0u8; 256];
            let frame = TborMlKemGenerateKeyReq::encode(&mut buf, (1, 1))
                .unwrap()
                .session_id(SessionId(1))
                .unwrap()
                .scope(KeyScope::Local)
                .unwrap()
                .key_kind(kind)
                .unwrap()
                .finish();

            assert_eq!(frame.key_kind(), kind);
        }
    }

    #[test]
    fn seed_kind_discriminants_are_contiguous_from_55() {
        assert_eq!(MlKemKeyKind::MlKem512Seed, MlKemKeyKind(55));
        assert_eq!(MlKemKeyKind::MlKem768Seed, MlKemKeyKind(56));
        assert_eq!(MlKemKeyKind::MlKem1024Seed, MlKemKeyKind(57));
    }

    #[test]
    fn response_round_trips_masked_and_pub() {
        let mut buf = [0u8; 8192];
        let masked = [0xABu8; MASKED_MLKEM_KEY_MAX_LEN];
        let pub_key = [0xCDu8; MLKEM_PUB_KEY_MAX_LEN];
        let frame = TborMlKemGenerateKeyResp::encode(&mut buf, (1, 1), 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
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
