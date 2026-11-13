// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-kind length contract.
//!
//! A single O(1) lookup table — indexed directly by the
//! [`HsmVaultKeyKind`] discriminant — is the *only* place that knows how
//! long a key of a given kind is. Every length decision in the vault
//! (create-time validation, storage cost, read-back, `vault_key_len`)
//! resolves through [`key_len`], so there is no per-kind branching
//! scattered through the code.
//!
//! The fixed sizes mirror the reference firmware's
//! `EntryKind::raw_key_blob_size()` and the variable HMAC min/max, so a
//! key stored here is byte-compatible with that firmware. The unit tests
//! pin every entry, so any drift fails the build.

use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::SESSION_AUTH_BINDING_LEN;
use tsra_fw_hsm_pal_traits::SESSION_MASKING_KEY_LEN;
use tsra_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;
use tsra_fw_hsm_pal_traits::SESSION_PENDING_BLOB_MAX;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_KEY_LEN;

const SESSION_EX_LEN: u16 = (8
    + SESSION_PARAM_KEY_LEN
    + SESSION_MASKING_KEY_LEN
    + SESSION_AUTH_BINDING_LEN
    + 2 * SESSION_TRANSPORT_KEY_LEN) as u16;

/// Length contract for one key kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyLen {
    /// Key material is exactly `n` bytes; `key.len()` must equal it.
    Fixed(u16),

    /// Key material length is chosen at creation within `min..=max`. The
    /// actual length is persisted per entry (so read-back is exact).
    Variable {
        /// Minimum accepted length, inclusive.
        min: u16,
        /// Maximum accepted length, inclusive.
        max: u16,
    },

    /// Not a real key kind (`Free` or reserved/unknown discriminant).
    Invalid,
}

impl KeyLen {
    /// Largest byte length a key of this kind can occupy.
    ///
    /// Returns the fixed size for [`Fixed`](KeyLen::Fixed) and the upper
    /// bound for [`Variable`](KeyLen::Variable).
    #[inline]
    pub fn max_len(self) -> Option<u16> {
        match self {
            KeyLen::Fixed(n) => Some(n),
            KeyLen::Variable { max, .. } => Some(max),
            KeyLen::Invalid => None,
        }
    }

    /// Validates a supplied key length against this contract and returns
    /// the length to persist.
    ///
    /// - [`Fixed`](KeyLen::Fixed): `actual` must equal the fixed size.
    /// - [`Variable`](KeyLen::Variable): `actual` must be in `min..=max`.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] if `actual` violates the contract or the
    ///   kind is [`Invalid`](KeyLen::Invalid).
    #[inline]
    pub fn check(self, actual: usize) -> HsmResult<u16> {
        match self {
            KeyLen::Fixed(n) if actual == usize::from(n) => Ok(n),
            KeyLen::Variable { min, max }
                if (usize::from(min)..=usize::from(max)).contains(&actual) =>
            {
                Ok(actual as u16)
            }
            _ => Err(HsmError::InvalidArg),
        }
    }
}

/// Stored length of an AES bulk (GCM / XTS) key.
///
/// With `bulk_crypto` the fast-path engine holds the material and the vault
/// keeps only its 2-byte handle (as the reference firmware did); otherwise
/// the HSM runs bulk crypto itself and the vault keeps the AES-256 key.
pub const BULK_KEY_LEN: u16 = if cfg!(feature = "bulk_crypto") { 2 } else { 32 };

/// Per-kind length table, indexed by `HsmVaultKeyKind` discriminant.
///
/// Mirrors the reference firmware's `raw_key_blob_size()` (fixed kinds)
/// and var-HMAC min/max. `SessionExPending` holds the in-flight TBOR
/// Pending blob (up to [`SESSION_PENDING_BLOB_MAX`]).
///
/// # `SessionEx`
///
/// Built by `session_promote` in `fw/plat/uno/fw/pal/src/session.rs`:
/// `api_rev(8) ‖ param_key(32) ‖ masking_key(32) ‖ auth_binding(68) ‖
/// h2m(32) ‖ m2h(32)` = 204 bytes.
///
/// **Do not derive this from `SESSION_MASKING_KEY_SIZE` (80).** That is
/// the *legacy CBC* masking key used by the MBOR `Session` kind;
/// `SessionEx` uses the 32-byte AES-256-GCM AEAD key
/// ([`SESSION_MASKING_KEY_LEN`]). `session_ex_len_is_derived_from_pal_layout`
/// pins the size to the PAL constants so it cannot drift.
static KIND_LEN: [KeyLen; 65] = [
    /* 0  Free                         */ KeyLen::Invalid,
    /* 1  Rsa2kPublic                  */ KeyLen::Fixed(260),
    /* 2  Rsa3kPublic                  */ KeyLen::Fixed(388),
    /* 3  Rsa4kPublic                  */ KeyLen::Fixed(516),
    /* 4  Rsa2kPrivate                 */ KeyLen::Fixed(516),
    /* 5  Rsa3kPrivate                 */ KeyLen::Fixed(772),
    /* 6  Rsa4kPrivate                 */ KeyLen::Fixed(1028),
    /* 7  Rsa2kPrivateCrt              */ KeyLen::Fixed(1284),
    /* 8  Rsa3kPrivateCrt              */ KeyLen::Fixed(1924),
    /* 9  Rsa4kPrivateCrt              */ KeyLen::Fixed(2564),
    /* 10 Ecc256Public                 */ KeyLen::Fixed(64),
    /* 11 Ecc384Public                 */ KeyLen::Fixed(96),
    /* 12 Ecc521Public                 */ KeyLen::Fixed(136),
    /* 13 Ecc256Private                */ KeyLen::Fixed(32),
    /* 14 Ecc384Private                */ KeyLen::Fixed(48),
    /* 15 Ecc521Private                */ KeyLen::Fixed(68),
    /* 16 Aes128                       */ KeyLen::Fixed(16),
    /* 17 Aes192                       */ KeyLen::Fixed(24),
    /* 18 Aes256                       */ KeyLen::Fixed(32),
    /* 19 AesXtsBulk256                */ KeyLen::Fixed(BULK_KEY_LEN),
    /* 20 AesGcmBulk256                */ KeyLen::Fixed(BULK_KEY_LEN),
    /* 21 AesGcmBulk256Unapproved      */ KeyLen::Fixed(BULK_KEY_LEN),
    /* 22 Secret256                    */ KeyLen::Fixed(32),
    /* 23 Secret384                    */ KeyLen::Fixed(48),
    /* 24 Secret521                    */ KeyLen::Fixed(68),
    /* 25 EstablishCred                */ KeyLen::Fixed(144),
    /* 26 SessionEncryption            */ KeyLen::Fixed(144),
    /* 27 Session                      */ KeyLen::Fixed(88),
    /* 28 _HmacSha256                  */ KeyLen::Fixed(32),
    /* 29 _HmacSha384                  */ KeyLen::Fixed(48),
    /* 30 _HmacSha512                  */ KeyLen::Fixed(64),
    /* 31 MaskingKey                   */ KeyLen::Fixed(80),
    /* 32 VarLenHmacSha256             */ KeyLen::Variable { min: 32, max: 64 },
    /* 33 VarLenHmacSha384             */ KeyLen::Variable { min: 48, max: 128 },
    /* 34 VarLenHmacSha512             */ KeyLen::Variable { min: 64, max: 128 },
    /* 35 SessionExPending           */
    KeyLen::Variable {
        min: 32,
        max: SESSION_PENDING_BLOB_MAX as u16,
    },
    /* 36 SessionEx                    */
    KeyLen::Fixed(SESSION_EX_LEN),
    /* 37 PartitionTrustAnchor         */ KeyLen::Fixed(48),
    /* 38 UniquePartitionSecret */ KeyLen::Fixed(48),
    /* 39 PartitionLocalMaskingKey     */ KeyLen::Fixed(32),
    /* 40 PartitionEphemeralMaskingKey */ KeyLen::Fixed(32),
    /* 41 SdSealing                    */ KeyLen::Fixed(48),
    /* 42 SdMasking                    */ KeyLen::Fixed(32),
    /* 43 SdPartitionOwnerSeed         */ KeyLen::Fixed(48),
    /* 44 DarcKex                      */ KeyLen::Fixed(48),
    /* 45 DarcTmk                      */ KeyLen::Fixed(32),
    /* 46 MlDsa44Seed                  */ KeyLen::Fixed(32),
    /* 47 MlDsa65Seed                  */ KeyLen::Fixed(32),
    /* 48 MlDsa87Seed                  */ KeyLen::Fixed(32),
    /* 49 MlDsa44Private               */ KeyLen::Fixed(2560),
    /* 50 MlDsa65Private               */ KeyLen::Fixed(4032),
    /* 51 MlDsa87Private               */ KeyLen::Fixed(4896),
    /* 52 MlDsa44Public                */ KeyLen::Fixed(1312),
    /* 53 MlDsa65Public                */ KeyLen::Fixed(1952),
    /* 54 MlDsa87Public                */ KeyLen::Fixed(2592),
    /* 55 MlKem512Seed                 */ KeyLen::Fixed(64),
    /* 56 MlKem768Seed                 */ KeyLen::Fixed(64),
    /* 57 MlKem1024Seed                */ KeyLen::Fixed(64),
    /* 58 MlKem512Private              */ KeyLen::Fixed(1632),
    /* 59 MlKem768Private              */ KeyLen::Fixed(2400),
    /* 60 MlKem1024Private             */ KeyLen::Fixed(3168),
    /* 61 MlKem512Public               */ KeyLen::Fixed(800),
    /* 62 MlKem768Public               */ KeyLen::Fixed(1184),
    /* 63 MlKem1024Public              */ KeyLen::Fixed(1568),
    /* 64 AesXts512                    */ KeyLen::Fixed(64),
];

/// Resolves the length contract for `kind` in O(1).
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] if `kind` is [`Free`](HsmVaultKeyKind::Free).
/// - [`HsmError::InvalidKeyType`] if `kind` is a reserved/unknown
///   discriminant.
#[inline]
pub fn key_len(kind: HsmVaultKeyKind) -> HsmResult<KeyLen> {
    let idx = usize::from(kind.0);
    match KIND_LEN.get(idx).copied().unwrap_or(KeyLen::Invalid) {
        KeyLen::Invalid if kind == HsmVaultKeyKind::Free => Err(HsmError::InvalidArg),
        KeyLen::Invalid => Err(HsmError::InvalidKeyType),
        spec => Ok(spec),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_fixed_kind_matches_reference_firmware() {
        // The full raw_key_blob_size table from the reference firmware.
        let table = [
            (HsmVaultKeyKind::Rsa2kPublic, 260),
            (HsmVaultKeyKind::Rsa3kPublic, 388),
            (HsmVaultKeyKind::Rsa4kPublic, 516),
            (HsmVaultKeyKind::Rsa2kPrivate, 516),
            (HsmVaultKeyKind::Rsa3kPrivate, 772),
            (HsmVaultKeyKind::Rsa4kPrivate, 1028),
            (HsmVaultKeyKind::Rsa2kPrivateCrt, 1284),
            (HsmVaultKeyKind::Rsa3kPrivateCrt, 1924),
            (HsmVaultKeyKind::Rsa4kPrivateCrt, 2564),
            (HsmVaultKeyKind::Ecc256Public, 64),
            (HsmVaultKeyKind::Ecc384Public, 96),
            (HsmVaultKeyKind::Ecc521Public, 136),
            (HsmVaultKeyKind::Ecc256Private, 32),
            (HsmVaultKeyKind::Ecc384Private, 48),
            (HsmVaultKeyKind::Ecc521Private, 68),
            (HsmVaultKeyKind::Aes128, 16),
            (HsmVaultKeyKind::Aes192, 24),
            (HsmVaultKeyKind::Aes256, 32),
            (HsmVaultKeyKind::AesXtsBulk256, BULK_KEY_LEN),
            (HsmVaultKeyKind::AesGcmBulk256, BULK_KEY_LEN),
            (HsmVaultKeyKind::AesGcmBulk256Unapproved, BULK_KEY_LEN),
            (HsmVaultKeyKind::Secret256, 32),
            (HsmVaultKeyKind::Secret384, 48),
            (HsmVaultKeyKind::Secret521, 68),
            (HsmVaultKeyKind::EstablishCred, 144),
            (HsmVaultKeyKind::SessionEncryption, 144),
            (HsmVaultKeyKind::Session, 88),
            (HsmVaultKeyKind::_HmacSha256, 32),
            (HsmVaultKeyKind::_HmacSha384, 48),
            (HsmVaultKeyKind::_HmacSha512, 64),
            (HsmVaultKeyKind::MaskingKey, 80),
            (HsmVaultKeyKind::PartitionTrustAnchor, 48),
            (HsmVaultKeyKind::UniquePartitionSecret, 48),
            (HsmVaultKeyKind::PartitionLocalMaskingKey, 32),
            (HsmVaultKeyKind::PartitionEphemeralMaskingKey, 32),
            (HsmVaultKeyKind::SdSealing, 48),
            (HsmVaultKeyKind::SdMasking, 32),
            (HsmVaultKeyKind::SdPartitionOwnerSeed, 48),
            (HsmVaultKeyKind::DarcKex, 48),
            (HsmVaultKeyKind::DarcTmk, 32),
            (HsmVaultKeyKind::MlDsa44Seed, 32),
            (HsmVaultKeyKind::MlDsa65Seed, 32),
            (HsmVaultKeyKind::MlDsa87Seed, 32),
            (HsmVaultKeyKind::MlDsa44Private, 2560),
            (HsmVaultKeyKind::MlDsa65Private, 4032),
            (HsmVaultKeyKind::MlDsa87Private, 4896),
            (HsmVaultKeyKind::MlDsa44Public, 1312),
            (HsmVaultKeyKind::MlDsa65Public, 1952),
            (HsmVaultKeyKind::MlDsa87Public, 2592),
            (HsmVaultKeyKind::MlKem512Seed, 64),
            (HsmVaultKeyKind::MlKem768Seed, 64),
            (HsmVaultKeyKind::MlKem1024Seed, 64),
            (HsmVaultKeyKind::MlKem512Private, 1632),
            (HsmVaultKeyKind::MlKem768Private, 2400),
            (HsmVaultKeyKind::MlKem1024Private, 3168),
            (HsmVaultKeyKind::MlKem512Public, 800),
            (HsmVaultKeyKind::MlKem768Public, 1184),
            (HsmVaultKeyKind::MlKem1024Public, 1568),
            (HsmVaultKeyKind::AesXts512, 64),
        ];
        for (kind, len) in table {
            assert_eq!(key_len(kind), Ok(KeyLen::Fixed(len)), "{kind:?}");
        }
    }

    #[test]
    fn free_is_invalid_arg() {
        assert_eq!(key_len(HsmVaultKeyKind::Free), Err(HsmError::InvalidArg));
    }

    #[test]
    fn unknown_discriminant_is_invalid_key_type() {
        // 200 is well outside the named 0..=41 range.
        assert_eq!(key_len(HsmVaultKeyKind(200)), Err(HsmError::InvalidKeyType));
    }

    #[test]
    fn fixed_lengths_match_reference_firmware() {
        // Spot-check the full fixed table against raw_key_blob_size().
        let cases = [
            (HsmVaultKeyKind::Rsa2kPublic, 260),
            (HsmVaultKeyKind::Rsa4kPrivateCrt, 2564),
            (HsmVaultKeyKind::Ecc256Public, 64),
            (HsmVaultKeyKind::Ecc521Private, 68),
            (HsmVaultKeyKind::Aes128, 16),
            (HsmVaultKeyKind::Aes256, 32),
            (HsmVaultKeyKind::AesXtsBulk256, BULK_KEY_LEN),
            (HsmVaultKeyKind::Secret521, 68),
            (HsmVaultKeyKind::EstablishCred, 144),
            (HsmVaultKeyKind::Session, 88),
            (HsmVaultKeyKind::_HmacSha512, 64),
            (HsmVaultKeyKind::MaskingKey, 80),
            (HsmVaultKeyKind::PartitionTrustAnchor, 48),
            (HsmVaultKeyKind::UniquePartitionSecret, 48),
            (HsmVaultKeyKind::DarcKex, 48),
            (HsmVaultKeyKind::DarcTmk, 32),
            (HsmVaultKeyKind::MlDsa44Seed, 32),
            (HsmVaultKeyKind::MlDsa87Private, 4896),
            (HsmVaultKeyKind::MlDsa87Public, 2592),
            (HsmVaultKeyKind::MlKem512Seed, 64),
            (HsmVaultKeyKind::MlKem1024Private, 3168),
            (HsmVaultKeyKind::MlKem1024Public, 1568),
            (HsmVaultKeyKind::AesXts512, 64),
        ];
        for (kind, len) in cases {
            assert_eq!(key_len(kind), Ok(KeyLen::Fixed(len)), "{kind:?}");
        }
    }

    #[test]
    fn variable_kinds_have_reference_min_max() {
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha256),
            Ok(KeyLen::Variable { min: 32, max: 64 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha384),
            Ok(KeyLen::Variable { min: 48, max: 128 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha512),
            Ok(KeyLen::Variable { min: 64, max: 128 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::SessionExPending),
            Ok(KeyLen::Variable {
                min: 32,
                max: SESSION_PENDING_BLOB_MAX as u16
            })
        );
    }

    /// The `SessionEx` size is the blob the PAL actually writes, derived
    /// from the same `pal_traits` constants `session_promote` uses, so if
    /// any component key length changes this fails here rather than
    /// silently rejecting real sessions on hardware.
    #[test]
    fn session_ex_len_is_derived_from_pal_layout() {
        use tsra_fw_hsm_pal_traits::SESSION_MASKING_KEY_LEN;
        use tsra_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;
        use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_KEY_LEN;

        // `api_rev` prefix on every SessionEx blob (mirrors the uno PAL's
        // private `SESSION_API_REV_SIZE` in `session.rs`).
        const API_REV: usize = 8;

        let len = API_REV
            + SESSION_PARAM_KEY_LEN
            + SESSION_MASKING_KEY_LEN
            + SESSION_AUTH_BINDING_LEN
            + 2 * SESSION_TRANSPORT_KEY_LEN;
        assert_eq!(len, 204);
        assert_eq!(
            key_len(HsmVaultKeyKind::SessionEx),
            Ok(KeyLen::Fixed(len as u16))
        );
    }

    /// The `SessionEx` size is tight, and the Pending kind holds the
    /// largest handshake blob.
    #[test]
    fn session_ex_rejects_other_sizes() {
        let len = key_len(HsmVaultKeyKind::SessionEx).expect("SessionEx kind");
        assert_eq!(len.check(204), Ok(204));
        // The retired PlainText / Authenticated sizes are rejected.
        assert!(len.check(140).is_err());
        assert!(len.check(236).is_err());
        assert!(len.check(203).is_err());
        assert!(len.check(205).is_err());
        let pending = key_len(HsmVaultKeyKind::SessionExPending).expect("Pending kind");
        assert_eq!(pending.check(230), Ok(230));
        assert_eq!(pending.check(SESSION_PENDING_BLOB_MAX), Ok(256));
        assert!(pending.check(SESSION_PENDING_BLOB_MAX + 1).is_err());
    }

    #[test]
    fn check_validates_fixed_and_variable() {
        let aes = key_len(HsmVaultKeyKind::Aes256).unwrap();
        assert_eq!(aes.check(32), Ok(32));
        assert_eq!(aes.check(31), Err(HsmError::InvalidArg));

        let var = key_len(HsmVaultKeyKind::VarLenHmacSha256).unwrap();
        assert_eq!(var.check(32), Ok(32));
        assert_eq!(var.check(48), Ok(48));
        assert_eq!(var.check(64), Ok(64));
        assert_eq!(var.check(31), Err(HsmError::InvalidArg));
        assert_eq!(var.check(65), Err(HsmError::InvalidArg));
    }

    #[test]
    fn max_len_reports_upper_bound() {
        assert_eq!(
            key_len(HsmVaultKeyKind::Aes256).unwrap().max_len(),
            Some(32)
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha512)
                .unwrap()
                .max_len(),
            Some(128)
        );
    }
}
