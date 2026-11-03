// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-key decode path.
//!
//! Classifies a raw 16 / 24 / 32-byte AES key into its vault kind and
//! returns the [`DecodedKey`](super::DecodedKey) the caller persists.
//! Any other byte length is a host contract violation.  The raw key is
//! itself the vault material.  A raw 64-byte AES-256-XTS key (`K1 ‖ K2`)
//! is classified as [`HsmVaultKeyKind::AesXts512`].

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::HSM_AES_XTS_KEY_LEN;

use super::DecodedKey;

/// Classify a raw AES key (16 / 24 / 32 B).
pub(super) fn decode(material: &HsmDmaBuf) -> HsmResult<DecodedKey<'_>> {
    let kind = match material.len() {
        16 => HsmVaultKeyKind::Aes128,
        24 => HsmVaultKeyKind::Aes192,
        32 => HsmVaultKeyKind::Aes256,
        _ => return Err(HsmError::InvalidArg),
    };

    // Symmetric — no public key.
    Ok(DecodedKey {
        kind,
        material,
        pub_key: None,
    })
}

/// Classify a raw AES-256-XTS key (`K1 ‖ K2`, 64 B).
///
/// IEEE 1619 requires the data key `K1` and tweak key `K2` to differ; the
/// halves are compared without early exit so timing does not reveal where
/// they first diverge.
pub(super) fn decode_xts(material: &HsmDmaBuf) -> HsmResult<DecodedKey<'_>> {
    if material.len() != HSM_AES_XTS_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let (k1, k2) = material.split_at(HSM_AES_XTS_KEY_LEN / 2);
    let diff = k1
        .iter()
        .zip(k2.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff == 0 {
        return Err(HsmError::InvalidArg);
    }

    Ok(DecodedKey {
        kind: HsmVaultKeyKind::AesXts512,
        material,
        pub_key: None,
    })
}
