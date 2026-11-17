// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared and generic secret key types.
//!
//! This module provides an HSM-managed shared-secret wrapper for ECDH results and
//! key-derivation operations.
//!
//! The primary use case is derived secrets (for example, an ECDH shared secret). The returned
//! value is still an HSM-managed key handle with associated properties; callers should set
//! appropriate usage flags and lifetimes via `HsmKeyProps` when creating/deriving the secret.
//! The wrapper also carries AES and HMAC derivation outputs until they are converted to
//! their concrete key wrappers; its properties retain the actual key kind.
//! Imported generic secrets are distinct keys used only as KBKDF inputs.

// Re-export shared algo/key types from the parent module.
pub use super::*;

// A shared secret key stored in the HSM.
//
// This type represents ECDH shared secrets and also carries AES/HMAC derivation outputs.
// The associated properties retain the actual key kind for conversion to a typed key wrapper.
define_hsm_key!(pub HsmSharedSecretKey);

impl HsmSharedSecretKey {
    /// Validates that these key properties describe a well-formed shared secret key.
    ///
    /// Used when creating or restoring a shared secret. KDF output properties are
    /// validated separately because their concrete kinds are AES or HMAC.
    ///
    /// Requirements enforced here:
    /// - `class` must be [`HsmKeyClass::Secret`]
    /// - `kind` must be [`HsmKeyKind::SharedSecret`]
    /// - `ecc_curve` must be `None`
    /// - `bits` must be non-zero
    /// - `DERIVE` must be set, with no other operation permissions
    pub(crate) fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        if props.kind() != HsmKeyKind::SharedSecret {
            Err(HsmError::InvalidKeyProps)?;
        }

        if !props.check_supported_flags(HsmKeyFlags::DERIVE) || !props.can_derive() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Secret keys in this layer should not have an associated ECC curve.
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check if key size is non-zero
        if props.bits() == 0 {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

impl HsmDerivationKey for HsmSharedSecretKey {}

impl HsmSecretKey for HsmSharedSecretKey {}

/// Algorithm for unmasking a shared secret key.
///
/// Rejects blobs containing other key kinds, including AES and HMAC KDF outputs.
#[derive(Default)]
pub struct HsmSharedSecretKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmSharedSecretKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmSharedSecretKey;
    type Error = HsmError;

    /// Unmasks a shared secret key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked secret key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked shared secret key on success.
    fn unmask_key(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;

        //construct key guard first to ensure handles are released if validation fails
        let key_id = ddi::HsmKeyIdGuard::new(session, handle);

        // Validate key props
        HsmSharedSecretKey::validate_props(&props)?;

        let key = HsmSharedSecretKey::new(session.clone(), props.clone(), key_id.release());

        Ok(key)
    }
}

// An imported HSM-managed generic secret. No generation operation is provided.
define_hsm_key!(pub HsmGenericSecretKey);

impl HsmGenericSecretKey {
    /// Minimum supported key size in bits (TSRA policy, not a PKCS#11 limit).
    pub const MIN_BITS: u32 = 128;
    /// Maximum supported key size in bits (TSRA policy, not a PKCS#11 limit).
    pub const MAX_BITS: u32 = 1024;

    pub(crate) fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        if props.class() != HsmKeyClass::Secret
            || props.kind() != HsmKeyKind::GenericSecret
            || props.ecc_curve().is_some()
            || !(Self::MIN_BITS..=Self::MAX_BITS).contains(&props.bits())
            || !props.bits().is_multiple_of(8)
            || !props.can_derive()
            || !props.check_supported_flags(HsmKeyFlags::DERIVE)
            || props.is_local()
        {
            return Err(HsmError::InvalidKeyProps);
        }
        Ok(())
    }
}

impl HsmSecretKey for HsmGenericSecretKey {}
impl HsmDerivationKey for HsmGenericSecretKey {}

/// Imports a generic secret using RSA-OAEP/AES-KWP wrapped key material.
pub struct HsmGenericSecretKeyRsaAesKeyUnwrapAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmGenericSecretKeyRsaAesKeyUnwrapAlgo {
    /// Selects the OAEP hash used by the wrapping operation.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmKeyUnwrapOp for HsmGenericSecretKeyRsaAesKeyUnwrapAlgo {
    type UnwrappingKey = HsmRsaPrivateKey;
    type Key = HsmGenericSecretKey;
    type Error = HsmError;

    fn unwrap_key(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        key_props: HsmKeyProps,
    ) -> HsmResult<Self::Key> {
        HsmGenericSecretKey::validate_props(&key_props)?;
        if !unwrapping_key.can_unwrap() {
            return Err(HsmError::UnsupportedKeyOperation);
        }
        let (handle, props) =
            ddi::rsa_aes_unwrap_key(unwrapping_key, wrapped_key, self.hash_algo, key_props)?;
        let session = unwrapping_key.session();
        let guard = ddi::HsmKeyIdGuard::new(&session, handle);
        HsmGenericSecretKey::validate_props(&props)?;
        Ok(HsmGenericSecretKey::new(
            session.clone(),
            props,
            guard.release(),
        ))
    }
}

/// Restores an imported generic secret from its authenticated masked blob.
#[derive(Default)]
pub struct HsmGenericSecretKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmGenericSecretKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmGenericSecretKey;
    type Error = HsmError;

    fn unmask_key(&mut self, session: &HsmSession, masked_key: &[u8]) -> HsmResult<Self::Key> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;
        let guard = ddi::HsmKeyIdGuard::new(session, handle);
        HsmGenericSecretKey::validate_props(&props)?;
        Ok(HsmGenericSecretKey::new(
            session.clone(),
            props,
            guard.release(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(bits: u32, kind: HsmKeyKind, flags: HsmKeyFlags) -> HsmKeyProps {
        HsmKeyProps::new(HsmKeyClass::Secret, kind, bits, None, flags, Vec::new())
    }

    #[test]
    fn generic_secret_accepts_byte_aligned_sizes_including_nist_inputs() {
        for bytes in [16, 17, 20, 32, 48, 64, 127, 128] {
            for flags in [
                HsmKeyFlags::DERIVE,
                HsmKeyFlags::DERIVE | HsmKeyFlags::SESSION,
            ] {
                assert!(
                    HsmGenericSecretKey::validate_props(&props(
                        bytes * 8,
                        HsmKeyKind::GenericSecret,
                        flags,
                    ))
                    .is_ok()
                );
            }
        }
        for bits in [0, 120, 129, 1023, 1032, u32::MAX] {
            assert!(
                HsmGenericSecretKey::validate_props(&props(
                    bits,
                    HsmKeyKind::GenericSecret,
                    HsmKeyFlags::DERIVE,
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn generic_secret_rejects_other_types_and_non_import_derive_permissions() {
        for kind in [
            HsmKeyKind::SharedSecret,
            HsmKeyKind::Aes,
            HsmKeyKind::HmacSha256,
        ] {
            assert!(
                HsmGenericSecretKey::validate_props(&props(256, kind, HsmKeyFlags::DERIVE))
                    .is_err()
            );
        }
        for flags in [
            HsmKeyFlags::empty(),
            HsmKeyFlags::DERIVE | HsmKeyFlags::LOCAL,
            HsmKeyFlags::DERIVE | HsmKeyFlags::SIGN,
            HsmKeyFlags::DERIVE | HsmKeyFlags::ENCRYPT,
            HsmKeyFlags::DERIVE | HsmKeyFlags::UNWRAP,
        ] {
            assert!(
                HsmGenericSecretKey::validate_props(&props(256, HsmKeyKind::GenericSecret, flags,))
                    .is_err()
            );
        }
        for (class, curve) in [
            (HsmKeyClass::Public, None),
            (HsmKeyClass::Private, None),
            (HsmKeyClass::Secret, Some(HsmEccCurve::P256)),
        ] {
            let props = HsmKeyProps::new(
                class,
                HsmKeyKind::GenericSecret,
                256,
                curve,
                HsmKeyFlags::DERIVE,
                Vec::new(),
            );
            assert!(HsmGenericSecretKey::validate_props(&props).is_err());
        }
    }
}
