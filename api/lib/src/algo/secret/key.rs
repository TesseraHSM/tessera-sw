// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared secret key types.
//!
//! This module provides an HSM-managed shared-secret wrapper for ECDH results and
//! key-derivation operations.
//!
//! The primary use case is derived secrets (for example, an ECDH shared secret). The returned
//! value is still an HSM-managed key handle with associated properties; callers should set
//! appropriate usage flags and lifetimes via `HsmKeyProps` when creating/deriving the secret.
//! The wrapper also carries AES and HMAC derivation outputs until they are converted to
//! their concrete key wrappers; its properties retain the actual key kind.

// Re-export shared algo/key types from the parent module.
pub use super::*;

// A shared secret key stored in the HSM.
//
// This type represents ECDH shared secrets and also carries AES/HMAC derivation outputs.
// The associated properties retain the actual key kind for conversion to a typed key wrapper.
define_hsm_key!(pub HsmSharedSecretKey);

impl HsmSharedSecretKey {
    /// Returns whether `props.kind()` is supported by this wrapper and whether its
    /// usage flags are valid for that kind.
    ///
    /// Supported kinds in this layer:
    /// - [`HsmKeyKind::SharedSecret`] (allowed flags: `DERIVE`)
    /// - [`HsmKeyKind::Aes`] (allowed flags: `ENCRYPT | DECRYPT`)
    /// - [`HsmKeyKind::HmacSha256`]/[`HsmKeyKind::HmacSha384`]/[`HsmKeyKind::HmacSha512`]
    ///   (allowed flags: `SIGN | VERIFY`)
    ///
    /// Note: [`HsmKeyProps::check_supported_flags`] permits the global `SESSION` flag in
    /// addition to the per-kind flags listed above.
    fn check_key_kind(props: &HsmKeyProps) -> bool {
        let supported_flag = match props.kind() {
            HsmKeyKind::SharedSecret => HsmKeyFlags::DERIVE,
            HsmKeyKind::Aes => HsmKeyFlags::ENCRYPT | HsmKeyFlags::DECRYPT,
            HsmKeyKind::HmacSha256 | HsmKeyKind::HmacSha384 | HsmKeyKind::HmacSha512 => {
                HsmKeyFlags::SIGN | HsmKeyFlags::VERIFY
            }
            _ => return false,
        };
        props.check_supported_flags(supported_flag)
    }

    /// Returns whether `props.flags()` contains the required usage flags for `props.kind()`.
    ///
    /// Required flags per supported kind:
    /// - [`HsmKeyKind::SharedSecret`] must contain `DERIVE`
    /// - [`HsmKeyKind::Aes`] must contain `ENCRYPT | DECRYPT`
    /// - [`HsmKeyKind::HmacSha256`]/[`HsmKeyKind::HmacSha384`]/[`HsmKeyKind::HmacSha512`]
    ///   must contain `SIGN | VERIFY`
    ///
    /// Any other kind is rejected.
    fn check_key_usage(props: &HsmKeyProps) -> bool {
        //check if key usage flags are valid for the key kind
        match props.kind() {
            HsmKeyKind::SharedSecret => props.can_derive(),
            HsmKeyKind::Aes => props.can_encrypt() && props.can_decrypt(),
            HsmKeyKind::HmacSha256 | HsmKeyKind::HmacSha384 | HsmKeyKind::HmacSha512 => {
                props.can_sign() && props.can_verify()
            }
            _ => false,
        }
    }

    /// Validates that these key properties describe a well-formed shared secret key.
    ///
    /// This is used by higher-level operations (e.g. ECDH/HKDF) to fail fast before issuing
    /// DDI calls when the requested key metadata is inconsistent.
    ///
    /// Requirements enforced here:
    /// - `class` must be [`HsmKeyClass::Secret`]
    /// - `kind` must be supported by this wrapper (see [`Self::check_key_kind`])
    /// - `ecc_curve` must be `None`
    /// - `bits` must be non-zero
    pub(crate) fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        // Kind/class: ensure we're validating a secret key.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check key kind, HsmSharedSecretKey can be of kind SharedSecret, AES or HMAC
        if !Self::check_key_kind(props) {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check key usage flags, HsmSharedSecretKey can be of kind SharedSecret, AES or HMAC
        if !Self::check_key_usage(props) {
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
