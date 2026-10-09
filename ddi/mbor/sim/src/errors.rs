// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Errors reported by Tessera HSM operations.

use tsra_ddi_mbor_types::DdiStatus;
// Imports for use in doc links.
#[allow(unused)]
use {crate::session::UserSession, uuid::Uuid};

/// Errors reported by Tessera HSM operations.
///
/// # Links
/// * [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
/// * [CBOR](https://en.wikipedia.org/wiki/CBOR)
/// * [PKCS8](https://en.wikipedia.org/wiki/PKCS_8)
///
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TesseraError {
    /// The argument is invalid.
    InvalidArgument,

    /// Unexpected failure
    InternalError,

    /// A session is not expected in this context.
    SessionNotExpected,

    /// A session is not expected in this context.
    SessionExpected,

    /// Not enough space exists to store keys.
    NotEnoughSpace,

    /// The maximum number of keys that can be stored has been reached.
    ReachedMaxKeys,

    /// The supplied key index is invalid.
    InvalidKeyIndex,

    /// The key could not be deleted because it is in use. Please try to delete it again later.
    /// However, it has been disabled for new requests.
    CannotDeleteKeyInUse,

    /// More than one keys could not be deleted because they are in use. Please try to delete them again later.
    /// However, they have been disabled for new requests.
    CannotDeleteSomeKeysInUse,

    /// The session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSessionInUse,

    /// More than one session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSomeSessionsInUse,

    /// Both at least one session and one key, each, could not be closed or deleted. Please try to close it again later.
    /// However, both session(s) and key(s) have been disabled for new requests.
    CannotDeleteKeyAndCloseSessionInUse,

    /// The app with given [Uuid] does not exist.
    AppNotFound,

    /// An app with given key already exists.
    AppAlreadyExists,

    /// The supplied key number is invalid.
    InvalidKeyNumber,

    /// The key was not found.
    KeyNotFound,

    /// Another key with given tag already exists.
    KeyTagAlreadyExists,

    /// This key can only be set once
    KeyAlreadyExists,

    /// The vault with given [Uuid] does not exist.
    VaultNotFound,

    /// The maximum number of sessions that can be active on the vault has been reached.
    VaultSessionLimitReached,

    /// The maximum number of apps that can be created have been created.
    VaultAppLimitReached,

    /// The supplied credentials are invalid.
    InvalidVaultManagerCredentials,

    /// The supplied credentials are invalid.
    InvalidAppCredentials,

    /// The credentials are default values, and should be changed before some operations.
    CannotUseDefaultCredentials,

    /// The supplied [Uuid] is reserved for internal use.
    /// Note: mapped to DdiStatus::EInvalidarg
    CannotUseReservedId,

    /// [AppSession] with given id does not exit.
    SessionNotFound,

    /// Session exists but needs renegotiation.
    SessionNeedsRenegotiation,

    /// The function is not found.
    FunctionNotFound,

    /// Unsupported API revision.
    UnsupportedRevision,

    /// Generic invalid key type error.
    InvalidKeyType,

    /// DER-encoded content does not decode to provided key type.
    DerAndKeyTypeMismatch,

    /// The key could not be read from DER-encoded format.
    RsaFromDerError,

    /// The key could not be converted to DER-encoded format.
    RsaToDerError,

    /// RSA key generation failed.
    RsaGenerateError,

    /// RSA encryption failed.
    RsaEncryptError,

    /// RSA decryption failed.
    RsaDecryptError,

    /// RSA signing failed.
    RsaSignError,

    /// RSA verification failed.
    RsaVerifyError,

    /// Get RSA modulus failed.
    RsaGetModulusError,

    /// Get RSA public exponent failed.
    RsaGetPublicExponentError,

    /// The key used for a cryptographic operation does not have expected type.
    RsaInvalidKeyType,

    /// The length of requested key is invalid. It can only be one of `[2048, 3072, 4096]`.
    RsaInvalidKeyLength,

    /// Not enough permissions to execute the requested operation.
    InvalidPermissions,

    /// Decoding from CBOR representation failed.
    CborDecodeError,

    /// Encoding to CBOR representation failed.
    CborEncodeError,

    /// The key could not be read from DER-encoded format.
    EccFromDerError,

    /// The key could not be converted to DER-encoded format.
    EccToDerError,

    /// ECC key generation failed.
    EccGenerateError,

    /// ECC signing failed.
    EccSignError,

    /// ECC verification failed.
    EccVerifyError,

    /// ECC Key derivation failed.
    EccDeriveError,

    /// Get ECC curve failed.
    EccGetCurveError,

    /// Get ECC coordinates failed.
    EccGetCoordinatesError,

    /// Sha computation failed.
    ShaError,

    /// The key used for a cryptographic operation does not have expected type.
    EccInvalidKeyType,

    /// AES Generate failed.
    AesGenerateError,

    /// AES Encryption failed.
    AesEncryptError,

    /// AES Decryption failed.
    AesDecryptError,

    /// The key used for a cryptographic operation does not have expected type.
    AesInvalidKeyType,

    /// The CoseSign1 signature is unexpected.
    CoseSign1UnexpectedSignature,

    /// HKDF failed.
    HkdfError,

    /// KBKDF failed.
    KbkdfError,

    /// HMAC operation failed.
    HmacError,

    /// PIN decryption failed because of tag/Hmac mismatch
    PinDecryptionFailed,

    /// RSA unwrap invalid request.
    RsaUnwrapInvalidReq,

    /// RSA unwrap invalid unwrapping key.
    RsaUnwrapInvalidUnwrappingKeyLength,

    /// RSA-Oaep decryption failed during RSA unwrap command.
    RsaUnwrapRsaOaepDecryptFailed,

    /// AES unwrap failed during RSA unwrap command.
    RsaUnwrapAesUnwrapFailed,

    /// Attest Key internal errors
    AttestKeyInternalErr,

    /// FP AES error codes
    /// AesGcmInvalidBufSize
    ///  buffer size is not valid
    ///
    AesGcmInvalidBufSize,

    /// AesInvalidShortAppId
    /// Short app id provided is not
    /// valid
    AesInvalidShortAppId,

    /// AesInvalidTag
    AesInvalidTag,

    /// FP AES XTS error code
    AesXtsInvalidBufSize,

    /// Data unit length provided
    /// is not valid
    AesXtsInvalidDul,

    /// The length of ECC key is invalid. It can only be one of `[256, 384, 521]`.
    EccInvalidKeyLength,

    /// The length of ECC key is invalid. It can only be one of `[16, 24, 32]`.
    AesInvalidKeyLength,

    /// Error in generating a public key certificate.
    EccPubKeyCertGenerateError,

    /// Cannot delete internal keys, such as RSA unwrap key
    CannotDeleteInternalKeys,

    /// RNG Error
    RngError,

    /// Nonce mismatch
    NonceMismatch,

    /// Masked key length is not valid
    MaskedKeyInvalidLength,

    /// Masked key pre-encode failed
    MaskedKeyPreEncodeFailed,

    /// Masked key encode failed
    MaskedKeyEncodeFailed,

    /// Masked key decode failed
    MaskedKeyDecodeFailed,

    /// Partition already provisioned
    PartitionAlreadyProvisioned,

    /// Sealed BK3 data is too large
    SealedBk3TooLarge,

    /// Sealed BK3 not present on device
    SealedBk3NotPresent,

    /// Credentials haven't been established. Cannot open a session
    CredentialsNotEstablished,

    /// Partition has not been provisioned.
    PartitionNotProvisioned,

    /// Invalid algorithm specified
    InvalidAlgorithm,

    /// Output buffer provided is too small
    OutputBufferTooSmall,

    /// Invalid parameter provided
    InvalidKeyLength,

    /// Mbor encoding failed
    MborEncodeFailed,

    /// Mbor decoding failed
    MetadataEncodeFailed,

    /// Mbor decoding failed
    MetadataDecodeFailed,

    /// AES encryption failed
    AesEncryptFailed,

    /// AES decryption failed
    AesDecryptFailed,

    /// Report signature does not match
    ReportSignatureMismatch,
    /// Bk3 Already Initialized
    Bk3AlreadyInitialized,

    /// BK3 provisioning PIN has already been set.
    Bk3PinAlreadySet,

    /// BK3 provisioning PIN has not been set.
    Bk3PinNotSet,

    /// BK3 transport integrity authentication failed.
    Bk3TransportTagMismatch,

    /// BK3 PIN authentication failed.
    Bk3PinTagMismatch,

    /// BK3 has not been provisioned, so sealed BK3 operations are unavailable.
    Bk3NotSecurelyProvisioned,

    /// Sealed BK3 already set
    SealedBk3AlreadySet,

    /// Partition ID Key Generation PCT failed
    PartitionIdKeyGenerationPctFailed,
}

impl From<TesseraError> for DdiStatus {
    fn from(value: TesseraError) -> Self {
        match value {
            TesseraError::InvalidArgument => DdiStatus::InvalidArg,
            TesseraError::InternalError => DdiStatus::InternalError,
            TesseraError::AppNotFound => DdiStatus::AppNotFound,
            TesseraError::AppAlreadyExists => DdiStatus::AppAlreadyExists,
            TesseraError::VaultNotFound => DdiStatus::VaultNotFound,
            TesseraError::VaultSessionLimitReached => DdiStatus::VaultSessionLimitReached,
            TesseraError::InvalidVaultManagerCredentials => DdiStatus::InvalidManagerCredentials,
            TesseraError::InvalidAppCredentials => DdiStatus::InvalidAppCredentials,
            TesseraError::CannotUseDefaultCredentials => DdiStatus::CannotUseDefaultCredentials,
            TesseraError::CannotUseReservedId => DdiStatus::InvalidArg,
            TesseraError::SessionNotExpected => DdiStatus::SessionNotExpected,
            TesseraError::SessionExpected => DdiStatus::SessionExpected,
            TesseraError::CborDecodeError => DdiStatus::DdiDecodeFailed,
            TesseraError::CborEncodeError => DdiStatus::DdiEncodeFailed,
            TesseraError::SessionNotFound => DdiStatus::SessionNotFound,
            TesseraError::SessionNeedsRenegotiation => DdiStatus::SessionNeedsRenegotiation,
            TesseraError::InvalidKeyIndex => DdiStatus::KeyNotFound,
            TesseraError::KeyNotFound => DdiStatus::KeyNotFound,
            TesseraError::KeyTagAlreadyExists => DdiStatus::KeyTagAlreadyExists,
            TesseraError::KeyAlreadyExists => DdiStatus::KeyTagAlreadyExists,
            TesseraError::RsaInvalidKeyType => DdiStatus::InvalidKeyType,
            TesseraError::InvalidKeyType => DdiStatus::InvalidKeyType,
            TesseraError::DerAndKeyTypeMismatch => DdiStatus::DerAndKeyTypeMismatch,
            TesseraError::RsaFromDerError => DdiStatus::KeyDecodeFailed,
            TesseraError::NotEnoughSpace => DdiStatus::NotEnoughSpace,
            TesseraError::ReachedMaxKeys => DdiStatus::ReachedMaxKeys,
            TesseraError::CannotDeleteKeyInUse => DdiStatus::CannotDeleteKeyInUse,
            TesseraError::CannotDeleteSomeKeysInUse => DdiStatus::CannotDeleteSomeKeysInUse,
            TesseraError::CannotCloseSessionInUse => DdiStatus::CannotCloseSessionInUse,
            TesseraError::CannotCloseSomeSessionsInUse => DdiStatus::CannotCloseSomeSessionsInUse,
            TesseraError::CannotDeleteKeyAndCloseSessionInUse => {
                DdiStatus::CannotDeleteKeyAndCloseSessionInUse
            }
            TesseraError::InvalidKeyNumber => DdiStatus::InvalidKeyNumber,
            TesseraError::FunctionNotFound => DdiStatus::FunctionNotFound,
            TesseraError::UnsupportedRevision => DdiStatus::UnsupportedRevision,
            TesseraError::RsaToDerError => DdiStatus::RsaToDerError,
            TesseraError::RsaGenerateError => DdiStatus::RsaGenerateError,
            TesseraError::RsaEncryptError => DdiStatus::InternalError, // only internal-facing API will throw TesseraError::RsaEncryptError
            TesseraError::RsaDecryptError => DdiStatus::RsaDecryptFailed,
            TesseraError::RsaSignError => DdiStatus::RsaSignFailed,
            TesseraError::RsaVerifyError => DdiStatus::InternalError, // only internal-facing API will throw TesseraError::RsaVerifyError
            TesseraError::RsaGetModulusError => DdiStatus::RsaGetModulusError,
            TesseraError::RsaGetPublicExponentError => DdiStatus::RsaGetPublicExponentError,
            TesseraError::RsaInvalidKeyLength => DdiStatus::RsaInvalidKeyLength,
            TesseraError::InvalidPermissions => DdiStatus::InvalidPermissions,
            TesseraError::EccFromDerError => DdiStatus::KeyDecodeFailed,
            TesseraError::EccToDerError => DdiStatus::EccToDerError,
            TesseraError::EccGenerateError => DdiStatus::EccGenerateError,
            TesseraError::EccSignError => DdiStatus::EccSignFailed,
            TesseraError::EccVerifyError => DdiStatus::EccVerifyFailed,
            TesseraError::EccDeriveError => DdiStatus::EccDeriveError,
            TesseraError::EccGetCurveError => DdiStatus::EccGetCurveError,
            TesseraError::EccGetCoordinatesError => DdiStatus::EccGetCoordinatesError,
            TesseraError::ShaError => DdiStatus::ShaError,
            TesseraError::HmacError => DdiStatus::HmacError,
            TesseraError::PinDecryptionFailed => DdiStatus::PinDecryptionFailed,
            TesseraError::EccInvalidKeyType => DdiStatus::InvalidKeyType,
            TesseraError::AesGenerateError => DdiStatus::AesGenerateError,
            TesseraError::AesEncryptError => DdiStatus::AesEncryptFailed,
            TesseraError::AesDecryptError => DdiStatus::AesDecryptFailed,
            TesseraError::AesInvalidKeyType => DdiStatus::InvalidKeyType,
            TesseraError::CoseSign1UnexpectedSignature => DdiStatus::CoseSign1UnexpectedSignature,
            TesseraError::HkdfError => DdiStatus::HkdfError,
            TesseraError::VaultAppLimitReached => DdiStatus::VaultAppLimitReached,
            TesseraError::KbkdfError => DdiStatus::KbkdfError,
            TesseraError::RsaUnwrapInvalidReq => DdiStatus::RsaUnwrapInvalidRequest,
            TesseraError::RsaUnwrapInvalidUnwrappingKeyLength => DdiStatus::RsaUnwrapInvalidKek,
            TesseraError::RsaUnwrapRsaOaepDecryptFailed => DdiStatus::RsaUnwrapOaepDecodeFailed,
            TesseraError::RsaUnwrapAesUnwrapFailed => DdiStatus::RsaUnwrapAesUnwrapFailed,
            TesseraError::AesGcmInvalidBufSize => DdiStatus::AesGcmInvalidBufferSize,
            TesseraError::AesInvalidShortAppId => DdiStatus::InvalidShortAppId,
            TesseraError::AesInvalidTag => DdiStatus::AesGcmDecryptTagDoesNotMatch,
            TesseraError::AttestKeyInternalErr => DdiStatus::AttestKeyInternalError,
            TesseraError::AesXtsInvalidBufSize => DdiStatus::AesXtsInvalidBufferSize,
            TesseraError::AesXtsInvalidDul => DdiStatus::AesXtsInvalidDul,
            TesseraError::EccInvalidKeyLength => DdiStatus::EccInvalidKeyLength,
            TesseraError::AesInvalidKeyLength => DdiStatus::AesInvalidKeyLength,
            TesseraError::EccPubKeyCertGenerateError => DdiStatus::InvalidCertificate,
            TesseraError::CannotDeleteInternalKeys => DdiStatus::CannotDeleteInternalKeys,
            TesseraError::RngError => DdiStatus::RngError,
            TesseraError::NonceMismatch => DdiStatus::NonceMismatch,
            TesseraError::MaskedKeyInvalidLength => DdiStatus::MaskedKeyInvalidLength,
            TesseraError::MaskedKeyPreEncodeFailed => DdiStatus::MaskedKeyPreEncodeFailed,
            TesseraError::MaskedKeyEncodeFailed => DdiStatus::MaskedKeyEncodeFailed,
            TesseraError::MaskedKeyDecodeFailed => DdiStatus::MaskedKeyDecodeFailed,
            TesseraError::PartitionAlreadyProvisioned => DdiStatus::PartitionAlreadyProvisioned,
            TesseraError::SealedBk3NotPresent => DdiStatus::SealedBk3NotPresent,
            TesseraError::SealedBk3TooLarge => DdiStatus::SealedBk3TooLarge,
            TesseraError::CredentialsNotEstablished => DdiStatus::CredentialsNotEstablished,
            TesseraError::PartitionNotProvisioned => DdiStatus::PartitionNotProvisioned,
            TesseraError::InvalidAlgorithm => DdiStatus::InvalidArg,
            TesseraError::OutputBufferTooSmall => DdiStatus::InvalidArg,
            TesseraError::InvalidKeyLength => DdiStatus::InvalidArg,
            TesseraError::MborEncodeFailed => DdiStatus::InvalidArg,
            TesseraError::MetadataEncodeFailed => DdiStatus::InvalidArg,
            TesseraError::MetadataDecodeFailed => DdiStatus::InvalidArg,
            TesseraError::AesEncryptFailed => DdiStatus::InvalidArg,
            TesseraError::AesDecryptFailed => DdiStatus::InvalidArg,
            TesseraError::ReportSignatureMismatch => DdiStatus::InvalidArg,
            TesseraError::Bk3AlreadyInitialized => DdiStatus::Bk3AlreadyInitialized,
            TesseraError::Bk3PinAlreadySet => DdiStatus::Bk3PinAlreadySet,
            TesseraError::Bk3PinNotSet => DdiStatus::Bk3PinNotSet,
            TesseraError::Bk3TransportTagMismatch => DdiStatus::Bk3TransportTagMismatch,
            TesseraError::Bk3PinTagMismatch => DdiStatus::Bk3PinTagMismatch,
            TesseraError::Bk3NotSecurelyProvisioned => DdiStatus::Bk3NotSecurelyProvisioned,
            TesseraError::SealedBk3AlreadySet => DdiStatus::SealedBk3AlreadySet,
            TesseraError::PartitionIdKeyGenerationPctFailed => {
                DdiStatus::PartitionIdKeyGenerationPctFailed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This test helps achieve 100% test coverage
    // as debug trait is mainly used for test purposes
    #[test]
    fn test_debug_trait_print() {
        println!("TesseraError {:?}", TesseraError::InvalidKeyNumber);
    }
}
