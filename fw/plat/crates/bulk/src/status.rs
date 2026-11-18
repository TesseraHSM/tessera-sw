// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bulk completion status and error codes.

use super::*;

/// CQE status code / error code pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkStatus {
    /// Status code (15 bits).
    pub sts: u16,
    /// Error code qualifying `sts`.
    pub err: u16,
}

/// CQE status codes.
pub mod sts {
    /// Success.
    pub const SUCCESS: u16 = 0x0;
    /// Invalid XTS command field.
    pub const INVALID_FIELD_XTS: u16 = 0x1;
    /// Invalid GCM command field.
    pub const INVALID_FIELD_GCM: u16 = 0x2;
    /// Crypto engine error.
    pub const CRYPTO_ENGINE_ERROR: u16 = 0x3;
    /// Data pointer / descriptor fetch error.
    pub const FETCH_ERROR: u16 = 0x4;
    /// Data transfer timeout.
    pub const DATA_TRANSFER_TIMEOUT: u16 = 0x5;
    /// Queue deleted.
    pub const DELETE_QUEUE: u16 = 0x7;
    /// Aborted.
    pub const ABORT_REQ: u16 = 0x8;
}

/// Error codes qualifying [`sts::INVALID_FIELD_GCM`].
pub mod gcm_err {
    /// Invalid key.
    pub const INVALID_KEY: u16 = 0x1;
    /// Key not owned by the queue's function.
    pub const INVALID_VFID: u16 = 0x2;
    /// Invalid session id.
    pub const INVALID_SESSION_ID: u16 = 0x3;
    /// Invalid short app id.
    pub const INVALID_APP_ID: u16 = 0x4;
    /// Invalid AAD length.
    pub const INVALID_AAD_LENGTH: u16 = 0x5;
    /// Data length not a multiple of 16.
    pub const LENGTH_UNALIGNED_16B: u16 = 0x6;
    /// Unspecified invalid field.
    pub const UNDEFINED: u16 = 0x7;
    /// Invalid key type.
    pub const INVALID_KEY_TYPE: u16 = 0x8;
}

/// Error codes qualifying [`sts::INVALID_FIELD_XTS`].
pub mod xts_err {
    /// Invalid key 1.
    pub const INVALID_KEY1: u16 = 0x1;
    /// Key not owned by the queue's function.
    pub const INVALID_VFID: u16 = 0x3;
    /// Same key passed as key 1 and key 2.
    pub const SAME_KEYS_PASSED: u16 = 0x5;
    /// Invalid key 1 session id.
    pub const INVALID_KEY1_SESSION_ID: u16 = 0x7;
    /// Invalid key 1 app id.
    pub const INVALID_KEY1_APP_ID: u16 = 0x9;
    /// Data length exceeded.
    pub const DATA_LENGTH_EXCEEDED: u16 = 0xB;
    /// Data length not a multiple of 16.
    pub const LENGTH_UNALIGNED_16B: u16 = 0xC;
    /// Unspecified invalid field.
    pub const UNDEFINED: u16 = 0xD;
    /// Invalid key 1 type.
    pub const INVALID_KEY1_TYPE: u16 = 0xE;
}

/// Error codes qualifying [`sts::CRYPTO_ENGINE_ERROR`].
pub mod engine_err {
    /// GCM tag mismatch.
    pub const TAG_MISMATCH: u16 = 0x9;
    /// Fatal engine error.
    pub const FATAL: u16 = 0xA;
}

impl BulkStatus {
    /// Success.
    pub const SUCCESS: Self = Self {
        sts: sts::SUCCESS,
        err: 0,
    };

    /// Returns whether this is a success status.
    pub fn is_success(&self) -> bool {
        self.sts == sts::SUCCESS && self.err == 0
    }

    /// Maps a failed bulk IO's error onto a (never successful) CQE status.
    ///
    /// # Parameters
    ///
    /// - `cipher` — the IO's cipher (selects the GCM or XTS field codes).
    /// - `err` — the error returned for the IO.
    pub fn from_error(cipher: BulkCipher, err: HsmError) -> Self {
        let (field, undefined) = match cipher {
            BulkCipher::Gcm => (sts::INVALID_FIELD_GCM, gcm_err::UNDEFINED),
            BulkCipher::Xts => (sts::INVALID_FIELD_XTS, xts_err::UNDEFINED),
        };
        let field_err = |gcm: u16, xts: u16| Self {
            sts: field,
            err: match cipher {
                BulkCipher::Gcm => gcm,
                BulkCipher::Xts => xts,
            },
        };

        match err {
            HsmError::AesGcmDecryptTagDoesNotMatch => Self {
                sts: sts::CRYPTO_ENGINE_ERROR,
                err: engine_err::TAG_MISMATCH,
            },
            HsmError::KeyNotFound => field_err(gcm_err::INVALID_KEY, xts_err::INVALID_KEY1),
            HsmError::InvalidKeyType | HsmError::UnsupportedKeyType => {
                field_err(gcm_err::INVALID_KEY_TYPE, xts_err::INVALID_KEY1_TYPE)
            }
            HsmError::KeyStructuralValidationFailed => {
                field_err(gcm_err::INVALID_KEY, xts_err::SAME_KEYS_PASSED)
            }
            HsmError::SessionNotFound => field_err(
                gcm_err::INVALID_SESSION_ID,
                xts_err::INVALID_KEY1_SESSION_ID,
            ),
            HsmError::InvalidShortAppId => {
                field_err(gcm_err::INVALID_APP_ID, xts_err::INVALID_KEY1_APP_ID)
            }
            HsmError::PartitionNotEnabled | HsmError::FailedToAssociateIoWithPartition => {
                field_err(gcm_err::INVALID_VFID, xts_err::INVALID_VFID)
            }
            HsmError::IoChannelInvalidBufferDescriptor
            | HsmError::IoChannelInvalidSrcLen
            | HsmError::IoChannelInvalidDstLen
            | HsmError::IoChannelInvalidSrcAlignment
            | HsmError::IoChannelInvalidDstAlignment
            | HsmError::DmaCompletedWithError
            | HsmError::DmaHardwareEmptyCompletionFound
            | HsmError::DmaIoIdentifierMismatch
            | HsmError::FailedToStartDmaTransaction => Self {
                sts: sts::FETCH_ERROR,
                err: 0,
            },
            HsmError::InternalError => Self {
                sts: sts::CRYPTO_ENGINE_ERROR,
                err: engine_err::FATAL,
            },
            _ => Self {
                sts: field,
                err: undefined,
            },
        }
    }
}
