// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-visible completion status codes.

use tsra_fw_hsm_pal_traits::HsmError;

/// Host-visible CQE status codes.
pub struct HostStatus;

impl HostStatus {
    /// Success.
    pub const SUCCESS: u16 = 0x000;

    /// Unknown command opcode.
    pub const INVALID_COMMAND_OPCODE: u16 = 0x001;

    /// Malformed command field.
    pub const INVALID_FIELD_IN_COMMAND: u16 = 0x002;

    /// Internal firmware error.
    pub const INTERNAL_ERROR: u16 = 0x007;

    /// Unsupported PSDT (PRP/SGL selector).
    pub const INVALID_PSDT: u16 = 0x0C0;

    /// Invalid source length.
    pub const INVALID_SRC_LEN: u16 = 0x0C1;

    /// Invalid destination length.
    pub const INVALID_DST_LEN: u16 = 0x0C2;

    /// Invalid source PRP.
    pub const INVALID_SRC_PRP: u16 = 0x0C3;

    /// Invalid destination PRP.
    pub const INVALID_DST_PRP: u16 = 0x0C4;

    /// Host transfer failed.
    pub const DMA_TXN_ERROR: u16 = 0x0C6;

    /// Request header failed to decode.
    pub const REQ_HDR_DECODE_ERR: u16 = 0x0C8;

    /// Request buffers could not be allocated.
    pub const ALLOC_ERR: u16 = 0x0C9;

    /// Invalid out-of-band length.
    pub const INVALID_OOB_LEN: u16 = 0x0CA;

    /// Invalid out-of-band pointer.
    pub const INVALID_OOB_PRP: u16 = 0x0CB;

    /// Secure-channel transport failure: the request failed GCM
    /// authentication, or the session has no transport keys.
    pub const SESSION_TRANSPORT_ERR: u16 = 0x0CC;
}

/// Maps `err` to its host-visible CQE status.
pub const fn host_status(err: HsmError) -> u16 {
    match err {
        HsmError::UnsupportedCmd | HsmError::IoChannelUnknownOp => {
            HostStatus::INVALID_COMMAND_OPCODE
        }
        HsmError::SqeInvalidPsdt => HostStatus::INVALID_PSDT,
        HsmError::IoChannelInvalidSrcLen => HostStatus::INVALID_SRC_LEN,
        HsmError::IoChannelInvalidDstLen => HostStatus::INVALID_DST_LEN,
        HsmError::IoChannelInvalidSrcAlignment => HostStatus::INVALID_SRC_PRP,
        HsmError::IoChannelInvalidDstAlignment => HostStatus::INVALID_DST_PRP,
        HsmError::IoChannelInvalidOobLen => HostStatus::INVALID_OOB_LEN,
        HsmError::IoChannelInvalidOobAlignment => HostStatus::INVALID_OOB_PRP,
        HsmError::NotEnoughSpace => HostStatus::ALLOC_ERR,
        HsmError::FailedToStartDmaTransaction => HostStatus::DMA_TXN_ERROR,
        HsmError::DdiDecodeFailed => HostStatus::REQ_HDR_DECODE_ERR,
        HsmError::InvalidArg => HostStatus::INVALID_FIELD_IN_COMMAND,
        HsmError::SessionTransportError => HostStatus::SESSION_TRANSPORT_ERR,
        _ => HostStatus::INTERNAL_ERROR,
    }
}
