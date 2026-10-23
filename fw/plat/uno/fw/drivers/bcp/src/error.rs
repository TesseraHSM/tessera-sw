// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BCP driver error definitions.

use tsra_fw_uno_error::make_component_error;
use tsra_fw_uno_error::ComponentId;
use tsra_fw_uno_error::HsmError;

/// BCP driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=BCP.
#[derive(Debug)]
pub struct BcpError;

impl BcpError {
    /// Key is not 32 bytes (the engine is AES-256 only).
    pub const INVALID_KEY_LEN: HsmError = make_component_error(ComponentId::BCP, 1);

    /// Buffers the engine cannot take: AAD not a 32-byte multiple, text
    /// empty or not a 16-byte multiple, source over one chunk, destination
    /// shorter than the source, or a misaligned address.
    pub const INVALID_DATA_LEN: HsmError = make_component_error(ComponentId::BCP, 2);

    /// The engine completed a command with an error other than a decrypt
    /// tag mismatch.
    pub const CMD_ERROR: HsmError = make_component_error(ComponentId::BCP, 4);

    /// The command did not complete in time; the engine was reset.
    pub const TIMEOUT: HsmError = make_component_error(ComponentId::BCP, 5);
}
