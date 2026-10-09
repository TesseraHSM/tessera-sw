// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PQC driver error definitions.

use tsra_fw_uno_error::make_component_error;
use tsra_fw_uno_error::ComponentId;
use tsra_fw_uno_error::HsmError;

/// PQC driver errors.
#[derive(Debug)]
pub struct PqcError;

impl PqcError {
    /// All waiter queue slots are occupied — more tasks are waiting for an
    /// FP core than the queue can hold.
    pub const QUEUE_FULL: HsmError = make_component_error(ComponentId::PQC, 1);

    /// The requested engine id is not a valid FP core.
    pub const INVALID_ENGINE: HsmError = make_component_error(ComponentId::PQC, 2);

    /// The FP core reported that it could not service the request.
    pub const FP_ERROR: HsmError = make_component_error(ComponentId::PQC, 3);

    /// The FP offload transport is not available yet.
    ///
    /// Returned while the FP firmware has no PQC responder: the engine pool
    /// and request encoding are exercised, but nothing is submitted over IPC
    /// because no reply would ever arrive.
    pub const FP_NOT_READY: HsmError = make_component_error(ComponentId::PQC, 4);

    /// An output buffer was not the length the parameter set requires.
    pub const INVALID_BUFFER_SIZE: HsmError = make_component_error(ComponentId::PQC, 5);

    /// The requested key kind is not an ML-DSA / ML-KEM kind this driver
    /// knows how to offload.
    pub const INVALID_KEY_KIND: HsmError = make_component_error(ComponentId::PQC, 6);
}
