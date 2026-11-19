// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `ApiRev` command.
//!
//! Both the request and response wire schemas live in
//! `tsra_fw_ddi_tbor_types::api_rev` (shared with the firmware
//! handler in `fw/core/lib/src/ddi/tbor/api_rev.rs`). This module
//! adds the host-facing value types so [`exec_op_tbor`] returns owned
//! response values rather than borrowing `View<'a>` accessors over the
//! driver's IO scratch buffer.
//!
//! [`exec_op_tbor`]: ../../tsra_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use crate::tbor;
use crate::tbor_int::U16;

/// TBOR opcode for `ApiRev`.
pub const TBOR_OP_API_REV: u8 = 0x01;

/// Host-facing TBOR `ApiRev` request. Carries no per-call data.
#[tbor(opcode = TBOR_OP_API_REV, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborApiRevReq;

impl TborApiRevReq {
    /// Construct a `ApiRev` request.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Host-facing TBOR `ApiRev` response.
///
/// Reports the inclusive range of SDK API revisions (`major.minor`) the
/// firmware supports.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborApiRevResp {
    /// Major version of the lowest supported API revision.
    pub min_major: U16,

    /// Minor version of the lowest supported API revision.
    pub min_minor: U16,

    /// Major version of the highest supported API revision.
    pub max_major: U16,

    /// Minor version of the highest supported API revision.
    pub max_minor: U16,
}
