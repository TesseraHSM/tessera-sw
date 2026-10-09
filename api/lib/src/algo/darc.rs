// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC key-transport key material.
//!
//! Defines [`HsmDarcTmk`], the Transfer Masking Key (TMK) established by
//! the DARC key-exchange handshake. The TMK is the wrapping/unwrapping key
//! for DARC key transport: on the source it wraps a designated key for
//! export ([`HsmKeyWrapOp`](crate::traits::HsmKeyWrapOp)); on the target it
//! unwraps a transferred key
//! ([`HsmKeyPairUnwrapOp`](crate::traits::HsmKeyPairUnwrapOp)).

use super::*;

/// The Transfer Masking Key (TMK) established by the DARC key-exchange
/// handshake, held as an opaque SDMK-masked blob together with the session
/// it was established on.
///
/// The TMK is never raw key material on the host: `masked_tmk` is the
/// masked blob returned by `darc_tmk_gen` (source) or `darc_tmk_import`
/// (target). It plays the role of the wrapping/unwrapping key for DARC key
/// transport, analogous to how an RSA private key is the unwrapping key for
/// RSA-AES key transport.
#[derive(Clone)]
pub struct HsmDarcTmk {
    /// Session the TMK was established on (source for wrap, target for
    /// unwrap).
    session: HsmSession,
    /// Masked TMK blob (SDMK-masked), exactly `MASKED_TMK_LEN` bytes.
    masked_tmk: Vec<u8>,
}

impl HsmDarcTmk {
    /// Creates a TMK handle from the masked TMK bytes and the session it
    /// belongs to.
    ///
    /// # Arguments
    ///
    /// * `session` - The session the TMK was established on (the source
    ///   session for wrapping, the target session for unwrapping).
    /// * `masked_tmk` - The masked TMK blob returned by `darc_tmk_gen`
    ///   (source) or `darc_tmk_import` (target).
    pub fn new(session: HsmSession, masked_tmk: impl Into<Vec<u8>>) -> Self {
        Self {
            session,
            masked_tmk: masked_tmk.into(),
        }
    }

    /// Returns the session the TMK was established on.
    pub(crate) fn session(&self) -> &HsmSession {
        &self.session
    }

    /// Returns the masked TMK blob.
    pub(crate) fn masked_tmk(&self) -> &[u8] {
        &self.masked_tmk
    }
}

impl HsmKey for HsmDarcTmk {}

impl HsmUnwrappingKey for HsmDarcTmk {}
