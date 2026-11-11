// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level HSM application struct.
//!
//! [`Hsm`] owns the platform abstraction layer and drives the
//! application lifecycle. The concrete PAL type is supplied by the
//! platform crate (e.g. `fw/plat/std/uno/lib`), which also provides the
//! Embassy task wiring and global static.

use super::*;

/// The top-level HSM application, generic over the platform abstraction
/// layer.
///
/// A single `Hsm<P>` lives in a platform-owned `OnceLock`. All Embassy
/// tasks access it through that global rather than receiving a reference,
/// because Embassy task functions cannot capture borrows.
pub struct Hsm<P: HsmPal> {
    /// The platform abstraction layer.
    pal: P,
}

impl<P: HsmPal> Hsm<P> {
    /// Creates a new `Hsm` wrapping the given PAL.
    pub fn new(pal: P) -> Self {
        Self { pal }
    }

    /// Returns a reference to the PAL.
    pub fn pal(&self) -> &P {
        &self.pal
    }

    /// Top-level IO handler invoked by each send-task: runs the pipeline
    /// selected by the platform's
    /// [`IoProtocol`](HsmPalFeatures::IoProtocol) marker. Only that
    /// pipeline is instantiated, so the future carries no state for the
    /// other protocol.
    #[inline(always)]
    pub fn handle_io(&self, io: P::Io) -> impl core::future::Future<Output = ()> + '_
    where
        P::IoProtocol: HsmIoPipeline<P>,
    {
        <P::IoProtocol as HsmIoPipeline<P>>::run(self, io)
    }
}

/// IO pipeline of a protocol marker ([`UnoIo`] or [`DuoIo`]); implemented
/// by core for every PAL.
pub trait HsmIoPipeline<P: HsmPal> {
    /// Runs one IO through this protocol's pipeline.
    fn run(hsm: &Hsm<P>, io: P::Io) -> impl core::future::Future<Output = ()> + '_;
}

impl<P: HsmPal> HsmIoPipeline<P> for UnoIo {
    #[inline(always)]
    fn run(hsm: &Hsm<P>, io: P::Io) -> impl core::future::Future<Output = ()> + '_ {
        hsm.uno_io(io)
    }
}

impl<P: HsmPal> HsmIoPipeline<P> for DuoIo {
    #[inline(always)]
    fn run(hsm: &Hsm<P>, io: P::Io) -> impl core::future::Future<Output = ()> + '_ {
        hsm.duo_io(io)
    }
}
