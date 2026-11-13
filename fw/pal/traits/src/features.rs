// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time platform capabilities.
//!
//! Platform differences that change core behavior are expressed as
//! associated consts rather than cargo features, so one core build can
//! serve several platforms (cargo unifies features across a build). Core
//! branches on them with `if`/`match`, which folds per platform.

/// An SDK API revision (`major.minor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HsmApiRevision {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

impl HsmApiRevision {
    /// Builds a revision from its parts.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// SQE/CQE wire protocol of a platform, implied by its API revision major.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmIoProtocol {
    /// API revision 1.x: 64 B SQE / 16 B CQE carrying MBOR or TBOR.
    Uno,
    /// API revision 2.x: 128 B SQE / 64 B CQE carrying plain or secure
    /// (session-encrypted) TBOR.
    Duo,
}

/// Type-level IO protocol marker, selected by
/// [`HsmPalFeatures::IoProtocol`].
///
/// A type (not a const) picks the pipeline so the IO future contains only
/// that protocol's state: an async `match` on a const still reserves
/// space for every arm.
pub trait HsmIoProtocolKind {
    /// The protocol this marker selects.
    const PROTOCOL: HsmIoProtocol;
}

/// Marker for [`HsmIoProtocol::Uno`].
pub struct UnoIo;

impl HsmIoProtocolKind for UnoIo {
    const PROTOCOL: HsmIoProtocol = HsmIoProtocol::Uno;
}

/// Marker for [`HsmIoProtocol::Duo`].
pub struct DuoIo;

impl HsmIoProtocolKind for DuoIo {
    const PROTOCOL: HsmIoProtocol = HsmIoProtocol::Duo;
}

/// Compile-time capabilities of a platform.
///
/// Platforms set the API revision range and the matching IO protocol
/// marker; the features the protocol implies are derived from it.
pub trait HsmPalFeatures {
    /// IO protocol marker ([`UnoIo`] or [`DuoIo`]); must match the API
    /// revision major (1 = Uno, 2 = Duo).
    type IoProtocol: HsmIoProtocolKind;

    /// Lowest SDK API revision this platform supports (reported by TBOR
    /// `ApiRev`).
    const API_REV_MIN: HsmApiRevision;

    /// Highest SDK API revision this platform supports (reported by TBOR
    /// `ApiRev`).
    const API_REV_MAX: HsmApiRevision;

    /// IO protocol of [`IoProtocol`](Self::IoProtocol), checked against
    /// the API revision range. Not meant to be overridden.
    const IO_PROTOCOL: HsmIoProtocol = {
        assert!(
            Self::API_REV_MIN.major == Self::API_REV_MAX.major,
            "API revision range must not span majors"
        );
        let major = match Self::IoProtocol::PROTOCOL {
            HsmIoProtocol::Uno => 1,
            HsmIoProtocol::Duo => 2,
        };
        assert!(
            Self::API_REV_MIN.major == major,
            "IoProtocol does not match the API revision major"
        );
        Self::IoProtocol::PROTOCOL
    };
}
