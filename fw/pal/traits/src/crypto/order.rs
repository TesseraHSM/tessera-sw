// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Byte order of crypto engine operands.
//!
//! Big integers that cross the PAL crypto boundary — ECC nonces,
//! coordinates and signature components, ECDH shared secrets, RSA
//! operands, and digests fed to ECC sign/verify — are in the platform's
//! *operand order*, [`HsmCryptoOrder::BYTE_ORDER`]:
//!
//! - [`HsmByteOrder::Le`] — little-endian.
//! - [`HsmByteOrder::Be`] — big-endian, the standard encoding.
//!
//! Each ECC operand component sits at the start of a lane padded to
//! [`HsmCryptoOrder::ECC_COORD_PAD`] bytes, followed by zero bytes
//! (P-521: 66 bytes in a 68-byte lane with a 4-byte pad, a 72-byte lane
//! with an 8-byte pad).
//!
//! ECC private keys are an exception: they use PAL-specific HSM/vault
//! encodings, not the value-first operand layout. Neither `BYTE_ORDER`
//! nor `ECC_COORD_PAD` specifies their byte order or padding placement.
//! The std PALs use big-endian scalars with leading zero padding, even
//! on std Uno. See [`HsmEcc`](crate::HsmEcc) for private-key conversions.
//!
//! Byte strings — hash and KDF outputs, AES data, ML-DSA / ML-KEM
//! encodings — have no byte order and are never converted.

/// Byte order of a platform's crypto operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmByteOrder {
    /// Little-endian.
    Le,

    /// Big-endian.
    Be,
}

impl HsmByteOrder {
    /// Whether operands are big-endian (the standard encoding).
    #[inline(always)]
    pub const fn is_be(self) -> bool {
        matches!(self, Self::Be)
    }
}

/// Operand form of a platform's crypto engines: byte order and ECC lane
/// padding.
///
/// A supertrait of the crypto traits whose operands are big integers
/// ([`HsmEcc`](crate::HsmEcc), [`HsmRsa`](crate::HsmRsa),
/// [`HsmHash`](crate::HsmHash)). Core branches on the consts;
/// the branch folds per platform.
pub trait HsmCryptoOrder {
    /// Operand byte order.
    const BYTE_ORDER: HsmByteOrder;

    /// ECC lane padding in bytes: every nonce, coordinate and signature
    /// component occupies a lane of its raw length rounded up to this
    /// multiple, value first and zero-filled after
    /// (see [`HsmEccCurve::wire_coord_len`](crate::HsmEccCurve::wire_coord_len)).
    ///
    /// This also determines ECC private-key buffer lengths, but not their
    /// PAL-specific byte order or padding placement.
    const ECC_COORD_PAD: usize;

    /// [`BYTE_ORDER`](Self::BYTE_ORDER), for call sites that only hold a
    /// PAL value.
    #[inline(always)]
    fn byte_order(&self) -> HsmByteOrder {
        Self::BYTE_ORDER
    }
}

/// Form of a digest produced by [`HsmHash`](crate::HsmHash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmDigestForm {
    /// The standard (FIPS 180-4 / 202) digest byte string.
    Standard,

    /// The digest as an ECC sign/verify operand, in
    /// [`HsmCryptoOrder::BYTE_ORDER`]: the byte reversal of the standard
    /// digest on [`HsmByteOrder::Le`] platforms, the standard digest on
    /// [`HsmByteOrder::Be`] ones.
    Operand,
}

impl HsmDigestForm {
    /// Whether a digest in this form is the byte reversal of the standard
    /// digest on a platform with operand order `order`.
    #[inline(always)]
    pub const fn reversed(self, order: HsmByteOrder) -> bool {
        matches!(self, Self::Operand) && !order.is_be()
    }
}
