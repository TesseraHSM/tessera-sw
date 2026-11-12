// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Byte order of crypto engine operands.
//!
//! Big integers that cross the PAL crypto boundary — ECC scalars,
//! coordinates and signature components, ECDH shared secrets, RSA
//! operands, and digests fed to ECC sign/verify — are in the platform's
//! *operand order*, [`HsmCryptoOrder::BYTE_ORDER`]:
//!
//! - [`HsmByteOrder::Le`] — little-endian. Each ECC component is
//!   zero-extended to a 4-byte word boundary (P-521: 66 bytes padded to
//!   68 with two trailing zero bytes).
//! - [`HsmByteOrder::Be`] — big-endian, the standard encoding. Each ECC
//!   component has its exact width (P-521: 66 bytes).
//!
//! Byte strings — hash and KDF outputs, AES data, ML-DSA / ML-KEM
//! encodings — have no byte order and are never converted.

/// Byte order of a platform's crypto operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmByteOrder {
    /// Little-endian, ECC components word-padded.
    Le,

    /// Big-endian, ECC components at their exact width.
    Be,
}

impl HsmByteOrder {
    /// Whether operands are big-endian (the standard encoding).
    #[inline(always)]
    pub const fn is_be(self) -> bool {
        matches!(self, Self::Be)
    }
}

/// Operand byte order of a platform's crypto engines.
///
/// A supertrait of the crypto traits whose operands are big integers
/// ([`HsmEcc`](crate::HsmEcc), [`HsmRsa`](crate::HsmRsa),
/// [`HsmHash`](crate::HsmHash)). Core branches on the const;
/// the branch folds per platform.
pub trait HsmCryptoOrder {
    /// Operand byte order.
    const BYTE_ORDER: HsmByteOrder;

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
