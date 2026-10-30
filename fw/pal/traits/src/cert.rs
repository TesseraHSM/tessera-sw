// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate store types and traits.
//!
//! Defines the [`HsmCertStore`] trait used by DDI handlers
//! (`get_cert_chain_info`, `get_certificate`) to read per-partition
//! certificate chains.  Each partition can hold multiple chains
//! addressed by a [`HsmCertSlot`]: manufacturer, device owner, or partition
//! owner. Each slot has a [`HsmCertBank`] selecting the certificate-chain
//! family: ECC or ML-DSA. Platforms may support only a subset of slots
//! and banks.
//!
//! ## Storage model
//!
//! A *chain* is an ordered list of DER-encoded X.509 certificates,
//! conventionally arranged leaf-first.  The store reports two pieces
//! of metadata per chain via [`HsmCertChainInfo`]:
//!
//! - the chain length (`count`), and
//! - the SHA-256 thumbprint of the leaf certificate.
//!
//! Individual certificates are streamed one at a time through
//! [`HsmCertStore::get_cert`] using the standard query/copy pattern.
//!
//! ## Addressing
//!
//! Every method takes the platform's IO handle. The platform resolves
//! the target partition from its private IO context; callers cannot
//! select another partition's chain. The handle also provides per-IO
//! scope for allocation, logging, and throttling.

use open_enum::open_enum;

use super::*;

/// Certificate-chain owner. Unknown IDs are preserved and must be rejected
/// by implementations that do not support them.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmCertSlot {
    /// Manufacturer certificate chain.
    Mfgr = 0,
    /// Device-owner certificate chain.
    DevOwner = 1,
    /// Partition-owner certificate chain.
    PartOwner = 2,
}

/// Certificate-chain family. Unknown IDs are preserved and must be rejected
/// by implementations that do not support them.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmCertBank {
    /// ECC certificate chain.
    Ecc = 0,
    /// ML-DSA certificate chain.
    MlDsa = 1,
}

/// Metadata for a single certificate chain selected by slot and bank.
///
/// Returned by [`HsmCertStore::get_cert_chain_info`].  The
/// thumbprint lets the host detect chain rotation without
/// downloading every certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsmCertChainInfo {
    /// Number of certificates in the chain.
    ///
    /// Indices passed to [`HsmCertStore::get_cert`] must satisfy
    /// `idx < count`.
    pub count: u8,

    /// SHA-256 thumbprint of the leaf certificate (DER bytes).
    ///
    /// Computed once at chain-load time and cached; reading it does
    /// not invoke the SHA accelerator.
    pub thumbprint: [u8; 32],
}

/// Per-partition certificate store interface.
///
/// Both methods are `async` so PAL implementations can stream
/// certificate bytes from non-volatile storage (flash, eMMC) without
/// blocking the core's IO loop.  Implementations backed by RAM may
/// resolve immediately; callers should still treat the await as
/// potentially yielding.
pub trait HsmCertStore: HsmIoTypes {
    /// Returns metadata for the certificate chain at
    /// `(slot, bank)` in the IO's bound partition.
    ///
    /// Cheap query that lets the host decide whether to fetch
    /// individual certificates; performs no buffer allocation.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context, bound to the target partition.
    /// - `slot` — certificate-chain owner.
    /// - `bank` — certificate-chain family. Standard and Uno PALs
    ///   currently support only [`HsmCertBank::Ecc`].
    ///
    /// # Returns
    ///
    /// - `Ok(info)` — populated [`HsmCertChainInfo`].
    /// - `Err(HsmError::InvalidArg)` — the bound partition or `slot`
    ///   is out of range, the bank is unsupported, or no chain is installed
    ///   at this slot and bank.
    /// - `Err(HsmError)` — propagated from the underlying storage
    ///   driver.
    async fn get_cert_chain_info(
        &self,
        io: &Self::Io,
        slot: HsmCertSlot,
        bank: HsmCertBank,
    ) -> HsmResult<HsmCertChainInfo>;

    /// Reads one certificate from a chain, optionally copying its
    /// bytes into a caller-supplied buffer.
    ///
    /// Follows the standard query/copy pattern used elsewhere in the
    /// PAL: pass `cert = None` to obtain the certificate's size
    /// without copying, then call again with `cert = Some(buf)` to
    /// perform the copy.  Both calls return the same canonical
    /// length.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context, bound to the target partition.
    /// - `slot` — certificate-chain owner.
    /// - `bank` — certificate-chain family; see [`Self::get_cert_chain_info`].
    /// - `idx` — zero-based certificate index; must satisfy
    ///   `idx < HsmCertChainInfo::count` for the same bound partition and
    ///   `(slot, bank)`. By convention `idx == 0` is the root and the
    ///   last index (`count - 1`) is the partition leaf.
    /// - `cert` — `None` to query the size, or `Some(buf)` to copy
    ///   the DER-encoded certificate into `buf[..size]`.  `buf.len()`
    ///   must be ≥ size.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — number of bytes that were (or would be)
    ///   written.
    /// - `Err(HsmError::InvalidArg)` — the bound partition, `slot`,
    ///   or `idx` is out of range, the bank is unsupported, or `cert = Some(buf)` and
    ///   `buf.len() < size`.
    /// - `Err(HsmError)` — propagated from the underlying storage
    ///   driver.
    async fn get_cert(
        &self,
        io: &Self::Io,
        slot: HsmCertSlot,
        bank: HsmCertBank,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize>;
}
