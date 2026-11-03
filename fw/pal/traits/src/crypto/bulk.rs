// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bulk (fast-path) AES-GCM / AES-XTS trait for the HSM PAL.
//!
//! Bulk keys and bulk IOs are platform-owned end to end:
//!
//! - **Keys.** Where a bulk key lives is platform-defined: an external
//!   bulk-crypto engine may hold the material (the vault keeping only a
//!   handle), or the vault may hold it directly. The core creates bulk
//!   keys through [`bulk_key_create`](HsmBulkCrypto::bulk_key_create) and
//!   reports the host-visible [`bulk_key_id`](HsmBulkCrypto::bulk_key_id);
//!   deletion goes through the ordinary [`HsmVault`] delete paths, which
//!   the platform extends to release any backend state.
//! - **IOs.** A bulk IO ([`HsmIoKind::Bulk`]) arrives on a bulk queue.
//!   Its [`sqe`](HsmIo::sqe) is the 32-dword (128-byte) Lion fast-path
//!   submission entry: a 64-byte NVMe-style command followed by the
//!   64-byte AES-GCM / AES-XTS fields. Its [`cqe`](HsmIo::cqe) is the
//!   16-dword completion entry, which
//!   [`bulk_crypt`](HsmBulkCrypto::bulk_crypt) fills on success (on Uno
//!   the bulk crypto engine produces it). Only a failed IO's CQE is built
//!   by the core, from the SQE and the returned [`HsmError`].
//!
//! The wire layouts live in the `tsra_fw_hsm_bulk` crate.

use super::*;

/// Bulk AES-GCM / AES-XTS key lifecycle and IO trait.
///
/// All methods take `io` as their second parameter; it scopes the call to
/// the caller's partition.
pub trait HsmBulkCrypto: HsmIoTypes {
    /// Creates a bulk key from raw `key` material and returns its vault
    /// handle together with its host-visible bulk key id.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key` — key material; its length must match `kind`.
    /// - `kind` — a bulk vault kind (AES-GCM / AES-XTS bulk).
    /// - `session_id` — `Some` for a session-scoped key, `None` for a
    ///   partition-wide key.
    /// - `attrs` — key permission attributes.
    ///
    /// # Returns
    ///
    /// - `Ok((key_id, bulk_key_id))` — the vault handle and the id the
    ///   host uses to address the key in bulk IOs.
    /// - `Err(HsmError::UnsupportedCmd)` — the platform has no bulk
    ///   backend.
    /// - `Err(HsmError::InvalidKeyType)` — `kind` is not a bulk kind.
    /// - `Err(HsmError::InvalidArg)` — `key.len()` does not match `kind`.
    /// - `Err(HsmError::NotEnoughSpace)` — no room for the key.
    /// - `Err(HsmError::SessionNotFound)` — `session_id` is not open.
    async fn bulk_key_create(
        &self,
        io: &Self::Io,
        key: &HsmDmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<(HsmKeyId, u16)>;

    /// Returns the host-visible bulk key id of the bulk key `key_id`.
    ///
    /// # Returns
    ///
    /// - `Ok(bulk_key_id)` — the id reported at creation.
    /// - `Err(HsmError::UnsupportedCmd)` — the platform has no bulk
    ///   backend.
    /// - `Err(HsmError::UnsupportedKeyType)` — `key_id` is not a bulk key.
    fn bulk_key_id(&self, io: &Self::Io, key_id: HsmKeyId) -> HsmResult<u16>;

    /// Runs one bulk IO.
    ///
    /// The platform validates the SQE in [`io.sqe()`](HsmIo::sqe),
    /// resolves its keys in the caller's partition, applies the IV and
    /// service-indicator policy, moves the data between the host buffers
    /// and the cipher, and writes the complete success CQE into
    /// [`io.cqe()`](HsmIo::cqe), which the core posts as is. On error the
    /// core writes the failure CQE from the SQE and the returned error.
    ///
    /// CQE layout (little-endian dwords):
    ///
    /// | DW | Field |
    /// |---|---|
    /// | 0 | Command attributes and command id, echoed from the SQE |
    /// | 1-4 | AES-GCM tag (zero for XTS) |
    /// | 5-7 | AES-GCM IV used (HSM-generated or the host's) |
    /// | 8-10 | Reserved (zero) |
    /// | 11 | AES-GCM text tail bytes written outside the SGL |
    /// | 12 | Service indicator |
    /// | 13 | Bytes written through the destination SGL |
    /// | 14 | SQ head (hardware) and SQ id |
    /// | 15 | Error code, phase tag (hardware) and status code |
    ///
    /// # Parameters
    ///
    /// - `io` — the bulk IO (partition scope, owning queue, SQE / CQE).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — the IO succeeded and `io.cqe()` holds the CQE.
    /// - `Err(HsmError::UnsupportedCmd)` — the platform has no bulk path,
    ///   or the command type / cipher is not supported.
    /// - `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — GCM decrypt
    ///   authentication failed.
    /// - `Err(HsmError)` — validation, key lookup or engine failure;
    ///   `io.cqe()` contents are unspecified.
    async fn bulk_crypt(&self, io: &mut Self::Io) -> HsmResult<()>;
}
