// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native C API bindings for Tessera Integrated HSM.
//!
//! This crate provides a Foreign Function Interface (FFI) layer that exposes
//! the Rust HSM API to C and C++ applications. It implements the ABI-stable
//! interface with proper error handling, panic catching, and resource management
//! through a global handle table.
//!
//! # Architecture
//!
//! The native API layer consists of:
//! - Handle-based resource management for partitions, sessions, and other objects
//! - ABI boundary functions that catch panics and convert errors
//! - Type-safe wrappers around the internal Rust API
//! - C-compatible types and calling conventions

mod algo;
mod crypto_digest;
mod crypto_enc_dec;
mod crypto_sign_verify;
mod darc;
#[allow(unused)]
#[path = "../../lib/src/error.rs"]
mod error;
mod handle_table;
mod key_mgmt;
mod key_props;
mod part_policy;
mod partition;
mod partition_props;
mod resiliency;
mod sd;
mod session;
mod session_ex;
mod session_props;
#[allow(unused)]
#[path = "../../lib/src/shared_types.rs"]
mod shared_types;
mod str;
mod utils;

use std::ffi::c_void;
use std::ops::AddAssign;
use std::ops::Deref;
use std::ops::DerefMut;
use std::panic::*;
use std::sync::*;

use algo::*;
use handle_table::*;
use key_props::*;
use resiliency::*;
use str::*;
use tsra_api as api;
use utils::*;
use zerocopy::*;

/// Handle type for referencing HSM objects across the FFI boundary.
///
/// A 32-bit unsigned integer used as an opaque handle to reference HSM objects
/// such as partitions, sessions, and keys. Handles are managed by the global
/// handle table and should be treated as opaque identifiers by C callers.
#[repr(transparent)]
#[derive(Eq, Hash, PartialEq, Copy, Clone, Default)]
pub struct TsraHandle(u32);

impl Deref for TsraHandle {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TsraHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AddAssign<u32> for TsraHandle {
    fn add_assign(&mut self, other: u32) {
        self.0 += other;
    }
}

/// Error type used throughout the native API.
///
/// An alias for `HsmError` that represents all possible error conditions
/// in the HSM API. This type is returned across the ABI boundary and can
/// be converted to appropriate error codes for C callers.
type TsraStatus = error::HsmError;

/// Key class type used in the native API.
///
/// An alias for `HsmKeyClass` that represents the class of a cryptographic key.
/// This type is used across the FFI boundary to indicate whether a key is
/// secret, public, or private.
type TsraKeyClass = shared_types::HsmKeyClass;

/// Key kind type used in the native API.
///
/// An alias for `HsmKeyKind` that represents the algorithm type of a cryptographic key.
/// This type is used across the FFI boundary to indicate whether a key is RSA, ECC, AES, etc.
type TsraKeyKind = shared_types::HsmKeyKind;

/// ECC curve type used in the native API.
///
/// An alias for `HsmEccCurve` that represents the elliptic curve used for ECC keys.
/// This type is used across the FFI boundary to specify curves like P-256, P-384, and P-521.
type TsraEccCurve = shared_types::HsmEccCurve;

/// Partition type used in the native API.
/// An alias for `HsmPartType` that represents the type of HSM partition
/// (virtual or physical).
type TsraPartType = shared_types::HsmPartType;

/// Owner backup key source used in the native API.
/// An alias for `HsmOwnerBackupKeySource` that represents the source of the owner backup key
/// (caller-provided or TPM-sealed).
type TsraOwnerBackupKeySource = shared_types::HsmOwnerBackupKeySource;

/// POTA endorsement source used in the native API.
/// An alias for `HsmPotaEndorsementSource` that represents the source of the POTA endorsement
/// (caller-provided or TPM-generated).
type TsraPotaEndorsementSource = shared_types::HsmPotaEndorsementSource;

impl TryFrom<u32> for TsraKeyKind {
    type Error = TsraStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TsraKeyKind::Rsa),
            2 => Ok(TsraKeyKind::Ecc),
            3 => Ok(TsraKeyKind::Aes),
            4 => Ok(TsraKeyKind::AesXts),
            5 => Ok(TsraKeyKind::SharedSecret),
            7 => Ok(TsraKeyKind::HmacSha256),
            8 => Ok(TsraKeyKind::HmacSha384),
            9 => Ok(TsraKeyKind::HmacSha512),
            10 => Ok(TsraKeyKind::AesGcm),
            11 => Ok(TsraKeyKind::Sealing),
            12 => Ok(TsraKeyKind::RsaCrt),
            _ => Err(TsraStatus::InvalidArgument),
        }
    }
}

impl TryFrom<u32> for TsraEccCurve {
    type Error = TsraStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TsraEccCurve::P256),
            2 => Ok(TsraEccCurve::P384),
            3 => Ok(TsraEccCurve::P521),
            _ => Err(TsraStatus::InvalidArgument),
        }
    }
}

impl TryFrom<u32> for TsraKeyClass {
    type Error = TsraStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TsraKeyClass::Secret),
            2 => Ok(TsraKeyClass::Public),
            3 => Ok(TsraKeyClass::Private),
            _ => Err(TsraStatus::InvalidArgument),
        }
    }
}

/// Global handle table for managing HSM object lifetimes.
///
/// This static variable provides a thread-safe, lazily-initialized handle table
/// that tracks all allocated HSM objects (partitions, sessions, keys, etc.).
/// Handles allocated from this table remain valid until explicitly freed or
/// the process terminates.
static HANDLE_TABLE: LazyLock<HandleTable> = LazyLock::new(HandleTable::default);

/// Executes a function at the ABI boundary with panic catching.
///
/// This internal function wraps API calls to provide a safe boundary between
/// Rust and C code. It catches any panics that occur during execution and
/// converts them to appropriate error codes, preventing unwinding across the
/// FFI boundary which would be undefined behavior.
///
/// # Arguments
///
/// * `f` - A closure that performs the API operation and returns a `Result`
///
/// # Returns
///
/// Returns an `TsraError` indicating:
/// - `TsraError::Success` if the operation completed successfully
/// - The specific error if the operation failed
/// - `TsraError::Panic` if a panic occurred during execution
///
/// # Type Parameters
///
/// * `F` - A function or closure that is `UnwindSafe` and returns a `Result<(), TsraError>`
pub(crate) fn abi_boundary<F: FnOnce() -> Result<(), TsraStatus> + UnwindSafe>(f: F) -> TsraStatus {
    match catch_unwind(f) {
        Ok(hr) => match hr {
            Ok(_) => TsraStatus::Success,
            Err(err) => err,
        },
        Err(_) => TsraStatus::Panic,
    }
}

impl From<api::HsmError> for TsraStatus {
    /// Converts an `api::HsmError` into an `TsraError`.
    #[allow(unsafe_code)]
    fn from(err: api::HsmError) -> Self {
        // SAFETY: TsraError and api::HsmError have the same representation
        unsafe { std::mem::transmute(err) }
    }
}

impl From<TsraStatus> for api::HsmError {
    /// Converts an `TsraError` into an `api::HsmError`.
    #[allow(unsafe_code)]
    fn from(err: TsraStatus) -> Self {
        // SAFETY: TsraError and api::HsmError have the same representation
        unsafe { std::mem::transmute(err) }
    }
}

impl From<api::HsmKeyClass> for TsraKeyClass {
    /// Converts an `api::HsmKeyClass` into an `TsraKeyClass`.
    #[allow(unsafe_code)]
    fn from(class: api::HsmKeyClass) -> Self {
        // SAFETY: TsraKeyClass and api::HsmKeyClass have the same representation
        unsafe { std::mem::transmute(class) }
    }
}

impl From<TsraKeyClass> for api::HsmKeyClass {
    /// Converts an `TsraKeyClass` into an `api::HsmKeyClass`.
    #[allow(unsafe_code)]
    fn from(class: TsraKeyClass) -> Self {
        // SAFETY: TsraKeyClass and api::HsmKeyClass have the same representation
        unsafe { std::mem::transmute(class) }
    }
}

impl From<api::HsmKeyKind> for TsraKeyKind {
    /// Converts an `api::HsmKeyKind` into an `TsraKeyKind`.
    #[allow(unsafe_code)]
    fn from(kind: api::HsmKeyKind) -> Self {
        // SAFETY: TsraKeyKind and api::HsmKeyKind have the same representation
        unsafe { std::mem::transmute(kind) }
    }
}

impl From<TsraKeyKind> for api::HsmKeyKind {
    /// Converts an `TsraKeyKind` into an `api::HsmKeyKind`.
    #[allow(unsafe_code)]
    fn from(kind: TsraKeyKind) -> Self {
        // SAFETY: TsraKeyKind and api::HsmKeyKind have the same representation
        unsafe { std::mem::transmute(kind) }
    }
}

impl From<api::HsmEccCurve> for TsraEccCurve {
    /// Converts an `api::HsmEccCurve` into an `TsraEccCurve`.
    #[allow(unsafe_code)]
    fn from(curve: api::HsmEccCurve) -> Self {
        // SAFETY: TsraEccCurve and api::HsmEccCurve have the same representation
        unsafe { std::mem::transmute(curve) }
    }
}

impl From<TsraEccCurve> for api::HsmEccCurve {
    /// Converts an `TsraEccCurve` into an `api::HsmEccCurve`.
    #[allow(unsafe_code)]
    fn from(curve: TsraEccCurve) -> Self {
        // SAFETY: TsraEccCurve and api::HsmEccCurve have the same representation
        unsafe { std::mem::transmute(curve) }
    }
}

impl From<api::HsmPartType> for TsraPartType {
    /// Converts an `api::HsmPartType` into an `TsraPartType`.
    #[allow(unsafe_code)]
    fn from(part_type: api::HsmPartType) -> Self {
        // SAFETY: TsraPartType and api::HsmPartType have the same representation
        unsafe { std::mem::transmute(part_type) }
    }
}

impl From<TsraPartType> for api::HsmPartType {
    /// Converts an `TsraPartType` into an `api::HsmPartType`.
    #[allow(unsafe_code)]
    fn from(part_type: TsraPartType) -> Self {
        // SAFETY: TsraPartType and api::HsmPartType have the same representation
        unsafe { std::mem::transmute(part_type) }
    }
}

impl From<api::HsmOwnerBackupKeySource> for TsraOwnerBackupKeySource {
    /// Converts an `api::HsmOwnerBackupKeySource` into an `TsraOwnerBackupKeySource`.
    #[allow(unsafe_code)]
    fn from(source: api::HsmOwnerBackupKeySource) -> Self {
        // SAFETY: TsraOwnerBackupKeySource and api::HsmOwnerBackupKeySource have the same representation
        unsafe { std::mem::transmute(source) }
    }
}

impl From<TsraOwnerBackupKeySource> for api::HsmOwnerBackupKeySource {
    /// Converts an `TsraOwnerBackupKeySource` into an `api::HsmOwnerBackupKeySource`.
    #[allow(unsafe_code)]
    fn from(source: TsraOwnerBackupKeySource) -> Self {
        // SAFETY: TsraOwnerBackupKeySource and api::HsmOwnerBackupKeySource have the same representation
        unsafe { std::mem::transmute(source) }
    }
}

impl From<api::HsmPotaEndorsementSource> for TsraPotaEndorsementSource {
    /// Converts an `api::HsmPotaEndorsementSource` into an `TsraPotaEndorsementSource`.
    #[allow(unsafe_code)]
    fn from(source: api::HsmPotaEndorsementSource) -> Self {
        // SAFETY: TsraPotaEndorsementSource and api::HsmPotaEndorsementSource have the same representation
        unsafe { std::mem::transmute(source) }
    }
}

impl From<TsraPotaEndorsementSource> for api::HsmPotaEndorsementSource {
    /// Converts an `TsraPotaEndorsementSource` into an `api::HsmPotaEndorsementSource`.
    #[allow(unsafe_code)]
    fn from(source: TsraPotaEndorsementSource) -> Self {
        // SAFETY: TsraPotaEndorsementSource and api::HsmPotaEndorsementSource have the same representation
        unsafe { std::mem::transmute(source) }
    }
}

/// credentials structure used for authentication.
///
/// This structure contains the identifier and PIN required
/// to authenticate with the HSM.
///
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TsraCredentials {
    /// Identifier (16 bytes)
    pub id: [u8; 16],

    /// PIN (16 bytes)
    pub pin: [u8; 16],
}

impl From<TsraCredentials> for api::HsmCredentials {
    fn from(creds: TsraCredentials) -> Self {
        let TsraCredentials { id, pin } = creds;
        api::HsmCredentials { id, pin }
    }
}

impl From<&TsraCredentials> for api::HsmCredentials {
    fn from(creds: &TsraCredentials) -> Self {
        Self::from(*creds)
    }
}

/// API revision structure used to specify the desired API version.
///
/// This structure allows clients to specify the major and minor version
/// numbers of the API they wish to use. It is used to ensure compatibility
/// between different versions of the HSM API.
///
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub struct TsraApiRev {
    /// Major version number
    pub major: u32,

    /// Minor version number
    pub minor: u32,
}

impl From<TsraApiRev> for api::HsmApiRev {
    fn from(rev: TsraApiRev) -> Self {
        api::HsmApiRev {
            major: rev.major,
            minor: rev.minor,
        }
    }
}

impl From<&TsraApiRev> for api::HsmApiRev {
    fn from(rev: &TsraApiRev) -> Self {
        Self::from(*rev)
    }
}

impl From<api::HsmApiRev> for TsraApiRev {
    fn from(rev: api::HsmApiRev) -> Self {
        TsraApiRev {
            major: rev.major,
            minor: rev.minor,
        }
    }
}

impl TryFrom<TsraHandle> for api::HsmSession {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmSession, Self::Error> {
        let session: &api::HsmSession = HANDLE_TABLE.as_ref(value, HandleType::Session)?;
        Ok(session.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmPartition {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmPartition, Self::Error> {
        let partition: &api::HsmPartition = HANDLE_TABLE.as_ref(value, HandleType::Partition)?;
        Ok(partition.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmAesKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmAesKey, Self::Error> {
        let key: &api::HsmAesKey = HANDLE_TABLE.as_ref(value, HandleType::AesKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmAesXtsKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmAesXtsKey, Self::Error> {
        let key: &api::HsmAesXtsKey = HANDLE_TABLE.as_ref(value, HandleType::AesXtsKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmGenericSecretKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmGenericSecretKey, Self::Error> {
        let key: &api::HsmGenericSecretKey =
            HANDLE_TABLE.as_ref(value, HandleType::GenericSecretKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmEccPrivateKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmEccPrivateKey, Self::Error> {
        let key: &api::HsmEccPrivateKey = HANDLE_TABLE.as_ref(value, HandleType::EccPrivKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmEccPublicKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmEccPublicKey, Self::Error> {
        let key: &api::HsmEccPublicKey = HANDLE_TABLE.as_ref(value, HandleType::EccPubKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for HandleType {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<HandleType, Self::Error> {
        HANDLE_TABLE.get_handle_type(value)
    }
}

/// Buffer structure for passing data
///
/// # Safety
/// When using this struct from C code:
/// - `ptr` must point to valid memory for `len` bytes
/// - `ptr` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
#[repr(C)]
pub struct TsraBuffer {
    pub ptr: *mut c_void,
    pub len: u32,
}

impl<'a> TryFrom<&'a TsraBuffer> for &'a [u8] {
    type Error = TsraStatus;

    /// Converts an TsraBuffer to a byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `buffer.buf` points to valid memory
    /// containing at least `buffer.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(buffer: &'a TsraBuffer) -> Result<Self, Self::Error> {
        // Check for null pointer - allow null only if length is 0 (empty buffer)
        if buffer.ptr.is_null() {
            if buffer.len == 0 {
                return Ok(&[]);
            } else {
                return Err(TsraStatus::InvalidArgument);
            }
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts(buffer.ptr as *const u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl<'a> TryFrom<&'a mut TsraBuffer> for &'a mut [u8] {
    type Error = TsraStatus;

    /// Converts a mutable TsraBuffer to a mutable byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `buffer.buf` points to valid memory
    /// containing at least `buffer.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(buffer: &'a mut TsraBuffer) -> Result<Self, Self::Error> {
        // Check for null pointer
        if buffer.ptr.is_null() {
            // Only allow null buffer if length is 0
            if buffer.len == 0 {
                return Ok(&mut []);
            } else {
                return Err(TsraStatus::InvalidArgument);
            }
        }

        // Safety: Caller ensures buffer.buf points to valid memory
        let slice =
            unsafe { std::slice::from_raw_parts_mut(buffer.ptr as *mut u8, buffer.len as usize) };

        Ok(slice)
    }
}

impl TryFrom<TsraHandle> for api::HsmHmacKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmHmacKey, Self::Error> {
        let key: &api::HsmHmacKey = HANDLE_TABLE.as_ref(value, HandleType::HmacKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<TsraHandle> for api::HsmSealingKey {
    type Error = TsraStatus;

    fn try_from(value: TsraHandle) -> Result<api::HsmSealingKey, Self::Error> {
        let key: &api::HsmSealingKey = HANDLE_TABLE.as_ref(value, HandleType::SealingKey)?;
        Ok(key.clone())
    }
}

impl<'a> TryFrom<&'a mut TsraKeyProp> for &'a mut [u8] {
    type Error = TsraStatus;

    /// Converts a mutable TsraKeyProp to a mutable byte slice.
    ///
    /// # Safety
    /// The caller must ensure that `key_prop.buf` points to valid memory
    /// containing at least `key_prop.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(key_prop: &'a mut TsraKeyProp) -> Result<Self, Self::Error> {
        // Check for null pointer
        if key_prop.val.is_null() {
            // Only allow null buffer if length is 0
            if key_prop.len == 0 {
                return Ok(&mut []);
            } else {
                return Err(TsraStatus::InvalidArgument);
            }
        }

        // Safety: Caller ensures key_prop.val points to valid memory
        let slice = unsafe {
            std::slice::from_raw_parts_mut(key_prop.val as *mut u8, key_prop.len as usize)
        };
        Ok(slice)
    }
}

type TsraSessionExType = shared_types::HsmSessionExType;

impl TryFrom<u32> for TsraSessionExType {
    type Error = TsraStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TsraSessionExType::PlainText),
            1 => Ok(TsraSessionExType::Authenticated),
            _ => Err(TsraStatus::InvalidArgument),
        }
    }
}

impl From<api::HsmSessionExType> for TsraSessionExType {
    /// Converts an `api::HsmSessionExType` into an `TsraSessionExType`.
    ///
    /// Both types are `#[open_enum]` wrappers over a `u32`, so the
    /// conversion copies the underlying discriminant directly and never
    /// relies on layout assumptions.
    fn from(session_type: api::HsmSessionExType) -> Self {
        shared_types::HsmSessionExType(session_type.0)
    }
}

impl From<TsraSessionExType> for api::HsmSessionExType {
    /// Converts an `TsraSessionExType` into an `api::HsmSessionExType`.
    ///
    /// Both types are `#[open_enum]` wrappers over a `u32`, so the
    /// conversion copies the underlying discriminant directly and never
    /// relies on layout assumptions.
    fn from(session_type: TsraSessionExType) -> Self {
        api::HsmSessionExType(session_type.0)
    }
}
