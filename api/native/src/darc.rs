// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC key-transfer command FFI for the native C API.
//!
//! FFI bindings for the six DARC commands (`DarcKexKeyGen`, `DarcTmkGen`,
//! `DarcTmkExport`, `DarcTmkImport`, `DarcKeyWrap`, `DarcKeyUnwrap`),
//! exposed to C callers through the ABI-compatible interface. All are
//! Crypto-Officer, in-session commands issued on a security-domain (V2)
//! session; a V1 session yields `InvalidSession`.

use super::*;

/// Maximum target-chain depth; PID source chains additionally allow PTA.
const DARC_CERT_CHAIN_MAX_CERTS: usize = 2;
const DARC_SOURCE_CERT_CHAIN_MAX_CERTS: usize = 3;

/// A DARC certificate chain: an array of `len` `tsra_buffer`s, each a
/// DER-encoded certificate (root to leaf). The DER bytes are borrowed, not
/// copied.
#[repr(C)]
pub struct TsraDarcCertChain {
    /// Pointer to an array of `len` DER certificate `tsra_buffer`s.
    pub certs: *const TsraBuffer,
    /// Number of certificates in `certs`.
    pub len: u32,
}

/// Borrows one C [`TsraDarcCertChain`] into a `Vec<HsmCert>`, rejecting an
/// empty or oversized chain up front so a bogus `len` cannot trigger an
/// unbounded allocation ahead of the host validation.
#[allow(unsafe_code)]
fn unpack_cert_chain(
    chain: &TsraDarcCertChain,
    max_certs: usize,
) -> Result<Vec<api::HsmCert<'_>>, TsraStatus> {
    let len = chain.len as usize;
    if len == 0 || len > max_certs {
        Err(TsraStatus::InvalidArgument)?;
    }
    validate_ptr(chain.certs)?;
    // SAFETY: `certs` is non-null and aligned for `TsraBuffer` (checked by
    // `validate_ptr`), the caller guarantees it points to `len` valid
    // `tsra_buffer`s, and `len` is bounded by the command's chain limit.
    let raw = unsafe { std::slice::from_raw_parts(chain.certs, len) };
    let mut certs = Vec::with_capacity(len);
    for buf in raw {
        let der: &[u8] = buf.try_into()?;
        certs.push(api::HsmCert { cert: der });
    }
    Ok(certs)
}

/// @brief Generate a DARC key-exchange (KEX) key
///
/// Generates a new DARC key-exchange key (ECC-P384) on the calling
/// session's partition and returns the masked private key plus its raw
/// P-384 public key (`x ‖ y`, 96 bytes, big-endian per coordinate). Run on
/// the target it yields the HPKE recipient key. The source uses its PID
/// to authenticate export reports. The key is not stored on the
/// device.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] scope Requested key scope (1-byte `KeyScope` discriminant)
/// @param[in,out] masked_key Output buffer for the masked KEX private key
///                (`MASKED_KEX_KEY_LEN`, 280 B)
/// @param[in,out] pub_key Output buffer for the raw P-384 public key
///                (`KEX_PUB_KEY_LEN`, 96 B)
///
/// Both output buffers follow the probe/fill convention and are validated
/// **before** the round-trip.
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - Each output buffer must be a valid `tsra_buffer` with writable
///   backing storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_kex_key_gen(
    sess_handle: TsraHandle,
    scope: u8,
    masked_key: *mut TsraBuffer,
    pub_key: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;

        validate_distinct_output_buffers(&[masked_key, pub_key])?;
        let masked_key = deref_mut_ptr(masked_key)?;
        let pub_key = deref_mut_ptr(pub_key)?;
        validate_output_sizes(&mut [
            (&mut *masked_key, api::MASKED_KEX_KEY_LEN),
            (&mut *pub_key, api::KEX_PUB_KEY_LEN),
        ])?;

        let (masked, pubk) = session.darc_kex_key_gen(scope)?;

        copy_to_buffer(masked_key, &masked)?;
        copy_to_buffer(pub_key, &pubk)?;
        Ok(())
    })
}

/// @brief Mint a DARC Transfer Masking Key (TMK)
///
/// Mints a fresh 256-bit TMK on the source's partition and returns it
/// masked under the partition SDMK. The key is not stored on the device.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in,out] masked_tmk Output buffer for the masked TMK
///                (`MASKED_TMK_LEN`, 264 B)
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `masked_tmk` must be a valid `tsra_buffer` with writable backing
///   storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_tmk_gen(
    sess_handle: TsraHandle,
    masked_tmk: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let masked_tmk = deref_mut_ptr(masked_tmk)?;
        validate_output_buffer(masked_tmk, api::MASKED_TMK_LEN)?;

        let tmk = session.darc_tmk_gen()?;
        copy_to_buffer(masked_tmk, &tmk)?;
        Ok(())
    })
}

/// Input buffers for [`tsra_darc_tmk_export`].
#[repr(C)]
pub struct TsraDarcTmkExportParams {
    /// Masked TMK (from `tsra_darc_tmk_gen`), exactly `MASKED_TMK_LEN`
    /// (264 B).
    pub masked_tmk: *const TsraBuffer,
    /// Partition policy CBOR document (at most 384 B) whose DATA key
    /// thumbprint anchors
    /// `target_cert_chain`.
    pub policy: *const TsraBuffer,
    /// DATA-anchored target certificate chain (1..=2 certs).
    pub target_cert_chain: TsraDarcCertChain,
}

/// @brief Seal a DARC TMK to an authenticated target
///
/// Validates the target certificate chain against the policy `data_spki_thumbprint`,
/// then HPKE Base seals the TMK to the target's KEX key and PID-signs the
/// complete encrypted envelope directly as COSE_Sign1.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Export input buffers
/// @param[in,out] sealed_tmk Output buffer for the sealed TMK
///                (`SEALED_TMK_LEN`, 367 B), including the PID signature.
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer pointers must be valid; the
///   `target_cert_chain.certs` array must hold `len` valid `tsra_buffer`s.
/// - The output buffer must be valid and writable.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_tmk_export(
    sess_handle: TsraHandle,
    params: *const TsraDarcTmkExportParams,
    sealed_tmk: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_tmk: &[u8] = deref_ptr(params.masked_tmk)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let target_cert_chain =
            unpack_cert_chain(&params.target_cert_chain, DARC_CERT_CHAIN_MAX_CERTS)?;

        let sealed_tmk = deref_mut_ptr(sealed_tmk)?;
        validate_output_buffer(sealed_tmk, api::SEALED_TMK_LEN)?;

        let sealed = session.darc_tmk_export(masked_tmk, policy, &target_cert_chain)?;
        copy_to_buffer(sealed_tmk, &sealed.sealed_tmk)?;
        Ok(())
    })
}

/// Input buffers for [`tsra_darc_tmk_import`].
#[repr(C)]
pub struct TsraDarcTmkImportParams {
    /// Target's masked DARC KEX key (from `tsra_darc_kex_key_gen`),
    /// exactly `MASKED_KEX_KEY_LEN` (280 B).
    pub masked_kex_key: *const TsraBuffer,
    /// Partition policy CBOR document (at most 384 B) whose POTA key
    /// thumbprint anchors
    /// `remote_cert_chain`.
    pub policy: *const TsraBuffer,
    /// Sealed TMK (from `tsra_darc_tmk_export`), exactly `SEALED_TMK_LEN`
    /// (367 B), including the PID signature.
    pub sealed_tmk: *const TsraBuffer,
    /// POTA-anchored source PID certificate chain (1..=3 certs).
    pub remote_cert_chain: TsraDarcCertChain,
}

/// @brief Import (open) a sealed DARC TMK on the target
///
/// Authorizes the source PID chain against the policy `pota_spki_thumbprint`,
/// verifies the `Darc` report and exact recipient/envelope binding,
/// HPKE Base opens the sealed TMK, and re-masks it under the partition
/// SDMK, returning the masked TMK.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Import input buffers
/// @param[in,out] masked_tmk Output buffer for the imported masked TMK
///                (`MASKED_TMK_LEN`, 264 B)
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer pointers must be valid; the
///   `remote_cert_chain.certs` array must hold `len` valid `tsra_buffer`s.
/// - `masked_tmk` must be a valid `tsra_buffer` with writable backing
///   storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_tmk_import(
    sess_handle: TsraHandle,
    params: *const TsraDarcTmkImportParams,
    masked_tmk: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_kex_key: &[u8] = deref_ptr(params.masked_kex_key)?.try_into()?;
        let policy: &[u8] = deref_ptr(params.policy)?.try_into()?;
        let sealed_tmk: &[u8] = deref_ptr(params.sealed_tmk)?.try_into()?;
        let remote_cert_chain =
            unpack_cert_chain(&params.remote_cert_chain, DARC_SOURCE_CERT_CHAIN_MAX_CERTS)?;

        let masked_tmk = deref_mut_ptr(masked_tmk)?;
        validate_output_buffer(masked_tmk, api::MASKED_TMK_LEN)?;

        let imported =
            session.darc_tmk_import(masked_kex_key, policy, sealed_tmk, &remote_cert_chain)?;
        copy_to_buffer(masked_tmk, &imported)?;
        Ok(())
    })
}

/// Input parameters for [`tsra_darc_key_wrap`].
#[repr(C)]
pub struct TsraDarcKeyWrapParams {
    /// Handle to the source EC private key to export (the transferred key).
    pub source_key: TsraHandle,
    /// Masked TMK (from `tsra_darc_tmk_gen` or `tsra_darc_tmk_import`),
    /// exactly `MASKED_TMK_LEN` (264 B).
    pub masked_tmk: *const TsraBuffer,
}

/// @brief Wrap a designated EC private key under a DARC TMK
///
/// AES-KWP-wraps the source key's EC2 `COSE_Key` under the TMK, returning
/// the wrapped transport blob. The source key is supplied as a handle (the
/// same handle model as `tsra_key_unwrap_pair`); the raw key material
/// never leaves the device.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Wrap input parameters (source key handle + masked TMK)
/// @param[in,out] wrapped_key Output buffer for the wrapped key (at most
///                `DARC_WRAP_WRAPPED_KEY_MAX_LEN`, 512 B). Follows the
///                probe/fill convention: on `BufferTooSmall` the required
///                size is written to `wrapped_key.len`.
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params.source_key` must be a valid EC private-key handle and
///   `params.masked_tmk` a valid `tsra_buffer`.
/// - `wrapped_key` must be a valid `tsra_buffer` with writable backing
///   storage of the advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_key_wrap(
    sess_handle: TsraHandle,
    params: *const TsraDarcKeyWrapParams,
    wrapped_key: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_tmk: &[u8] = deref_ptr(params.masked_tmk)?.try_into()?;
        let source_key = api::HsmEccPrivateKey::try_from(params.source_key)?;

        let wrapped_key = deref_mut_ptr(wrapped_key)?;

        let tmk = api::HsmDarcTmk::new(session, masked_tmk);
        let wrapped = api::HsmKeyManager::wrap_key(
            &mut api::HsmEccKeyDarcKeyWrapAlgo::new(),
            &tmk,
            &source_key,
        )?;
        copy_to_buffer(wrapped_key, &wrapped)?;
        Ok(())
    })
}

/// Input parameters for [`tsra_darc_key_unwrap`].
#[repr(C)]
pub struct TsraDarcKeyUnwrapParams {
    /// Masked TMK (from `tsra_darc_tmk_import`), exactly `MASKED_TMK_LEN`
    /// (264 B).
    pub masked_tmk: *const TsraBuffer,
    /// AES-KWP-wrapped `COSE_Key` (from `tsra_darc_key_wrap`), at most
    /// `DARC_UNWRAP_WRAPPED_KEY_MAX_LEN` (512 B).
    pub wrapped_key: *const TsraBuffer,
    /// Requested properties for the recovered private key. The recovered
    /// key's kind (curve) is validated against these.
    pub priv_key_props: *const TsraKeyPropList,
    /// Requested properties for the recovered public key.
    pub pub_key_props: *const TsraKeyPropList,
}

/// @brief Unwrap and install a transferred key pair on the target
///
/// AES-KWP-unwraps `wrapped_key` under the TMK and installs the recovered
/// EC key pair, returning handles to the private and public keys (the same
/// handle model as `tsra_key_unwrap_pair`). The recovered curve is
/// validated against `priv_key_props`.
///
/// @param[in] sess_handle Handle to the security-domain session
/// @param[in] params Unwrap input parameters
/// @param[out] priv_key_handle Handle to the recovered private key
/// @param[out] pub_key_handle Handle to the recovered public key
///
/// @return `TsraStatus` indicating the result of the operation
///
/// # Safety
///
/// - `sess_handle` must be a valid security-domain session handle.
/// - `params` and each of its buffer/prop-list pointers must be valid.
/// - `priv_key_handle` and `pub_key_handle` must be valid, writable,
///   distinct handle pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_darc_key_unwrap(
    sess_handle: TsraHandle,
    params: *const TsraDarcKeyUnwrapParams,
    priv_key_handle: *mut TsraHandle,
    pub_key_handle: *mut TsraHandle,
) -> TsraStatus {
    abi_boundary(|| {
        validate_output_handle_ptrs(priv_key_handle, pub_key_handle)?;

        let session = api::HsmSession::try_from(sess_handle)?;
        let params = deref_ptr(params)?;

        let masked_tmk: &[u8] = deref_ptr(params.masked_tmk)?.try_into()?;
        let wrapped_key: &[u8] = deref_ptr(params.wrapped_key)?.try_into()?;

        let priv_props = deref_ptr(params.priv_key_props)?;
        let priv_key_props = api::HsmKeyProps::try_from(priv_props)?;
        let pub_props = deref_ptr(params.pub_key_props)?;
        let pub_key_props = api::HsmKeyProps::try_from(pub_props)?;

        let tmk = api::HsmDarcTmk::new(session, masked_tmk);
        let (priv_key, pub_key): (api::HsmEccPrivateKey, api::HsmEccPublicKey) =
            api::HsmKeyManager::unwrap_key_pair(
                &mut api::HsmEccKeyDarcKeyUnwrapAlgo::new(),
                &tmk,
                wrapped_key,
                priv_key_props,
                pub_key_props,
            )?;

        let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
        let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

        assign_ptr(priv_key_handle, priv_handle)?;
        assign_ptr(pub_key_handle, pub_handle)?;
        Ok(())
    })
}
