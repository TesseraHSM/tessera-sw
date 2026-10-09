// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use algo::sha::*;
use api::HsmHashAlgo;
use tsra_api::HsmSession;

use super::*;

/// Compute cryptographic digest (hash) of data using the specified algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] data Pointer to data buffer to be hashed
/// @param[out] digest Pointer to digest output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_crypt_digest(
    sess_handle: TsraHandle,
    algo: *const TsraAlgo,
    data: *const TsraBuffer,
    digest: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let algo_spec = deref_ptr(algo)?;
        let input_buf = deref_ptr(data)?;
        let output_buf = deref_mut_ptr(digest)?;
        let session: HsmSession = HsmSession::try_from(sess_handle)?;
        let input_data: &[u8] = input_buf.try_into()?;

        // Match on algorithm ID and call appropriate handler
        match algo_spec.id {
            TsraAlgoId::Sha1 => {
                sha_digest(&session, HsmHashAlgo::Sha1, input_data, output_buf)?;
            }
            TsraAlgoId::Sha256 => {
                sha_digest(&session, HsmHashAlgo::Sha256, input_data, output_buf)?;
            }
            TsraAlgoId::Sha384 => {
                sha_digest(&session, HsmHashAlgo::Sha384, input_data, output_buf)?;
            }
            TsraAlgoId::Sha512 => {
                sha_digest(&session, HsmHashAlgo::Sha512, input_data, output_buf)?;
            }
            _ => return Err(TsraStatus::InvalidArgument),
        }

        Ok(())
    })
}

/// Initialize a streaming digest operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[out] ctx_handle Pointer to receive the digest context handle
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_crypt_digest_init(
    sess_handle: TsraHandle,
    algo: *const TsraAlgo,
    ctx_handle: *mut TsraHandle,
) -> TsraStatus {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;
        let algo_spec = deref_ptr(algo)?;
        let ctx_handle_out = deref_mut_ptr(ctx_handle)?;

        // Get session from handle table
        let session: HsmSession = HsmSession::try_from(sess_handle)?;

        // Match on algorithm ID and call appropriate handler
        let handle = match algo_spec.id {
            TsraAlgoId::Sha1 => sha_digest_init(session, HsmHashAlgo::Sha1)?,
            TsraAlgoId::Sha256 => sha_digest_init(session, HsmHashAlgo::Sha256)?,
            TsraAlgoId::Sha384 => sha_digest_init(session, HsmHashAlgo::Sha384)?,
            TsraAlgoId::Sha512 => sha_digest_init(session, HsmHashAlgo::Sha512)?,
            _ => return Err(TsraStatus::InvalidArgument),
        };

        // Return the handle
        assign_ptr(ctx_handle_out, handle)?;

        Ok(())
    })
}

/// Update a streaming digest operation with more data.
///
/// @param[in] ctx_handle Handle to the digest context
/// @param[in] data Pointer to data buffer to digest
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_crypt_digest_update(
    ctx_handle: TsraHandle,
    data: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let data_buf = deref_ptr(data)?;
        let input_data: &[u8] = data_buf.try_into()?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::ShaCtx => {
                sha_digest_update(ctx_handle, input_data)?;
            }
            // Add support for other context types here as needed (HMAC, etc.)
            _ => Err(TsraStatus::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finish a streaming digest operation and produce the digest.
///
/// @param[in] ctx_handle Handle to the digest context
/// @param[out] digest Pointer to digest output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// TSRA_STATUS_BUFFER_TOO_SMALL is returned.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_crypt_digest_finish(
    ctx_handle: TsraHandle,
    digest: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let digest_buf = deref_mut_ptr(digest)?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::ShaCtx => {
                sha_digest_finish(ctx_handle, digest_buf)?;
            }
            // Add support for other context types here as needed (HMAC, etc.)
            _ => Err(TsraStatus::InvalidHandle)?,
        }

        Ok(())
    })
}
