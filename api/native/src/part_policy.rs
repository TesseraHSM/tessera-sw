// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition-policy builder for the native C API.
//!
//! The partition init/final, security-domain and DARC entry points take
//! the partition policy as an opaque CBOR document. This module exposes
//! an opaque builder that sets typed fields and serializes the canonical
//! document into a caller-provided buffer, plus a helper that computes a
//! public key's SPKI thumbprint. Callers may equally encode the document
//! with any conforming CBOR encoder.

use super::*;

/// Encoding of a public key passed to the policy builder.
pub type TsraPolicyKeyFormat = u32;

/// A precomputed 48-byte SPKI thumbprint (SHA-384 of the key's DER
/// SubjectPublicKeyInfo).
pub const TSRA_POLICY_KEY_FORMAT_THUMBPRINT: TsraPolicyKeyFormat = 0;

/// A DER SubjectPublicKeyInfo of any key algorithm, hashed as given.
pub const TSRA_POLICY_KEY_FORMAT_SPKI_DER: TsraPolicyKeyFormat = 1;

/// A raw uncompressed ECC P-384 public key, `X || Y` (96 bytes).
pub const TSRA_POLICY_KEY_FORMAT_ECC_P384: TsraPolicyKeyFormat = 2;

/// Opaque partition-policy builder handle.
///
/// Created by [`tsra_part_policy_builder_new`], populated through the
/// `tsra_part_policy_builder_set_*` setters, serialized with
/// [`tsra_part_policy_build`], and released with
/// [`tsra_part_policy_builder_free`].
pub struct TsraPartPolicyBuilder {
    inner: api::PartPolicyBuilder,
}

fn key_format(format: TsraPolicyKeyFormat) -> Result<api::PolicyKeyFormat, TsraStatus> {
    match format {
        TSRA_POLICY_KEY_FORMAT_THUMBPRINT => Ok(api::PolicyKeyFormat::Thumbprint),
        TSRA_POLICY_KEY_FORMAT_SPKI_DER => Ok(api::PolicyKeyFormat::SpkiDer),
        TSRA_POLICY_KEY_FORMAT_ECC_P384 => Ok(api::PolicyKeyFormat::EccP384),
        _ => Err(TsraStatus::InvalidArgument),
    }
}

/// Apply a fluent setter to the boxed builder in place, keeping the C
/// handle's address stable.
fn with_builder<F>(builder: *mut TsraPartPolicyBuilder, f: F) -> Result<(), TsraStatus>
where
    F: FnOnce(api::PartPolicyBuilder) -> api::PartPolicyBuilder,
{
    let b = deref_mut_ptr(builder)?;
    b.inner = f(std::mem::take(&mut b.inner));
    Ok(())
}

/// Shared body of the `tsra_part_policy_builder_set_*_key` setters.
fn set_key<F>(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
    set: F,
) -> Result<(), TsraStatus>
where
    F: FnOnce(api::PartPolicyBuilder, api::PolicyKeyFormat, &[u8]) -> api::PartPolicyBuilder,
{
    let format = key_format(format)?;
    let raw: &[u8] = deref_ptr(key)?.try_into()?;
    with_builder(builder, |b| set(b, format, raw))
}

/// @brief Allocate a new partition-policy builder
///
/// The builder starts empty: no keys, no flags and no optional fields.
/// Set the required POTA and SATA keys and any optional fields through the
/// `tsra_part_policy_builder_set_*` functions, then serialize it with
/// `tsra_part_policy_build`. Release it with
/// `tsra_part_policy_builder_free`.
///
/// Setters only report NULL/misaligned handles or buffers and unknown key
/// formats; invalid field values are reported by `tsra_part_policy_build`.
///
/// @param[out] out_builder Receives the non-NULL builder handle on
///             success; left unmodified on failure.
///
/// @return `TSRA_STATUS_SUCCESS` on success, or
///         `TSRA_STATUS_INVALID_ARGUMENT` if `out_builder` is NULL.
///
/// # Safety
///
/// - `out_builder` must be a valid, writable pointer to storage for one
///   `tsra_part_policy_builder *`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_new(
    out_builder: *mut *mut TsraPartPolicyBuilder,
) -> TsraStatus {
    abi_boundary(|| {
        validate_ptr(out_builder)?;

        let handle = Box::into_raw(Box::new(TsraPartPolicyBuilder {
            inner: api::PartPolicyBuilder::new(),
        }));
        assign_ptr(out_builder, handle)
    })
}

/// @brief Free a partition-policy builder
///
/// Releases a handle returned by `tsra_part_policy_builder_new`.
/// Passing NULL is a no-op. The handle must not be used afterwards.
///
/// @param[in] builder Builder handle to free (may be NULL)
///
/// # Safety
///
/// - `builder` must be NULL or a handle returned by
///   `tsra_part_policy_builder_new` that has not already been freed.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_free(builder: *mut TsraPartPolicyBuilder) {
    if !builder.is_null() {
        // Safety: reclaim the Box allocated in `_new`.
        drop(unsafe { Box::from_raw(builder) });
    }
}

/// @brief Set the POTA (Partition Owner Trust Anchor) public key (required)
///
/// @param[in] builder Builder handle
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer or an unknown `format`
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `key` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_pota_key(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| set_key(builder, format, key, |b, f, k| b.pota_key(f, k)))
}

/// @brief Set the SATA (Sealing Authority Trust Anchor) public key (required)
///
/// @param[in] builder Builder handle
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer or an unknown `format`
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `key` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_sata_key(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| set_key(builder, format, key, |b, f, k| b.sata_key(f, k)))
}

/// @brief Set the SAPOTA (Sealing Authority's POTA) public key
///
/// @param[in] builder Builder handle
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer or an unknown `format`
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `key` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_sapota_key(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| set_key(builder, format, key, |b, f, k| b.sapota_key(f, k)))
}

/// @brief Set the backing-partition identifier
///
/// Must be exactly 16 bytes and set together with
/// `tsra_part_policy_builder_set_backup_part_key`.
///
/// @param[in] builder Builder handle
/// @param[in] id Backing-partition identifier bytes
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `id` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_backup_part_id(
    builder: *mut TsraPartPolicyBuilder,
    id: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(id)?.try_into()?;
        with_builder(builder, |b| b.backup_part_id(raw))
    })
}

/// @brief Set the backing partition's PID public key
///
/// Must be set together with `tsra_part_policy_builder_set_backup_part_id`.
///
/// @param[in] builder Builder handle
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer or an unknown `format`
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `key` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_backup_part_key(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| set_key(builder, format, key, |b, f, k| b.backup_part_key(f, k)))
}

/// @brief Set the DATA (DARC TMK authority) public key
///
/// @param[in] builder Builder handle
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer or an unknown `format`
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `key` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_data_key(
    builder: *mut TsraPartPolicyBuilder,
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| set_key(builder, format, key, |b, f, k| b.data_key(f, k)))
}

/// @brief Set the caller-provided opaque `info` field
///
/// At most 64 bytes; an empty buffer omits the field.
///
/// @param[in] builder Builder handle
/// @param[in] info Opaque info bytes
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         handle / buffer
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `info` must be NULL or point to a valid `tsra_buffer`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_info(
    builder: *mut TsraPartPolicyBuilder,
    info: *const TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let raw: &[u8] = deref_ptr(info)?.try_into()?;
        with_builder(builder, |b| b.info(raw))
    })
}

/// @brief Set the policy flag bits
///
/// Bit 0 `include_fmc_cdi`, bit 1 `require_trusted_sa_key`, bit 2
/// `allow_peer_cloning`; reserved bits 3-7 are rejected by
/// `tsra_part_policy_build`.
///
/// @param[in] builder Builder handle
/// @param[in] flags Raw flag bits
/// @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL handle
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_builder_set_flags(
    builder: *mut TsraPartPolicyBuilder,
    flags: u8,
) -> TsraStatus {
    abi_boundary(|| with_builder(builder, |b| b.flags(api::PolicyFlags::from_bits(flags))))
}

/// @brief Serialize the policy into its CBOR document
///
/// Validates the fields and writes the deterministic CBOR document (at
/// most 384 bytes) accepted by the partition, security-domain and DARC
/// entry points into `out`. If `out` is too small, sets `out.len` to the
/// required size and returns `TSRA_STATUS_BUFFER_TOO_SMALL` without
/// writing. The builder is left unchanged and remains usable.
///
/// Returns `TSRA_STATUS_INVALID_ARGUMENT`, even for a size probe, if a
/// setter received an invalid key, identifier or `info`, the POTA or SATA
/// key is missing, only one of the backing-partition identifier and key
/// is set, or a reserved flag bit is set.
///
/// @param[in] builder Builder handle
/// @param[out] out Buffer to receive the encoded policy
/// @return `TSRA_STATUS_SUCCESS`, `TSRA_STATUS_INVALID_ARGUMENT`, or
///         `TSRA_STATUS_BUFFER_TOO_SMALL` if `out` is too small
///
/// # Safety
///
/// - `builder` must be a live handle from `tsra_part_policy_builder_new`.
/// - `out` must be a valid pointer to a `tsra_buffer` with writable
///   backing storage of its advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_part_policy_build(
    builder: *mut TsraPartPolicyBuilder,
    out: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let b = deref_mut_ptr(builder)?;
        let output = deref_mut_ptr(out)?;
        let policy = b.inner.build()?;
        copy_to_buffer(output, &policy)
    })
}

/// @brief Compute a public key's SPKI thumbprint
///
/// Writes the 48-byte SHA-384 of the key's DER SubjectPublicKeyInfo, the
/// value the policy uses to name the key. If `out` is too small, sets
/// `out.len` to 48 and returns `TSRA_STATUS_BUFFER_TOO_SMALL`.
///
/// @param[in] format Key encoding (`TSRA_POLICY_KEY_FORMAT_*`)
/// @param[in] key Key bytes in `format`
/// @param[out] out Buffer to receive the thumbprint
/// @return `TSRA_STATUS_SUCCESS`, `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
///         buffer, unknown `format` or malformed `key`, or
///         `TSRA_STATUS_BUFFER_TOO_SMALL` if `out` is too small
///
/// # Safety
///
/// - `key` must be NULL or point to a valid `tsra_buffer`.
/// - `out` must be a valid pointer to a `tsra_buffer` with writable
///   backing storage of its advertised length.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn tsra_policy_key_thumbprint(
    format: TsraPolicyKeyFormat,
    key: *const TsraBuffer,
    out: *mut TsraBuffer,
) -> TsraStatus {
    abi_boundary(|| {
        let format = key_format(format)?;
        let raw: &[u8] = deref_ptr(key)?.try_into()?;
        let output = deref_mut_ptr(out)?;
        let thumbprint = api::policy_key_thumbprint(format, raw)?;
        copy_to_buffer(output, &thumbprint)
    })
}
