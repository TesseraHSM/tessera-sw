// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::c_void;

use super::*;

/// Validates that `ptr` is non-null **and** correctly aligned for `T`.
///
/// Both properties are required before the pointer is dereferenced (via
/// [`deref_ptr`] / [`deref_mut_ptr`]) or used to form a slice with
/// [`std::slice::from_raw_parts`]: a null or misaligned pointer from a C
/// caller is undefined behavior to dereference, so reject it up front with
/// `InvalidArgument` rather than rely solely on the caller's `# Safety`
/// contract.
pub(crate) fn validate_ptr<T>(ptr: *const T) -> Result<(), TsraStatus> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(std::mem::align_of::<T>()) {
        Err(TsraStatus::InvalidArgument)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_algo_params<T>(algo: &TsraAlgo) -> Result<(), TsraStatus> {
    if algo.len != std::mem::size_of::<T>() as u32 {
        Err(TsraStatus::InvalidArgument)?;
    }
    // Validate against the concrete `T` (not the `*const c_void` field type)
    // so the alignment check uses `align_of::<T>()`, matching the `&T` that
    // `cast_ptr` / `deref_mut_ptr` will form from this pointer.
    validate_ptr(algo.params as *const T)
}

/// Validates that an algorithm descriptor intentionally carries no parameter payload.
///
/// Some algorithm IDs are defined by the C ABI as "parameterless" (there is no
/// corresponding `struct` to parse). For those algorithms, callers must pass:
/// - `algo.params == NULL`
/// - `algo.len == 0`
///
/// This is a strict ABI-shape check at the FFI boundary. It ensures malformed
/// pointer/length combinations are rejected early with `InvalidArgument` instead
/// of being silently ignored.
pub(crate) fn validate_algo_params_absent(algo: &TsraAlgo) -> Result<(), TsraStatus> {
    if !algo.params.is_null() || algo.len != 0 {
        Err(TsraStatus::InvalidArgument)?;
    }

    Ok(())
}

pub(crate) fn validate_and_cast_algo_params<T>(algo: &TsraAlgo) -> Result<&T, TsraStatus> {
    validate_algo_params::<T>(algo)?;
    cast_ptr::<T>(algo.params)
}

pub(crate) fn validate_and_cast_algo_params_mut<T>(
    algo: &mut TsraAlgo,
) -> Result<&mut T, TsraStatus> {
    validate_algo_params::<T>(algo)?;
    deref_mut_ptr::<T>(algo.params as *mut T)
}

/// Safely dereference a mutable pointer
///
/// # Safety
/// The function validates that the pointer is non-null and aligned before
/// dereferencing.
#[allow(unsafe_code)]
#[allow(unused)]
pub(crate) fn deref_mut_ptr<'a, T>(ptr: *mut T) -> Result<&'a mut T, TsraStatus> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null and aligned above
    Ok(unsafe { &mut *ptr })
}

/// Safely dereference a constant pointer
///
/// # Safety
/// The function validates that the pointer is non-null and aligned before
/// dereferencing.
#[allow(unsafe_code)]
pub(crate) fn deref_ptr<'a, T>(ptr: *const T) -> Result<&'a T, TsraStatus> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null and aligned above
    Ok(unsafe { &*ptr })
}

/// Safely assign a value to a pointer
///
/// # Safety
///
/// The function validates that the pointer is non-null before writing.
#[allow(unsafe_code)]
pub(crate) fn assign_ptr<T>(ptr: *mut T, value: T) -> Result<(), TsraStatus> {
    validate_ptr(ptr)?;

    // SAFETY: Pointer has been validated as non-null above
    unsafe {
        *ptr = value;
    }
    Ok(())
}

/// Validates that two output handle pointers are non-null and distinct.
///
/// Used at the FFI boundary for APIs that return a key pair (private + public).
/// Rejects null pointers and the case where the caller passes the same pointer
/// for both outputs, which would silently overwrite the first handle.
pub(crate) fn validate_output_handle_ptrs(
    first: *mut TsraHandle,
    second: *mut TsraHandle,
) -> Result<(), TsraStatus> {
    validate_ptr(first)?;
    validate_ptr(second)?;

    if std::ptr::eq(first, second) {
        Err(TsraStatus::InvalidArgument)?;
    }

    Ok(())
}

/// Validate and prepare the caller-provided output buffer.
///
/// - If the buffer is large enough, returns a mutable slice to write into.
/// - If it is too small, sets `output_buf.len` to `required_len` and returns
///   `TsraError::BufferTooSmall` so the caller can resize and retry.
///
/// This function does not write any data; it only checks size and produces
/// a slice on success.
pub(crate) fn validate_output_buffer(
    output_buf: &mut crate::TsraBuffer,
    required_len: usize,
) -> Result<&mut [u8], TsraStatus> {
    if output_buf.ptr.is_null() && output_buf.len != 0 {
        // Only allow null buffer if length is 0 (for size-query case)
        Err(TsraStatus::InvalidArgument)?;
    }

    // Check if output buffer is large enough
    if output_buf.len < required_len as u32 {
        output_buf.len = required_len as u32;
        Err(TsraStatus::BufferTooSmall)?;
    }

    // Get output buffer slice
    output_buf.try_into()
}

/// Validates that every output-buffer pointer is non-null, aligned, and
/// pairwise distinct.
///
/// Used at the FFI boundary for APIs with multiple `tsra_buffer` outputs:
/// two identical pointers would let the callee form two `&mut TsraBuffer`
/// references to the same location, which is undefined behavior. Rejects
/// null/misaligned or aliasing pointers with `InvalidArgument`.
pub(crate) fn validate_distinct_output_buffers(
    buffers: &[*mut crate::TsraBuffer],
) -> Result<(), TsraStatus> {
    for (i, &ptr) in buffers.iter().enumerate() {
        validate_ptr(ptr)?;
        if buffers[..i].iter().any(|&other| std::ptr::eq(other, ptr)) {
            Err(TsraStatus::InvalidArgument)?;
        }
    }
    Ok(())
}

/// Size-check already-dereferenced output buffers; if any is too small, sets
/// **every** buffer's `len` to its required length before returning
/// `BufferTooSmall`, so one probe advertises all capacities.
pub(crate) fn validate_output_sizes(
    buffers: &mut [(&mut crate::TsraBuffer, usize)],
) -> Result<(), TsraStatus> {
    let mut too_small = false;
    for (buf, required_len) in buffers.iter_mut() {
        match validate_output_buffer(buf, *required_len) {
            Ok(_) => {}
            Err(TsraStatus::BufferTooSmall) => too_small = true,
            Err(other) => return Err(other),
        }
    }
    if too_small {
        for (buf, required_len) in buffers.iter_mut() {
            buf.len = *required_len as u32;
        }
        Err(TsraStatus::BufferTooSmall)?;
    }
    Ok(())
}

/// Cast a raw pointer to a typed reference after validation
///
/// # Safety
/// The caller must ensure that:
/// - The pointer points to valid memory containing a properly initialized value of type T
/// - The memory layout matches the expected type T
/// - The pointer's lifetime exceeds the returned reference lifetime
///
/// # Arguments
/// * `ptr` - Raw pointer to cast
///
/// # Returns
/// * `Ok(&T)` - Reference to the typed value
/// * `Err(TsraStatus::InvalidArgument)` - If the pointer is null or
///   misaligned for `T`
#[allow(unsafe_code)]
pub(crate) fn cast_ptr<'a, T>(ptr: *const c_void) -> Result<&'a T, TsraStatus> {
    // Cast to `*const T` before validating so the check uses `align_of::<T>()`;
    // forming `&T` from a misaligned address is undefined behavior.
    let ptr = ptr as *const T;
    validate_ptr(ptr)?;

    // SAFETY: `ptr` has been validated as non-null and aligned for `T`. The
    // caller is responsible for ensuring it points to valid memory containing
    // a properly initialized value of type `T`.
    Ok(unsafe { &*ptr })
}

/// Copy a byte slice into a key property buffer
///
/// # Arguments
///
/// * `key_prop` - The key property to copy into
/// * `bytes` - The byte slice to copy from
///
/// # Returns
///
/// * `Ok(())` - On success
/// * `Err(TsraError::BufferTooSmall)` - If the key property buffer is too small
pub(crate) fn copy_to_key_prop(key_prop: &mut TsraKeyProp, bytes: &[u8]) -> Result<(), TsraStatus> {
    let required_len = bytes.len() as u32;
    if key_prop.len < required_len {
        key_prop.len = required_len;
        Err(TsraStatus::BufferTooSmall)?;
    }
    let buf: &mut [u8] = key_prop.try_into()?;
    buf[..bytes.len()].copy_from_slice(bytes);
    key_prop.len = required_len;
    Ok(())
}

/// Copy a byte slice into a caller-provided output buffer.
///
/// On success, writes `bytes` into `output_buf` and sets `output_buf.len`
/// to the number of bytes written. If the buffer is too small, sets
/// `output_buf.len` to the required size and returns
/// [`TsraStatus::BufferTooSmall`] without writing.
pub(crate) fn copy_to_buffer(output_buf: &mut TsraBuffer, bytes: &[u8]) -> Result<(), TsraStatus> {
    let buf = validate_output_buffer(output_buf, bytes.len())?;
    buf[..bytes.len()].copy_from_slice(bytes);
    output_buf.len = bytes.len() as u32;
    Ok(())
}

/// Converts an optional TsraBuffer pointer to Option<&[u8]>
///
/// # Arguments
///
/// * `buf` - Pointer to an TsraBuffer, may be null
///
/// # Returns
///
/// * `Ok(None)` - if the pointer is null
/// * `Ok(Some(&[u8]))` - if the pointer is valid and contains data
/// * `Err(TsraStatus)` - if the pointer is invalid or the buffer is malformed
pub(crate) fn buffer_to_optional_slice<'a>(
    buf: *const TsraBuffer,
) -> Result<Option<&'a [u8]>, TsraStatus> {
    if buf.is_null() {
        Ok(None)
    } else {
        let buffer = deref_ptr(buf)?;
        Ok(Some(buffer.try_into()?))
    }
}
