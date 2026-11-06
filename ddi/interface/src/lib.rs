// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) interface library

mod error;

use std::cmp::Ordering;

pub use error::DdiError;
use tsra_ddi_mbor_types::DdiAesOp;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiOpReq;
use tsra_ddi_tbor_types::TborOpReq;

/// DDI Result
pub type DdiResult<T> = Result<T, DdiError>;

/// DDI Cookie
pub type DdiCookie = u64;

/// Device Info
#[derive(Clone, Debug)]
pub struct DevInfo {
    /// Device path
    pub path: String,

    /// Driver Version
    pub driver_ver: String,

    /// Firmware Version
    pub firmware_ver: String,

    /// Hardware Version
    pub hardware_ver: String,

    /// PCI BDF information
    pub pci_info: String,

    /// entropy data 32-bytes
    pub entropy_data: Vec<u8>,
}

impl Ord for DevInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl PartialOrd for DevInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DevInfo {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq(&other.path)
    }
}

impl Eq for DevInfo {}

/// Device Driver Interface trait
pub trait Ddi: Default {
    /// Device
    type Dev: DdiDev;

    /// Returns the HSM device information list
    ///
    /// # Returns
    /// * `Vec<DevInfo>` - HSM device information list
    fn dev_info_list(&self) -> Vec<DevInfo>;

    /// Open HSM device
    ///
    /// # Arguments
    /// `path` - Device path
    ///
    /// # Returns
    /// `Self::Dev` - HSM Device
    ///
    /// # Error
    /// * `DdiError` - Error encountered while opening the device
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev>;
}

#[derive(Default, Clone)]
/// AES GCM input parameter
pub struct DdiAesGcmParams {
    /// key id
    pub key_id: u32,

    /// initial vector
    pub iv: [u8; 12usize],

    /// Optional
    /// *`aad`. Optional input to encryption operation
    pub aad: Option<Vec<u8>>,

    /// tag
    pub tag: Option<[u8; 16usize]>,

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,
}

#[derive(Default, Clone, Debug)]
/// AES GCM output
pub struct DdiAesGcmResult {
    /// Tag
    pub tag: Option<[u8; 16usize]>,

    /// IV returned from the device
    pub iv: Option<[u8; 12usize]>,

    /// FIPS approved indication
    pub fips_approved: bool,

    /// output data
    pub data: Vec<u8>,
}

#[derive(Default, Clone)]
/// Aes Xts input parameter
pub struct DdiAesXtsParams {
    /// dataUnitLen
    pub data_unit_len: usize,

    /// keyid1
    pub key_id1: u32,

    /// keyid2
    pub key_id2: u32,

    /// tweak vector
    pub tweak: [u8; 16usize],

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,
}

/// Version of the dedicated unpinned bulk IOCTL's reserved-word extension.
pub const FP_UNPINNED_ABI_VERSION: u32 = 1;

/// Largest supported masked AES key envelope (AES-256-XTS).
pub const FP_MAX_MASKED_KEY_LEN: usize = 8 + 16 + 192 + 64 + 16;

/// Maximum bulk source length, including padded GCM AAD.
pub const FP_MAX_DATA_LEN: usize = 16 * 1024;

/// GCM key source. Existing MBOR parameters select the resident-key variant.
#[derive(Clone)]
pub enum DdiAesGcmRequest {
    /// Unchanged MBOR bulk parameters.
    Pinned(DdiAesGcmParams),
    /// TBOR operation using a caller-held masked key, never registered.
    Unpinned {
        /// Cipher parameters; the resident key id must be zero.
        params: DdiAesGcmParams,
        /// Masked AES-256 key supplied for this operation.
        masked_key: Vec<u8>,
        /// Generate a fresh encryption IV on the device.
        device_iv: bool,
    },
}

impl From<DdiAesGcmParams> for DdiAesGcmRequest {
    fn from(params: DdiAesGcmParams) -> Self {
        Self::Pinned(params)
    }
}

/// XTS key source. Existing MBOR parameters select the resident-key variant.
#[derive(Clone)]
pub enum DdiAesXtsRequest {
    /// Unchanged MBOR bulk parameters.
    Pinned(DdiAesXtsParams),
    /// TBOR operation using a caller-held masked key, never registered.
    Unpinned {
        /// Cipher parameters; both resident key ids must be zero.
        params: DdiAesXtsParams,
        /// Masked `K1 || K2` supplied for this operation.
        masked_key: Vec<u8>,
    },
}

impl From<DdiAesXtsParams> for DdiAesXtsRequest {
    fn from(params: DdiAesXtsParams) -> Self {
        Self::Pinned(params)
    }
}

impl DdiAesGcmRequest {
    /// Encode the unpinned IOCTL extension, rejecting mixed key modes.
    /// Keep these parameters alive until the synchronous IOCTL returns.
    pub fn unpinned_descriptor(&self) -> DdiResult<Option<[u32; 30]>> {
        match self {
            Self::Pinned(_) => Ok(None),
            Self::Unpinned {
                params,
                masked_key,
                device_iv,
            } => unpinned_descriptor(Some(masked_key), params.key_id != 0, *device_iv),
        }
    }

    /// Separate transport parameters from the operation-owned masked key.
    pub fn into_parts(self) -> (DdiAesGcmParams, Option<Vec<u8>>, bool) {
        match self {
            Self::Pinned(params) => (params, None, false),
            Self::Unpinned {
                params,
                masked_key,
                device_iv,
            } => (params, Some(masked_key), device_iv),
        }
    }
}

impl DdiAesXtsRequest {
    /// Encode the unpinned IOCTL extension, rejecting mixed key modes.
    /// Keep these parameters alive until the synchronous IOCTL returns.
    pub fn unpinned_descriptor(&self) -> DdiResult<Option<[u32; 30]>> {
        match self {
            Self::Pinned(_) => Ok(None),
            Self::Unpinned { params, masked_key } => unpinned_descriptor(
                Some(masked_key),
                params.key_id1 != 0 || params.key_id2 != 0,
                false,
            ),
        }
    }

    /// Separate transport parameters from the operation-owned masked key.
    pub fn into_parts(self) -> (DdiAesXtsParams, Option<Vec<u8>>) {
        match self {
            Self::Pinned(params) => (params, None),
            Self::Unpinned { params, masked_key } => (params, Some(masked_key)),
        }
    }
}

fn unpinned_descriptor(
    masked_key: Option<&[u8]>,
    has_key_id: bool,
    device_iv: bool,
) -> DdiResult<Option<[u32; 30]>> {
    let Some(masked_key) = masked_key else {
        if device_iv {
            return Err(DdiError::InvalidParameter);
        }
        return Ok(None);
    };
    if has_key_id || masked_key.is_empty() || masked_key.len() > FP_MAX_MASKED_KEY_LEN {
        return Err(DdiError::InvalidParameter);
    }
    let addr = masked_key.as_ptr() as u64;
    let fields = [
        FP_UNPINNED_ABI_VERSION,
        u32::from(device_iv),
        addr as u32,
        (addr >> 32) as u32,
        u32::try_from(masked_key.len()).map_err(|_| DdiError::InvalidParameter)?,
    ];
    let mut descriptor = [0; 30];
    descriptor[..fields.len()].copy_from_slice(&fields);
    Ok(Some(descriptor))
}

#[cfg(test)]
mod unpinned_tests {
    use super::*;

    #[test]
    fn legacy_params_have_no_extension() {
        assert!(DdiAesGcmRequest::from(DdiAesGcmParams::default())
            .unpinned_descriptor()
            .expect("legacy GCM parameters")
            .is_none());
        assert!(DdiAesXtsRequest::from(DdiAesXtsParams::default())
            .unpinned_descriptor()
            .expect("legacy XTS parameters")
            .is_none());
    }

    #[test]
    fn unpinned_params_reject_mixed_ids() {
        let gcm = DdiAesGcmRequest::Unpinned {
            params: DdiAesGcmParams {
                key_id: 1,
                ..Default::default()
            },
            masked_key: vec![0; FP_MAX_MASKED_KEY_LEN],
            device_iv: false,
        };
        assert!(gcm.unpinned_descriptor().is_err());
        for (key_id1, key_id2) in [(1, 0), (0, 1)] {
            let xts = DdiAesXtsRequest::Unpinned {
                params: DdiAesXtsParams {
                    key_id1,
                    key_id2,
                    ..Default::default()
                },
                masked_key: vec![0; FP_MAX_MASKED_KEY_LEN],
            };
            assert!(xts.unpinned_descriptor().is_err());
        }
    }

    #[test]
    fn unpinned_params_bound_key_length() {
        for len in [0, FP_MAX_MASKED_KEY_LEN + 1] {
            let gcm = DdiAesGcmRequest::Unpinned {
                params: DdiAesGcmParams::default(),
                masked_key: vec![0; len],
                device_iv: false,
            };
            assert!(gcm.unpinned_descriptor().is_err());
        }
        let gcm = DdiAesGcmRequest::Unpinned {
            params: DdiAesGcmParams::default(),
            masked_key: vec![0; FP_MAX_MASKED_KEY_LEN],
            device_iv: true,
        };
        assert!(gcm
            .unpinned_descriptor()
            .expect("bounded masked key")
            .is_some());
    }
}

#[derive(Default, Clone, Debug)]
///DdiAesXtsResult
pub struct DdiAesXtsResult {
    /// output data
    pub data: Vec<u8>,

    /// FIPS approved indication
    pub fips_approved: bool,
}

/// Driver Error Status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    /// Io abort is in progress
    IoAbortInProgress = 0x04000001,

    /// Io aborted
    IoAborted = 0x04000002,
}

/// Device Trait
pub trait DdiDev {
    /// Returns the device kind.
    ///
    /// The kind is fixed at construction time per backend
    /// (`DdiDeviceKind::Virtual` for mock; `DdiDeviceKind::Physical`
    /// for nix/win/emu). Used by the host-side codec to select the
    /// matching wire-format mode.
    fn device_kind(&self) -> DdiDeviceKind;

    /// Execute GCM operation (encryption / decryption) with slice buffers
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `gcm_params` -- required. GCM parameters
    /// * `src_buf` --- source buffer slice to encrypt or decrypt
    /// * `dst_buf` --- destination buffer slice to write encrypted or decrypted data
    /// * `fips_approved` -- output parameter to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to destination buffer
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: impl Into<DdiAesGcmRequest>,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError>;

    /// Execute GCM operation (encryption / decryption)
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `gcm_params` -- required. GCM parameters
    /// * `src_buf` --- source buffer to encrypt or decrypt
    ///
    /// # Returns
    /// * `DdiAesGcmResult` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: impl Into<DdiAesGcmRequest>,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError>;

    /// Execute Xts operation (encryption / decryption)
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `xts_params` -- required. Xts parameters
    /// * `src_buf` --- source buffer to encrypt or decrypt
    ///
    /// # Returns
    /// * `DdiAesXtsResult` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: impl Into<DdiAesXtsRequest>,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError>;

    /// Execute Xts operation (encryption / decryption) with slice buffers
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `xts_params` -- required. Xts parameters
    /// * `src_buf` --- source buffer slice to encrypt or decrypt
    /// * `dst_buf` --- destination buffer slice to write encrypted or decrypted data
    /// * `fips_approved` -- output parameter to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to destination buffer
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: impl Into<DdiAesXtsRequest>,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError>;

    /// Erase the device.
    ///
    /// Resets device state, clearing active sessions and other volatile
    /// cryptographic state so the device returns to a clean operational
    /// state. Implementations may preserve some persistent state across
    /// this operation, so this method does not guarantee that all sealed
    /// or stored material is discarded.
    ///
    /// # Returns
    /// * `Ok(())` - Successfully erased the device
    /// * `Err(DdiError)` - Error occurred while executing the command
    fn erase(&self) -> Result<(), DdiError>;

    /// Execute a DDI command whose body is MBOR-encoded.
    ///
    /// # Arguments
    /// * `req`    - MBOR-encodable request
    /// * `cookie` - Optional cookie threaded through to the backend
    ///
    /// # Returns
    /// * `T::OpResp` - Decoded response
    ///
    /// # Errors
    /// Returns a [`DdiError`] on encoding, IO, or device-side failure.
    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp>;

    /// Execute a DDI command whose body is TBOR-encoded.
    ///
    /// # Arguments
    /// * `req`       - TBOR-encodable request
    /// * `oob_items` - Optional out-of-band payloads (each becomes one
    ///   NVMe SGL Data Block descriptor the device indexes by position).
    ///   Pass `None` for commands that carry no out-of-band data.
    /// * `cookie`    - Optional cookie threaded through to the backend
    ///
    /// # Default
    ///
    /// Returns [`DdiError::UnsupportedEncoding`]. Override on backends
    /// that have been wired to emit `OP_TBOR` SQEs.
    fn exec_op_tbor<T: TborOpReq>(
        &self,
        _req: &T,
        _oob_items: Option<&[&[u8]]>,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        Err(DdiError::UnsupportedEncoding)
    }

    /// Execute a TBOR command whose out-of-band items may be written by
    /// the device.
    ///
    /// Like [`Self::exec_op_tbor`], but each item carries a direction:
    /// [`TborOobItem::In`] buffers are read by the device and
    /// [`TborOobItem::Out`] buffers are written by it (e.g. the output of
    /// an out-of-band AES-GCM / AES-XTS operation). Items are indexed by
    /// position, as in [`Self::exec_op_tbor`].
    ///
    /// # Default
    ///
    /// Forwards to [`Self::exec_op_tbor`] when every item is
    /// [`TborOobItem::In`]; otherwise returns
    /// [`DdiError::UnsupportedEncoding`]. Override on backends that can
    /// map device-writable buffers.
    fn exec_op_tbor_oob<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: &mut [TborOobItem<'_>],
        cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let mut inputs = Vec::with_capacity(oob_items.len());
        for item in oob_items.iter() {
            match item {
                TborOobItem::In(buf) => inputs.push(*buf),
                TborOobItem::Out(_) => return Err(DdiError::UnsupportedEncoding),
            }
        }
        self.exec_op_tbor(req, Some(&inputs), cookie)
    }
}

/// One out-of-band item of a TBOR command (see
/// [`DdiDev::exec_op_tbor_oob`]).
#[derive(Debug)]
pub enum TborOobItem<'a> {
    /// A buffer the device reads.
    In(&'a [u8]),
    /// A buffer the device writes.
    Out(&'a mut [u8]),
}

impl TborOobItem<'_> {
    /// Host address of the item for DMA. Taken through `&mut self` so an
    /// [`TborOobItem::Out`] pointer carries write provenance.
    pub fn dma_ptr(&mut self) -> *mut u8 {
        match self {
            Self::In(buf) => buf.as_ptr().cast_mut(),
            Self::Out(buf) => buf.as_mut_ptr(),
        }
    }

    /// Length of the item in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::In(buf) => buf.len(),
            Self::Out(buf) => buf.len(),
        }
    }

    /// Whether the item is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the device writes this item.
    pub fn is_out(&self) -> bool {
        matches!(self, Self::Out(_))
    }
}
