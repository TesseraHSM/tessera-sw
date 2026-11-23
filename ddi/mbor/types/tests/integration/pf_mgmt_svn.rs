// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side check that the PF management interface reports a non-zero SVN.
//!
//! Firmware advertises SVN support in the controller's capability register,
//! and the PF driver only returns the SVN from Identify when that bit is set.
//! If the bit is lost, for example when a host reboot (PERST) resets the
//! controller registers, the driver reports SVN = 0. This test reads device
//! info through `AziHSMPfMgmtDll`, the interface the live migration agent
//! uses, so run it on a Windows host with the Manticore PF driver loaded.
//! Set `AZIHSM_PF_MGMT_DLL` to the DLL path if it is not on the DLL search
//! path.

#![cfg(all(test, target_os = "windows"))]
// Loading the management DLL and calling its exports requires FFI.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;

use test_with_tracing::test;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::FreeLibrary;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::libloaderapi::LoadLibraryW;

const PF_MGMT_DLL_ENV: &str = "AZIHSM_PF_MGMT_DLL";
const PF_MGMT_DLL_DEFAULT: &str = "AziHSMPfMgmtDll.dll";
const AZIHSMPFMGMTDLL_STATUS_SUCCESS: DWORD = 0;

/// `AziHSM_DeviceInfo` from `AziHSMPfDll.h`.
#[repr(C)]
struct AziHsmDeviceInfo {
    pci_info: [u8; 256],
    serial_num: [u8; 256],
    model_num: [u8; 256],
    firmware_rev: [u8; 256],
    driver_rev: [u8; 128],
    svn: u64,
    rsvd: [u8; 120],
}

type EnumerateDevicesFn = unsafe extern "C" fn(count: *mut DWORD, status: *mut DWORD) -> BOOL;
type GetDeviceInfoFn = unsafe extern "C" fn(
    device_index: DWORD,
    dev_info: *mut AziHsmDeviceInfo,
    status: *mut DWORD,
) -> BOOL;

/// The loaded `AziHSMPfMgmtDll` and the exports this test uses.
struct PfMgmtDll {
    module: HMODULE,
    enumerate_devices: EnumerateDevicesFn,
    get_device_info: GetDeviceInfoFn,
}

impl PfMgmtDll {
    fn load() -> Self {
        let path = std::env::var(PF_MGMT_DLL_ENV).unwrap_or_else(|_| PF_MGMT_DLL_DEFAULT.into());
        let wide: Vec<u16> = std::ffi::OsStr::new(&path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        assert!(
            !module.is_null(),
            "failed to load {path} (set {PF_MGMT_DLL_ENV} to the AziHSMPfMgmtDll.dll path)"
        );

        // SAFETY: Both exports are declared in `AziHSMPfDll.h` with the signatures above.
        unsafe {
            Self {
                module,
                enumerate_devices: std::mem::transmute::<FARPROC, EnumerateDevicesFn>(
                    Self::export(module, "AziHSM_EnumerateAziHSMDevices"),
                ),
                get_device_info: std::mem::transmute::<FARPROC, GetDeviceInfoFn>(Self::export(
                    module,
                    "AziHSM_GetDeviceInfo",
                )),
            }
        }
    }

    fn export(module: HMODULE, name: &str) -> FARPROC {
        let symbol = CString::new(name).expect("export name has no NUL");
        // SAFETY: `module` is a loaded module and `symbol` is NUL-terminated.
        let proc = unsafe { GetProcAddress(module, symbol.as_ptr()) };
        assert!(!proc.is_null(), "AziHSMPfMgmtDll does not export {name}");
        proc
    }

    fn device_count(&self) -> DWORD {
        let mut count: DWORD = 0;
        let mut status: DWORD = 0;
        // SAFETY: Both out-pointers are valid for writes for the duration of the call.
        let ok = unsafe { (self.enumerate_devices)(&mut count, &mut status) };
        assert!(
            ok != 0 && status == AZIHSMPFMGMTDLL_STATUS_SUCCESS,
            "AziHSM_EnumerateAziHSMDevices failed: ok={ok} status={status:#x}"
        );
        count
    }

    fn device_info(&self, index: DWORD) -> Box<AziHsmDeviceInfo> {
        // SAFETY: `AziHsmDeviceInfo` is plain data, so all-zero bytes are a valid value.
        let mut info: Box<AziHsmDeviceInfo> = Box::new(unsafe { std::mem::zeroed() });
        let mut status: DWORD = 0;
        // SAFETY: `info` and `status` are valid for writes for the duration of the call.
        let ok = unsafe { (self.get_device_info)(index, &mut *info, &mut status) };
        assert!(
            ok != 0 && status == AZIHSMPFMGMTDLL_STATUS_SUCCESS,
            "AziHSM_GetDeviceInfo({index}) failed: ok={ok} status={status:#x}"
        );
        info
    }
}

impl Drop for PfMgmtDll {
    fn drop(&mut self) {
        // SAFETY: `module` was returned by `LoadLibraryW` and is released once.
        unsafe { FreeLibrary(self.module) };
    }
}

fn c_str(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_owned()
}

#[test]
#[ignore = "needs a Windows host with the Manticore PF driver and AziHSMPfMgmtDll"]
fn test_pf_mgmt_svn_is_non_zero() {
    let mgmt = PfMgmtDll::load();
    let count = mgmt.device_count();
    assert_ne!(count, 0, "no Manticore PF devices enumerated");

    for index in 0..count {
        let info = mgmt.device_info(index);
        println!(
            "device {index}: pci={} fw={} driver={} svn={}",
            c_str(&info.pci_info),
            c_str(&info.firmware_rev),
            c_str(&info.driver_rev),
            info.svn
        );
        assert_ne!(
            info.svn, 0,
            "device {index}: PF driver reports SVN 0, so the firmware SVN capability is not set"
        );
    }
}
