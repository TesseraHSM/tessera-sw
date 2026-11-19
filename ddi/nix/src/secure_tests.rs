// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn discovery_preserves_uno_and_requires_secure_transport_for_duo() {
    let uno = DdiNixDev::discover_with((0x1414, 0xc003), || {
        panic!("legacy discovery must not issue a secure IOCTL")
    })
    .expect("legacy discovery");
    assert_eq!(uno.model, DdiDeviceModel::Uno);
    let mut probed = false;
    let duo = DdiNixDev::discover_with((0x1414, 0xc008), || {
        probed = true;
        Ok(())
    })
    .expect("Gen2 discovery");
    assert!(probed);
    assert_eq!(duo.model, DdiDeviceModel::Duo);
    for identity in [(0xffff, 0xc008), (0x1414, 0xffff)] {
        assert!(matches!(
            DdiNixDev::discover_with(identity, || panic!("unknown device must not be probed")),
            Err(DdiError::DeviceNotFound)
        ));
    }
}

#[test]
fn discovery_never_falls_back_to_uno_on_probe_errors() {
    for error in [
        nix::errno::Errno::ENOTTY,
        nix::errno::Errno::EOPNOTSUPP,
        nix::errno::Errno::EACCES,
        nix::errno::Errno::EIO,
    ] {
        assert!(matches!(
            DdiNixDev::discover_with((0x1414, 0xc008), || Err(DdiError::NixError(error))),
            Err(DdiError::NixError(actual)) if actual == error
        ));
    }
    assert!(matches!(
        dev().discover(),
        Err(DdiError::IoError(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn discovery_reads_pci_identity_from_the_open_handle() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove owned sysfs fixture");
        }
    }
    let root = std::env::temp_dir().join(format!("tsra_pci_discovery_{}", std::process::id()));
    std::fs::create_dir(&root).expect("create owned sysfs fixture");
    let fixture = Fixture(root);
    let dev = dev();
    let metadata = dev
        .file
        .read()
        .metadata()
        .expect("metadata of existing handle");
    let rdev = metadata.rdev();
    let pci = fixture.0.join(format!(
        "{}:{}/device",
        nix::libc::major(rdev),
        nix::libc::minor(rdev)
    ));
    std::fs::create_dir_all(&pci).expect("create PCI parent");
    std::fs::write(pci.join("vendor"), "0x1414\n").expect("write vendor");
    for (text, expected) in [("0xc003\n", 0xc003), ("0xc008\n", 0xc008)] {
        std::fs::write(pci.join("device"), text).expect("write device");
        assert_eq!(
            dev.pci_identity(&fixture.0).expect("read PCI identity"),
            (0x1414, expected)
        );
    }
    std::fs::write(pci.join("vendor"), "invalid\n").expect("write malformed vendor");
    assert!(matches!(
        dev.pci_identity(&fixture.0),
        Err(DdiError::DeviceInfoIoctlInvalidData)
    ));
    std::fs::write(pci.join("vendor"), "0x1414\n").expect("restore vendor");
    std::fs::remove_file(pci.join("device")).expect("remove device attribute");
    assert!(matches!(
        dev.pci_identity(&fixture.0),
        Err(DdiError::IoError(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    let regular = DdiNixDev::from_file(
        File::create(fixture.0.join("regular")).expect("create non-device fixture"),
    );
    assert!(matches!(
        regular.pci_identity(&fixture.0),
        Err(DdiError::DeviceNotFound)
    ));
}

fn dev() -> DdiNixDev {
    DdiNixDev::from_file(File::open("/dev/null").expect("open hardware-free test device"))
}

#[test]
fn secure_ioctl_round_trips_ciphertext_and_seals() {
    assert_eq!(mem::size_of::<TborSecureCmd>(), 160);
    assert_eq!(mem::offset_of!(TborSecureCmd, transport), 112);
    let request_seal = DdiTransportSeal {
        iv: [0x12; 12],
        tag: [0x34; 16],
    };
    let response_seal = DdiTransportSeal {
        iv: [0x56; 12],
        tag: [0x78; 16],
    };
    let (response, seal) = dev()
        .exec_secure_ioctl_with(1, 23, b"sealed request", request_seal, |cmd| {
            assert_eq!(cmd.generic.in_data.session_id, 23);
            assert_eq!(cmd.generic.in_data.session_control_flags.into_bits(), 7);
            assert_eq!(cmd.transport.op, 1);
            assert_eq!(cmd.transport.iv, request_seal.iv);
            assert_eq!(cmd.transport.tag, request_seal.tag);
            // SAFETY: the submit wrapper borrows the live request until this closure returns.
            let request = unsafe {
                std::slice::from_raw_parts(
                    cmd.generic.in_data.src_buf,
                    cmd.generic.in_data.src_length as usize,
                )
            };
            assert_eq!(request, b"sealed request");
            let reply = b"sealed response";
            // SAFETY: the wrapper provides an 8192-byte writable response buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    reply.as_ptr(),
                    cmd.generic.in_data.dst_buf,
                    reply.len(),
                );
            }
            cmd.generic.out_data.byte_count = reply.len() as u32;
            cmd.transport.iv = response_seal.iv;
            cmd.transport.tag = response_seal.tag;
            Ok(0)
        })
        .expect("sealed IOCTL round trip");
    assert_eq!(response, b"sealed response");
    assert_eq!(seal, response_seal);
}

#[test]
fn secure_ioctl_rejects_bad_completion_lengths_and_propagates_errors() {
    let seal = DdiTransportSeal::default();
    for (status, error, count) in [(0xc8, 0, 0), (0, 1, 0), (0, 0, 8193)] {
        let result = dev().exec_secure_ioctl_with(1, 23, b"x", seal, |cmd| {
            cmd.generic.out_data.status = status;
            cmd.transport.error = error;
            cmd.generic.out_data.byte_count = count;
            Ok(0)
        });
        if status != 0 {
            assert!(matches!(result, Err(DdiError::DdiError(0xc8))));
        } else {
            assert!(matches!(result, Err(DdiError::InvalidParameter)));
        }
    }
    let result =
        dev().exec_secure_ioctl_with(1, 23, b"x", seal, |_| Err(nix::errno::Errno::ENOTTY));
    assert!(matches!(
        result,
        Err(DdiError::NixError(nix::errno::Errno::ENOTTY))
    ));
    for payload in [&[][..], &[0; 8193][..]] {
        assert!(matches!(
            dev().exec_secure_ioctl_with(1, 23, payload, seal, |_| {
                panic!("invalid length must not reach ioctl")
            }),
            Err(DdiError::InvalidParameter)
        ));
    }
}

#[test]
fn flush_and_probe_have_no_dma_buffers_and_oob_is_not_dropped() {
    for op in [0, 2] {
        dev()
            .exec_secure_ioctl_with(op, 23, &[], DdiTransportSeal::default(), |cmd| {
                assert_eq!(cmd.transport.op, op);
                assert!(cmd.generic.in_data.src_buf.is_null());
                assert!(cmd.generic.in_data.dst_buf.is_null());
                assert_eq!(cmd.generic.in_data.src_length, 0);
                assert_eq!(cmd.generic.in_data.dst_length, 0);
                Ok(0)
            })
            .expect("bufferless transport probe or flush");
    }
    let result = dev().exec_op_tbor_secure(
        23,
        b"x",
        DdiTransportSeal::default(),
        &mut [TborOobItem::In(b"oob")],
    );
    assert!(matches!(
        result,
        Err(DdiError::NixError(nix::errno::Errno::ENOTTY))
    ));
}

#[test]
fn secure_oob_maps_directions_and_preserves_completion_and_seals() {
    assert_eq!(mem::size_of::<TborSecureDataXferCmd>(), 1704);
    assert_eq!(mem::offset_of!(TborSecureDataXferCmd, transport), 1656);
    let input = [0x12; 65536];
    let mut output = [0u8; 8];
    let oob = [
        OobRaw {
            addr: input.as_ptr(),
            len: input.len(),
            dev_write: false,
        },
        OobRaw {
            addr: output.as_mut_ptr(),
            len: output.len(),
            dev_write: true,
        },
    ];
    let request_seal = DdiTransportSeal {
        iv: [0x34; 12],
        tag: [0x56; 16],
    };
    let (response, seal) = dev()
        .exec_secure_data_xfer_with(23, b"sealed", request_seal, &oob, |cmd| {
            let generic = &mut cmd.data_xfer_cmd.generic_cmd;
            assert_eq!(generic.hdr.ioctl_data_size, 1704);
            assert!(matches!(
                generic.in_data.command_set,
                TsraCpCmdSet::DataXfer
            ));
            assert_eq!(generic.in_data.session_id, 23);
            assert_eq!(generic.in_data.session_control_flags.into_bits(), 7);
            assert_eq!(cmd.transport.tag, request_seal.tag);
            assert_eq!(cmd.transport.iv, request_seal.iv);
            let buffers = &cmd.data_xfer_cmd.data_xfer;
            assert_eq!(buffers.buffer_count, 2);
            assert_eq!(buffers.buffers[0].flags, 0);
            assert_eq!(buffers.buffers[0].xfer_length, 65536);
            assert_eq!(buffers.buffers[0].buffer_addr, input.as_ptr());
            assert_eq!(buffers.buffers[1].flags, TSRA_DATA_XFER_BUF_DEV_WRITE);
            assert_eq!(buffers.buffers[1].buffer_addr, oob[1].addr);
            // SAFETY: the OOB output and response buffers are live and large enough.
            unsafe {
                (buffers.buffers[1].buffer_addr as *mut u8).write_bytes(0xab, 8);
                generic.in_data.dst_buf.write(0xcd);
            }
            generic.out_data.byte_count = 1;
            cmd.transport.tag = [0xef; 16];
            Ok(0)
        })
        .expect("sealed directional OOB round trip");
    assert_eq!(output, [0xab; 8]);
    assert_eq!(response, [0xcd]);
    assert_eq!(seal.tag, [0xef; 16]);
    assert_eq!(seal.iv, request_seal.iv);
}

#[test]
fn secure_oob_validates_bounds_and_propagates_completion_errors() {
    let input = [0; 1];
    for (count, len, addr) in [
        (0, 1, input.as_ptr()),
        (65, 1, input.as_ptr()),
        (1, 0, input.as_ptr()),
        (1, 65537, input.as_ptr()),
        (1, 1, std::ptr::null()),
    ] {
        let oob: Vec<_> = (0..count)
            .map(|_| OobRaw {
                addr,
                len,
                dev_write: false,
            })
            .collect();
        assert!(matches!(
            dev().exec_secure_data_xfer_with(
                23,
                b"x",
                DdiTransportSeal::default(),
                &oob,
                |_| panic!("invalid OOB must not reach IOCTL"),
            ),
            Err(DdiError::InvalidParameter)
        ));
    }
    let oob: Vec<_> = (0..64)
        .map(|_| OobRaw {
            addr: input.as_ptr(),
            len: 1,
            dev_write: false,
        })
        .collect();
    for (status, error, count) in [(0xc8, 0, 0), (0, 1, 0), (0, 0, 8193)] {
        let result =
            dev().exec_secure_data_xfer_with(23, b"x", DdiTransportSeal::default(), &oob, |cmd| {
                assert_eq!(cmd.data_xfer_cmd.data_xfer.buffer_count, 64);
                cmd.data_xfer_cmd.generic_cmd.out_data.status = status;
                cmd.data_xfer_cmd.generic_cmd.out_data.byte_count = count;
                cmd.transport.error = error;
                Ok(0)
            });
        if status != 0 {
            assert!(matches!(result, Err(DdiError::DdiError(0xc8))));
        } else {
            assert!(matches!(result, Err(DdiError::InvalidParameter)));
        }
    }
    let result =
        dev().exec_secure_data_xfer_with(23, b"x", DdiTransportSeal::default(), &oob, |_| {
            Err(nix::errno::Errno::EIO)
        });
    assert!(matches!(
        result,
        Err(DdiError::NixError(nix::errno::Errno::EIO))
    ));
}
