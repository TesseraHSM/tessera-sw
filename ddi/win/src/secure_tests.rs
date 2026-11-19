// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use winapi::shared::winerror::ERROR_INVALID_FUNCTION;

use super::*;

const COMPLETION_SIZE: u32 = mem::size_of::<TborSecureIoctlOutData>() as u32;

fn dev() -> DdiWinDev {
    DdiWinDev::open("NUL").expect("open hardware-free test device")
}

#[test]
fn discovery_preserves_uno_and_requires_secure_transport_for_duo() {
    let uno = DdiWinDev::discover_with((0x1414, 0xc003), || {
        panic!("legacy discovery must not issue a secure IOCTL")
    })
    .expect("legacy discovery");
    assert_eq!(uno.model, DdiDeviceModel::Uno);
    let mut probed = false;
    let duo = DdiWinDev::discover_with((0x1414, 0xc008), || {
        probed = true;
        Ok(())
    })
    .expect("Gen2 discovery");
    assert!(probed);
    assert_eq!(duo.model, DdiDeviceModel::Duo);
    for identity in [(0xffff, 0xc008), (0x1414, 0xffff)] {
        assert!(matches!(
            DdiWinDev::discover_with(identity, || panic!("unknown device must not be probed")),
            Err(DdiError::DeviceNotFound)
        ));
    }
}

#[test]
fn discovery_never_falls_back_to_uno_on_probe_errors() {
    use winapi::shared::winerror::ERROR_ACCESS_DENIED;
    use winapi::shared::winerror::ERROR_GEN_FAILURE;
    use winapi::shared::winerror::ERROR_NOT_SUPPORTED;

    for error in [
        ERROR_INVALID_FUNCTION,
        ERROR_NOT_SUPPORTED,
        ERROR_ACCESS_DENIED,
        ERROR_GEN_FAILURE,
    ] {
        assert!(matches!(
            DdiWinDev::discover_with((0x1414, 0xc008), || {
                Err(DdiError::IoError(std::io::Error::from_raw_os_error(error as i32)))
            }),
            Err(DdiError::IoError(actual)) if actual.raw_os_error() == Some(error as i32)
        ));
    }
}

#[test]
fn secure_ioctl_round_trips_ciphertext_and_seals() {
    let request_seal = DdiTransportSeal {
        iv: [0x12; 12],
        tag: [0x34; 16],
    };
    let response_seal = DdiTransportSeal {
        iv: [0x56; 12],
        tag: [0x78; 16],
    };
    let (response, seal) = dev()
        .exec_secure_ioctl_with(1, 23, b"sealed request", request_seal, |input, output| {
            assert_eq!(input.generic.ioctl_hdr.ioctl_data_size, 392);
            assert_eq!(input.generic.opc, 2);
            assert_eq!(input.generic.cmdset, TSRA_CP_CMD_SESSION_GENERIC);
            assert_eq!(input.generic.session_id, 23);
            assert_eq!(input.generic.session_control.into_bits(), 7);
            assert_eq!(input.transport.op, 1);
            assert_eq!(input.transport.frame_id, 0);
            assert_eq!(input.transport.key_index, 0);
            assert_eq!(input.transport.aad_length, 0);
            assert_eq!(input.transport.iv, request_seal.iv);
            assert_eq!(input.transport.tag, request_seal.tag);
            let buffers = &input.generic.user_buffers;
            // SAFETY: the live request and response are borrowed through submit.
            let request =
                unsafe { std::slice::from_raw_parts(buffers.src_buf, buffers.src_length as usize) };
            assert_eq!(request, b"sealed request");
            let reply = b"sealed response";
            assert_eq!(buffers.dst_length, 8192);
            // SAFETY: the wrapper provides a live 8192-byte writable buffer.
            unsafe {
                ptr::copy_nonoverlapping(reply.as_ptr(), buffers.dst_buf, reply.len());
            }
            output.generic.byte_count = reply.len() as u32;
            output.transport.iv = response_seal.iv;
            output.transport.tag = response_seal.tag;
            Ok(COMPLETION_SIZE)
        })
        .expect("sealed IOCTL round trip");
    assert_eq!(response, b"sealed response");
    assert_eq!(seal, response_seal);
}

#[test]
fn secure_ioctl_rejects_malformed_completions_and_preserves_errors() {
    let seal = DdiTransportSeal::default();
    for (status, error, count) in [(0xcc, 0, 0), (0, 1, 0), (0, 0, 8193)] {
        let result = dev().exec_secure_ioctl_with(1, 23, b"x", seal, |_, output| {
            output.generic.status = status;
            output.transport.error = error;
            output.generic.byte_count = count;
            Ok(COMPLETION_SIZE)
        });
        if status != 0 {
            assert!(matches!(result, Err(DdiError::DdiError(0xcc))));
        } else {
            assert!(matches!(result, Err(DdiError::InvalidParameter)));
        }
    }
    for returned in [0, COMPLETION_SIZE - 1, COMPLETION_SIZE + 1] {
        assert!(matches!(
            dev().exec_secure_ioctl_with(1, 23, b"x", seal, |_, _| Ok(returned)),
            Err(DdiError::InvalidParameter)
        ));
    }
    for status in [12, 0xdead] {
        let result = dev().exec_secure_ioctl_with(1, 23, b"x", seal, |_, output| {
            output.generic.ioctl_status = status;
            Ok(COMPLETION_SIZE)
        });
        if status == 12 {
            assert!(matches!(
                result,
                Err(DdiError::TborStatus(TborStatus::SessionNotFound))
            ));
        } else {
            assert!(matches!(result, Err(DdiError::WinError(0xdead))));
        }
    }
    let result = dev().exec_secure_ioctl_with(1, 23, b"x", seal, |_, output| {
        output.generic.ioctl_status = 12;
        Err(DdiError::IoError(std::io::Error::from_raw_os_error(5)))
    });
    match result {
        Err(DdiError::IoError(error)) => assert_eq!(error.raw_os_error(), Some(5)),
        other => panic!("expected OS error before reading unreliable output: {other:?}"),
    }
}

#[test]
fn secure_ioctl_validates_payload_and_bufferless_operations() {
    let seal = DdiTransportSeal::default();
    for (op, payload) in [
        (1, &[][..]),
        (1, &[0; 8193][..]),
        (0, &b"x"[..]),
        (2, &b"x"[..]),
        (3, &[][..]),
    ] {
        assert!(matches!(
            dev().exec_secure_ioctl_with(op, 23, payload, seal, |_, _| {
                panic!("invalid request must not reach IOCTL")
            }),
            Err(DdiError::InvalidParameter)
        ));
    }
    for op in [0, 2] {
        let (response, _) = dev()
            .exec_secure_ioctl_with(op, 23, &[], seal, |input, _| {
                assert_eq!(input.transport.op, op);
                let buffers = &input.generic.user_buffers;
                assert!(buffers.src_buf.is_null());
                assert!(buffers.dst_buf.is_null());
                assert_eq!(buffers.src_length, 0);
                assert_eq!(buffers.dst_length, 0);
                Ok(COMPLETION_SIZE)
            })
            .expect("bufferless capability probe or flush");
        assert!(response.is_empty());
        assert!(matches!(
            dev().exec_secure_ioctl_with(op, 23, &[], seal, |_, output| {
                output.generic.byte_count = 1;
                Ok(COMPLETION_SIZE)
            }),
            Err(DdiError::InvalidParameter)
        ));
    }
    dev()
        .exec_secure_ioctl_with(1, 23, &[0; 8192], seal, |input, output| {
            assert_eq!(input.generic.user_buffers.src_length, 8192);
            output.generic.byte_count = 8192;
            Ok(COMPLETION_SIZE)
        })
        .expect("maximum inline request and response");
}

#[test]
fn secure_oob_maps_directions_and_preserves_response_and_seals() {
    let input = [0x12; 65536];
    let mut output = [0u8; 8];
    let output_ptr = output.as_mut_ptr();
    let request_seal = DdiTransportSeal {
        iv: [0x34; 12],
        tag: [0x56; 16],
    };
    let response_seal = DdiTransportSeal {
        iv: [0x78; 12],
        tag: [0x9a; 16],
    };
    let (response, seal) = dev()
        .exec_secure_data_xfer_with(
            23,
            b"sealed",
            request_seal,
            &mut [TborOobItem::In(&input), TborOobItem::Out(&mut output)],
            |cmd, completion| {
                let generic = &cmd.data_xfer.generic;
                assert_eq!(generic.ioctl_hdr.ioctl_data_size, 4488);
                assert_eq!(generic.cmdset, TSRA_CP_CMD_DATA_XFER);
                assert_eq!(generic.session_id, 23);
                assert_eq!(generic.session_control.into_bits(), 7);
                assert_eq!(cmd.transport.tag, request_seal.tag);
                assert_eq!(cmd.transport.iv, request_seal.iv);
                // SAFETY: the builder initialized the union as DataXferBuffers.
                let buffers = unsafe { &cmd.data_xfer.input_data.data_xfer };
                assert_eq!(buffers.buffer_count, 2);
                assert_eq!(buffers.buffers[0].flags, 0);
                assert_eq!(buffers.buffers[0].xfer_length, 65536);
                assert_eq!(buffers.buffers[0].buffer_addr.cast_const(), input.as_ptr());
                assert_eq!(buffers.buffers[1].flags, TSRA_DATA_XFER_BUF_DEV_WRITE);
                assert_eq!(buffers.buffers[1].buffer_addr, output_ptr);
                assert_eq!(buffers.buffers[1].xfer_length, 8);
                // SAFETY: the caller's OOB output and inline response are live.
                unsafe {
                    buffers.buffers[1].buffer_addr.write_bytes(0xab, 8);
                    generic.user_buffers.dst_buf.write(0xcd);
                }
                completion.generic.byte_count = 1;
                completion.transport.iv = response_seal.iv;
                completion.transport.tag = response_seal.tag;
                Ok(COMPLETION_SIZE)
            },
        )
        .expect("sealed directional OOB round trip");
    assert_eq!(output, [0xab; 8]);
    assert_eq!(response, [0xcd]);
    assert_eq!(seal, response_seal);
}

#[test]
fn secure_oob_validates_bounds_before_submission() {
    let input = [0; 65537];
    for (count, len) in [(0, 1), (65, 1), (1, 0), (1, 65537)] {
        let mut items: Vec<_> = (0..count).map(|_| TborOobItem::In(&input[..len])).collect();
        assert!(matches!(
            dev().exec_secure_data_xfer_with(
                23,
                b"x",
                DdiTransportSeal::default(),
                &mut items,
                |_, _| panic!("invalid OOB must not reach IOCTL"),
            ),
            Err(DdiError::InvalidParameter)
        ));
    }
    let mut empty = [];
    assert!(matches!(
        dev().exec_secure_data_xfer_with(
            23,
            b"x",
            DdiTransportSeal::default(),
            &mut [TborOobItem::Out(&mut empty)],
            |_, _| panic!("empty output must not reach IOCTL"),
        ),
        Err(DdiError::InvalidParameter)
    ));
}

#[test]
fn secure_oob_accepts_last_descriptor_and_propagates_errors() {
    let input = [0x12];
    let mut output = [0];
    let mut items: Vec<_> = (0..63).map(|_| TborOobItem::In(&input)).collect();
    items.push(TborOobItem::Out(&mut output));
    dev()
        .exec_secure_data_xfer_with(
            23,
            b"x",
            DdiTransportSeal::default(),
            &mut items,
            |cmd, _| {
                // SAFETY: the builder initialized the union as DataXferBuffers.
                let buffers = unsafe { &cmd.data_xfer.input_data.data_xfer };
                assert_eq!(buffers.buffer_count, 64);
                assert_eq!(buffers.buffers[63].flags, TSRA_DATA_XFER_BUF_DEV_WRITE);
                // SAFETY: the last descriptor borrows the live output byte.
                unsafe { buffers.buffers[63].buffer_addr.write(0xab) };
                Ok(COMPLETION_SIZE)
            },
        )
        .expect("64 descriptors including final output");
    drop(items);
    assert_eq!(output, [0xab]);
    for status in [0xcc, 0] {
        let result = dev().exec_secure_data_xfer_with(
            23,
            b"x",
            DdiTransportSeal::default(),
            &mut [TborOobItem::In(&input)],
            |_, completion| {
                completion.generic.status = status;
                if status == 0 {
                    Err(DdiError::WinError(5))
                } else {
                    Ok(COMPLETION_SIZE)
                }
            },
        );
        if status == 0 {
            assert!(matches!(result, Err(DdiError::WinError(5))));
        } else {
            assert!(matches!(result, Err(DdiError::DdiError(0xcc))));
        }
    }
}

#[test]
fn unsupported_driver_errors_reach_public_transport_methods() {
    let dev = dev();
    let seal = DdiTransportSeal::default();
    let input = [0x12];
    for result in [
        dev.discover().map(|_| ()),
        dev.check_secure_transport(),
        dev.flush_session(23),
        dev.exec_op_tbor_secure(23, b"sealed", seal, &mut [])
            .map(|_| ()),
        dev.exec_op_tbor_secure(23, b"sealed", seal, &mut [TborOobItem::In(&input)])
            .map(|_| ()),
    ] {
        match result {
            Err(DdiError::IoError(error)) => {
                assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_FUNCTION as i32));
            }
            other => panic!("expected unsupported-IOCTL error, got {other:?}"),
        }
    }
}
