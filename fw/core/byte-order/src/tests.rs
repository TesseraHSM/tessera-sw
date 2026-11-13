// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

const CURVES: [HsmEccCurve; 3] = [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521];
const ORDERS: [HsmByteOrder; 2] = [HsmByteOrder::Le, HsmByteOrder::Be];

fn be_value(len: usize, seed: u8) -> [u8; 80] {
    let mut v = [0u8; 80];
    for (i, b) in v[..len].iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    v
}

#[test]
fn int_le_reverses_be_is_noop() {
    let mut le = [1u8, 2, 3, 4];
    int_to_be(HsmByteOrder::Le, &mut le);
    assert_eq!(le, [4, 3, 2, 1]);
    int_from_be(HsmByteOrder::Le, &mut le);
    assert_eq!(le, [1, 2, 3, 4]);

    let mut be = [1u8, 2, 3, 4];
    int_to_be(HsmByteOrder::Be, &mut be);
    assert_eq!(be, [1, 2, 3, 4]);
    int_from_be(HsmByteOrder::Be, &mut be);
    assert_eq!(be, [1, 2, 3, 4]);
}

#[test]
fn int_copy_reverses_on_le_only() {
    let src = [1u8, 2, 3];
    let mut dst = [0u8; 3];
    int_copy_to_be(HsmByteOrder::Le, &mut dst, &src).expect("le");
    assert_eq!(dst, [3, 2, 1]);
    int_copy_from_be(HsmByteOrder::Be, &mut dst, &src).expect("be");
    assert_eq!(dst, src);
    assert_eq!(
        int_copy_to_be(HsmByteOrder::Le, &mut dst[..2], &src).err(),
        Some(HsmError::InvalidArg)
    );
}

#[test]
fn coord_round_trip() {
    for order in ORDERS {
        for curve in CURVES {
            let raw = curve.priv_key_len();
            let wire = curve.wire_coord_len(order);
            let expected = be_value(raw, 0x10);
            let mut slot = [0xAAu8; 80];
            slot[..raw].copy_from_slice(&expected[..raw]);

            let operand = coord_from_be(order, curve, &mut slot).expect("from_be");
            assert_eq!(operand.len(), wire);
            assert!(operand[raw..].iter().all(|&b| b == 0));
            if order.is_be() {
                assert_eq!(&operand[..raw], &expected[..raw]);
            } else {
                assert_eq!(operand[0], expected[raw - 1]);
                assert_eq!(operand[raw - 1], expected[0]);
            }

            let be = coord_to_be(order, curve, &mut slot).expect("to_be");
            assert_eq!(be, &expected[..raw]);
        }
    }
}

#[test]
fn pair_round_trip() {
    for order in ORDERS {
        for curve in CURVES {
            let raw = curve.priv_key_len();
            let wire = curve.wire_coord_len(order);
            let x = be_value(raw, 0x20);
            let y = be_value(raw, 0x90);
            let mut expected = [0u8; 160];
            expected[..raw].copy_from_slice(&x[..raw]);
            expected[raw..2 * raw].copy_from_slice(&y[..raw]);

            let mut buf = [0xAAu8; 160];
            buf[..2 * raw].copy_from_slice(&expected[..2 * raw]);

            let operand = pair_from_be(order, curve, &mut buf).expect("from_be");
            assert_eq!(operand.len(), 2 * wire);
            assert!(operand[raw..wire].iter().all(|&b| b == 0));
            assert!(operand[wire + raw..].iter().all(|&b| b == 0));
            let mut y_operand = [0u8; 80];
            y_operand[..raw].copy_from_slice(&operand[wire..wire + raw]);
            int_to_be(order, &mut y_operand[..raw]);
            assert_eq!(&y_operand[..raw], &y[..raw]);

            let be = pair_to_be(order, curve, &mut buf).expect("to_be");
            assert_eq!(be, &expected[..2 * raw]);
        }
    }
}

#[test]
fn p521_slot_widths() {
    assert_eq!(HsmEccCurve::P521.wire_coord_len(HsmByteOrder::Le), 68);
    assert_eq!(HsmEccCurve::P521.wire_coord_len(HsmByteOrder::Be), 66);
}

#[test]
fn short_buffers_rejected() {
    for order in ORDERS {
        for curve in CURVES {
            let wire = curve.wire_coord_len(order);
            let mut buf = [0u8; 160];
            assert_eq!(
                coord_to_be(order, curve, &mut buf[..wire - 1]).err(),
                Some(HsmError::InvalidArg)
            );
            assert_eq!(
                coord_from_be(order, curve, &mut buf[..wire - 1]).err(),
                Some(HsmError::InvalidArg)
            );
            assert_eq!(
                pair_to_be(order, curve, &mut buf[..2 * wire - 1]).err(),
                Some(HsmError::InvalidArg)
            );
            assert_eq!(
                pair_from_be(order, curve, &mut buf[..2 * wire - 1]).err(),
                Some(HsmError::InvalidArg)
            );
        }
    }
}
