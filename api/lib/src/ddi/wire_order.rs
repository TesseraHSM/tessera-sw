// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Byte order of TBOR crypto operands on the wire.
//!
//! TBOR carries integer operands (ECC coordinates and scalars, digests,
//! RSA moduli and ciphertexts) in the device's native crypto byte order so
//! firmware never has to copy them to convert. The host derives that order
//! from the negotiated API revision and converts at the DDI boundary:
//! revisions below [`SESSION_TRANSPORT_API_REV`] are little-endian, later
//! revisions are big-endian.

use super::*;

/// Byte order of TBOR integer operands for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireOrder {
    /// Little-endian.
    Le,
    /// Big-endian.
    Be,
}

impl WireOrder {
    /// Returns the wire order used by API revision `rev`.
    pub(crate) fn for_rev(rev: HsmApiRev) -> Self {
        if rev >= SESSION_TRANSPORT_API_REV {
            Self::Be
        } else {
            Self::Le
        }
    }

    /// Returns the wire order negotiated by `session`.
    pub(crate) fn of(session: &HsmSession) -> Self {
        Self::for_rev(session.api_rev())
    }

    /// Returns the wire length of one ECC coordinate whose big-endian
    /// length is `coord`.
    ///
    /// On [`Le`](Self::Le) each coordinate is zero-extended to a 4-byte
    /// multiple (P-521: 66 bytes become 68); on [`Be`](Self::Be) it is
    /// exactly `coord` bytes. Only ECC coordinate pairs are padded; other
    /// operands are byte-reversed at their natural width.
    pub(crate) fn coord_len(self, coord: usize) -> usize {
        match self {
            Self::Le => coord.next_multiple_of(4),
            Self::Be => coord,
        }
    }

    /// Converts a wire integer to big-endian, trimming it to `len` bytes.
    ///
    /// Fails if the wire value is shorter than `len` or carries non-zero
    /// bytes above the low `len` bytes.
    pub(crate) fn int_to_be(self, wire: &[u8], len: usize) -> HsmResult<Vec<u8>> {
        let pad = wire.len().checked_sub(len).ok_or(HsmError::InternalError)?;
        let (high, low) = match self {
            Self::Le => (&wire[len..], &wire[..len]),
            Self::Be => (&wire[..pad], &wire[pad..]),
        };
        if high.iter().any(|&byte| byte != 0) {
            return Err(HsmError::InternalError);
        }
        let mut be = low.to_vec();
        if self == Self::Le {
            be.reverse();
        }
        Ok(be)
    }

    /// Converts a big-endian integer to the wire, zero-extending it to
    /// `len` bytes.
    pub(crate) fn int_from_be(self, be: &[u8], len: usize) -> HsmResult<Vec<u8>> {
        let pad = len.checked_sub(be.len()).ok_or(HsmError::InternalError)?;
        let mut wire = vec![0u8; len];
        wire[pad..].copy_from_slice(be);
        self.convert_in_place(&mut wire);
        Ok(wire)
    }

    /// Converts a fixed-width integer between big-endian and the wire in
    /// place. The conversion is its own inverse.
    pub(crate) fn convert_in_place(self, buf: &mut [u8]) {
        if self == Self::Le {
            buf.reverse();
        }
    }

    /// Splits a wire `a ‖ b` coordinate pair into big-endian halves of
    /// `coord` bytes each.
    pub(crate) fn pair_to_be(self, wire: &[u8], coord: usize) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let half = self.coord_len(coord);
        if wire.len() != half * 2 {
            return Err(HsmError::InternalError);
        }
        let (a, b) = wire.split_at(half);
        Ok((self.int_to_be(a, coord)?, self.int_to_be(b, coord)?))
    }

    /// Joins big-endian `a` and `b` into a wire `a ‖ b` coordinate pair.
    pub(crate) fn pair_from_be(self, a: &[u8], b: &[u8], coord: usize) -> HsmResult<Vec<u8>> {
        let half = self.coord_len(coord);
        let mut wire = self.int_from_be(a, half)?;
        wire.extend_from_slice(&self.int_from_be(b, half)?);
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rev_selects_order() {
        assert_eq!(
            WireOrder::for_rev(HsmApiRev { major: 1, minor: 1 }),
            WireOrder::Le
        );
        assert_eq!(
            WireOrder::for_rev(HsmApiRev { major: 2, minor: 0 }),
            WireOrder::Be
        );
    }

    #[test]
    fn pair_round_trips_p521_both_orders() {
        let x: Vec<u8> = (1..=66).collect();
        let y: Vec<u8> = (101..=166).collect();
        for (order, half) in [(WireOrder::Le, 68), (WireOrder::Be, 66)] {
            let wire = order.pair_from_be(&x, &y, 66).expect("encode");
            assert_eq!(wire.len(), half * 2);
            let (rx, ry) = order.pair_to_be(&wire, 66).expect("decode");
            assert_eq!((rx, ry), (x.clone(), y.clone()));
        }
        let le = WireOrder::Le.pair_from_be(&x, &y, 66).expect("encode");
        assert_eq!(le[0], 66);
        assert_eq!(&le[66..68], &[0, 0]);
    }

    #[test]
    fn int_to_be_rejects_nonzero_pad() {
        assert!(WireOrder::Le.int_to_be(&[1, 2, 0, 9], 3).is_err());
        assert!(WireOrder::Be.int_to_be(&[9, 1, 2, 3], 3).is_err());
        assert_eq!(
            WireOrder::Be.int_to_be(&[0, 1, 2, 3], 3).expect("trim"),
            [1, 2, 3]
        );
        assert!(WireOrder::Be.int_to_be(&[1, 2], 3).is_err());
    }
}
