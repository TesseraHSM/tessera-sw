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

    /// Returns the wire lane length of one ECC coordinate whose big-endian
    /// length is `coord`.
    ///
    /// Each coordinate sits at the head of a lane padded to 4 bytes on
    /// [`Le`](Self::Le) and 8 bytes on [`Be`](Self::Be) (P-521: 66 bytes in
    /// a 68- or 72-byte lane), followed by zero bytes. Only ECC components
    /// are padded; other operands are byte-reversed at their natural width.
    pub(crate) fn coord_len(self, coord: usize) -> usize {
        match self {
            Self::Le => coord.next_multiple_of(4),
            Self::Be => coord.next_multiple_of(8),
        }
    }

    /// Converts a wire ECC coordinate lane to its `coord`-byte big-endian
    /// value.
    ///
    /// Fails if the lane is not [`coord_len`](Self::coord_len) bytes or its
    /// zero tail is not zero.
    pub(crate) fn coord_to_be(self, lane: &[u8], coord: usize) -> HsmResult<Vec<u8>> {
        if lane.len() != self.coord_len(coord) {
            return Err(HsmError::InternalError);
        }
        let (value, tail) = lane.split_at(coord);
        if tail.iter().any(|&byte| byte != 0) {
            return Err(HsmError::InternalError);
        }
        let mut be = value.to_vec();
        self.convert_in_place(&mut be);
        Ok(be)
    }

    /// Converts the big-endian ECC coordinate `be` (at most `coord` bytes,
    /// zero-extended to `coord`) to a wire lane of
    /// [`coord_len`](Self::coord_len) bytes, value first, zero tail.
    pub(crate) fn coord_from_be(self, be: &[u8], coord: usize) -> HsmResult<Vec<u8>> {
        let mut lane = self.int_from_be(be, coord)?;
        lane.resize(self.coord_len(coord), 0);
        Ok(lane)
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
        Ok((self.coord_to_be(a, coord)?, self.coord_to_be(b, coord)?))
    }

    /// Joins big-endian `a` and `b` (each at most `coord` bytes) into a
    /// wire `a ‖ b` coordinate pair.
    pub(crate) fn pair_from_be(self, a: &[u8], b: &[u8], coord: usize) -> HsmResult<Vec<u8>> {
        let mut wire = self.coord_from_be(a, coord)?;
        wire.extend_from_slice(&self.coord_from_be(b, coord)?);
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
        for (order, half) in [(WireOrder::Le, 68), (WireOrder::Be, 72)] {
            let wire = order.pair_from_be(&x, &y, 66).expect("encode");
            assert_eq!(wire.len(), half * 2);
            let (rx, ry) = order.pair_to_be(&wire, 66).expect("decode");
            assert_eq!((rx, ry), (x.clone(), y.clone()));
        }
        let le = WireOrder::Le.pair_from_be(&x, &y, 66).expect("encode");
        assert_eq!(le[0], 66);
        assert_eq!(&le[66..68], &[0, 0]);
        let be = WireOrder::Be.pair_from_be(&x, &y, 66).expect("encode");
        assert_eq!(&be[..66], &x[..]);
        assert_eq!(&be[66..72], &[0; 6]);
        assert_eq!(&be[72..138], &y[..]);
    }

    #[test]
    fn coord_to_be_rejects_bad_lane() {
        let mut lane = vec![0u8; 72];
        lane[0] = 1;
        assert_eq!(WireOrder::Be.coord_to_be(&lane, 66).expect("lane")[0], 1);
        lane[66] = 1;
        assert!(WireOrder::Be.coord_to_be(&lane, 66).is_err());
        assert!(WireOrder::Be.coord_to_be(&lane[..68], 66).is_err());
    }
}
