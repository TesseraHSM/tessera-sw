// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DER encoding helpers for runtime certificate and CSR assembly.
//!
//! These helpers handle the variable-length parts of DER encoding that
//! arise when assembling a final certificate from a patched TBS template
//! and an ECDSA-P384 signature.
//!
//! # Key Functions
//!
//! - [`encode_ecdsa_signature`](super::der_helpers::encode_ecdsa_signature): Encodes raw `(r, s)` into DER BIT STRING
//!   wrapping a SEQUENCE of two INTEGERs.
//! - [`encode_der_length`](super::der_helpers::encode_der_length) / [`der_length_size`](super::der_helpers::der_length_size): Write or compute the size
//!   of a DER definite-length field.
//!
//! # Constants
//!
//! - [`MAX_ECDSA384_SIG_DER_LEN`](super::der_helpers::MAX_ECDSA384_SIG_DER_LEN): Upper bound on encoded sig size (108 bytes).
//! - [`MAX_CERT_DER_LEN`](super::der_helpers::MAX_CERT_DER_LEN): Upper bound on a complete certificate (1024 bytes).
//! - [`ECDSA_SHA384_ALG_ID`](super::der_helpers::ECDSA_SHA384_ALG_ID): Pre-encoded AlgorithmIdentifier for ECDSA-SHA384.

/// Maximum DER-encoded ECDSA-384 signature size in bytes.
///
/// Breakdown: BIT STRING (tag 1 + len 1 + unused_bits 1) +
/// SEQUENCE (tag 1 + len 1) + two INTEGERs (each: tag 1 + len 1 + optional pad 1 + 48 value).
/// Worst case: 3 + 2 + 2×51 = 107, rounded up to 108.
pub const MAX_ECDSA384_SIG_DER_LEN: usize = 108;

/// Maximum certificate or CSR DER size in bytes (TBS + AlgId + Signature).
///
/// 1024 bytes is generous for P-384-based certificates with the extension
/// profiles used by TSRA.
pub const MAX_CERT_DER_LEN: usize = 1024;

/// DER-encoded AlgorithmIdentifier for ECDSA with SHA-384
/// (OID 1.2.840.10045.4.3.3).
pub const ECDSA_SHA384_ALG_ID: [u8; 12] = [
    0x30, 0x0A, // SEQUENCE, length 10
    0x06, 0x08, // OID, length 8
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, // 1.2.840.10045.4.3.3
];

/// Uncompressed P-384 public key length (`0x04 || x || y`).
pub const P384_PUBLIC_KEY_LEN: usize = 97;

/// DER prefix of a P-384 `SubjectPublicKeyInfo`, up to and including the
/// BIT STRING's unused-bits octet; the uncompressed point follows.
pub const P384_SPKI_HEADER: [u8; 23] = [
    0x30, 0x76, // SEQUENCE, length 118
    0x30, 0x10, // SEQUENCE (AlgorithmIdentifier), length 16
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, // secp384r1
    0x03, 0x62, 0x00, // BIT STRING, length 98, 0 unused bits
];

/// ML-DSA-87 public key length (FIPS 204).
pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;

/// ML-DSA-87 signature length (FIPS 204).
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;

/// DER-encoded AlgorithmIdentifier for ML-DSA-87
/// (OID 2.16.840.1.101.3.4.3.19, parameters absent — RFC 9881). Used both
/// as the signature algorithm and inside the `SubjectPublicKeyInfo`.
pub const MLDSA87_ALG_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, // OID, length 9
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, // 2.16.840.1.101.3.4.3.19
];

/// DER prefix of an ML-DSA-87 `SubjectPublicKeyInfo`, up to and including
/// the BIT STRING's unused-bits octet; the raw public key follows.
pub const MLDSA87_SPKI_HEADER: [u8; 22] = [
    0x30, 0x82, 0x0A, 0x32, // SEQUENCE, length 2610
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, // ML-DSA-87
    0x03, 0x82, 0x0A, 0x21, 0x00, // BIT STRING, length 2593, 0 unused bits
];

/// DER prefix of an ML-DSA-87 `signatureValue` BIT STRING, up to and
/// including the unused-bits octet; the raw signature follows.
pub const MLDSA87_SIG_BIT_STRING_HEADER: [u8; 5] = [0x03, 0x82, 0x12, 0x14, 0x00];

/// Size of `SEQUENCE { tbs, alg_id, sig }` with contents of the given sizes.
pub fn signed_len(tbs_len: usize, alg_id_len: usize, sig_len: usize) -> usize {
    let content = tbs_len + alg_id_len + sig_len;
    1 + der_length_size(content) + content
}

/// Write `SEQUENCE { tbs, alg_id, sig_parts[0] || sig_parts[1] || .. }`
/// into `out`, where `sig_parts` is the complete DER signature field.
///
/// # Returns
/// `Some(n)` — bytes written, or `None` if `out` is too small or the
/// content exceeds the supported DER length.
pub fn assemble_signed(
    out: &mut [u8],
    tbs: &[u8],
    alg_id: &[u8],
    sig_parts: &[&[u8]],
) -> Option<usize> {
    let sig_len: usize = sig_parts.iter().map(|part| part.len()).sum();
    let content_len = tbs.len() + alg_id.len() + sig_len;
    if out.len() < signed_len(tbs.len(), alg_id.len(), sig_len) {
        return None;
    }
    *out.first_mut()? = 0x30;
    let mut pos = 1 + encode_der_length(&mut out[1..], content_len)?;
    for part in [tbs, alg_id].into_iter().chain(sig_parts.iter().copied()) {
        out[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    Some(pos)
}

/// Encode a DER length field into `buf`.
///
/// Supports lengths up to 65535 (two-byte long form).
///
/// # Arguments
/// * `buf` — Destination buffer (must have room for 1–3 bytes).
/// * `length` — The length value to encode.
///
/// # Returns
/// `Some(n)` — number of bytes written (1, 2, or 3), or `None` if
/// `length` ≥ 65536 or `buf` is too small.
pub fn encode_der_length(buf: &mut [u8], length: usize) -> Option<usize> {
    if length < 0x80 {
        *buf.first_mut()? = length as u8;
        Some(1)
    } else if length < 0x100 {
        *buf.first_mut()? = 0x81;
        *buf.get_mut(1)? = length as u8;
        Some(2)
    } else if length < 0x10000 {
        *buf.first_mut()? = 0x82;
        *buf.get_mut(1)? = (length >> 8) as u8;
        *buf.get_mut(2)? = length as u8;
        Some(3)
    } else {
        None // Unsupported length
    }
}

/// Compute the number of bytes needed to encode a DER length field.
///
/// Returns 1 for `length` < 128, 2 for < 256, 3 otherwise.
pub fn der_length_size(length: usize) -> usize {
    if length < 0x80 {
        1
    } else if length < 0x100 {
        2
    } else {
        3
    }
}

/// Encode a raw ECDSA-P384 `(r, s)` signature as a DER BIT STRING.
///
/// The output structure is:
/// ```text
/// BIT STRING {
///   unused_bits = 0x00,
///   SEQUENCE {
///     INTEGER r,
///     INTEGER s
///   }
/// }
/// ```
///
/// Each of `r` and `s` must be exactly 48 bytes (big-endian, unsigned).
/// Leading-zero trimming and sign-padding are handled automatically.
///
/// # Arguments
/// * `buf` — Destination buffer (should be at least [`MAX_ECDSA384_SIG_DER_LEN`] bytes).
/// * `r` — The `r` component of the ECDSA signature (48 bytes).
/// * `s` — The `s` component of the ECDSA signature (48 bytes).
///
/// # Returns
/// `Some(n)` — number of bytes written, or `None` if the buffer is too small.
pub fn encode_ecdsa_signature(buf: &mut [u8], r: &[u8; 48], s: &[u8; 48]) -> Option<usize> {
    // Encode r and s as DER INTEGERs
    let mut r_int = [0u8; 51]; // tag(1) + len(1) + leading_zero(1) + 48
    let r_len = encode_der_integer(&mut r_int, r)?;

    let mut s_int = [0u8; 51];
    let s_len = encode_der_integer(&mut s_int, s)?;

    // SEQUENCE { r_int, s_int }
    let seq_content_len = r_len + s_len;
    let seq_header_len = 1 + der_length_size(seq_content_len); // 0x30 + length
    let seq_total_len = seq_header_len + seq_content_len;

    // BIT STRING { 0x00 (unused bits), SEQUENCE }
    let bit_string_content_len = 1 + seq_total_len; // unused_bits + sequence
    let bit_string_header_len = 1 + der_length_size(bit_string_content_len);
    let total_len = bit_string_header_len + bit_string_content_len;

    if buf.len() < total_len {
        return None;
    }

    let mut pos = 0;

    // BIT STRING tag
    buf[pos] = 0x03;
    pos += 1;
    pos += encode_der_length(&mut buf[pos..], bit_string_content_len)?;

    // Unused bits = 0
    buf[pos] = 0x00;
    pos += 1;

    // SEQUENCE tag
    buf[pos] = 0x30;
    pos += 1;
    pos += encode_der_length(&mut buf[pos..], seq_content_len)?;

    // r INTEGER
    buf[pos..pos + r_len].copy_from_slice(&r_int[..r_len]);
    pos += r_len;

    // s INTEGER
    buf[pos..pos + s_len].copy_from_slice(&s_int[..s_len]);
    pos += s_len;

    Some(pos)
}

/// Encode a big-endian unsigned integer as a DER INTEGER (TLV).
///
/// Handles minimality (strips leading zeros) and sign-correctness
/// (prepends `0x00` when the high bit is set to keep the value positive).
///
/// # Arguments
/// * `buf` — Destination buffer (must be large enough for tag + length + value).
/// * `value` — Big-endian unsigned integer bytes.
///
/// # Returns
/// `Some(n)` — total TLV length written, or `None` if `buf` is too small.
fn encode_der_integer(buf: &mut [u8], value: &[u8]) -> Option<usize> {
    // Skip leading zeros for minimality
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];

    // Need leading 0x00 if high bit is set (to keep positive)
    let needs_pad = trimmed[0] & 0x80 != 0;
    let content_len = trimmed.len() + usize::from(needs_pad);

    let mut pos = 0;
    // Tag
    *buf.get_mut(pos)? = 0x02;
    pos += 1;
    // Length
    pos += encode_der_length(&mut buf[pos..], content_len)?;
    // Leading zero if needed
    if needs_pad {
        *buf.get_mut(pos)? = 0x00;
        pos += 1;
    }
    // Value
    buf.get_mut(pos..pos + trimmed.len())?
        .copy_from_slice(trimmed);
    pos += trimmed.len();

    Some(pos)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_der_length_short() {
        let mut buf = [0u8; 4];
        let n = encode_der_length(&mut buf, 0x50).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x50);
    }

    #[test]
    fn test_encode_der_length_medium() {
        let mut buf = [0u8; 4];
        let n = encode_der_length(&mut buf, 200).unwrap();
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x81);
        assert_eq!(buf[1], 200);
    }

    #[test]
    fn test_encode_der_length_long() {
        let mut buf = [0u8; 4];
        let n = encode_der_length(&mut buf, 300).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf[0], 0x82);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x2C);
    }

    #[test]
    fn test_encode_der_integer_no_pad() {
        let mut buf = [0u8; 10];
        let value = [0x01, 0x02, 0x03];
        let n = encode_der_integer(&mut buf, &value).unwrap();
        assert_eq!(&buf[..n], &[0x02, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_der_integer_with_pad() {
        let mut buf = [0u8; 10];
        let value = [0x80, 0x01]; // high bit set
        let n = encode_der_integer(&mut buf, &value).unwrap();
        assert_eq!(&buf[..n], &[0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn test_encode_der_integer_strip_leading_zeros() {
        let mut buf = [0u8; 10];
        let value = [0x00, 0x00, 0x42];
        let n = encode_der_integer(&mut buf, &value).unwrap();
        assert_eq!(&buf[..n], &[0x02, 0x01, 0x42]);
    }

    #[test]
    fn test_encode_ecdsa_signature() {
        let r = [0x01u8; 48];
        let s = [0x02u8; 48];
        let mut buf = [0u8; MAX_ECDSA384_SIG_DER_LEN];
        let n = encode_ecdsa_signature(&mut buf, &r, &s).unwrap();
        // Verify BIT STRING tag
        assert_eq!(buf[0], 0x03);
        // Verify unused bits = 0 (after length bytes)
        assert!(n > 10); // sanity check
    }
}
