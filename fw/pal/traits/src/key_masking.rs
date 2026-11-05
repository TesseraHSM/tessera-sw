// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// In-place AES-256-GCM key masking.
///
/// The exact operation buffer is laid out as:
///
/// ```text
/// [IV:16 | AAD:aad_len | zero-padded payload | tag:16]
/// ```
///
/// IV stores a 12-byte GCM nonce followed by `[0, 0, 0, 1]`.
/// Only the first 12 bytes are used; the unauthenticated suffix is ignored
/// on unmask and must not carry metadata.
/// The masking key is exactly 32 bytes.
/// AAD is opaque, authenticated, and never encrypted or interpreted.
/// AAD length must be a multiple of 32 bytes; the staged payload length
/// must be a multiple of 16 bytes.
/// The caller zero-pads plaintext and authenticates its padding count in AAD.
///
/// Neither operation moves regions. Implementations may use temporary
/// buffers internally.
/// On error, callers must not publish the buffer or use its payload.
pub trait HsmKeyMasking: HsmIoTypes {
    /// Validate AAD alignment and return `(total_len, data_pad_len)`,
    /// where `data_pad_len` is 0..=15 and rounds the payload up to 16 bytes.
    /// `total_len` is `16 + aad_len + payload_len + data_pad_len + 16`,
    /// excluding any outer envelope header, without allocation or crypto.
    /// Arithmetic overflow is rejected.
    fn key_mask_len(&self, aad_len: usize, payload_len: usize) -> HsmResult<(usize, u8)>;

    /// Mask caller-staged plaintext in place, generating the nonce and
    /// writing the authentication tag. AAD is unchanged.
    async fn key_mask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Authenticate and decrypt at the original payload offset.
    /// On success, IV, AAD and tag are unchanged.
    async fn key_unmask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;
}
