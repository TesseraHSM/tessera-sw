// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v1 masked-key format: AEAD envelope over
//! [`tsra_fw_core_crypto_aead_envelope`].
//!
//! Firmware-internal format used for session BMK wrapping and any
//! future masked-key flow that doesn't need to be host-readable.
//! Uses a fixed 192 B [`MaskedKeyMetadata`] record as AAD; carries
//! vault primitives ([`HsmVaultKeyKind`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind),
//! [`HsmVaultKeyAttrs`](tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs))
//! directly so call sites never translate between schema-local and
//! vault-local enums.

mod decode;
mod encode;
mod format;

pub use decode::peek_metadata;
pub use decode::peek_scope;
pub use decode::unmask;
pub use decode::UnmaskedView;
pub use encode::mask;
pub use encode::mask_in_place;
pub use encode::payload_offset;
pub use encode::MaskParams;
pub use format::blob_len as masked_blob_len;
pub use format::MaskedKeyMetadata;
pub use format::KEY_LABEL_MAX;
pub use format::META_MAGIC;
pub use format::META_VERSION_V1;
pub use tsra_fw_core_crypto_aead_envelope::AeadAlg;
