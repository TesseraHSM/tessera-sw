// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKexKeyGen` handler.
//!
//! Generates a fresh DARC key-exchange (recipient) key for the requested
//! HPKE KEM — a P-384 ECC keypair (DHKEM), an ML-KEM-1024 seed (HPKE-13) or
//! an MLKEM1024-P384 hybrid seed (HPKE-10) — under the active session's
//! partition, and returns the **masked** private key plus the public key.
//! Key generation and masking are shared with `SdSealingKeyGen`; only the
//! vault kinds and the metadata label differ.
//!
//! The private key is **not** stored on the device.  Instead it is
//! masked (AEAD-GCM-256) under the masking key associated with the
//! requested [`scope`](HsmKeyScope) and the masked blob is returned to
//! the caller, which re-imports it (unmask-on-use) when the key is later
//! needed.  Because nothing is persisted, the command records no
//! rollback on the undo log.
//!
//! Scope → masking key:
//!
//! * [`Ephemeral`](HsmKeyScope::Ephemeral) → the partition
//!   [`PartitionEphemeralMaskingKey`](HsmVaultKeyKind::PartitionEphemeralMaskingKey).
//! * [`Local`](HsmKeyScope::Local) → the partition
//!   [`PartitionLocalMaskingKey`](HsmVaultKeyKind::PartitionLocalMaskingKey).
//!
//! * [`SecurityDomain`](HsmKeyScope::SecurityDomain) uses the
//!   [`SdMasking`](HsmVaultKeyKind::SdMasking) key once the SD exists.
//!
//! This command requires a partition in the
//! [`Initialized`](HsmPartState::Initialized) lifecycle state; scopes without
//! a masking key are rejected with [`HsmError::UnsupportedKeyScope`].
//!
//! This command is **Crypto-Officer-only**: a Crypto-User session is
//! rejected with [`HsmError::InvalidPermissions`].

use tsra_fw_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_fw_ddi_tbor_types::TborDarcKexKeyGenResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::sd_sealing_key_gen::generate_masked_recipient;
use super::sd_sealing_key_gen::RecipientKeyClass;

/// DARC key-exchange keys.
const DARC_KEX: RecipientKeyClass = RecipientKeyClass {
    kinds: [
        HsmVaultKeyKind::DarcKex,
        HsmVaultKeyKind::DarcKexMlKem1024,
        HsmVaultKeyKind::DarcKexMlKem1024P384,
    ],
    label: b"DarcKexKey",
};

/// Handle a TBOR `DarcKexKeyGen` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it reads partition state and returns a freshly generated,
/// masked keypair, so a concurrently-dispatched command can neither observe
/// it half-done nor require its rollback on failure.  The raw private key
/// is wiped from the per-IO DMA pool during IO teardown.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let req = TborDarcKexKeyGenReq::decode(cmd_buf.request())?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    // Byte-identical 3-bit scope discriminants; unknown values round-trip.
    let scope = HsmKeyScope(req.scope().0);
    let (masked_key, pub_key) =
        generate_masked_recipient(pal, io, sess_id, scope, req.kem(), &DARC_KEX).await?;
    cmd_buf.encode_response(|buf| {
        let frame = TborDarcKexKeyGenResp::encode(buf, 0, false)?
            .masked_key(masked_key)?
            .pub_key(pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
