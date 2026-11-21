// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM and AES-256-XTS self-tests (CAST) on the BCP, the engine
//! that serves host bulk IOs in the default build.
//!
//! GCM runs through the PAL's GCM on the BCP: the vector's 16-byte AAD and
//! 51-byte text take the engine and the tag correction around it (`H` on
//! the AES engine, GHASH in software), the parts bulk GCM IOs use. XTS runs
//! one engine command per direction. Both check encrypt and decrypt
//! against the vector, as the FP firmware's CDMA self-tests did.

use tsra_fw_hsm_pal_traits::HsmAesGcm;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_uno_drivers_bcp::BCP_TWEAK_LEN;
use tsra_fw_uno_drivers_bcp::BcpData;
use tsra_fw_uno_drivers_bcp::BcpError;
use tsra_fw_uno_drivers_bcp::BcpOp;
use tsra_fw_uno_drivers_bcp::XtsRequest;
use tsra_fw_uno_trace::tracing::error;

use super::vectors::AES_GCM_256_KAT;
use super::vectors::AES_XTS_256_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Padded AAD length of the GCM vector's 16-byte AAD: `[0¹²⁸ | AAD]`, per
/// `tsra_fw_core_crypto_gcm_buf`.
const GCM_PADDED_AAD_LEN: usize = 32;

/// Offset of the AAD within its padded region.
const GCM_AAD_OFFSET: usize = 16;

/// Runs the AES-256-GCM known-answer test on the BCP.
pub(super) async fn run_aes_gcm(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &AES_GCM_256_KAT;
    if v.aad.len() != GCM_PADDED_AAD_LEN - GCM_AAD_OFFSET {
        return Err(HsmError::InternalError);
    }

    pal.alloc_scoped_async(io, async |scope| {
        let key = scope.dma_alloc(v.key.len())?;
        key.copy_from_slice(v.key);
        let iv = scope.dma_alloc(v.iv.len())?;
        iv.copy_from_slice(v.iv);
        let len = GCM_PADDED_AAD_LEN + v.plaintext.len();

        // ── Encrypt: [padded AAD | plaintext] → ciphertext and tag ──
        let pt = scope.dma_alloc_zeroed(len)?;
        pt[GCM_AAD_OFFSET..GCM_PADDED_AAD_LEN].copy_from_slice(v.aad);
        pt[GCM_PADDED_AAD_LEN..].copy_from_slice(v.plaintext);
        let ct = scope.dma_alloc_zeroed(len)?;
        let tag = scope.dma_alloc_zeroed(v.tag.len())?;
        pal.gcm_encrypt(io, &*key, &*iv, v.aad.len(), &*pt, &mut *ct, &mut *tag)
            .await?;
        // KAT vectors are public, fixed test data: a plain comparison is
        // correct.
        if &ct[GCM_PADDED_AAD_LEN..] != v.ciphertext || &tag[..] != v.tag {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "bulk AES-GCM encrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        // ── Decrypt: the vector's ciphertext and tag → plaintext ──
        ct[GCM_PADDED_AAD_LEN..].copy_from_slice(v.ciphertext);
        tag.copy_from_slice(v.tag);
        let out = scope.dma_alloc_zeroed(len)?;
        pal.gcm_decrypt(io, &*key, &*iv, v.aad.len(), &*tag, &*ct, &mut *out)
            .await?;
        if &out[GCM_PADDED_AAD_LEN..] != v.plaintext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "bulk AES-GCM decrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}

/// Runs the AES-256-XTS known-answer test on the BCP.
pub(super) async fn run_aes_xts(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &AES_XTS_256_KAT;
    let tweak: &[u8; BCP_TWEAK_LEN] = v.tweak.try_into().map_err(|_| HsmError::InternalError)?;

    pal.alloc_scoped_async(io, async |scope| {
        let pt = scope.dma_alloc(v.plaintext.len())?;
        pt.copy_from_slice(v.plaintext);
        let ct = scope.dma_alloc_zeroed(v.ciphertext.len())?;
        xts(pal, BcpOp::Encrypt, v.key1, v.key2, tweak, pt, ct).await?;
        if &ct[..] != v.ciphertext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "bulk AES-XTS encrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        ct.copy_from_slice(v.ciphertext);
        let out = scope.dma_alloc_zeroed(v.plaintext.len())?;
        xts(pal, BcpOp::Decrypt, v.key1, v.key2, tweak, ct, out).await?;
        if &out[..] != v.plaintext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "bulk AES-XTS decrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}

/// One whole-transfer XTS command on the BCP, `src` to `dst`.
async fn xts(
    pal: &UnoHsmPal,
    op: BcpOp,
    key1: &[u8],
    key2: &[u8],
    tweak: &[u8; BCP_TWEAK_LEN],
    src: &HsmDmaBuf,
    dst: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let done = pal
        .bcp
        .xts(XtsRequest {
            op,
            key1,
            key2,
            tweak,
            dul: 0,
            data: BcpData::Copy { src, dst },
        })
        .await?;
    if !done.ok() {
        return Err(BcpError::CMD_ERROR);
    }
    Ok(())
}
