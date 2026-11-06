// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmBulkCrypto`] implementation for the Uno PAL.
//!
//! - **default build** — a bulk key is a vault entry holding its AES-256
//!   material, and its host-visible bulk key id is its vault key id. Bulk
//!   IOs run on the BCP (see `crypto::bulk_bcp`).
//! - **`bulk_crypto`** — the fast-path firmware hosts the bulk engine: the
//!   key is registered with it over IPC, the vault keeps the 2-byte engine
//!   handle, and that handle is the bulk key id. Bulk IOs never reach the
//!   HSM core.
//!
//! Deletion goes through the [`HsmVault`](tsra_fw_hsm_pal_traits::HsmVault)
//! delete paths in [`crate::vault`], which release any engine state.

use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkDir;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::GCM_IV_LEN;
use tsra_fw_hsm_bulk::GCM_TAG_LEN;
use tsra_fw_hsm_pal_traits::HsmAesGcm;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmBulkCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_drivers_bcp::BCP_MAX_SRC_LEN;
use zeroize::Zeroize;

use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::vault::FP_BULK_KEY_LEN;
use crate::vault::is_bulk_kind;

impl HsmBulkCrypto for UnoHsmPal {
    async fn bulk_key_create(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<(HsmKeyId, u16)> {
        if !is_bulk_kind(kind) {
            return Err(HsmError::InvalidKeyType);
        }
        if key.len() != FP_BULK_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }

        #[cfg(feature = "bulk_crypto")]
        let key_id = crate::vault::fp_bulk_create(self, io, key, kind, session_id, attrs).await?;
        #[cfg(not(feature = "bulk_crypto"))]
        let key_id = {
            // Serialized with session teardown, as in `fp_bulk_create`. The
            // guard drops before the cleanup below, which takes it again.
            let _guard = self.fp_bulk_lock.lock().await;
            crate::vault::check_bulk_session(self, io, session_id)?;
            let app_id = u8::from(io.pid());
            let session = session_id.map(u16::from);
            crate::vault::vault(io)
                .create(self, io, app_id, key, kind, session, attrs)
                .await?
        };

        match self.bulk_key_id(io, key_id) {
            Ok(bulk_key_id) => Ok((key_id, bulk_key_id)),
            Err(e) => {
                // Don't leave a key (or engine registration) the host has
                // no handle for.
                let _ = self.vault_key_delete(io, key_id).await;
                Err(e)
            }
        }
    }

    fn bulk_key_id(&self, io: &UnoHsmIo, key_id: HsmKeyId) -> HsmResult<u16> {
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return Err(HsmError::UnsupportedKeyType);
        }
        #[cfg(feature = "bulk_crypto")]
        {
            // The vault entry holds the 2-byte engine handle.
            let bytes: &[u8] = self.vault_key(io, key_id)?;
            let handle: [u8; 2] = bytes.try_into().map_err(|_| HsmError::InternalError)?;
            Ok(u16::from_le_bytes(handle))
        }
        #[cfg(not(feature = "bulk_crypto"))]
        Ok(u16::from(key_id))
    }

    async fn bulk_crypt(&self, io: &mut UnoHsmIo) -> HsmResult<()> {
        #[cfg(not(feature = "bulk_crypto"))]
        return self.bulk_bcp_crypt(io).await;
        #[cfg(feature = "bulk_crypto")]
        {
            let _ = io;
            Err(HsmError::UnsupportedCmd)
        }
    }

    async fn bulk_crypt_unpinned(&self, io: &mut UnoHsmIo, key: &HsmDmaBuf) -> HsmResult<()> {
        let sqe = BulkSqe::parse(io.sqe())?;
        let key_ref = sqe.masked_key.ok_or(HsmError::InvalidArg)?;
        let BulkParams::Gcm(gcm) = sqe.params else {
            return Err(HsmError::UnsupportedCmd);
        };
        let body_len = sqe.src_len as usize;
        let tail_len = gcm.tail.map_or(0, |tail| usize::from(tail.len));
        let len = body_len + tail_len;
        let block_len = tsra_fw_hsm_bulk::BLOCK_LEN as usize;
        let aad_align = tsra_fw_hsm_bulk::GCM_AAD_ALIGN as usize;
        if len.next_multiple_of(block_len) > BCP_MAX_SRC_LEN {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
        let aad_len = gcm.aad_len as usize;
        let padded = gcm.aligned_aad_len as usize;
        let aad_offset = if (1..=block_len).contains(&(aad_len % aad_align)) {
            block_len
        } else {
            0
        };
        if aad_offset + aad_len > padded {
            return Err(HsmError::InvalidArg);
        }
        let mut cqe = BulkCqe::success(&sqe, 0);
        let io_ref = &*io;
        self.alloc_scoped_async(io_ref, async |scope| {
            let allocation = scope.dma_alloc(len.max(block_len))?;
            let data = &mut allocation[..len];
            let iv = scope.dma_alloc(GCM_IV_LEN)?;
            let tag = scope.dma_alloc(GCM_TAG_LEN)?;
            let outcome: HsmResult<()> = async {
                if body_len != 0 {
                    self.copy_mem_from_host(
                        io_ref,
                        host_addr(sqe.src_addr),
                        HsmDmaAddr::ZERO,
                        &mut data[..body_len],
                        false,
                    )
                    .await?;
                }
                if let Some(tail) = gcm.tail {
                    self.copy_mem_from_host(
                        io_ref,
                        host_addr(tail.src),
                        HsmDmaAddr::ZERO,
                        &mut data[body_len..],
                        false,
                    )
                    .await?;
                }
                if aad_offset != 0 {
                    data.copy_within(..aad_len, aad_offset);
                    data[..aad_offset].fill(0);
                }
                data[aad_offset + aad_len..padded].fill(0);
                iv.copy_from_slice(&gcm.iv);
                tag.copy_from_slice(&gcm.tag);
                match sqe.dir {
                    BulkDir::Encrypt => {
                        if key_ref.device_iv {
                            self.rng_fill_bytes(io_ref, iv)?;
                        }
                        self.gcm_encrypt_in_place(io_ref, key, iv, aad_len, data, tag)
                            .await?;
                    }
                    BulkDir::Decrypt => {
                        self.gcm_decrypt_in_place(io_ref, key, iv, aad_len, tag, data)
                            .await?
                    }
                }
                if aad_offset != 0 {
                    data.copy_within(aad_offset..aad_offset + aad_len, 0);
                    data[aad_len..padded].fill(0);
                }
                if body_len != 0 {
                    self.copy_mem_to_host(
                        io_ref,
                        &data[..body_len],
                        host_addr(sqe.dst_addr),
                        HsmDmaAddr::ZERO,
                        false,
                    )
                    .await?;
                }
                if let Some(tail) = gcm.tail {
                    self.copy_mem_to_host(
                        io_ref,
                        &data[body_len..],
                        host_addr(tail.dst),
                        HsmDmaAddr::ZERO,
                        false,
                    )
                    .await?;
                }
                cqe.iv.copy_from_slice(iv);
                cqe.tag.copy_from_slice(tag);
                cqe.fips_approved = key_ref.device_iv;
                Ok(())
            }
            .await;
            allocation.zeroize();
            iv.zeroize();
            tag.zeroize();
            outcome
        })
        .await?;
        cqe.write(io.cqe())
    }
}

fn host_addr(addr: u64) -> HsmDmaAddr {
    HsmDmaAddr {
        lo: addr as u32,
        hi: (addr >> 32) as u32,
    }
}
