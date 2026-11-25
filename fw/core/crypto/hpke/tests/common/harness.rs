// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std-PAL harness shared by the HPKE integration tests: PAL/IO setup,
//! DMA views and two-pass wrappers around the firmware entry points.

#![allow(dead_code, unsafe_code)]

use tokio::runtime::Handle;
use tsra_fw_core_crypto_hpke::*;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmIo;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::*;

pub fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
    let (_tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, Handle::current());
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
    (pal, io)
}

pub fn dma(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

pub fn dma_mut(bytes: &mut [u8]) -> &mut HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw_mut(bytes) }
}

pub async fn fw_seal(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    cfg: &HpkeSealConfig<'_>,
    pt: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    pal.alloc_scoped_async(io, async |alloc| {
        let sizes = seal(pal, io, cfg, dma(pt), None, None, alloc).await?;
        let mut enc = vec![0u8; sizes.enc_len];
        let mut ct = vec![0u8; sizes.ct_len];
        let got = seal(
            pal,
            io,
            cfg,
            dma(pt),
            Some(&mut enc),
            Some(dma_mut(&mut ct)),
            alloc,
        )
        .await?;
        assert_eq!(got, sizes);
        Ok((enc, ct))
    })
    .await
}

pub async fn fw_open(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    cfg: &HpkeOpenConfig<'_>,
    enc: &[u8],
    ct: &[u8],
) -> HsmResult<Vec<u8>> {
    pal.alloc_scoped_async(io, async |alloc| {
        let mut pt = vec![0u8; ct.len()];
        let n = open(pal, io, cfg, enc, ct, Some(&mut pt), alloc).await?;
        pt.truncate(n);
        Ok(pt)
    })
    .await
}

pub async fn fw_send_export(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    cfg: &HpkeSendExportConfig<'_>,
    len: usize,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    pal.alloc_scoped_async(io, async |alloc| {
        let mut enc = vec![0u8; cfg.suite.nenc()];
        let mut out = vec![0u8; len];
        send_export(pal, io, cfg, Some(&mut enc), Some(&mut out), alloc).await?;
        Ok((enc, out))
    })
    .await
}

pub async fn fw_receive_export(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    cfg: &HpkeReceiveExportConfig<'_>,
    enc: &[u8],
    len: usize,
) -> HsmResult<Vec<u8>> {
    pal.alloc_scoped_async(io, async |alloc| {
        let mut out = vec![0u8; len];
        receive_export(pal, io, cfg, enc, Some(&mut out), alloc).await?;
        Ok(out)
    })
    .await
}
