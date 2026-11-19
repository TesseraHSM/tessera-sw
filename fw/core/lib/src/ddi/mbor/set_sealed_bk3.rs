// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI SetSealedBk3 command handler.
//!
//! Stores the sealed BK3 blob on the partition. Returns
//! `SealedBk3AlreadySet` if one has already been stored, or
//! `SealedBk3TooLarge` if the blob exceeds the PAL's
//! [`SEALED_BK3_MAX_LEN`](tsra_fw_pal_traits::SEALED_BK3_MAX_LEN)
//! bound.

use tsra_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Req;
use tsra_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Resp;
use tsra_fw_hsm_pal_traits::SEALED_BK3_MAX_LEN;

use super::*;

/// Handle DdiSetSealedBk3Cmd.
///
/// 1. **Body decode** — Decodes `DdiSetSealedBk3Req` with the blob.
///
/// 2. **Already-set check** — Rejects a repeated write before checking size,
///    so it returns `SealedBk3AlreadySet` even for an oversized payload.
///
/// 3. **Size check** — Rejects blobs larger than
///    [`SEALED_BK3_MAX_LEN`] with `SealedBk3TooLarge` before the
///    PAL property setter (which would otherwise surface the
///    overflow as the generic `InvalidArg`).
///
/// 4. **Store** — Writes the blob via the PAL.
///
/// 5. **Response** — Encodes `DdiSetSealedBk3Resp` (empty) into a
///    heap-allocated response buffer.
pub(crate) async fn set_sealed_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p HsmDmaBuf> {
    let body: DdiSetSealedBk3Req<'_> = decoder.decode_data()?;

    let _lock = pal.partition_lock(io).await?;
    if !crate::part_state::part_is_bk3_initialized(pal, io)? {
        return Err(HsmError::Bk3NotSecurelyProvisioned);
    }
    if crate::part_state::prop_present(crate::part_state::part_sealed_bk3(pal, io))? {
        return Err(HsmError::SealedBk3AlreadySet);
    }
    if body.sealed_bk3.len() > usize::from(SEALED_BK3_MAX_LEN) {
        return Err(HsmError::SealedBk3TooLarge);
    }

    let resp_hdr = super::success_hdr(hdr, DdiOp::SetSealedBk3);
    let resp_data = DdiSetSealedBk3Resp {};

    let resp = pal.dma_alloc_var(io, |buf| super::encode_resp(&resp_hdr, &resp_data, buf))?;
    crate::part_state::part_set_sealed_bk3(pal, io, body.sealed_bk3)?;

    Ok(resp)
}
