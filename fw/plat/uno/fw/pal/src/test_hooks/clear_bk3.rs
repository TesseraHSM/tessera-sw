// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clear persistent BK3 provisioning state for FIPS validation.

use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_drivers_part_store::PartStore;

use super::common::ReqHdr;
use super::test_action::encode_success;
use super::test_action::expect_empty_payload;
use crate::UnoHsmIo;
use crate::pal::UnoHsmPal;

/// Validate and execute `TestAction::ClearBk3` (22).
pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'p HsmDmaBuf> {
    expect_empty_payload(decoder, request_field_count, request_len)?;
    let _lock = pal.partition_lock(io).await?;
    let part = PartStore::partition(io.pid())?;

    // Nothing is cleared if response allocation/encoding fails.
    let resp = encode_success(pal, io, hdr)?;
    part.clear_bk3_info();
    Ok(resp)
}
