// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clear provisioning without deleting existing vault keys or backups.

use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;
use tsra_fw_hsm_pal_traits::HsmPartitionManager;
use tsra_fw_hsm_pal_traits::HsmResult;

use super::common::ReqHdr;
use super::test_action::encode_success;
use super::test_action::expect_empty_payload;
use crate::UnoHsmIo;
use crate::pal::UnoHsmPal;

/// Validate and execute `TestAction::ClearProvisioningState`.
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
    let resp = encode_success(pal, io, hdr)?;
    pal.part_prop_clear(io, HsmPartPropId::MK_KEY_ID)?;
    Ok(resp)
}
