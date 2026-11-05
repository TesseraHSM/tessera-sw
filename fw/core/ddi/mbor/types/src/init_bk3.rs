// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiInitBk3Req<'a> {
    #[ddi(id = 1, len = 48)]
    pub bk3: &'a mut HsmDmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiInitBk3Resp<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub masked_bk3: &'a [u8],
    #[ddi(id = 2, len = 16)]
    pub vm_launch_guid: &'a [u8],
}

ddi_op_req_resp!(DdiInitBk3, 'a);
