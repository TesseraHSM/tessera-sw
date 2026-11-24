// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEncryptedBk3<'a> {
    #[ddi(id = 1, len = 48)]
    pub encrypted_bk3: &'a mut HsmDmaBuf,
    #[ddi(id = 2, len = 16)]
    pub iv: &'a mut HsmDmaBuf,
    #[ddi(id = 3, len = 32)]
    pub nonce: &'a mut HsmDmaBuf,
    #[ddi(id = 4, len = 48)]
    pub tag_transport: &'a mut HsmDmaBuf,
    #[ddi(id = 5, len = 48)]
    pub tag_pin: &'a mut HsmDmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSecureInitBk3Req<'a> {
    #[ddi(id = 1)]
    pub encrypted_bk3: DdiEncryptedBk3<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSecureInitBk3Resp<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub masked_bk3: &'a [u8],
    #[ddi(id = 2, len = 16)]
    pub vm_launch_guid: &'a [u8],
}

ddi_op_req_resp!(DdiSecureInitBk3, 'a);
