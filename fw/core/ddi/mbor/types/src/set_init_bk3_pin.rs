// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_fw_ddi_mbor_derive::Ddi;

use crate::open_session::DdiEncryptedEstablishCredential;
use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetInitBk3PinReq<'a> {
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedEstablishCredential<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetInitBk3PinResp {}

ddi_op_req_resp!(DdiSetInitBk3Pin, req 'a);
