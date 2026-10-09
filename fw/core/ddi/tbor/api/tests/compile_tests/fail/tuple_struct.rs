// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: #[tbor] on a tuple struct (must have named fields).
use tsra_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct TupleReq(u8, u16);

fn main() {}
