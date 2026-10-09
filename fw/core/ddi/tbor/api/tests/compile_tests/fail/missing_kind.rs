// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: #[tbor] without opcode or response.
use tsra_fw_ddi_tbor_api::tbor;

#[tbor]
pub struct NoKind {
    a: u8,
}

fn main() {}
