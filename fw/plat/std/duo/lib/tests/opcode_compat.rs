// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The Duo wire codec and the core dispatcher define the opcodes
//! independently; they must agree.

use tsra_fw_hsm_core::DuoOp as CoreOp;
use tsra_fw_hsm_io::duo::DuoOp as WireOp;

#[test]
fn duo_opcodes_match_core() {
    for (wire, core) in [
        (WireOp::Tbor, CoreOp::Tbor),
        (WireOp::TborSecure, CoreOp::TborSecure),
        (WireOp::FlushSession, CoreOp::FlushSession),
    ] {
        assert_eq!(u16::from(wire as u8), core as u16);
    }
}
