// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The Uno wire codec and the core dispatcher define the opcodes
//! independently; they must agree.

#[test]
fn uno_opcodes_match_core() {
    assert_eq!(tsra_fw_hsm_io::OP_MBOR, tsra_fw_hsm_core::OP_MBOR);
    assert_eq!(tsra_fw_hsm_io::OP_FLUSH, tsra_fw_hsm_core::OP_FLUSH);
    assert_eq!(tsra_fw_hsm_io::OP_TBOR, tsra_fw_hsm_core::OP_TBOR);
}
