// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::Command;

#[test]
fn independent_leaf_binary_exposes_its_own_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_leaf_svc"))
        .arg("--help")
        .output()
        .expect("run leaf app");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for command in ["create", "join", "restore-local", "restore-remote"] {
        assert!(help.contains(command));
    }
    assert!(!help.contains("create-leaf"));
    assert!(!help.contains("clone"));
    assert!(!help.contains("upload-backup"));
}
