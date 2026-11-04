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

#[cfg(feature = "sock")]
#[test]
fn require_emu_does_not_accept_socket_builds() {
    let output = Command::new(env!("CARGO_BIN_EXE_leaf_svc"))
        .args([
            "--require-emu",
            "create",
            "--name",
            "orders",
            "--root",
            "http://127.0.0.1:8080",
            "--state-dir",
            "unused",
        ])
        .output()
        .expect("run backend guard");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires an emulator build"));
}
