// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    fs::copy("device.x", out_dir.join("device.x")).expect("copy device.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=device.x");
}
