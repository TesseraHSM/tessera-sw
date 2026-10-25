// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Copy memory.x to OUT_DIR so the linker can find it.
    // memory.x lives at the FP workspace root (one level up from app/).
    let memory_x = manifest.join("../memory.x");
    fs::copy(&memory_x, out.join("memory.x")).unwrap();
    // cortex-m-rt's `device` feature makes its link.x `INCLUDE device.x`,
    // which a PAC would supply. This app takes no interrupts, so there are
    // no handlers to name.
    fs::write(
        out.join("device.x"),
        "/* No device interrupts on the FP cores. */\n",
    )
    .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", memory_x.display());
}
