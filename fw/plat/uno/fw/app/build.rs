// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must set CARGO_MANIFEST_DIR"),
    );

    // Copy memory.x to OUT_DIR so the linker can find it.
    // memory.x lives at the platform workspace root (one level up from app/).
    let memory_x = manifest.join("../memory.x");
    fs::copy(&memory_x, out.join("memory.x")).expect("copy memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", memory_x.display());

    // Force the linker to keep Embassy trace hook symbols
    // even under LTO, so profiling works correctly.
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_task_exec_begin");
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_task_exec_end");
    println!("cargo:rustc-link-arg=--undefined=_embassy_trace_executor_idle");
}
