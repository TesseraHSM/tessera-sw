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
    let memory_x = manifest.join("memory.x");
    fs::copy(&memory_x, out.join("memory.x")).expect("copy memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", memory_x.display());

    // `cargo xtask log-fixture` points TSRA_LOG_MAP at a scratch copy of the
    // map directory.
    println!("cargo:rerun-if-env-changed=TSRA_LOG_MAP");
    let map = env::var_os("TSRA_LOG_MAP").map_or_else(|| manifest.join("log_map"), PathBuf::from);
    tsra_log_map::build_script(&map, &out);

    println!("cargo:rustc-check-cfg=cfg(fail_case, values(any()))");
    println!("cargo:rustc-check-cfg=cfg(outside)");
}
