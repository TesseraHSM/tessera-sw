// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // `cfg!(target_os)` here is the build host; the target is in the env.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    // Never unload the library: its statics (the handle table, the device
    // connection) own heap memory and may be referenced by Rust std's
    // thread-local and atexit machinery, so `dlclose` must be a no-op. This
    // also keeps LeakSanitizer from reporting their backing storage when a
    // host (e.g. the PKCS#11 module's tests) unloads it.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-z,nodelete");

    // Get the output directory and pass it to CMake
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = std::path::PathBuf::from(&out_dir);

    // Navigate up to find the target directory: OUT_DIR is in target/profile/build/crate-hash/out
    // We need to go up 3 levels to get to target/profile/
    if let Some(target_dir) = out_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
    {
        println!("cargo:rustc-env=TSRA_TARGET_DIR={}", target_dir.display());
    }
}
