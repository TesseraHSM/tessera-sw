// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Build script: assemble pqm4 Keccak-f[1600] for ARM targets.
// On thumbv7em targets, assembles asm/keccakf1600.S from
// https://github.com/mupq/pqm4 using the cc crate.
// Set CC_thumbv7em_none_eabi to your arm-none-eabi-gcc path if needed.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.starts_with("thumbv7em") {
        cc::Build::new()
            .file("asm/keccakf1600.S")
            .compile("keccakf1600");

        println!("cargo:rerun-if-changed=asm/keccakf1600.S");
    }
}
