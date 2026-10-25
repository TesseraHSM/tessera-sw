// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Build script: assemble the ARM kernels for thumbv7em targets with the cc
// crate -- pqm4's Keccak-f[1600] (https://github.com/mupq/pqm4) and ML-DSA
// inverse NTT, both as scheduled for the Cortex-M7 by SLOTHY, the ML-DSA
// forward NTT, and the ML-KEM transforms, products and compression.
// Set CC_thumbv7em_none_eabi to your arm-none-eabi-gcc path if needed.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.starts_with("thumbv7em") {
        cc::Build::new()
            .file("asm/keccakf1600.S")
            .file("asm/dilithium_intt.S")
            .file("asm/dsa_ntt.S")
            .file("asm/kem_ntt.S")
            .file("asm/kem_compress.S")
            .file("asm/kem_basemul.S")
            .compile("pqc_ml_asm");

        println!("cargo:rerun-if-changed=asm/keccakf1600.S");
        println!("cargo:rerun-if-changed=asm/dilithium_intt.S");
        println!("cargo:rerun-if-changed=asm/dsa_ntt.S");
        println!("cargo:rerun-if-changed=asm/kem_ntt.S");
        println!("cargo:rerun-if-changed=asm/kem_compress.S");
        println!("cargo:rerun-if-changed=asm/kem_basemul.S");
    }
}
