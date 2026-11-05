// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Build script: assemble the ARM kernels for thumbv7em targets with the cc
// crate -- pqm4's Keccak-f[1600] (https://github.com/mupq/pqm4) and ML-DSA
// inverse NTT, both as scheduled for the Cortex-M7 by SLOTHY, and the
// ML-DSA forward NTT.
// Set CC_thumbv7em_none_eabi to your arm-none-eabi-gcc path if needed.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.starts_with("thumbv7em") {
        cc::Build::new()
            .file("asm/keccakf1600.S")
            .file("asm/dilithium_intt.S")
            .file("asm/dsa_ntt.S")
            .file("asm/dsa_unpack_z.S")
            .file("asm/dsa_unpack_key.S")
            .compile("pqc_ml_asm");

        println!("cargo:rerun-if-changed=asm/keccakf1600.S");
        println!("cargo:rerun-if-changed=asm/dilithium_intt.S");
        println!("cargo:rerun-if-changed=asm/dsa_ntt.S");
        println!("cargo:rerun-if-changed=asm/dsa_unpack_z.S");
        println!("cargo:rerun-if-changed=asm/dsa_unpack_key.S");
    }
}
