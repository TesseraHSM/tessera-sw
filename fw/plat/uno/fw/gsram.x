/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

/* Self-test and cold-path code (certificate chain validation, session open,
   partition provisioning and security-domain backup/restore) and their
   read-only data are kept in separate output
   sections: .gsram_text (executable) first, then .gsram_rodata (not
   executable). The boundary is 32-byte aligned, the ARMv7-M MPU region
   granularity, so the rodata can be mapped execute-never on its own. */
SECTIONS
{
    .gsram_text : ALIGN(32)
    {
        __gsram_text_start = .;
        *(.text.*self_test*)
        /* Only present in non-production test-hook builds. */
        *(.text.*test_hooks*)
        /* Cold path: certificate chain validation is not on the crypto
           hot path. */
        *(.text.*tsra_fw_core_crypto_x509_chain*)
        /* Cold paths: session open and partition provisioning. */
        *(.text.*session_open_init*)
        *(.text.*9part_init*)
        *(.text.*10part_final*)
        /* Security-domain provisioning and backup/restore handlers, including
           their async poll bodies and shared backup helpers. */
        *(.text.*sd_sealing_key_gen*)
        *(.text.*sd_create_remote_backup*)
        *(.text.*sd_create_peer_backup*)
        *(.text.*sd_reseal_remote_backup*)
        *(.text.*sd_restore_remote_backup*)
        *(.text.*sd_restore_peer_backup*)
        *(.text.*sd_restore_local_backup*)
        *(.text.*sd_backup*)
        . = ALIGN(32);
        __gsram_text_end = .;
    } > GSRAM_CODE

    .gsram_rodata : ALIGN(32)
    {
        __gsram_rodata_start = .;
        *(.rodata.*self_test*)
        *(.rodata.*tsra_fw_core_crypto_x509_chain*)
        . = ALIGN(32);
        __gsram_rodata_end = .;
    } > GSRAM_CODE
}
INSERT BEFORE .text;

ASSERT(SIZEOF(.gsram_text) > 0, "No self-test sections selected for GSRAM");
/* KAT vectors reach .gsram_rodata only through the `kat!` macro
   (pal/src/self_test/vectors.rs); plain literals land in ITCM .rodata. */
ASSERT(SIZEOF(.gsram_rodata) > 0, "No self-test KAT vectors selected for GSRAM");
