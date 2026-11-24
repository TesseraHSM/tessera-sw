/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

/* Self-test and cold-path code (certificate chain validation, session open,
   partition and BK3 provisioning, security-domain backup/restore, and the
   PAL's boot-only setup and admin IPC) and their read-only data are kept in
   separate output sections: .gsram_text (executable) first, then
   .gsram_rodata (not executable). The boundary is 32-byte aligned, the
   ARMv7-M MPU region granularity, so the rodata can be mapped execute-never
   on its own. */
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
        /* BK3 provisioning only (init_bk3 also matches secure_init_bk3 and
           set_init_bk3_pin); keep shared credential and crypto code in ITCM. */
        *(.text.*tsra_fw_hsm_core*mbor*init_bk3*)
        *(.text.*tsra_fw_hsm_core*mbor*get_sealed_bk3*)
        *(.text.*tsra_fw_hsm_core*mbor*set_sealed_bk3*)
        *(.text.*tsra_fw_ddi_mbor_types*init_bk3*)
        *(.text.*tsra_fw_ddi_mbor_types*get_sealed_bk3*)
        *(.text.*tsra_fw_ddi_mbor_types*set_sealed_bk3*)
        /* Cold path: the PAL's boot-only setup and admin IPC handlers,
           placed here by `link_section` attributes. */
        *(.gsram_text.*)
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
