/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

/* Self-test and cold-path code (certificate chain validation) and their
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
        /* HPKE (classic and PQ suites) is not on the bulk crypto hot path. */
        *(.text.*tsra_fw_core_crypto_hpke*)
        /* Cold path: partition init / final run once per provisioning. */
        *(.text.*part_init*)
        *(.text.*part_final*)
        /* Cold path: SD backup/transfer and DARC TBOR handlers
           and their TBOR request types (module names are length-prefixed
           in mangled symbols). */
        *(.text.*tbor*[0-9]sd_* .text.*tbor*[0-9][0-9]sd_*)
        *(.text.*tbor*[0-9]darc_* .text.*tbor*[0-9][0-9]darc_*)
        /* Cold path: MBOR establish credential (once per partition). */
        *(.text.*establish_cred*)
        . = ALIGN(32);
        __gsram_text_end = .;
    } > GSRAM_CODE

    .gsram_rodata : ALIGN(32)
    {
        __gsram_rodata_start = .;
        *(.rodata.*self_test*)
        *(.rodata.*tsra_fw_core_crypto_x509_chain*)
        *(.rodata.*tsra_fw_core_crypto_hpke*)
        *(.rodata.*part_init*)
        *(.rodata.*part_final*)
        *(.rodata.*tbor*[0-9]sd_* .rodata.*tbor*[0-9][0-9]sd_*)
        *(.rodata.*tbor*[0-9]darc_* .rodata.*tbor*[0-9][0-9]darc_*)
        *(.rodata.*establish_cred*)
        . = ALIGN(32);
        __gsram_rodata_end = .;
    } > GSRAM_CODE
}
INSERT BEFORE .text;

ASSERT(SIZEOF(.gsram_text) > 0, "No self-test sections selected for GSRAM");
/* KAT vectors reach .gsram_rodata only through the `kat!` macro
   (pal/src/self_test/vectors.rs); plain literals land in ITCM .rodata. */
ASSERT(SIZEOF(.gsram_rodata) > 0, "No self-test KAT vectors selected for GSRAM");
