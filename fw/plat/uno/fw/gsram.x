/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

/* Self-test code and its read-only data are kept in separate output
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
        . = ALIGN(32);
        __gsram_text_end = .;
    } > GSRAM_CODE

    .gsram_rodata : ALIGN(32)
    {
        __gsram_rodata_start = .;
        *(.rodata.*self_test*)
        . = ALIGN(32);
        __gsram_rodata_end = .;
    } > GSRAM_CODE
}
INSERT BEFORE .text;

ASSERT(SIZEOF(.gsram_text) > 0, "No self-test sections selected for GSRAM");
/* KAT vectors reach .gsram_rodata only through the `kat!` macro
   (pal/src/self_test/vectors.rs); plain literals land in ITCM .rodata. */
ASSERT(SIZEOF(.gsram_rodata) > 0, "No self-test KAT vectors selected for GSRAM");
