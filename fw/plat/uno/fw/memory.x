/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

INCLUDE gsram-memory.x

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 512K
    /* DTCM — CPU-only, holds stack and .bss.
       Upper region reserved (see rdl/soc/dtcm_map.rdl):
         0x2002_EC00  DTCM_IO_BUF[33]   (49.5 KB, 1.5 KB each)
         0x2003_B400  DEV_ID_CERT_BLOB  (16 KB)
         0x2003_F400  CRASHDUMP_BASE    (1024 B)
         0x2003_F800  CORE_RUN_STATUS   (4 B)
       LENGTH capped at 187K. */
    RAM   : ORIGIN = 0x20000000, LENGTH = 187K
}

/* Include before link.x consumes the .text/.rodata self-test inputs. */
INCLUDE gsram.x
ASSERT(__gsram_rodata_end <= ORIGIN(GSRAM_CODE) + LENGTH(GSRAM_CODE), "Self-tests exceed GSRAM_CODE");

/* .data has no load copy: the previous boot stage writes .data straight to
   its run address, and the reset handler doesn't copy it (cortex-m-rt's
   skip-data-copy feature, turned on in app/Cargo.toml). This block is the
   .data rule of cortex-m-rt 0.7.7's link.x without AT>FLASH, and LLD's
   OVERWRITE_SECTIONS puts it in place of that one. link.x still sets
   __edata and __sidata after it, so __sidata equals __sdata. */
OVERWRITE_SECTIONS
{
    .data : ALIGN(4)
    {
        . = ALIGN(4);
        __sdata = .;
        *(.data .data.*);
        . = ALIGN(4);
    } > RAM
}
ASSERT(LOADADDR(.data) == ADDR(.data), ".data must load at its run address: the previous boot stage writes it there, and the reset handler doesn't copy it");
