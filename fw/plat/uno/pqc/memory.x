/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT License. */

/* FP core memory map.
 *
 * One image is built for all three FP cores, so only memory that is present
 * and identical on FP0, FP1 and FP2 may be used here:
 *
 *   ITCM  0x0000_0000  32 KB on every core (code + vector table)
 *   DTCM  0x2000_0000  32 KB on FP0/FP2, 64 KB on FP1 -> only the common
 *                      32 KB window is used
 */

MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 32K
    RAM   : ORIGIN = 0x20000000, LENGTH = 32K
}
