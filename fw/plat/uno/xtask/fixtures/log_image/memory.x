/* Copyright (c) Microsoft Corporation. Licensed under the MIT License. */

/* The fixture image's memory. Any Cortex-M layout works. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM : ORIGIN = 0x20000000, LENGTH = 64K
}
