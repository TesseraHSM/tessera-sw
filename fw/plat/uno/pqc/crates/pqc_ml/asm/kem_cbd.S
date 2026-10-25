@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-KEM's centered binomial sampling (SamplePolyCBD) for the Cortex-M7.
@
@ A coefficient is the popcount of eta bits less the popcount of the next
@ eta. Both routines take every field's popcount across a whole word with
@ the usual subtract-the-shifted-bits trick, then pair the fields up with
@ the SIMD instructions so each output word carries two coefficients --
@ a few instructions for four coefficients rather than several for each.

.syntax unified
.thumb
.text

@ void pqc_ml_kem_cbd2(int16_t r[256], const uint32_t buf[32])
@
@ A little-endian word holds eight coefficients, four bits apiece: a0 a0
@ b0 b0 a1 a1 b1 b1 ... from bit 0. After the 2-bit popcounts, masking
@ every fourth field into bytes gives the a and b of the even coefficients
@ and, shifted by four, of the odd; ssub8 takes the differences, and a
@ halfword swap between the two lines them up as c0 c2 c1 c3 so that
@ sxtb16 widens them to the pairs (c0, c1) and (c2, c3).
.global pqc_ml_kem_cbd2
.type pqc_ml_kem_cbd2, %function
.align 2
pqc_ml_kem_cbd2:
    push    {r4-r7}
    mov     r2, #0x55555555
    mov     r3, #0x03030303
    mov     r12, #32
1:
    ldr     r4, [r1], #4
    and     r5, r2, r4, lsr #1
    sub     r4, r4, r5              @ 2-bit popcounts
    and     r5, r4, r3              @ a0 a2 a4 a6
    and     r6, r3, r4, lsr #2      @ b0 b2 b4 b6
    and     r7, r3, r4, lsr #4      @ a1 a3 a5 a7
    and     r4, r3, r4, lsr #6      @ b1 b3 b5 b7
    ssub8   r5, r5, r6              @ c0 c2 c4 c6
    ssub8   r7, r7, r4              @ c1 c3 c5 c7
    pkhbt   r4, r5, r7, lsl #16     @ c0 c2 c1 c3
    pkhtb   r7, r7, r5, asr #16     @ c4 c6 c5 c7
    sxtb16  r5, r4                  @ (c0, c1)
    sxtb16  r4, r4, ror #8          @ (c2, c3)
    sxtb16  r6, r7                  @ (c4, c5)
    sxtb16  r7, r7, ror #8          @ (c6, c7)
    subs    r12, r12, #1
    strd    r5, r4, [r0], #8
    strd    r6, r7, [r0], #8
    bne     1b
    pop     {r4-r7}
    bx      lr
.size pqc_ml_kem_cbd2, .-pqc_ml_kem_cbd2

@ void pqc_ml_kem_cbd3(int16_t r[256], const uint8_t buf[193])
@
@ Three bytes hold four coefficients, six bits apiece, read as a word that
@ need not be aligned -- so buf must have a byte to spare past the 192 the
@ coefficients take. After the 3-bit popcounts the fields are 3 apart:
@ one pkh lines the popcounts of coefficients 0 and 1 up at the bottom of
@ the two halfwords, another those of 2 and 3, and a mask pair and ssub16
@ make each a pair of coefficients.
.global pqc_ml_kem_cbd3
.type pqc_ml_kem_cbd3, %function
.align 2
pqc_ml_kem_cbd3:
    push    {r4-r6, lr}
    movw    r2, #0xb6db
    movt    r2, #0x6d               @ 0b011 in every field
    movw    r3, #0x9249
    movt    r3, #0x24               @ 0b001 in every field
    mov     r12, #0x00070007
    mov     lr, #64
1:
    ldr     r4, [r1], #3            @ bits 24-31 are the next group's
    and     r5, r2, r4, lsr #1
    and     r6, r3, r4, lsr #2
    add     r5, r5, r6
    sub     r4, r4, r5              @ 3-bit popcounts: a0 b0 a1 b1 ... a3 b3
    pkhbt   r5, r4, r4, lsl #10     @ a0 b0 at bit 0, a1 b1 at bit 16
    lsr     r6, r4, #2
    pkhtb   r4, r6, r4, asr #12     @ a2 b2 at bit 0, a3 b3 at bit 16
    and     r6, r5, r12
    and     r5, r12, r5, lsr #3
    ssub16  r5, r6, r5              @ (c0, c1)
    and     r6, r4, r12
    and     r4, r12, r4, lsr #3
    ssub16  r4, r6, r4              @ (c2, c3)
    subs    lr, lr, #1
    strd    r5, r4, [r0], #8
    bne     1b
    pop     {r4-r6, pc}
.size pqc_ml_kem_cbd3, .-pqc_ml_kem_cbd3
