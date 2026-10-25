@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-KEM Compress_d and its packing, for the Cortex-M7.
@
@ void pqc_ml_kem_compress(uint8_t *out, const int16_t a[256], uint32_t d)
@
@ Writes round(2^d * (a mod q) / q) mod 2^d for every coefficient, d bits
@ each and least significant first -- ByteEncode_d(Compress_d(a)) -- for d
@ in 1..=11. `out` takes 32*d bytes and need not be aligned.
@
@ The coefficients need not be reduced: anything within +-5000 is exact.
@ Adding 4096*q leaves the result unchanged mod 2^d (2^11 divides 4096) and
@ makes every numerator positive, so one rounded-up reciprocal serves,
@
@     ((a << d) + q/2 + 4096*q) * ceil(2^36 / q) >> 36,
@
@ which is the true quotient for every numerator below 2^25. The callers
@ hand over inverse-transform outputs plus small noise, and a difference
@ of one with a decompressed polynomial, without the Barrett pass that a
@ canonical input would need; every case is checked against the
@ reference in the host model of this file.

.syntax unified
.thumb
.text

.equ CR,    0x013afb77      @ ceil(2^36 / q)
.equ C0,    0x00d01680      @ q/2 + 4096*q

.global pqc_ml_kem_compress
.type pqc_ml_kem_compress, %function
.align 2
pqc_ml_kem_compress:
    push    {r4-r10, lr}
    movw    r3, #(CR & 0xffff)
    movt    r3, #(CR >> 16)
    movw    r10, #(C0 & 0xffff)
    movt    r10, #(C0 >> 16)
    movs    r4, #1
    lsls    r4, r4, r2
    subs    r4, r4, #1              @ 2^d - 1
    movs    r5, #0                  @ bits not yet stored
    movs    r6, #0                  @ how many
    movs    r7, #128                @ input words, two coefficients each
1:
    ldr     r8, [r1], #4
    sxth    r9, r8
    asrs    r8, r8, #16
    lsls    r9, r9, r2
    add     r9, r9, r10
    umull   r12, r9, r9, r3
    and     r9, r4, r9, lsr #4      @ Compress_d of the low coefficient
    lsl     r12, r9, r6
    orrs    r5, r5, r12
    adds    r6, r6, r2
    cmp     r6, #32
    blo     2f
    str     r5, [r0], #4            @ a word is full; keep what spilled over
    subs    r6, r6, #32
    sub     r12, r2, r6
    lsr     r5, r9, r12
2:
    lsls    r8, r8, r2
    add     r8, r8, r10
    umull   r12, r8, r8, r3
    and     r8, r4, r8, lsr #4      @ and of the high one
    lsl     r12, r8, r6
    orrs    r5, r5, r12
    adds    r6, r6, r2
    cmp     r6, #32
    blo     3f
    str     r5, [r0], #4
    subs    r6, r6, #32
    sub     r12, r2, r6
    lsr     r5, r8, r12
3:
    subs    r7, r7, #1
    bne     1b
    pop     {r4-r10, pc}
.size pqc_ml_kem_compress, .-pqc_ml_kem_compress
