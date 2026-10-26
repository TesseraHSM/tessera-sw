@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA's Decompose straight off the inverse transform, for the Cortex-M7:
@ each coefficient w of w (|w| < q) becomes (r0 << 6) | r1 in place, and r1
@ is packed as the commitment hash takes it (see `poly_decompose_pack` in
@ dsa/rounding.rs).
@
@ With a = w mod q and D = 2 * gamma2, the reference's
@ r1 = (((a + 127) >> 7) * c + 2^(s-1)) >> s is exactly floor((a + gamma2 -
@ 1) / D) -- checked for every a in [0, q) -- which a multiply by a 32-bit
@ reciprocal and one shift give exactly too: (a + gamma2 - 1) * 8396809 >> 42
@ for gamma2 = (q - 1) / 32, and * 2886403 >> 39 for (q - 1) / 88. One
@ umull and a ubfx replace four dependent shifts and adds.
@
@ That r1 runs to 16 (or 44) at the top of [0, q), where the reference
@ wraps it to 0 and takes q from r0. But 16 * D = q - 1 (and 44 * D), so
@ there r0 = a - r1 * D - 1 is already the reference's a - q: the wrap is
@ that 1 and clearing r1, not the reference's compare-and-subtract of q
@ against (q - 1) / 2. The M7 runs the result about 27% (gamma2 = (q -
@ 1) / 32) and 38% ((q - 1) / 88) faster than the shift-and-add version.

.syntax unified
.thumb
.text

@ r3 = q, r4 = the reciprocal, r5 = D, r11 = gamma2 - 1. w0 and w1 are a
@ pair of coefficients, h0 and h1 their r1, t0 and t1 scratch; s is the
@ reciprocal's shift less 32, b the bits r1 takes.
.macro r1_of w0, w1, h0, h1, t0, t1, s, b
    and     \t0, r3, \w0, asr #31
    and     \t1, r3, \w1, asr #31
    add     \w0, \w0, \t0           @ a = w mod q
    add     \w1, \w1, \t1
    add     \t0, \w0, r11
    add     \t1, \w1, r11
    umull   \t0, \h0, \t0, r4
    umull   \t1, \h1, \t1, r4
    ubfx    \h0, \h0, #\s, #\b      @ r1, 0 to 16 (44)
    ubfx    \h1, \h1, #\s, #\b
    mls     \w0, \h0, r5, \w0       @ a - r1 * D
    mls     \w1, \h1, r5, \w1
.endm

@ void pqc_ml_dsa_decompose_pack32(int32_t w[256], uint8_t packed[128])
@
@ gamma2 = (q - 1) / 32: r1 is 4 bits, packed a byte a pair. At the top
@ r1 is 16, the only value with bit 4 set, so bit 4 is the wrap.
.global pqc_ml_dsa_decompose_pack32
.type pqc_ml_dsa_decompose_pack32, %function
.align 2
pqc_ml_dsa_decompose_pack32:
    push    {r4-r11, lr}
    movw    r3, #0xE001
    movt    r3, #0x7F               @ q
    movw    r4, #0x2009
    movt    r4, #0x80               @ 2^42 / D, rounded up
    movw    r5, #0xFE00
    movt    r5, #0x7                @ D = 523776
    movw    r11, #0xFEFF
    movt    r11, #0x3               @ gamma2 - 1
    movs    r2, #128
1:
    ldrd    r6, r7, [r0]
    r1_of   r6, r7, r8, r9, r10, r12, 10, 5
    sub     r6, r6, r8, lsr #4      @ less 1 at the wrap
    sub     r7, r7, r9, lsr #4
    and     r8, r8, #15             @ and r1 0 there
    and     r9, r9, #15
    orr     r6, r8, r6, lsl #6
    orr     r7, r9, r7, lsl #6
    orr     r10, r8, r9, lsl #4
    strd    r6, r7, [r0], #8
    strb    r10, [r1], #1
    subs    r2, r2, #1
    bne     1b
    pop     {r4-r11, pc}
.size pqc_ml_dsa_decompose_pack32, .-pqc_ml_dsa_decompose_pack32

@ gamma2 = (q - 1) / 88, after r1_of: r1 + 20 reaches 64 only at the wrap,
@ r1 = 44, so its bit 6 is the wrap: less 1 from r0 and r1 times it from
@ r1. A compare and an IT block run slower here.
.macro wrap88 w0, w1, h0, h1, t0, t1
    add     \t0, \h0, #20
    add     \t1, \h1, #20
    lsr     \t0, \t0, #6
    lsr     \t1, \t1, #6
    sub     \w0, \w0, \t0
    sub     \w1, \w1, \t1
    mls     \h0, \t0, \h0, \h0
    mls     \h1, \t1, \h1, \h1
    orr     \w0, \h0, \w0, lsl #6
    orr     \w1, \h1, \w1, lsl #6
.endm

@ void pqc_ml_dsa_decompose_pack88(int32_t w[256], uint8_t packed[192])
@
@ r1 is 6 bits: four coefficients make three bytes, so two pairs an
@ iteration.
.global pqc_ml_dsa_decompose_pack88
.type pqc_ml_dsa_decompose_pack88, %function
.align 2
pqc_ml_dsa_decompose_pack88:
    push    {r4-r11, lr}
    movw    r3, #0xE001
    movt    r3, #0x7F               @ q
    movw    r4, #0x0B03
    movt    r4, #0x2C               @ 2^39 / D, rounded up
    movw    r5, #0xE800
    movt    r5, #0x2                @ D = 190464
    movw    r11, #0x73FF
    movt    r11, #0x1               @ gamma2 - 1
    movs    r2, #64
1:
    ldrd    r6, r7, [r0]
    r1_of   r6, r7, r8, r9, r10, r12, 7, 6
    wrap88  r6, r7, r8, r9, r10, r12
    strd    r6, r7, [r0], #8
    orr     lr, r8, r9, lsl #6
    ldrd    r6, r7, [r0]
    r1_of   r6, r7, r8, r9, r10, r12, 7, 6
    wrap88  r6, r7, r8, r9, r10, r12
    strd    r6, r7, [r0], #8
    orr     lr, lr, r8, lsl #12
    orr     lr, lr, r9, lsl #18
    strh    lr, [r1], #2
    lsr     lr, lr, #16
    strb    lr, [r1], #1
    subs    r2, r2, #1
    bne     1b
    pop     {r4-r11, pc}
.size pqc_ml_dsa_decompose_pack88, .-pqc_ml_dsa_decompose_pack88
