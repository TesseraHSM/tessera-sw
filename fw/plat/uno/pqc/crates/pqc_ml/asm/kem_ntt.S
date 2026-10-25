@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-KEM number-theoretic transforms for the Cortex-M7, two coefficients to
@ a register.
@
@ The twiddle multiplications use Plantard arithmetic (Huang et al.,
@ "Improved Plantard Arithmetic for Lattice-based Cryptography", TCHES
@ 2022/4) rather than Montgomery: with b' = b * q^-1 mod 2^32,
@
@     r = (((a * b') mod 2^32 >> 16) + 2^3) * q >> 16
@
@ is a * b * -2^-32 mod q, exactly, for every 16-bit a and |b| <= q/2, and
@ |r| <= 1664. That is `smulw` (the low half of its result is the middle of
@ the product) and `smlabt` (multiply by q, add 8q) -- two multiplies a
@ coefficient where Montgomery takes three -- and the result is half the
@ size, which is what lets the inverse skip most of its reductions.
@
@ Twiddles are the 16-bit b, from the table the caller passes; each window
@ turns its own into b' with one `mul`. The outputs differ from the
@ Montgomery transforms' by multiples of q, never in value mod q; every
@ caller reduces before anything depends on the representative.

.syntax unified
.thumb
.text

.equ QQ,    0x0d010000      @ q in the top half, for smlabt
.equ C8Q,   26632           @ 2^3 * q
.equ QP,    0x6ba8f301      @ q^-1 mod 2^32
.equ ONEP,  0x0013afb7      @ b' that multiplies by 1 (b = -2^32 mod q = -1353)
.equ FSCP,  0x275f6ed0      @ b' for 1441 * 2^-16, the reference's mont(a * f) (b = -304)
.equ FZ1P,  0xeb8b6b6e      @ b' for that times zeta_1, the last twiddle (b = 366)
.equ RMONTP, 0xafb7680c     @ b' that multiplies by 2^16 mod q = 2285 (b = 1036)

@ Two words of y in \y0/\y1 times b' in \z, Plantard reduced and packed back
@ in place; \t0/\t1 are scratch. QQ is in r3, 8q in r4.
.macro plant2 z, y0, y1, t0, t1
    smulwb  \t0, \z, \y0
    smulwt  \y0, \z, \y0
    smulwb  \t1, \z, \y1
    smulwt  \y1, \z, \y1
    smlabt  \t0, \t0, r3, r4
    smlabt  \y0, \y0, r3, r4
    smlabt  \t1, \t1, r3, r4
    smlabt  \y1, \y1, r3, r4
    pkhtb   \y0, \y0, \t0, asr #16
    pkhtb   \y1, \y1, \t1, asr #16
.endm

@ void pqc_ml_kem_ntt(int16_t p[256], const int16_t tw[127])
@
@ Forward Cooley-Tukey transform, the reference's layer and twiddle order:
@ y' = x - zeta*y, x' = x + zeta*y. An input bounded by B comes out
@ bounded by B + 7 * 1664.
.global pqc_ml_kem_ntt
.type pqc_ml_kem_ntt, %function
.align 2
pqc_ml_kem_ntt:
    push    {r0, r4-r11, lr}        @ [sp] = p
    movw    r3, #(QQ & 0xffff)
    movt    r3, #(QQ >> 16)
    movw    r4, #C8Q
    add     lr, r0, #512            @ end of the polynomial
    mov     r5, #256                @ half-window in bytes: len 128
1:  @ window: r0 = x half, r5 = half-window bytes
    adds    r2, r0, r5
    lsrs    r5, r5, #3              @ two words a pass
    ldrsh   r6, [r1], #2
    movw    r12, #(QP & 0xffff)
    movt    r12, #(QP >> 16)
    mul     r6, r6, r12
2:  @ two words of x against two of y; the flags wait for the bne
    ldr     r9, [r2]
    ldr     r10, [r2, #4]
    ldr     r7, [r0]
    ldr     r8, [r0, #4]
    subs    r5, r5, #1
    smulwb  r11, r6, r9
    smulwt  r9, r6, r9
    smulwb  r12, r6, r10
    smulwt  r10, r6, r10
    smlabt  r11, r11, r3, r4
    smlabt  r9, r9, r3, r4
    smlabt  r12, r12, r3, r4
    smlabt  r10, r10, r3, r4
    pkhtb   r9, r9, r11, asr #16
    ssub16  r11, r7, r9             @ word 0 while word 1's product lands
    sadd16  r7, r7, r9
    pkhtb   r10, r10, r12, asr #16
    ssub16  r12, r8, r10
    sadd16  r8, r8, r10
    strd    r11, r12, [r2], #8
    strd    r7, r8, [r0], #8
    bne     2b
    subs    r5, r2, r0              @ both cursors moved by the half-window
    mov     r0, r2                  @ next window starts where y ended
    cmp     r0, lr
    bne     1b
    ldr     r0, [sp]
    lsrs    r5, r5, #1
    cmp     r5, #4
    bne     1b

    @ len 2: a window is one word of x and one of y, each with its own
    @ twiddle, so a pass takes two windows.
    movw    lr, #(QP & 0xffff)
    movt    lr, #(QP >> 16)
    movs    r5, #32
3:
    ldrsh   r6, [r1], #2
    ldrsh   r12, [r1], #2
    ldrd    r7, r9, [r0]
    ldrd    r8, r10, [r0, #8]
    mul     r6, r6, lr
    mul     r12, r12, lr
    subs    r5, r5, #1
    smulwb  r11, r6, r9
    smulwt  r9, r6, r9
    smulwb  r6, r12, r10
    smulwt  r10, r12, r10
    smlabt  r11, r11, r3, r4
    smlabt  r9, r9, r3, r4
    smlabt  r6, r6, r3, r4
    smlabt  r10, r10, r3, r4
    pkhtb   r9, r9, r11, asr #16
    pkhtb   r10, r10, r6, asr #16
    ssub16  r11, r7, r9
    sadd16  r7, r7, r9
    ssub16  r12, r8, r10
    sadd16  r8, r8, r10
    strd    r7, r11, [r0], #8
    strd    r8, r12, [r0], #8
    bne     3b
    pop     {r0, r4-r11, pc}
.size pqc_ml_kem_ntt, .-pqc_ml_kem_ntt

@ void pqc_ml_kem_invntt(int16_t p[256], const int16_t *tw_end)
@
@ Inverse Gentleman-Sande transform with the reference's final scaling:
@ x' = x + y, y' = zeta*(y - x), twiddles read down from tw_end (one past
@ tw[126]), every output multiplied by f = mont^2/128.
@
@ A twiddle product is at most 1664, so only the sums grow, doubling a
@ layer at worst. Reducing the sums of layers 1 and 5 (multiplying them by
@ 1) keeps every sum in 16 bits for an input B below 2^14: 2B in layer 1,
@ then 2*1664 doubling to 26624 in layer 5, then 6656 in layer 7. Layer 7
@ folds f into both of its multipliers, so its sums are reduced too and
@ the separate scaling pass is gone. Outputs are at most 1664.
.global pqc_ml_kem_invntt
.type pqc_ml_kem_invntt, %function
.align 2
pqc_ml_kem_invntt:
    push    {r0, r4-r11, lr}        @ [sp] = p
    mov     lr, r1                  @ twiddle cursor
    movw    r3, #(QQ & 0xffff)
    movt    r3, #(QQ >> 16)
    movw    r4, #C8Q
    movw    r1, #(ONEP & 0xffff)
    movt    r1, #(ONEP >> 16)
    movw    r2, #(QP & 0xffff)
    movt    r2, #(QP >> 16)

    @ len 2: two windows a pass; both the sums and the products reduced.
    movs    r5, #32
1:
    ldrsh   r6, [lr, #-2]!
    ldrsh   r12, [lr, #-2]!
    ldrd    r7, r9, [r0]
    ldrd    r8, r10, [r0, #8]
    mul     r6, r6, r2
    mul     r12, r12, r2
    subs    r5, r5, #1
    ssub16  r11, r9, r7
    sadd16  r7, r7, r9
    ssub16  r9, r10, r8
    sadd16  r8, r8, r10
    smulwb  r10, r6, r11
    smulwt  r11, r6, r11
    smulwb  r6, r12, r9
    smulwt  r9, r12, r9
    smlabt  r10, r10, r3, r4
    smlabt  r11, r11, r3, r4
    smlabt  r6, r6, r3, r4
    smlabt  r9, r9, r3, r4
    pkhtb   r11, r11, r10, asr #16
    pkhtb   r9, r9, r6, asr #16
    plant2  r1, r7, r8, r10, r6
    strd    r7, r11, [r0], #8
    strd    r8, r9, [r0], #8
    bne     1b

    ldr     r0, [sp]
    movs    r5, #8                  @ half-window in bytes: len 4
    movs    r1, #0                  @ no reduction
2:  @ window: r0 = x half, r5 = half-window bytes, r1 = sum multiplier or 0
    adds    r2, r0, r5
    lsrs    r5, r5, #3
    ldrsh   r6, [lr, #-2]!
    movw    r12, #(QP & 0xffff)
    movt    r12, #(QP >> 16)
    mul     r6, r6, r12
3:  @ two words of x against two of y; the flags wait for the bne
    ldr     r9, [r2]
    ldr     r10, [r2, #4]
    ldr     r7, [r0]
    ldr     r8, [r0, #4]
    subs    r5, r5, #1
    ssub16  r11, r9, r7
    ssub16  r12, r10, r8
    sadd16  r7, r7, r9
    sadd16  r8, r8, r10
    plant2  r6, r11, r12, r9, r10
    strd    r11, r12, [r2], #8
    cbz     r1, 4f
    plant2  r1, r7, r8, r9, r10
4:
    strd    r7, r8, [r0], #8
    bne     3b
    subs    r5, r2, r0
    mov     r0, r2
    ldr     r12, [sp]
    add     r12, r12, #512
    cmp     r0, r12
    bne     2b
    @ next layer
    ldr     r0, [sp]
    lsls    r5, r5, #1
    cmp     r5, #256
    bhi     7f                      @ past len 128: done
    beq     6f
    movs    r1, #0
    cmp     r5, #64                 @ len 32: reduce the sums
    bne     2b
    movw    r1, #(ONEP & 0xffff)
    movt    r1, #(ONEP >> 16)
    b       2b
6:  @ len 128: one window, f folded into both multipliers
    add     r2, r0, #256
    movs    r5, #32
    movw    r6, #(FZ1P & 0xffff)
    movt    r6, #(FZ1P >> 16)
    movw    r1, #(FSCP & 0xffff)
    movt    r1, #(FSCP >> 16)
    b       3b
7:
    pop     {r0, r4-r11, pc}
.size pqc_ml_kem_invntt, .-pqc_ml_kem_invntt

@ void pqc_ml_kem_tomont_add(int16_t t[256], const int16_t e[256])
@
@ t = t * 2^16 + e mod q, as at most 1664 in magnitude: key generation's
@ last steps for each row of t_hat -- cancelling the 2^-16 basemul leaves,
@ adding e_hat, reducing for ByteEncode_12 -- in one pass of two Plantard
@ multiplies a coefficient. Any 16-bit t and e with |t*2^16 mod q + e|
@ below 2^15 is exact; e_hat is at most 3 + 7*1664.
.global pqc_ml_kem_tomont_add
.type pqc_ml_kem_tomont_add, %function
.align 2
pqc_ml_kem_tomont_add:
    push    {r4-r11, lr}
    movw    r3, #(QQ & 0xffff)
    movt    r3, #(QQ >> 16)
    movw    r4, #C8Q
    movw    r5, #(RMONTP & 0xffff)
    movt    r5, #(RMONTP >> 16)
    movw    r6, #(ONEP & 0xffff)
    movt    r6, #(ONEP >> 16)
    movs    r2, #64
1:
    ldrd    r7, r8, [r0]
    ldrd    r9, r10, [r1], #8
    subs    r2, r2, #1
    plant2  r5, r7, r8, r11, r12
    sadd16  r7, r7, r9
    sadd16  r8, r8, r10
    plant2  r6, r7, r8, r11, r12
    strd    r7, r8, [r0], #8
    bne     1b
    pop     {r4-r11, pc}
.size pqc_ml_kem_tomont_add, .-pqc_ml_kem_tomont_add

@ void pqc_ml_kem_reduce(int16_t a[256])
@
@ a mod q, as at most 1664 in magnitude, for every 16-bit a: a Plantard
@ multiply by 1, two coefficients a word.
.global pqc_ml_kem_reduce
.type pqc_ml_kem_reduce, %function
.align 2
pqc_ml_kem_reduce:
    push    {r4-r8, lr}
    movw    r3, #(QQ & 0xffff)
    movt    r3, #(QQ >> 16)
    movw    r4, #C8Q
    movw    r5, #(ONEP & 0xffff)
    movt    r5, #(ONEP >> 16)
    movs    r2, #64
1:
    ldrd    r6, r7, [r0]
    subs    r2, r2, #1
    plant2  r5, r6, r7, r8, r12
    strd    r6, r7, [r0], #8
    bne     1b
    pop     {r4-r8, pc}
.size pqc_ml_kem_reduce, .-pqc_ml_kem_reduce
