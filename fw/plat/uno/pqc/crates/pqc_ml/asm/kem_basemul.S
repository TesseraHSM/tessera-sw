@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-KEM matrix-vector products for the Cortex-M7, accumulated in 32 bits.
@
@ A row of A_hat * r_hat is k basemuls added together. Reducing each one
@ to 16 bits, as poly_basemul_acc does, costs five multiplies a pair of
@ coefficients for the a1*b1*zeta term and the two Montgomery reductions,
@ and a load and store of the 16-bit accumulator besides. Instead:
@
@ - basemul_prep, once for each b that several rows share, stores beside
@   every pair (b0, b1) the pair (b0, b1*zeta mod q);
@ - basemul_acc32 then needs two multiplies a pair, smlad for
@   a0*b0 + a1*(b1*zeta) and smladx for a0*b1 + a1*b0, into two 32-bit
@   accumulators, with no reduction;
@ - acc_reduce takes each sum down to 16 bits once, by Montgomery, as the
@   reductions it replaces did -- the result carries the same 2^-16.
@
@ On this core a load or store does not issue alongside a multiply, so
@ the memory traffic -- the 64-bit accumulator pair in and out -- sets the
@ pace at about six cycles a pair against fourteen.
@
@ Bounds, for a below 2^12 and b within +-11651 (a transform output):
@ |a0*b0 + a1*b1z| < 6.1e7 and |a0*b1 + a1*b0| < 9.6e7 a term, so four
@ terms stay below 3.9e8 and their Montgomery reduction, which adds at
@ most q*2^15, below 2^31; it returns at most 7464 in magnitude.

.syntax unified
.thumb
.text

.equ QINV_QNEG, 0xf2fff301  @ qinv = 62209 in the bottom half, -q in the top

@ void pqc_ml_kem_basemul_prep(uint32_t bb[256], const int16_t b[256],
@                              const int16_t zetas[64])
@
@ bb[2i] = (b0, b1) and bb[2i+1] = (b0, b1*zeta_i mod q) for each pair i,
@ zeta_i = +-zetas[i/2] by the parity of i, as basemul pairs them; zetas
@ is in the Montgomery domain, so Montgomery reducing b1*zeta gives the
@ product itself.
.global pqc_ml_kem_basemul_prep
.type pqc_ml_kem_basemul_prep, %function
.align 2
pqc_ml_kem_basemul_prep:
    push    {r4-r8, lr}
    movw    r3, #(QINV_QNEG & 0xffff)
    movt    r3, #(QINV_QNEG >> 16)
    movs    r12, #64
1:
    ldrsh   r4, [r2], #2            @ zeta
    ldrd    r5, r6, [r1], #8        @ two pairs
    smultb  r7, r5, r4              @ b1 * zeta
    rsb     r4, r4, #0
    smultb  r8, r6, r4              @ b1' * -zeta
    mul     lr, r7, r3
    smlabt  r7, lr, r3, r7          @ top: mont(b1 * zeta)
    mul     lr, r8, r3
    smlabt  r8, lr, r3, r8
    pkhtb   r7, r7, r5              @ (b0, b1*zeta)
    pkhtb   r8, r8, r6
    strd    r5, r7, [r0], #8
    strd    r6, r8, [r0], #8
    subs    r12, r12, #1
    bne     1b
    pop     {r4-r8, pc}
.size pqc_ml_kem_basemul_prep, .-pqc_ml_kem_basemul_prep

@ void pqc_ml_kem_basemul_acc32(int32_t acc[256], const int16_t a[256],
@                               const uint32_t bb[256], uint32_t first)
@
@ acc += the products of a and the b prepared in bb, two 32-bit sums a
@ pair (acc[2i] for the even coefficient, acc[2i+1] the odd); with first
@ nonzero, acc = rather than +=.
.global pqc_ml_kem_basemul_acc32
.type pqc_ml_kem_basemul_acc32, %function
.align 2
pqc_ml_kem_basemul_acc32:
    push    {r4-r11, lr}
    movs    r12, #64
    cbnz    r3, 3f
1:  @ two pairs a pass
    ldrd    r3, r4, [r1], #8        @ a, a'
    ldrd    r5, r6, [r2], #8        @ b, b~
    ldrd    r7, r8, [r0]            @ acc0, acc1
    ldrd    r9, r10, [r2], #8       @ b', b~'
    smlad   r7, r3, r6, r7          @ a0*b0 + a1*b1z
    smladx  r8, r3, r5, r8          @ a0*b1 + a1*b0
    ldrd    r5, r6, [r0, #8]
    smlad   r5, r4, r10, r5
    smladx  r6, r4, r9, r6
    subs    r12, r12, #1
    strd    r7, r8, [r0], #8
    strd    r5, r6, [r0], #8
    bne     1b
    pop     {r4-r11, pc}
3:  @ the first column: assign
    ldrd    r3, r4, [r1], #8
    ldrd    r5, r6, [r2], #8
    ldrd    r9, r10, [r2], #8
    smuad   r7, r3, r6
    smuadx  r8, r3, r5
    smuad   r5, r4, r10
    smuadx  r6, r4, r9
    subs    r12, r12, #1
    strd    r7, r8, [r0], #8
    strd    r5, r6, [r0], #8
    bne     3b
    pop     {r4-r11, pc}
.size pqc_ml_kem_basemul_acc32, .-pqc_ml_kem_basemul_acc32

@ void pqc_ml_kem_acc_reduce(int16_t r[256], const int32_t acc[256])
@
@ r = mont(acc): each 32-bit sum Montgomery reduced to 16 bits, which is
@ what poly_basemul_acc's per-term reductions summed to (2^-16 included).
@ r may be the start of acc's own buffer.
.global pqc_ml_kem_acc_reduce
.type pqc_ml_kem_acc_reduce, %function
.align 2
pqc_ml_kem_acc_reduce:
    push    {r4-r6, lr}
    movw    r3, #(QINV_QNEG & 0xffff)
    movt    r3, #(QINV_QNEG >> 16)
    movs    r12, #128
1:
    ldrd    r4, r5, [r1], #8
    subs    r12, r12, #1
    mul     r6, r4, r3
    mul     lr, r5, r3
    smlabt  r4, r6, r3, r4
    smlabt  r5, lr, r3, r5
    pkhtb   r4, r5, r4, asr #16
    str     r4, [r0], #4
    bne     1b
    pop     {r4-r6, pc}
.size pqc_ml_kem_acc_reduce, .-pqc_ml_kem_acc_reduce
