@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA forward NTT for the Cortex-M7.
@
@ void pqc_ml_dsa_ntt(int32_t p[256])
@
@ The reference transform: layers len = 128 down to 1, with the reference's
@ twiddles, mont(zeta^brv(i)), y' = x - zeta*y and x' = x + zeta*y under a
@ Montgomery product. The output is congruent to the reference's mod q and
@ as far inside 32 bits, coefficient by coefficient.
@
@ On this core a load or store does not issue alongside a multiply, so a
@ butterfly costs its three multiplies plus its share of the ldrd/strd
@ traffic however the rest is arranged, and what is left to win is stalls
@ and loop scaffolding.
@
@ - Layers 128 to 4 load x with y at the top of the pass, so the adds wait
@   on nothing but the multiplies (14.5 -> 13.5 cycles a pair), and walk
@   their windows here rather than in Rust.
@ - Layers 2 and 1 run together over blocks of four, each loaded and
@   stored once, as scheduled for the M7 by the SLOTHY superoptimizer
@   (https://github.com/slothy-optimizer/slothy, MIT License): the
@   layer78_loop of examples/opt/armv7m/dilithium/ntt_dilithium_opt_m7.s,
@   from pqm4's Dilithium NTT (based on code by Markus Krausz; CC0 with
@   permission of the authors). Software-pipelined one block deep, it
@   needs the block's three twiddles side by side, hence its own table.

.syntax unified
.thumb
.text

.equ DQ,    8380417         @ q
.equ DQINV, 58728449        @ q^-1 mod 2^32
.equ NQ,    0xff801fff      @ -q, for smlal
.equ NQINV, 0xfc7fdfff      @ -q^-1 mod 2^32

.global pqc_ml_dsa_ntt
.type pqc_ml_dsa_ntt, %function
.align 2
pqc_ml_dsa_ntt:
    movw    r1, #:lower16:pqc_ml_dsa_zetas
    movt    r1, #:upper16:pqc_ml_dsa_zetas
    push    {r0, r1, r4-r11, lr}    @ [sp] = p, [sp, #4] = twiddle cursor
    movw    r4, #(DQINV & 0xffff)
    movt    r4, #(DQINV >> 16)
    movw    r5, #(NQ & 0xffff)
    movt    r5, #(NQ >> 16)
    mov     r2, #512                @ half-window in bytes: len 128

    @ len 128 to 4: two butterflies a pass under the window's twiddle.
1:  @ window: r0 = x half, r2 = half-window bytes
    adds    r1, r0, r2
    lsrs    r2, r2, #3
    ldr     r6, [sp, #4]
    ldr     r3, [r6], #4            @ zeta
    str     r6, [sp, #4]
2:
    ldrd    r6, r7, [r1]            @ y0, y1
    ldrd    r12, lr, [r0]           @ x0, x1
    smull   r8, r9, r6, r3
    smull   r10, r11, r7, r3
    mul     r6, r8, r4              @ m
    mul     r7, r10, r4
    smlal   r8, r9, r6, r5          @ hi: (y*zeta - m*q) >> 32
    smlal   r10, r11, r7, r5
    subs    r2, r2, #1
    sub     r6, r12, r9
    add     r12, r12, r9
    sub     r7, lr, r11
    add     lr, lr, r11
    strd    r6, r7, [r1], #8
    strd    r12, lr, [r0], #8
    bne     2b
    subs    r2, r1, r0              @ both cursors moved by the half-window
    mov     r0, r1                  @ next window starts where y ended
    ldr     r6, [sp]
    add     r6, r6, #1024
    cmp     r0, r6
    bne     1b
    ldr     r0, [sp]
    lsrs    r2, r2, #1
    cmp     r2, #8                  @ len 2 and 1 have their own loop
    bne     1b

    @ len 2 and 1 together, a block of four coefficients a pass: len 2
    @ pairs (a0, a2) and (a1, a3) under the block's layer-7 twiddle, then
    @ len 1 pairs (a0, a1) and (a2, a3) under its two layer-8 ones. The
    @ products here are (a*zeta + m*q) >> 32 with m = a * -q^-1, the same
    @ Montgomery product as above with m negated. r0 = p.
    movw    r1, #:lower16:pqc_ml_dsa_zetas78
    movt    r1, #:upper16:pqc_ml_dsa_zetas78
    movw    r2, #(NQINV & 0xffff)
    movt    r2, #(NQINV >> 16)
    movw    r3, #(DQ & 0xffff)
    movt    r3, #(DQ >> 16)
    add     r4, r0, #1024
    ldr     r6, [r1], #12
    ldr.w   r14, [r0, #8]
    ldr.w   r5, [r0, #12]
    smull   r5, r9, r5, r6
    mul     r10, r5, r2
    sub     r4, r4, #16
3:
    smull   r11, r12, r14, r6
    ldr.w   r14, [r0, #4]
    smlal   r5, r9, r10, r3
    ldr     r8, [r1, #-8]
    mul     r6, r11, r2
    add     r14, r14, r9
    ldr     r7, [r1, #-4]
    sub.w   r9, r14, r9, lsl #1
    smull   r5, r8, r14, r8
    ldr.w   r10, [r0]
    smlal   r11, r12, r6, r3
    ldr     r6, [r1], #12
    mul     r14, r5, r2
    add     r11, r10, r12
    smull   r7, r10, r9, r7
    ldr.w   r9, [r0, #28]
    smlal   r5, r8, r14, r3
    sub.w   r12, r11, r12, lsl #1
    mul     r14, r7, r2
    add     r11, r11, r8
    smull   r5, r9, r9, r6
    sub.w   r8, r11, r8, lsl #1
    smlal   r7, r10, r14, r3
    ldr.w   r14, [r0, #24]
    str.w   r8, [r0, #4]
    str     r11, [r0], #16
    add     r12, r12, r10
    str     r12, [r0, #-8]
    cmp.w   r0, r4
    sub.w   r12, r12, r10, lsl #1
    mul     r10, r5, r2
    str     r12, [r0, #-4]
    bne.w   3b
    ldr.w   r12, [r0, #4]
    smull   r7, r8, r14, r6
    ldr     r14, [r1, #-8]
    smlal   r5, r9, r10, r3
    ldr     r5, [r1, #-4]
    mul     r10, r7, r2
    add     r12, r12, r9
    ldr.w   r6, [r0]
    sub.w   r9, r12, r9, lsl #1
    smull   r12, r14, r12, r14
    smlal   r7, r8, r10, r3
    mul     r7, r12, r2
    add     r10, r6, r8
    smull   r5, r9, r9, r5
    sub.w   r8, r10, r8, lsl #1
    smlal   r12, r14, r7, r3
    mul     r12, r5, r2
    add     r7, r10, r14
    str     r7, [r0], #16
    smlal   r5, r9, r12, r3
    sub.w   r12, r7, r14, lsl #1
    str     r12, [r0, #-12]
    add     r12, r8, r9
    str     r12, [r0, #-8]
    sub.w   r12, r12, r9, lsl #1
    str     r12, [r0, #-4]
    pop     {r0, r1, r4-r11, pc}
.size pqc_ml_dsa_ntt, .-pqc_ml_dsa_ntt

.section .rodata.pqc_ml_dsa_zetas, "a", %progbits
.align 2
@ ZETAS[1..64]: the twiddles of layers len = 128 to 4, in order.
pqc_ml_dsa_zetas:
    .word 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347
    .word 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103, 2725464
    .word 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549, -2118186
    .word -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005, 2706023
    .word 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115
    .word -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267
    .word -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596, 811944
    .word 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779

@ The last two layers', a block's three side by side: ZETAS[64 + b],
@ ZETAS[128 + 2b], ZETAS[129 + 2b].
pqc_ml_dsa_zetas78:
    .word -3930395, 2091667, 3407706, -1528703, 2316500, 3817976, -3677745, -3342478
    .word 2244091, -3041255, -2446433, -3562462, -1452451, 266997, 2434439, 3475950
    .word -1235728, 3513181, 2176455, -3520352, -3759364, -1585221, -1197226, -3193378
    .word -1257611, 900702, 1859098, 1939314, 909542, 819034, -4083598, 495491
    .word -1613174, -1000202, -43260, -522500, -3190144, -655327, -3122442, -3157330
    .word 2031748, 3207046, -3632928, -3556995, -525098, 126922, -768622, -3595838
    .word 3412210, 342297, 286988, -983419, -2437823, 4108315, 2147896, 3437287
    .word -3342277, 2715295, 1735879, 203044, -2967645, 2842341, 2691481, -3693493
    .word -2590150, 1265009, -411027, 4055324, 1247620, -2477047, 2486353, 1595974
    .word -671102, -3767016, 1250494, -1228525, 2635921, -3548272, -22981, -2994039
    .word 1869119, -1308169, 1903435, -1050970, -381987, -1333058, 1237275, 1349076
    .word -3318210, -1430225, 1852771, -451100, 1312455, -1430430, 3306115, -1962642
    .word -3343383, -1279661, 1917081, 264944, -2546312, -1374803, 508951, 1500165
    .word 777191, 3097992, 2235880, 3406031, 44288, -542412, -2831860, -1100098
    .word -1671176, -1846953, 904516, -2584293, -3724270, 3958618, 594136, -3776993
    .word -3724342, -2013608, 2432395, -8578, 2454455, -164721, 1653064, 1957272
    .word 3369112, -3249728, 185531, -1207385, 2389356, -3183426, 162844, -210977
    .word 1616392, 3014001, 759969, 810149, 1652634, -1316856, -3694233, -1799107
    .word 189548, -3038916, 3523897, -3553272, 3866901, 269760, 3159746, 2213111
    .word -975884, -1851402, 1717735, 472078, -2409325, -426683, 1723600, -177440
    .word -1803090, 1910376, 1315589, -1667432, -1104333, 1341330, -260646, -3833893
    .word 1285669, -2939036, -2235985, -1584928, -420899, -2286327, -812732, 183443
    .word -976891, -1439742, 1612842, -3545687, -3019102, -554416, 3919660, -3881060
    .word -48306, -1362209, -3628969, 3937738, 1400424, 3839961, -846154, 1976782
