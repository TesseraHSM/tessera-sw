@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA forward NTT for the Cortex-M7.
@
@ void pqc_ml_dsa_ntt(int32_t p[256])
@
@ The reference transform -- layers len = 128 down to 1, the reference's
@ twiddles mont(zeta^brv(i)), y' = x - zeta*y and x' = x + zeta*y -- taken
@ two layers at a time over blocks of four coefficients, each block loaded
@ and stored once a pass. The Montgomery product is (a*zeta + m*q) >> 32
@ with m = a*zeta * -q^-1 mod 2^32, which is the reference's (a*zeta -
@ m'*q) >> 32 with m' = -m, so the output is the reference's bit for bit
@ but when m' = -2^31, where it is the reference's plus or minus q.
@
@ Every pass runs the Cortex-M7 schedule the SLOTHY superoptimizer
@ (https://github.com/slothy-optimizer/slothy, MIT License) produced for
@ the layer78_loop of pqm4's Dilithium NTT (based on code by Markus
@ Krausz; CC0 with permission of the authors), examples/opt/armv7m/
@ dilithium/ntt_dilithium_opt_m7.s: software-pipelined one block deep, 17
@ cycles a block. The last pass is that loop as it stands, its blocks four
@ consecutive coefficients, each with its own three twiddles. The first
@ three take theirs at a stride S of 64, 16 and 4 coefficients inside a
@ window of 4S, every block of a window under the same three twiddles,
@ so they only change its addressing: the next block is 4 bytes on rather
@ than 16, the twiddles are re-read in place, and each window primes and
@ drains the pipeline itself. All 255 twiddles sit in one table, a
@ window's three side by side, in the order the passes use them.

.syntax unified
.thumb
.text

.equ DQ,    8380417         @ q
.equ NQINV, 0xfc7fdfff      @ -q^-1 mod 2^32

@ One pass of windows S bytes a step apart inside, 4S apart from each
@ other, from r0 to [sp, #4]; r1 walks the twiddle triples, r2 = -q^-1,
@ r3 = q. Leaves r0 at the end of the pass.
.macro pass4 S
1:
    ldr     r6, [r1], #12
    ldr.w   r14, [r0, #(2*\S)]
    ldr.w   r5, [r0, #(3*\S)]
    smull   r5, r9, r5, r6
    mul     r10, r5, r2
    add     r4, r0, #(\S - 4)
2:
    smull   r11, r12, r14, r6
    ldr.w   r14, [r0, #\S]
    smlal   r5, r9, r10, r3
    ldr     r8, [r1, #-8]
    mul     r6, r11, r2
    add     r14, r14, r9
    ldr     r7, [r1, #-4]
    sub.w   r9, r14, r9, lsl #1
    smull   r5, r8, r14, r8
    ldr.w   r10, [r0]
    smlal   r11, r12, r6, r3
    ldr     r6, [r1, #-12]
    mul     r14, r5, r2
    add     r11, r10, r12
    smull   r7, r10, r9, r7
    ldr.w   r9, [r0, #(3*\S + 4)]
    smlal   r5, r8, r14, r3
    sub.w   r12, r11, r12, lsl #1
    mul     r14, r7, r2
    add     r11, r11, r8
    smull   r5, r9, r9, r6
    sub.w   r8, r11, r8, lsl #1
    smlal   r7, r10, r14, r3
    ldr.w   r14, [r0, #(2*\S + 4)]
    str.w   r8, [r0, #\S]
    str     r11, [r0], #4
    add     r12, r12, r10
    str     r12, [r0, #(2*\S - 4)]
    cmp.w   r0, r4
    sub.w   r12, r12, r10, lsl #1
    mul     r10, r5, r2
    str     r12, [r0, #(3*\S - 4)]
    bne.w   2b
    ldr.w   r12, [r0, #\S]
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
    str     r7, [r0], #4
    smlal   r5, r9, r12, r3
    sub.w   r12, r7, r14, lsl #1
    str     r12, [r0, #(\S - 4)]
    add     r12, r8, r9
    str     r12, [r0, #(2*\S - 4)]
    sub.w   r12, r12, r9, lsl #1
    str     r12, [r0, #(3*\S - 4)]
    add     r0, r0, #(3*\S)
    ldr     r12, [sp, #4]
    cmp     r0, r12
    bne     1b
.endm

.global pqc_ml_dsa_ntt
.type pqc_ml_dsa_ntt, %function
.align 2
pqc_ml_dsa_ntt:
    add     r1, r0, #1024
    push    {r0, r1, r4-r11, lr}    @ [sp] = p, [sp, #4] = p + 1024
    movw    r1, #:lower16:pqc_ml_dsa_zetas
    movt    r1, #:upper16:pqc_ml_dsa_zetas
    movw    r2, #(NQINV & 0xffff)
    movt    r2, #(NQINV >> 16)
    movw    r3, #(DQ & 0xffff)
    movt    r3, #(DQ >> 16)

    pass4   256                     @ len 128 and 64: one window
    ldr     r0, [sp]
    pass4   64                      @ len 32 and 16: four windows
    ldr     r0, [sp]
    pass4   16                      @ len 8 and 4: sixteen windows
    ldr     r0, [sp]

    @ len 2 and 1: the original loop, a block's own three twiddles each
    @ block, 4 bytes = one coefficient apart.
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
@ The twiddles of each pass's windows, three side by side: for pass p and
@ window w, ZETAS[4^p + w] then ZETAS[2*4^p + 2w] and ZETAS[2*4^p + 2w + 1].
pqc_ml_dsa_zetas:
    .word 25847, -2608894, -518909, 237124, 1826347, 2353451, -777960, -359251
    .word -2091905, -876248, 3119733, -2884855, 466468, 3111497, 2680103, 2725464
    .word 2706023, 95776, 1024112, 3077325, 3530437, -1079900, -1661693, -3592148
    .word 3585928, -2537516, 3915439, -549488, -3861115, -3043716, -1119584, 3574422
    .word -2867647, 2619752, 3539968, -300467, -2108549, 2348700, -539299, -2118186
    .word -1699267, -1643818, -3859737, 3505694, -3821735, -1399561, 3507263, -2140649
    .word -3277672, -1600420, 3699596, 1757237, 811944, 531354, -19422, 954230
    .word 3881043, 4010497, 3900724, -2556880, 280005, 2071892, -2797779, -3930395
    .word 2091667, 3407706, -1528703, 2316500, 3817976, -3677745, -3342478, 2244091
    .word -3041255, -2446433, -3562462, -1452451, 266997, 2434439, 3475950, -1235728
    .word 3513181, 2176455, -3520352, -3759364, -1585221, -1197226, -3193378, -1257611
    .word 900702, 1859098, 1939314, 909542, 819034, -4083598, 495491, -1613174
    .word -1000202, -43260, -522500, -3190144, -655327, -3122442, -3157330, 2031748
    .word 3207046, -3632928, -3556995, -525098, 126922, -768622, -3595838, 3412210
    .word 342297, 286988, -983419, -2437823, 4108315, 2147896, 3437287, -3342277
    .word 2715295, 1735879, 203044, -2967645, 2842341, 2691481, -3693493, -2590150
    .word 1265009, -411027, 4055324, 1247620, -2477047, 2486353, 1595974, -671102
    .word -3767016, 1250494, -1228525, 2635921, -3548272, -22981, -2994039, 1869119
    .word -1308169, 1903435, -1050970, -381987, -1333058, 1237275, 1349076, -3318210
    .word -1430225, 1852771, -451100, 1312455, -1430430, 3306115, -1962642, -3343383
    .word -1279661, 1917081, 264944, -2546312, -1374803, 508951, 1500165, 777191
    .word 3097992, 2235880, 3406031, 44288, -542412, -2831860, -1100098, -1671176
    .word -1846953, 904516, -2584293, -3724270, 3958618, 594136, -3776993, -3724342
    .word -2013608, 2432395, -8578, 2454455, -164721, 1653064, 1957272, 3369112
    .word -3249728, 185531, -1207385, 2389356, -3183426, 162844, -210977, 1616392
    .word 3014001, 759969, 810149, 1652634, -1316856, -3694233, -1799107, 189548
    .word -3038916, 3523897, -3553272, 3866901, 269760, 3159746, 2213111, -975884
    .word -1851402, 1717735, 472078, -2409325, -426683, 1723600, -177440, -1803090
    .word 1910376, 1315589, -1667432, -1104333, 1341330, -260646, -3833893, 1285669
    .word -2939036, -2235985, -1584928, -420899, -2286327, -812732, 183443, -976891
    .word -1439742, 1612842, -3545687, -3019102, -554416, 3919660, -3881060, -48306
    .word -1362209, -3628969, 3937738, 1400424, 3839961, -846154, 1976782
