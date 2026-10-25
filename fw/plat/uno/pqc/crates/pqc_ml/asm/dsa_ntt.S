@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA forward NTT for the Cortex-M7.
@
@ void pqc_ml_dsa_ntt(int32_t p[256], const int32_t zetas[255])
@
@ The reference transform: layers len = 128 down to 1, twiddles taken in
@ order from zetas (ZETAS[1..]), y' = x - zeta*y and x' = x + zeta*y with
@ the Montgomery product (a - m*q) >> 32, m = a * q^-1 mod 2^32. The
@ output is bit for bit the reference's.
@
@ On this core a load or store does not issue alongside a multiply, so a
@ butterfly costs its three multiplies plus its share of the ldrd/strd
@ traffic however the rest is arranged, and what is left to win is stalls
@ and loop scaffolding. Measured on CP1 against the inline-assembly layers
@ this replaces (8166 cycles): 7634.
@
@ - Layers 128 to 4 load x with y at the top of the pass, so the adds wait
@   on nothing but the multiplies (14.5 -> 13.5 cycles a pair), and walk
@   their windows here rather than in Rust.
@ - Layers 2 and 1 run together over blocks of four, each loaded and
@   stored once, which is where a window of one butterfly pair spent more
@   on scaffolding than on arithmetic (2087 -> 1825 cycles). Its products
@   are formed from high halves -- with zq = zeta * q^-1 mod 2^32,
@   smmul(y, zeta) - smmul(y*zq, q) is exactly (y*zeta - m*q) >> 32 -- which
@   is no faster per multiply but holds two registers a product instead of
@   three, and the block needs the room.

.syntax unified
.thumb
.text

.equ DQ,    8380417         @ q
.equ DQINV, 58728449        @ q^-1 mod 2^32
.equ NQ,    0xff801fff      @ -q, for smlal

.global pqc_ml_dsa_ntt
.type pqc_ml_dsa_ntt, %function
.align 2
pqc_ml_dsa_ntt:
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
    @ pairs (a0, a2) and (a1, a3) under one twiddle, then len 1 pairs
    @ (a0, a1) and (a2, a3) under the next two of the last layer's.
    movw    r3, #(DQ & 0xffff)
    movt    r3, #(DQ >> 16)
    ldr     r1, [sp, #4]            @ len 2 twiddles: ZETAS[64..128]
    add     lr, r1, #256            @ len 1 twiddles: ZETAS[128..256]
    movw    r12, #(DQINV & 0xffff)
    movt    r12, #(DQINV >> 16)
    movs    r2, #64
3:
    ldr     r8, [r1], #4            @ zeta_A
    ldrd    r6, r7, [r0, #8]        @ a2, a3
    ldrd    r4, r5, [r0]            @ a0, a1
    mul     r9, r8, r12             @ zq_A
    subs    r2, r2, #1
    smmul   r10, r6, r8             @ hi(a2 * zeta_A)
    smmul   r11, r7, r8
    mul     r6, r6, r9              @ m: a2 * zq_A
    mul     r7, r7, r9
    ldrd    r8, r9, [lr], #8        @ zeta_B, zeta_C
    smmul   r6, r6, r3
    smmul   r7, r7, r3
    sub     r10, r10, r6            @ t0
    sub     r11, r11, r7            @ t1
    mul     r6, r8, r12             @ zq_B
    mul     r7, r9, r12             @ zq_C
    sub     r5, r5, r11             @ a3' = a1 - t1, kept in r5 for now
    add     r11, r5, r11, lsl #1    @ a1' = a1 + t1
    sub     r10, r4, r10            @ a2' = a0 - t0
    rsb     r4, r10, r4, lsl #1     @ a0' = a0 + t0
    mul     r6, r11, r6             @ m_B: a1' * zq_B
    mul     r7, r5, r7              @ m_C: a3' * zq_C
    smmul   r11, r11, r8            @ hi(a1' * zeta_B)
    smmul   r5, r5, r9              @ hi(a3' * zeta_C)
    smmul   r6, r6, r3
    smmul   r7, r7, r3
    sub     r11, r11, r6            @ u_B
    sub     r5, r5, r7              @ u_C
    sub     r6, r4, r11             @ a1'' = a0' - u_B
    add     r4, r4, r11             @ a0''
    sub     r7, r10, r5             @ a3'' = a2' - u_C
    add     r10, r10, r5            @ a2''
    strd    r4, r6, [r0], #8
    strd    r10, r7, [r0], #8
    bne     3b
    pop     {r0, r1, r4-r11, pc}
.size pqc_ml_dsa_ntt, .-pqc_ml_dsa_ntt
