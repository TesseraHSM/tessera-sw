@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA pointwise Montgomery multiply-accumulate, the left operand packed
@ three bytes to a coefficient as the matrix spill packs it (see spill.rs):
@
@ void pqc_ml_dsa_pointwise_acc_packed(int32_t c[256], const int32_t a[192],
@                                      const int32_t b[256])
@     c[n] += a[n] * b[n] * 2^-32 mod q, for a[n] in [0, 2^24)
@
@ Each coefficient is the reference's montgomery_reduce -- smull, mul by
@ q^-1, smlal by -q -- and an add, so the result is exactly what it gives.
@ Scheduled for the Cortex-M7 by SLOTHY (https://github.com/slothy-optimizer
@ /slothy), software-pipelined across groups of four coefficients: 21
@ cycles a group by its model of the core. All pointers word aligned.

.syntax unified
.thumb
.text

.global pqc_ml_dsa_pointwise_acc_packed
.type pqc_ml_dsa_pointwise_acc_packed, %function
.align 2
pqc_ml_dsa_pointwise_acc_packed:
    push.w {r4-r11, r14}
    movw r3, #:lower16:0x03802001
    movt r3, #:upper16:0x03802001
    movw r4, #:lower16:0xff801fff
    movt r4, #:upper16:0xff801fff
    movw r12, #64
    @ Each pass reads ahead the third packed word of the next group of
    @ four, so the first group's is read here, and the loop stops one
    @ group short: the last is finished below without reading past a.
    ldr r8, [r1, #8]
    sub r12, r12, #1
1:
    ubfx r11, r8, #0, #8
    ldr r10, [r2, #12]
    ubfx r9, r8, #8, #24
    ldr r8, [r1, #4]
    ldr r7, [r1], #12
    smull r10, r9, r9, r10
    ubfx r6, r8, #16, #16
    ldr r14, [r2, #8]
    orr r11, r6, r11, lsl #16
    mul r6, r10, r3
    ubfx r5, r7, #24, #8
    smull r11, r14, r11, r14
    ubfx r8, r8, #0, #16
    smlal r10, r9, r6, r4
    ubfx r7, r7, #0, #24
    mul r6, r11, r3
    ldr r10, [r2, #4]
    orr r5, r5, r8, lsl #8
    ldr r8, [r2], #16
    smlal r11, r14, r6, r4
    ldr r11, [r0, #12]
    smull r10, r6, r5, r10
    add r9, r9, r11
    smull r11, r5, r7, r8
    ldr r7, [r0, #8]
    mul r8, r10, r3
    add r14, r14, r7
    mul r7, r11, r3
    subs r12, #1
    smlal r10, r6, r8, r4
    ldr r8, [r1, #8]
    smlal r11, r5, r7, r4
    ldr r10, [r0, #4]
    str r14, [r0, #8]
    str r9, [r0, #12]
    ldr r9, [r0]
    add r10, r6, r10
    str r10, [r0, #4]
    add r11, r5, r9
    str r11, [r0], #16
    bne.w 1b
    @ The last group.
    ubfx r6, r8, #0, #8
    ldr r7, [r2, #12]
    ubfx r5, r8, #8, #24
    ldr r11, [r1, #4]
    ldr r14, [r1], #12
    smull r5, r9, r5, r7
    ubfx r7, r11, #16, #16
    ldr r10, [r2, #8]
    orr r8, r7, r6, lsl #16
    mul r7, r5, r3
    ubfx r6, r14, #24, #8
    smull r8, r10, r8, r10
    ubfx r11, r11, #0, #16
    smlal r5, r9, r7, r4
    ubfx r5, r14, #0, #24
    mul r7, r8, r3
    ldr r14, [r2, #4]
    orr r6, r6, r11, lsl #8
    ldr r11, [r2], #16
    smlal r8, r10, r7, r4
    ldr r7, [r0, #12]
    smull r6, r8, r6, r14
    add r14, r9, r7
    smull r11, r5, r5, r11
    ldr r9, [r0, #8]
    mul r7, r6, r3
    add r10, r10, r9
    mul r9, r11, r3
    subs r12, #1
    smlal r6, r8, r7, r4
    ldr r7, [r0, #4]
    smlal r11, r5, r9, r4
    str r10, [r0, #8]
    ldr r9, [r0]
    str r14, [r0, #12]
    add r14, r8, r7
    str r14, [r0, #4]
    add r7, r5, r9
    str r7, [r0], #16
    pop.w {r4-r11, pc}
.size pqc_ml_dsa_pointwise_acc_packed, .-pqc_ml_dsa_pointwise_acc_packed
