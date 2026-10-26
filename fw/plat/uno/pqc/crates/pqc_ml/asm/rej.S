@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ Rejection sampling of uniform coefficients from squeezed SHAKE128 words,
@ for the Cortex-M7: the parsing half of ML-DSA's RejNTTPoly.
@
@ Each accepted candidate is stored through a post-incremented pointer
@ under an IT block, so acceptance costs no branch, and the space left is
@ checked once a group rather than once a candidate. A routine stops at
@ the first group that might not fit and returns
@
@     (groups consumed << 16) | coefficients now held,
@
@ leaving the caller to finish the last few slots one candidate at a time.

.syntax unified
.thumb
.text

.equ DQ, 8380417

@ uint32_t pqc_ml_dsa_rej(int32_t a[256], uint32_t ctr, const uint32_t *buf,
@                         uint32_t groups)
@
@ A group is three little-endian words: four 3-byte candidates, the low
@ 23 bits of each kept if below q.
.global pqc_ml_dsa_rej
.type pqc_ml_dsa_rej, %function
.align 2
pqc_ml_dsa_rej:
    push    {r4-r9, lr}
    mov     r5, r0
    add     r4, r0, r1, lsl #2      @ next free slot
    add     r6, r0, #(252 * 4)      @ past this, four might not fit
    movw    r7, #(DQ & 0xffff)
    movt    r7, #(DQ >> 16)
    mov     r1, r3                  @ groups offered, for the count
1:
    cbz     r3, 9f
    cmp     r4, r6
    bhi     9f
    ldm     r2!, {r8, r9, r12}
    subs    r3, r3, #1
    ubfx    lr, r8, #0, #23
    cmp     lr, r7
    it      lo
    strlo   lr, [r4], #4
    lsr     lr, r8, #24
    bfi     lr, r9, #8, #15
    cmp     lr, r7
    it      lo
    strlo   lr, [r4], #4
    lsr     lr, r9, #16
    bfi     lr, r12, #16, #7
    cmp     lr, r7
    it      lo
    strlo   lr, [r4], #4
    ubfx    lr, r12, #8, #23
    cmp     lr, r7
    it      lo
    strlo   lr, [r4], #4
    b       1b
9:
    sub     r0, r4, r5
    lsrs    r0, r0, #2
    subs    r1, r1, r3              @ groups consumed
    orr     r0, r0, r1, lsl #16
    pop     {r4-r9, pc}
.size pqc_ml_dsa_rej, .-pqc_ml_dsa_rej
