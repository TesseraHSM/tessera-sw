@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ ML-DSA signing's norm checks.
@
@ uint32_t pqc_ml_dsa_r0_check(int32_t w[256], const int32_t cs2[256],
@                              int32_t bound)
@
@ w[n] holds (w0 << 6) | w1, w0 the centred low part and w1 the high part
@ (below 64). For every n, r0 = reduce32(w0 - cs2[n]) replaces w0 in place
@ -- w[n] = (r0 << 6) | w1 -- and the return is nonzero exactly when some
@ |r0| >= bound. cs2 must be below q in magnitude, as an inverse NTT
@ leaves it, so w0 - cs2 is inside reduce32's range.

.syntax unified
.thumb
.text

.equ DQ, 8380417

.global pqc_ml_dsa_r0_check
.type pqc_ml_dsa_r0_check, %function
.align 2
pqc_ml_dsa_r0_check:
    push    {r4-r11, lr}
    sub     r10, r2, #1             @ bound - 1
    lsl     r11, r2, #1
    sub     r11, r11, #2            @ 2*bound - 2
    movw    r12, #(DQ & 0xffff)
    movt    r12, #(DQ >> 16)
    mov     r2, #0                  @ bad
    mov     lr, #128
1:
    ldrd    r3, r4, [r0]            @ v0, v1
    ldrd    r5, r6, [r1], #8        @ cs2
    rsb     r5, r5, r3, asr #6      @ w0 - cs2
    rsb     r6, r6, r4, asr #6
    add     r7, r5, #0x400000
    add     r8, r6, #0x400000
    asr     r7, r7, #23
    asr     r8, r8, #23
    mls     r5, r7, r12, r5         @ r0 = reduce32(w0 - cs2)
    mls     r6, r8, r12, r6
    add     r7, r5, r10
    add     r8, r6, r10
    bfi     r3, r5, #6, #26
    bfi     r4, r6, #6, #26
    cmp     r7, r11                 @ |r0| < bound iff r0 + bound - 1,
    it      hi                      @ unsigned, is at most 2*bound - 2
    movhi   r2, #1
    cmp     r8, r11
    it      hi
    movhi   r2, #1
    strd    r3, r4, [r0], #8
    subs    lr, lr, #1
    bne     1b
    mov     r0, r2
    pop     {r4-r11, pc}
.size pqc_ml_dsa_r0_check, .-pqc_ml_dsa_r0_check

@ uint32_t pqc_ml_dsa_find_close(const int32_t a[256], uint32_t n,
@                                int32_t k, uint32_t m)
@
@ The first index i >= n with (uint32_t)(a[i] + k) >= m, or 256 if none:
@ with k and m chosen by the caller, the first coefficient within some
@ distance of a bound. Signing calls it for the few coefficients a norm
@ check has to look at exactly, which are rare enough that the scan is
@ the cost: two coefficients a pass.

.global pqc_ml_dsa_find_close
.type pqc_ml_dsa_find_close, %function
.align 2
pqc_ml_dsa_find_close:
    push    {r4, r5, lr}
    add     r12, r0, #1024          @ end
    add     r0, r0, r1, lsl #2      @ p = &a[n]
    tst     r1, #1
    beq     2f
    ldr     r4, [r0], #4            @ odd start: that one alone
    add     r4, r4, r2
    cmp     r4, r3
    bhs     3f
2:
    cmp     r0, r12
    beq     4f
    ldrd    r4, r5, [r0], #8
    add     r4, r4, r2
    add     r5, r5, r2
    cmp     r4, r3
    bhs     5f
    cmp     r5, r3
    blo     2b
3:
    sub     r0, r0, #4              @ found: the word before p
    b       6f
5:
    sub     r0, r0, #8              @ found: the first of the pair
6:
    sub     r0, r0, r12             @ (p - end) / 4 + 256
    asr     r0, r0, #2
    add     r0, r0, #256
    pop     {r4, r5, pc}
4:
    mov     r0, #256
    pop     {r4, r5, pc}
.size pqc_ml_dsa_find_close, .-pqc_ml_dsa_find_close
