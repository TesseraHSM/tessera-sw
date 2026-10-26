@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ void pqc_ml_dsa_unpack_eta(int32_t r[256], const uint8_t *s, int32_t eta,
@                            uint32_t d)
@
@ ML-DSA's s1 and s2 polynomials, packed eta - f in d = 3 or 4 bits (eta
@ = 2 or 4), for the Cortex-M7: r[i] = eta - field i. Every d bytes hold
@ eight fields, so each group is one word load, shifts and masks -- no
@ per-coefficient test for a word running out, as a bit-at-a-time reader
@ has.
@
@ The word is loaded so that it ends at the group's last byte: from 4 - d
@ bytes before the group, its first 8 * (4 - d) bits skipped. It thus
@ never reads past the stream, which `unpack_centered` stages at the very
@ end of r; and no group's eight coefficients overtake a stream byte yet to
@ be read.

.syntax unified
.thumb
.text

.global pqc_ml_dsa_unpack_eta
.type pqc_ml_dsa_unpack_eta, %function
.align 2
pqc_ml_dsa_unpack_eta:
    push    {r4-r7, lr}
    rsb     r12, r3, #4
    sub     r1, r1, r12
    lsl     r12, r12, #3            @ bits before the group
    movs    r7, #1
    lsls    r7, r3
    subs    r7, #1                  @ field mask
    mov     lr, #32
1:
    ldr     r4, [r1]
    add     r1, r3
    lsr     r4, r4, r12
    .rept 4
    and     r5, r4, r7
    lsrs    r4, r3
    and     r6, r4, r7
    lsrs    r4, r3
    subs    r5, r2, r5
    subs    r6, r2, r6
    strd    r5, r6, [r0], #8
    .endr
    subs    lr, lr, #1
    bne     1b
    pop     {r4-r7, pc}
.size pqc_ml_dsa_unpack_eta, .-pqc_ml_dsa_unpack_eta
