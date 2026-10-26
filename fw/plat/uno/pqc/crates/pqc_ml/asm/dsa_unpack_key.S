@ Copyright (c) Microsoft Corporation.
@ Licensed under the MIT License.
@
@ Unpacking ML-DSA's secret key for signing, for the Cortex-M7.
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

@ void pqc_ml_dsa_unpack_t0(int32_t r[256], const uint8_t *s)
@
@ t0, packed 2^12 - f in 13 bits: r[i] = 4096 - field i. Every 13 bytes
@ hold eight fields, each inside some word that starts in the group and
@ ends in it -- a load (unaligned, as LDR may be) at a fixed offset and a
@ ubfx at a fixed shift, the last two fields from one word. Staged as
@ s1 and s2 are, at the end of r, and as safe in place.
.global pqc_ml_dsa_unpack_t0
.type pqc_ml_dsa_unpack_t0, %function
.align 2
pqc_ml_dsa_unpack_t0:
    push    {r4, lr}
    mov     r12, #4096
    mov     lr, #32
1:
    ldr     r2, [r1]
    ldr     r3, [r1, #1]
    ubfx    r2, r2, #0, #13
    ubfx    r3, r3, #5, #13
    sub     r2, r12, r2
    sub     r3, r12, r3
    strd    r2, r3, [r0], #8
    ldr     r2, [r1, #3]
    ldr     r3, [r1, #4]
    ubfx    r2, r2, #2, #13
    ubfx    r3, r3, #7, #13
    sub     r2, r12, r2
    sub     r3, r12, r3
    strd    r2, r3, [r0], #8
    ldr     r2, [r1, #6]
    ldr     r3, [r1, #8]
    ubfx    r2, r2, #4, #13
    ubfx    r3, r3, #1, #13
    sub     r2, r12, r2
    sub     r3, r12, r3
    strd    r2, r3, [r0], #8
    ldr     r4, [r1, #9]
    add     r1, r1, #13
    ubfx    r2, r4, #6, #13
    ubfx    r3, r4, #19, #13
    sub     r2, r12, r2
    sub     r3, r12, r3
    strd    r2, r3, [r0], #8
    subs    lr, lr, #1
    bne     1b
    pop     {r4, pc}
.size pqc_ml_dsa_unpack_t0, .-pqc_ml_dsa_unpack_t0
