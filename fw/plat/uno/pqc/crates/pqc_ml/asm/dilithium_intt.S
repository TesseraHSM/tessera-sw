@ ML-DSA inverse NTT for the Cortex-M7: void pqc_ml_dsa_invntt(int32_t p[256]).
@
@ Reference semantics (invntt_tomont: inverse NTT and multiplication by the
@ Montgomery factor 2^32), outputs below q in magnitude. pqm4's Dilithium
@ inverse NTT -- three, three and two merged layers with "light" first
@ butterflies, the final scaling folded into the last pass (based on code
@ by Markus Krausz; CC0 with permission of the authors) -- as scheduled for
@ the M7 by the SLOTHY superoptimizer (https://github.com/slothy-optimizer/
@ slothy, MIT License): examples/opt/armv7m/dilithium/
@ intt_dilithium_123_456_78_opt_m7.s.
@
@ SLOTHY's code keeps its loop bounds and each block's twiddles in FPU
@ registers s0-s10, but FP0 has no FPU, so every such access here goes to
@ an eleven-word stack frame instead (the sN_ofs offsets below; a vldm
@ became an ldm/stm through registers that are dead at that point). Its
@ CT-style layers grow the coefficients at most eightfold before reducing,
@ so the unreduced sums the callers pass in stay far inside 32 bits.
@ r12 is clobbered.

.syntax unified
.thumb
.equ s0_ofs, 0
.equ s1_ofs, 4
.equ s2_ofs, 8
.equ s3_ofs, 12
.equ s4_ofs, 16
.equ s5_ofs, 20
.equ s6_ofs, 24
.equ s7_ofs, 28
.equ s8_ofs, 32
.equ s9_ofs, 36
.equ s10_ofs, 40

.thumb

.macro montgomery_mul_32 a, b, Qprime, Q, tmp, tmp2
    smull \tmp, \a, \a, \b
    mul \tmp2, \tmp, \Qprime
    smlal \tmp, \a, \tmp2, \Q
.endm

.macro addSub1 c0, c1
    add.w \c0, \c0, \c1
    sub.w \c1, \c0, \c1, lsl #1
.endm

.macro addSub2 c0, c1, c2, c3
    add \c0, \c1
    add \c2, \c3
    sub.w \c1, \c0, \c1, lsl #1
    sub.w \c3, \c2, \c3, lsl #1
.endm

.macro addSub4 c0, c1, c2, c3, c4, c5, c6, c7
    add \c0, \c1
    add \c2, \c3
    add \c4, \c5
    add \c6, \c7
    sub.w \c1, \c0, \c1, lsl #1
    sub.w \c3, \c2, \c3, lsl #1
    sub.w \c5, \c4, \c5, lsl #1
    sub.w \c7, \c6, \c7, lsl #1
.endm

.macro _2_layer_inv_CT_32 c0, c1, c2, c3, zeta0, zeta1, zeta2, Qprime, Q, tmp, tmp2
    montgomery_mul_32 \c1, \zeta0, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta0, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c1, \c2, \c3

    montgomery_mul_32 \c2, \zeta1, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta2, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c2, \c1, \c3
.endm

.macro _3_layer_inv_CT_32 c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    ldr \twiddle, [sp, #\xi0\()_ofs]
    montgomery_mul_32 \c1, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c1, \c2, \c3, \c4, \c5, \c6, \c7

    ldr \twiddle, [sp, #\xi1\()_ofs]
    montgomery_mul_32 \c2, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    ldr \twiddle, [sp, #\xi2\()_ofs]
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c2, \c1, \c3, \c4, \c6, \c5, \c7

    ldr \twiddle, [sp, #\xi3\()_ofs]
    montgomery_mul_32 \c4, \twiddle, \Qprime, \Q, \tmp, \tmp2
    ldr \twiddle, [sp, #\xi4\()_ofs]
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    ldr \twiddle, [sp, #\xi5\()_ofs]
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    ldr \twiddle, [sp, #\xi6\()_ofs]
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c4, \c1, \c5, \c2, \c6, \c3, \c7
.endm

/************************************************************
* Name:         _3_layer_inv_butterfly_light_fast_first
*
* Description:  upper half of 3-layer inverse butterfly
*               defined over X^8 - 1
*
* Input:        (c4, c1, c6, c3) = coefficients on the upper half;
*               (xi0, xi1, xi2, xi3, xi4, xi5, xi6) =
*               (  1,  1,  w_4,   1, w_8, w_4, w_8^3) in
*               Montgomery domain
*
* Symbols:      R = 2^32
*
* Constants:    Qprime = -MOD^{-1} mod^{+-} R, Q = MOD
*
* Output:
*               c4 =  c4 + c1        + (c6 + c3)
*               c5 = (c4 - c1) w_4   + (c6 + c3) w_8^3
*               c6 =  c4 + c1        - (c6 + c3)
*               c7 = (c4 - c1) w_8^3 + (c6 + c3) w_4
************************************************************/

.macro _3_layer_inv_butterfly_light_fast_first c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    addSub2 \c4, \c1, \c6, \c3
    addSub1 \c4, \c6

    ldr \tmp, [sp, #\xi4\()_ofs]
    ldr \tmp2, [sp, #\xi6\()_ofs]

    smull \c0, \c5, \c1, \tmp
    smlal \c0, \c5, \c3, \tmp2
    mul \twiddle, \c0, \Qprime
    smlal \c0, \c5, \twiddle, \Q

    smull \c2, \c7, \c1, \tmp2
    smlal \c2, \c7, \c3, \tmp
    mul \twiddle, \c2, \Qprime
    smlal \c2, \c7, \twiddle, \Q
.endm

/************************************************************
* Name:         _3_layer_inv_butterfly_light_fast_second
*
* Description:  lower half of 3-layer inverse butterfly
*               defined over X^8 - 1, and the 2nd
*               layer of butterflies
*
* Input:
*               (c4, c5, c6, c7) = results of the upper half;
*               (c0, c1, c2, c3) = coefficients on the lower half;
*               (xi0, xi1, xi2, xi3, xi4, xi5, xi6) =
*               (  1,  1,  w_4,   1, w_8, w_4, w_8^3) in
*               Montgomery domain
*
* Symbols:      R = 2^32
*
* Constants:    Qprime = -MOD^{-1} mod^{+-} R, Q = MOD
*
* Output:       (normal order)
*               c0 =   c0 + c1     + (c2 + c3)         + (  c4 + c5     + (c6 + c7)       )
*               c1 =  (c0 - c1) w3 + (c2 - c3)  w4     + ( (c4 - c5) w5 + (c6 - c7) w6    )
*               c2 = ( c0 + c1     - (c2 + c3)) w1     + (( c4 + c5     - (c6 + c7)   ) w2)
*               c3 = ((c0 - c1) w3 - (c2 - c3)  w4) w1 + (((c4 - c5) w5 - (c6 - c7) w6) w2)
*               c4 =   c0 + c1     - (c2 + c3)         - (  c4 + c5     + (c6 + c7)       ) w0
*               c5 =  (c0 - c1) w3 + (c2 - c3)  w4     - ( (c4 - c5) w5 + (c6 - c7) w6    ) w0
*               c6 = ( c0 + c1     - (c2 + c3)) w1     - (( c4 + c5     - (c6 + c7)   ) w2) w0
*               c7 = ((c0 - c1) w3 - (c2 - c3)  w4) w1 - (((c4 - c5) w5 - (c6 - c7) w6) w2) w0
************************************************************/

.macro _3_layer_inv_butterfly_light_fast_second c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    addSub2 \c0, \c1, \c2, \c3

    ldr \twiddle, [sp, #\xi2\()_ofs]
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c2, \c1, \c3

    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2

    addSub4 \c0, \c4, \c1, \c5, \c2, \c6, \c3, \c7
.endm

.global pqc_ml_dsa_invntt
.type pqc_ml_dsa_invntt,%function
.align 2
pqc_ml_dsa_invntt:

  ptr_p     .req R0
  ptr_zeta  .req R1
  zeta      .req R1
  qinv      .req R2
  q         .req R3
  cntr      .req R4
  pol4      .req R4
  pol0      .req R5
  pol1      .req R6
  pol2      .req R7
  pol3      .req R8
  temp_h    .req R9
  temp_l    .req R10
  zeta0     .req R11
  zeta1     .req R12
  zeta2     .req R14
  pol5     .req R11
  pol6     .req R12
  pol7     .req R14

  push {R4-R11, R14}
  sub sp, #44

  ldr.w qinv, inv_ntt_asm_smull_qinv
  ldr.w q, inv_ntt_asm_smull_q

  .equ distance, 16
  .equ strincr, 32

  ldr ptr_zeta, =#zetas_new332inv
    ldm ptr_zeta!, {r4-r10}
    add.w r11, sp, #8
    stm r11, {r4-r10}
        str ptr_zeta, [sp, #0]

  add.w temp_l, ptr_p, #32*strincr
        str temp_l, [sp, #36]

        ldr.w r5, [r0, #24]
        ldr.w r4, [r0, #28]

        push {r14}
        ldr r14, [sp, #40]
        sub r14, r14, #32
        str r14, [sp, #40]
        pop {r14}
layer123_loop:

        ldr r6, [sp, #16]
        ldr.w r10, [r0, #16]
        add r5, r4
        ldr.w r14, [r0, #20]
        add r10, r14
        ldr.w r11, [r0, #12]
        sub.w r1, r5, r4, lsl #1
        add.w r9, r10, r5
        sub.w r12, r9, r5, lsl #1
        ldr.w r7, [r0, #8]
        sub.w r10, r10, r14, lsl #1
        ldr.w r14, [r0]
        ldr.w r4, [r0, #4]
        smull r8, r12, r12, r6
        add r14, r4
        add r7, r11
        sub.w r5, r7, r11, lsl #1
        mul r11, r8, r2
        sub.w r4, r14, r4, lsl #1
        smull r5, r6, r5, r6
        add r14, r7
        smlal r8, r12, r11, r3
        sub.w r7, r14, r7, lsl #1
        mul r11, r5, r2
        add r14, r9
        str.w r14, [r0], #32
        sub.w r14, r14, r9, lsl #1
        str r14, [r0, #-16]
        ldr r8, [sp, #24]
        smlal r5, r6, r11, r3
        ldr r5, [sp, #32]
        smull r9, r11, r10, r8
        ldr r14, [sp, #36]
        smlal r9, r11, r1, r5
        cmp.w r0, r14
        smull r14, r10, r10, r5
        add r7, r12
        mul r5, r9, r2
        add r4, r6
        smlal r14, r10, r1, r8
        sub.w r1, r4, r6, lsl #1
        smlal r9, r11, r5, r3
        ldr.w r5, [r0, #24]
        mul r6, r14, r2
        add r4, r11
        str r4, [r0, #-28]
        sub.w r9, r4, r11, lsl #1
        smlal r14, r10, r6, r3
        sub.w r12, r7, r12, lsl #1
        str r9, [r0, #-12]
        add r1, r10
        str r1, [r0, #-20]
        ldr.w r4, [r0, #28]
        str r12, [r0, #-8]
        str r7, [r0, #-24]
        sub.w r7, r1, r10, lsl #1
        str r7, [r0, #-4]
        bne.w layer123_loop

        ldr.w r11, [r0, #20]
        ldr.w r14, [r0, #16]
        ldr r9, [sp, #24]
        ldr.w r1, [r0, #12]
        ldr r6, [sp, #32]
        add r14, r11
        sub.w r12, r14, r11, lsl #1
        add r5, r4
        sub.w r4, r5, r4, lsl #1
        smull r10, r7, r12, r6
        ldr.w r11, [r0, #8]
        smlal r10, r7, r4, r9
        add.w r8, r14, r5
        smull r9, r14, r12, r9
        add r11, r1
        mul r12, r10, r2
        sub.w r1, r11, r1, lsl #1
        smlal r9, r14, r4, r6
        ldr.w r4, [r0]
        smlal r10, r7, r12, r3
        ldr.w r12, [r0, #4]
        mul r10, r9, r2
        add r4, r12
        ldr r6, [sp, #16]
        sub.w r5, r8, r5, lsl #1
        smlal r9, r14, r10, r3
        sub.w r9, r4, r12, lsl #1
        smull r5, r10, r5, r6
        add r4, r11
        smull r1, r12, r1, r6
        sub.w r6, r4, r11, lsl #1
        mul r11, r5, r2
        add r4, r8
        str.w r4, [r0], #32
        sub.w r8, r4, r8, lsl #1
        smlal r5, r10, r11, r3
        ldr r4, [sp, #36]
        mul r11, r1, r2
        add r6, r10
        str r6, [r0, #-24]
        sub.w r6, r6, r10, lsl #1
        smlal r1, r12, r11, r3
        str r8, [r0, #-16]
        cmp.w r0, r4
        add r9, r12
        str r6, [r0, #-8]
        sub.w r6, r9, r12, lsl #1
        add r9, r14
        str r9, [r0, #-28]
        add r6, r7
        str r6, [r0, #-20]
        sub.w r12, r9, r14, lsl #1
        str r12, [r0, #-12]
        sub.w r8, r6, r7, lsl #1
        str r8, [r0, #-4]

  sub ptr_p, #32*strincr

  .equ distance2, 128
  .equ strincr2, 256

  movw temp_l, #4
  add.w temp_l, ptr_p, #4*256
        str temp_l, [sp, #40]

        ldr ptr_zeta, [sp, #0]
    ldm ptr_zeta!, {r4-r10}
    add.w r11, sp, #8
    stm r11, {r4-r10}
        str ptr_zeta, [sp, #0]

layer456_first_loop:

        ldr.w r7, [r0, #128]
        ldr r5, [sp, #32]
        ldr.w r9, [r0, #160]
        ldr r1, [sp, #16]
        add r7, r9
        ldr.w r6, [r0, #192]
        ldr.w r11, [r0, #224]
        ldr r12, [sp, #24]
        add r6, r11
        sub.w r8, r7, r9, lsl #1
        add.w r7, r7, r6
        smull r14, r4, r8, r5
        sub.w r10, r6, r11, lsl #1
        smull r9, r11, r8, r12
        ldr r8, [r0, #96]
        smlal r14, r4, r10, r12
        ldr r12, [r0, #64]
        smlal r9, r11, r10, r5
        sub.w r5, r7, r6, lsl #1
        mul r10, r14, r2
        add r12, r8
        mul r6, r9, r2
        sub.w r8, r12, r8, lsl #1
        smlal r14, r4, r10, r3
        ldr.w r14, [r0]
        smlal r9, r11, r6, r3
        ldr r9, [r0, #32]
        smull r6, r5, r5, r1
        smull r8, r10, r8, r1
        add r14, r9
        mul r1, r6, r2
        sub.w r9, r14, r9, lsl #1
        add r14, r12
        smlal r6, r5, r1, r3
        sub.w r12, r14, r12, lsl #1
        mul r6, r8, r2
        add r12, r5
        str r12, [r0, #64]
        sub.w r5, r12, r5, lsl #1
        str.w r5, [r0, #192]
        add r14, r7
        smlal r8, r10, r6, r3
        str r14, [r0]
        sub.w r8, r14, r7, lsl #1
        add r9, r10
        str.w r8, [r0, #128]
        sub.w r10, r9, r10, lsl #1
        add r9, r11
        sub.w r6, r9, r11, lsl #1
        str.w r6, [r0, #160]
        str r9, [r0, #32]
        add r10, r4
        str r10, [r0, #96]
        sub.w r6, r10, r4, lsl #1
        str.w r6, [r0, #224]
        add.w r0, r0, #256

        ldr temp_l, [sp, #40]
        cmp ptr_p, temp_l
        bne layer456_first_loop

  sub.w ptr_p, #4*256-4

  add.w temp_l, ptr_p, #7*4
        str temp_l, [sp, #36]
  1:
    add.w temp_l, ptr_p, #4*strincr2
        str temp_l, [sp, #40]

        ldr ptr_zeta, [sp, #0]
    ldm ptr_zeta!, {r4-r10}
    add.w r11, sp, #8
    stm r11, {r4-r10}
        str ptr_zeta, [sp, #0]

layer456_loop:

        ldr r12, [sp, #8]
        ldr r11, [r0, #96]
        ldr r10, [r0, #32]
        smull r5, r7, r11, r12
        smull r9, r11, r10, r12
        ldr.w r4, [r0, #224]
        mul r6, r5, r2
        ldr.w r10, [r0, #192]
        mul r14, r9, r2
        smull r4, r1, r4, r12
        smlal r9, r11, r14, r3
        ldr.w r14, [r0, #160]
        mul r8, r4, r2
        ldr r9, [r0, #64]
        smlal r5, r7, r6, r3
        ldr r5, [sp, #12]
        smull r12, r6, r14, r12
        add r9, r7
        smlal r4, r1, r8, r3
        sub.w r14, r9, r7, lsl #1
        mul r8, r12, r2
        add r10, r1
        smull r7, r4, r9, r5
        sub.w r1, r10, r1, lsl #1
        smlal r12, r6, r8, r3
        ldr r8, [sp, #16]
        mul r9, r7, r2
        smull r12, r1, r1, r8
        smlal r7, r4, r9, r3
        ldr.w r9, [r0, #128]
        mul r7, r12, r2
        smull r5, r10, r10, r5
        add r9, r6
        smlal r12, r1, r7, r3
        sub.w r12, r9, r6, lsl #1
        mul r7, r5, r2
        add r12, r1
        smull r6, r8, r14, r8
        ldr r14, [sp, #32]
        smlal r5, r10, r7, r3
        sub.w r1, r12, r1, lsl #1
        mul r5, r6, r2
        add r9, r10
        smull r7, r1, r1, r14
        ldr.w r14, [r0]
        smlal r6, r8, r5, r3
        ldr r5, [sp, #24]
        mul r6, r7, r2
        add r14, r11
        smull r12, r5, r12, r5
        sub.w r10, r9, r10, lsl #1
        smlal r7, r1, r6, r3
        ldr r6, [sp, #28]
        mul r7, r12, r2
        sub.w r11, r14, r11, lsl #1
        smull r6, r10, r10, r6
        add r11, r8
        smlal r12, r5, r7, r3
        sub.w r8, r11, r8, lsl #1
        mul r7, r6, r2
        add r8, r1
        str r8, [r0, #96]
        sub.w r12, r8, r1, lsl #1
        str.w r12, [r0, #224]
        ldr r12, [sp, #20]
        smlal r6, r10, r7, r3
        add r11, r5
        smull r9, r8, r9, r12
        add r14, r4
        str r11, [r0, #32]
        sub.w r11, r11, r5, lsl #1
        mul r5, r9, r2
        sub.w r1, r14, r4, lsl #1
        str.w r11, [r0, #160]
        add r1, r10
        smlal r9, r8, r5, r3
        str r1, [r0, #64]
        sub.w r9, r1, r10, lsl #1
        add r14, r8
        str.w r9, [r0, #192]
        sub.w r1, r14, r8, lsl #1
        str.w r1, [r0, #128]
        str r14, [r0]
        add.w r0, r0, #256

        ldr temp_l, [sp, #40]
        cmp ptr_p, temp_l
        bne layer456_loop

    sub.w ptr_p, #4*strincr2-4

        ldr temp_l, [sp, #36]
    cmp.w ptr_p, temp_l
  bne 1b

  sub ptr_p, #8*4
        ldr ptr_zeta, [sp, #0]

  .equ strincr3, 4

  add.w cntr, ptr_p, #64*strincr3
        str cntr, [sp, #36]

        ldr.w r9, [r0, #768]
        ldr r11, [r1], #12
        ldr.w r14, [r0, #512]
        ldr.w r10, [r0, #256]
        smull r9, r6, r9, r11
        ldr r4, [r1, #-8]
        ldr.w r12, [r1], #16
        mul r7, r9, r2
        smlal r9, r6, r7, r3

        push {r8}
        ldr r8, [sp, #40]
        sub r8, r8, #4
        str r8, [sp, #40]
        pop {r8}
layer78_loop:

        add r14, r6
        smull r11, r9, r10, r11
        smull r4, r5, r14, r4
        sub.w r7, r14, r6, lsl #1
        mul r10, r11, r2
        ldr r6, [r1, #-20]
        mul r8, r4, r2
        ldr.w r14, [r0]
        smlal r11, r9, r10, r3
        ldr r11, [r1], #12
        smull r7, r10, r7, r6
        ldr.w r6, [r0, #772]
        smlal r4, r5, r8, r3
        add r14, r9
        mul r8, r7, r2
        sub.w r4, r14, r9, lsl #1
        smull r9, r6, r6, r11
        smlal r7, r10, r8, r3
        add r14, r5
        mul r7, r9, r2
        sub.w r5, r14, r5, lsl #1
        smull r14, r12, r14, r12
        ldr r8, [r1, #-24]
        smlal r9, r6, r7, r3
        add r4, r10
        mul r9, r14, r2
        sub.w r10, r4, r10, lsl #1
        smull r8, r7, r4, r8
        smlal r14, r12, r9, r3
        mul r14, r8, r2
        str r12, [r0], #4
        ldr r4, [r1, #-20]
        smlal r8, r7, r14, r3
        str.w r7, [r0, #252]
        ldr r14, [r1, #-16]
        ldr r8, [sp, #36]
        smull r12, r7, r5, r4
        cmp.w r0, r8
        smull r5, r9, r10, r14
        ldr.w r14, [r0, #512]
        mul r4, r12, r2
        mul r8, r5, r2
        ldr.w r10, [r0, #256]
        smlal r12, r7, r4, r3
        ldr r4, [r1, #-8]
        smlal r5, r9, r8, r3
        ldr.w r12, [r1], #16
        str.w r9, [r0, #764]
        str.w r7, [r0, #508]
        bne.w layer78_loop

        add r14, r6
        smull r8, r9, r10, r11
        sub.w r7, r14, r6, lsl #1
        smull r4, r14, r14, r4
        ldr.w r11, [r0]
        mul r5, r8, r2
        ldr r10, [r1, #-20]
        mul r6, r4, r2
        smlal r8, r9, r5, r3
        smlal r4, r14, r6, r3
        add r11, r9
        smull r8, r5, r7, r10
        sub.w r10, r11, r9, lsl #1
        add r11, r14
        sub.w r6, r11, r14, lsl #1
        smull r11, r12, r11, r12
        ldr r7, [r1, #-12]
        mul r9, r8, r2
        ldr r14, [r1, #-4]
        mul r4, r11, r2
        smlal r8, r5, r9, r3
        ldr r8, [r1, #-8]
        smlal r11, r12, r4, r3
        add r10, r5
        str r12, [r0], #4
        sub.w r12, r10, r5, lsl #1
        smull r5, r4, r6, r8
        smull r6, r8, r12, r14
        ldr r14, [sp, #36]
        smull r12, r11, r10, r7
        mul r10, r6, r2
        mul r9, r5, r2
        smlal r6, r8, r10, r3
        smlal r5, r4, r9, r3
        str.w r4, [r0, #508]
        mul r5, r12, r2
        str.w r8, [r0, #764]
        cmp.w r0, r14
        smlal r12, r11, r5, r3
        str.w r11, [r0, #252]

  add sp, #44
    pop {R4-R11, PC}

    .unreq ptr_p
    .unreq ptr_zeta
    .unreq qinv
    .unreq q
    .unreq cntr
    .unreq pol0
    .unreq pol1
    .unreq pol2
    .unreq pol3
    .unreq temp_h
    .unreq temp_l
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2

.size pqc_ml_dsa_invntt, .-pqc_ml_dsa_invntt

.align 2
inv_ntt_asm_smull_qinv:
.word 0xfc7fdfff
.align 2
inv_ntt_asm_smull_q:
.word 8380417

.section .rodata

.type zetas_new332inv, %object
.align 2
zetas_new332inv:
.word 4193792, 4193792, -25847, 4193792, 518909, -25847, 2608894, 4193792, 4193792, -25847, 4193792, 518909, -25847, 2608894, -466468, -2680103, -3111497, -280005, 19422, -4010497, -1757237, 518909, -466468, 876248, -2680103, 2884855, -3111497, -3119733, 777960, 2091905, 359251, 2108549, 1119584, -2619752, 549488, -25847, 518909, 2608894, -466468, 777960, 876248, -237124, 876248, 2884855, -3119733, 3277672, 3859737, 1399561, 2118186, 2608894, 777960, -237124, 2091905, -2353451, 359251, -1826347, -237124, -2353451, -1826347, -3585928, -1024112, 1079900, -2725464, 4193792, 4193792, -25847, 41978, 3024400, 3975713, -1225192, 2797779, -3839961, 3628969, -1711436, 3835778, 485110, -3954267, -280005, 2797779, -2071892, -2831100, -2698859, -908040, -2292170, 539299, 1430430, -1852771, -3658785, 3512212, 1859141, -1607594, -2680103, -280005, -4010497, 715005, 1483994, -1045894, -980943, -3699596, 1316856, -759969, -955715, 3677139, 3933849, 2719610, 2108549, 539299, -2348700, 1658328, -1403403, 1775852, -2460465, -3915439, -126922, 3632928, 1067023, 3847594, 4179270, 1652689, -466468, -2680103, -3111497, -2953811, -284642, 2507426, -324139, -3881043, -1341330, -1315589, 3990128, -2137097, -4109898, 4092021, 3277672, -3699596, 1600420, 1541634, 3493410, 3487504, 2497815, 2867647, 2477047, 411027, 1654972, 1326223, -2608226, -2752209, 2091905, 2108549, -2619752, 1836700, 2945615, -1908953, 729864, 3821735, -3958618, -904516, 2080615, 1555380, -3471815, -1978758, -3585928, -3915439, 2537516, -892788, -553664, -3095038, 658596, -3530437, 1585221, -2176455, 3355482, -1783485, 2780552, -3623330, 518909, -466468, 876248, -442683, 2523147, -2847660, -3683140, 2556880, 1439742, 812732, 774207, -3168108, 1877157, 3406477, 19422, -3881043, -954230, -214686, -1182619, 2453526, -2201920, 300467, 1308169, 22981, 3614022, 2136260, 1459487, -2233803, 2884855, 3277672, 1399561, 394072, -3933227, 4136064, 156486, 2140649, 3249728, -1653064, 1596950, 633578, 2722529, -554462, 1119584, 2867647, -3574422, 1004840, 191586, 3969463, 1161373, 3592148, 1000202, 4083598, 3189243, 3561667, -3650125, 3490511, 777960, 2091905, 359251, -1829156, -3707725, -661807, 1144558, -531354, 1851402, -3159746, 1543095, -2903948, 1505516, -1500460, 3859737, 3821735, -3505694, -2413330, 3908886, -1203856, 3570263, 3043716, -2715295, -2147896, 758741, 3917553, -2414897, -1613811, -2353451, -3585928, 1079900, 990020, -719638, 2718792, 2260310, 1643818, -3097992, -508951, -783456, -2089539, 2616547, 4060031, -1024112, -3530437, -3077325, -1821861, 1920615, 3988525, 2048419, -95776, 3041255, 3677745, -971504, 2190617, 2311312, -1170082, -25847, 518909, 2608894, 1261528, -2073537, -959585, 3948120, -2071892, 3881060, 3019102, -1342633, -1115066, 3589694, -1929116, -4010497, 2556880, -3900724, 3360006, 1758630, -2306989, -1841637, -2348700, -1349076, 381987, -1699982, 3189673, 3531558, -1210546, -3111497, 19422, -1757237, 2977353, 2612035, -2718155, -1544829, 1600420, 210977, -2389356, 2052582, -2737802, 2383976, -450259, -2619752, 300467, -3539968, 1698289, -4065084, -644023, -1114140, 2537516, 3157330, 3190144, -993399, -2220524, 2920588, 252737, 876248, 2884855, -3119733, 1490985, -34731, -1212610, -3183745, -954230, 177440, 2409325, -3302554, -2390327, -2749545, 653128, 1399561, 2140649, -3507263, -3745105, -1942293, -3367121, 2734884, -3574422, 3693493, 2967645, 1393803, -2467905, 1786029, -1633410, 359251, 1119584, 549488, -2824548, -1325638, -2207625, -2601586, -3505694, 1100098, -44288, 3478676, -2457992, -1617107, 2551364, 1079900, 3592148, 1661693, 1593929, 318899, -3366475, 3118416, -3077325, -3475950, 1452451, 3772814, 1424805, -3391376, 632820, 2608894, 777960, -237124, 2062597, 4064335, 2197148, -1127864, -3900724, 1584928, -1285669, 2525341, -896437, -1915773, 1792087, -1757237, -531354, -811944, 938441, -674578, 2876837, 3959371, -3539968, 1228525, 671102, 1219592, -3853560, 2630979, -2134676, -3119733, 3859737, 2118186, -2432637, 2746655, 718593, -2353280, -3507263, 8578, 3724342, -34852, 1387945, 358956, 1604944, 549488, 3043716, 3861115, 1290746, 3208584, 2538711, -1442830, 1661693, -1939314, 1257611, -367371, -1308058, 264382, 2614173, -237124, -2353451, -1826347, 2050674, 592050, -138487, 2310528, -811944, 3553272, -189548, -2728561, -4168358, -79, 3844932, 2118186, 1643818, 1699267, 500408, 743398, 879633, -3105206, 3861115, 983419, -3412210, 712597, -23479, 3729381, -1010481, -1826347, -1024112, -2725464, -2361217, -1864453, 3850522, 2337144, 1699267, -264944, 3343383, 3842267, 4181974, -4032642, 3983585, -2725464, -95776, -2706023, 260345, 2526550, 2000777, 987079, -2706023, 1528703, 3930395, -3030761, -3082055, -2374824, 1836319
.size zetas_new332inv,.-zetas_new332inv
