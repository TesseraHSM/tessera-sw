@
@ Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
@ Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
@ denoted as "the implementer".
@ Additional optimizations by Alexandre Adomnicai.
@
@ For more information, feedback or questions, please refer to our websites:
@ http://keccak.noekeon.org/
@ http://keyak.noekeon.org/
@ http://ketje.noekeon.org/
@
@ To the extent possible under law, the implementer has waived all copyright
@ and related or neighboring rights to the source code in this file.
@ http://creativecommons.org/publicdomain/zero/1.0/
@
@ The KeccakF1600_StatePermute round loop body is the Cortex-M7 instruction
@ schedule that the SLOTHY superoptimizer (https://github.com/slothy-optimizer/slothy,
@ MIT License) produced for this same lazy-rotation round code:
@ examples/opt/armv7m/keccak/keccakf1600_adomnicai_m4_opt_m7.s, with its
@ scheduling comments stripped and "ror #0" operands written as plain registers.
@ It replaces the KeccakRound0-3 macros and runs ~23% faster on the M7.
@

@ WARNING: These functions work only on little endian CPU with@ ARMv7m architecture (ARM Cortex-M3, ...).


	.thumb
	.syntax unified
.text

	@ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro	toBitInterleaving	x0,x1,s0,s1,t,over

	and		\t,\x0,#0x55555555
	orr		\t,\t,\t, LSR #1
	and		\t,\t,#0x33333333
	orr		\t,\t,\t, LSR #2
	and		\t,\t,#0x0F0F0F0F
	orr		\t,\t,\t, LSR #4
	and		\t,\t,#0x00FF00FF
	bfi		\t,\t,#8, #8
	.if \over != 0
	lsr		\s0,\t, #8
	.else
	eor		\s0,\s0,\t, LSR #8
	.endif

	and		\t,\x1,#0x55555555
	orr		\t,\t,\t, LSR #1
	and		\t,\t,#0x33333333
	orr		\t,\t,\t, LSR #2
	and		\t,\t,#0x0F0F0F0F
	orr		\t,\t,\t, LSR #4
	and		\t,\t,#0x00FF00FF
	orr		\t,\t,\t, LSR #8
	eor		\s0,\s0,\t, LSL #16

	and		\t,\x0,#0xAAAAAAAA
	orr		\t,\t,\t, LSL #1
	and		\t,\t,#0xCCCCCCCC
	orr		\t,\t,\t, LSL #2
	and		\t,\t,#0xF0F0F0F0
	orr		\t,\t,\t, LSL #4
	and		\t,\t,#0xFF00FF00
	orr		\t,\t,\t, LSL #8
	.if \over != 0
	lsr		\s1,\t, #16
	.else
	eor		\s1,\s1,\t, LSR #16
	.endif

	and		\t,\x1,#0xAAAAAAAA
	orr		\t,\t,\t, LSL #1
	and		\t,\t,#0xCCCCCCCC
	orr		\t,\t,\t, LSL #2
	and		\t,\t,#0xF0F0F0F0
	orr		\t,\t,\t, LSL #4
	and		\t,\t,#0xFF00FF00
	orr		\t,\t,\t, LSL #8
	bfc		\t, #0, #16
	eors	\s1,\s1,\t
	.endm

	@ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro	fromBitInterleaving		x0, x1, t

	movs	\t, \x0					@ t = x0@
	bfi		\x0, \x1, #16, #16		@ x0 = (x0 & 0x0000FFFF) | (x1 << 16)@
	bfc		\x1, #0, #16			@	x1 = (t >> 16) | (x1 & 0xFFFF0000)@
	orr		\x1, \x1, \t, LSR #16

    eor		\t, \x0, \x0, LSR #8    @ t = (x0 ^ (x0 >>  8)) & 0x0000FF00UL@  x0 = x0 ^ t ^ (t <<  8)@
	and		\t, #0x0000FF00
    eors	\x0, \x0, \t
    eor		\x0, \x0, \t, LSL #8

    eor		\t, \x0, \x0, LSR #4	@ t = (x0 ^ (x0 >>  4)) & 0x00F000F0UL@  x0 = x0 ^ t ^ (t <<  4)@
	and		\t, #0x00F000F0
    eors	\x0, \x0, \t
    eor		\x0, \x0, \t, LSL #4

    eor		\t, \x0, \x0, LSR #2	@ t = (x0 ^ (x0 >>  2)) & 0x0C0C0C0CUL@  x0 = x0 ^ t ^ (t <<  2)@
	and		\t, #0x0C0C0C0C
    eors	\x0, \x0, \t
    eor		\x0, \x0, \t, LSL #2

    eor		\t, \x0, \x0, LSR #1	@ t = (x0 ^ (x0 >>  1)) & 0x22222222UL@  x0 = x0 ^ t ^ (t <<  1)@
	and		\t, #0x22222222
    eors	\x0, \x0, \t
    eor		\x0, \x0, \t, LSL #1

    eor		\t, \x1, \x1, LSR #8    @ t = (x1 ^ (x1 >>  8)) & 0x0000FF00UL@  x1 = x1 ^ t ^ (t <<  8)@
	and		\t, #0x0000FF00
    eors	\x1, \x1, \t
    eor		\x1, \x1, \t, LSL #8

    eor		\t, \x1, \x1, LSR #4	@ t = (x1 ^ (x1 >>  4)) & 0x00F000F0UL@  x1 = x1 ^ t ^ (t <<  4)@
	and		\t, #0x00F000F0
    eors	\x1, \x1, \t
    eor		\x1, \x1, \t, LSL #4

    eor		\t, \x1, \x1, LSR #2	@ t = (x1 ^ (x1 >>  2)) & 0x0C0C0C0CUL@  x1 = x1 ^ t ^ (t <<  2)@
	and		\t, #0x0C0C0C0C
    eors	\x1, \x1, \t
    eor		\x1, \x1, \t, LSL #2

    eor		\t, \x1, \x1, LSR #1	@ t = (x1 ^ (x1 >>  1)) & 0x22222222UL@  x1 = x1 ^ t ^ (t <<  1)@
	and		\t, #0x22222222
    eors	\x1, \x1, \t
    eor		\x1, \x1, \t, LSL #1
	.endm

@	--- offsets in state
.equ Aba0, 0*4
.equ Aba1, 1*4
.equ Abe0, 2*4
.equ Abe1, 3*4
.equ Abi0, 4*4
.equ Abi1, 5*4
.equ Abo0, 6*4
.equ Abo1, 7*4
.equ Abu0, 8*4
.equ Abu1, 9*4
.equ Aga0, 10*4
.equ Aga1, 11*4
.equ Age0, 12*4
.equ Age1, 13*4
.equ Agi0, 14*4
.equ Agi1, 15*4
.equ Ago0, 16*4
.equ Ago1, 17*4
.equ Agu0, 18*4
.equ Agu1, 19*4
.equ Aka0, 20*4
.equ Aka1, 21*4
.equ Ake0, 22*4
.equ Ake1, 23*4
.equ Aki0, 24*4
.equ Aki1, 25*4
.equ Ako0, 26*4
.equ Ako1, 27*4
.equ Aku0, 28*4
.equ Aku1, 29*4
.equ Ama0, 30*4
.equ Ama1, 31*4
.equ Ame0, 32*4
.equ Ame1, 33*4
.equ Ami0, 34*4
.equ Ami1, 35*4
.equ Amo0, 36*4
.equ Amo1, 37*4
.equ Amu0, 38*4
.equ Amu1, 39*4
.equ Asa0, 40*4
.equ Asa1, 41*4
.equ Ase0, 42*4
.equ Ase1, 43*4
.equ Asi0, 44*4
.equ Asi1, 45*4
.equ Aso0, 46*4
.equ Aso1, 47*4
.equ Asu0, 48*4
.equ Asu1, 49*4

@	--- offsets on stack
.equ mDa0, 0*4
.equ mDa1, 1*4
.equ mDo0, 2*4
.equ mDo1, 3*4
.equ mDi0, 4*4
.equ mRC	, 5*4
.equ mSize, 6*4

@----------------------------------------------------------------------------
@
@ void KeccakF1600_Initialize( void )
@
.align 8
.global   KeccakF1600_Initialize
KeccakF1600_Initialize:
	bx		lr



@----------------------------------------------------------------------------
@
@ void KeccakF1600_StateXORBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakF1600_StateXORBytes
KeccakF1600_StateXORBytes:
	cbz		r3, KeccakF1600_StateXORBytes_Exit1
	push	{r4 - r8, lr}							@ then
	bic		r4, r2, #7								@ offset &= ~7
	adds	r0, r0, r4								@ add whole lane offset to state pointer
	ands	r2, r2, #7								@ offset &= 7 (part not lane aligned)
	beq		KeccakF1600_StateXORBytes_CheckLanes	@ .if offset != 0
	movs	r4, r3									@ then, do remaining bytes in first lane
	rsb		r5, r2, #8								@ max size in lane = 8 - offset
	cmp		r4, r5
	ble		KeccakF1600_StateXORBytes_BytesAlign
	movs	r4, r5
KeccakF1600_StateXORBytes_BytesAlign:
	sub		r8, r3, r4								@ size left
	movs	r3, r4
	bl		__KeccakF1600_StateXORBytesInLane
	mov		r3, r8
KeccakF1600_StateXORBytes_CheckLanes:
	lsrs	r2, r3, #3								@ .if length >= 8
	beq		KeccakF1600_StateXORBytes_Bytes
	mov		r8, r3
	bl		__KeccakF1600_StateXORLanes
	and		r3, r8, #7
KeccakF1600_StateXORBytes_Bytes:
	cbz		r3, KeccakF1600_StateXORBytes_Exit
	movs	r2, #0
	bl		__KeccakF1600_StateXORBytesInLane
KeccakF1600_StateXORBytes_Exit:
	pop		{r4 - r8, pc}
KeccakF1600_StateXORBytes_Exit1:
	bx		lr


@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateXORLanes
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 laneCount
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@ Changed: r2-r7
@
.align 8
__KeccakF1600_StateXORLanes:
__KeccakF1600_StateXORLanes_LoopAligned:
	ldr		r4, [r1], #4
	ldr		r5, [r1], #4
	ldrd    r6, r7, [r0]
	toBitInterleaving	r4, r5, r6, r7, r3, 0
	strd	r6, r7, [r0], #8
	subs	r2, r2, #1
	bne		__KeccakF1600_StateXORLanes_LoopAligned
	bx		lr


@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateXORBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r7
@
.align 8
__KeccakF1600_StateXORBytesInLane:
	movs	r4, #0
	movs	r5, #0
	push	{ r4 - r5 }
	add		r2, r2, sp
__KeccakF1600_StateXORBytesInLane_Loop:
	ldrb	r5, [r1], #1
	strb	r5, [r2], #1
	subs	r3, r3, #1
	bne		__KeccakF1600_StateXORBytesInLane_Loop
	pop		{ r4 - r5 }
	ldrd    r6, r7, [r0]
	toBitInterleaving	r4, r5, r6, r7, r3, 0
	strd	r6, r7, [r0], #8
	bx		lr




@----------------------------------------------------------------------------
@
@ void KeccakF1600_StateExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 8
.global   KeccakF1600_StateExtractBytes
KeccakF1600_StateExtractBytes:
	cbz		r3, KeccakF1600_StateExtractBytes_Exit1	@ .if length != 0
	push	{r4 - r8, lr}							@ then
	bic		r4, r2, #7								@ offset &= ~7
	adds	r0, r0, r4								@ add whole lane offset to state pointer
	ands	r2, r2, #7								@ offset &= 7 (part not lane aligned)
	beq		KeccakF1600_StateExtractBytes_CheckLanes	@ .if offset != 0
	movs	r4, r3									@ then, do remaining bytes in first lane
	rsb		r5, r2, #8								@ max size in lane = 8 - offset
	cmp		r4, r5
	ble		KeccakF1600_StateExtractBytes_BytesAlign
	movs	r4, r5
KeccakF1600_StateExtractBytes_BytesAlign:
	sub		r8, r3, r4								@ size left
	movs	r3, r4
	bl		__KeccakF1600_StateExtractBytesInLane
	mov		r3, r8
KeccakF1600_StateExtractBytes_CheckLanes:
	lsrs	r2, r3, #3								@ .if length >= 8
	beq		KeccakF1600_StateExtractBytes_Bytes
	mov		r8, r3
	bl		__KeccakF1600_StateExtractLanes
	and		r3, r8, #7
KeccakF1600_StateExtractBytes_Bytes:
	cbz		r3, KeccakF1600_StateExtractBytes_Exit
	movs	r2, #0
	bl		__KeccakF1600_StateExtractBytesInLane
KeccakF1600_StateExtractBytes_Exit:
	pop		{r4 - r8, pc}
KeccakF1600_StateExtractBytes_Exit1:
	bx		lr


@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateExtractLanes
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 laneCount
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@ Changed: r2-r5
@
.align 8
__KeccakF1600_StateExtractLanes:
__KeccakF1600_StateExtractLanes_LoopAligned:
	ldrd	r4, r5, [r0], #8
	fromBitInterleaving	r4, r5, r3
	str		r4, [r1], #4
	subs	r2, r2, #1
	str		r5, [r1], #4
	bne		__KeccakF1600_StateExtractLanes_LoopAligned
	bx		lr


@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateExtractBytesInLane
@
@ Input:
@  r0 state pointer
@  r1 data pointer
@  r2 offset in lane
@  r3 length
@
@ Output:
@  r0 state pointer next lane
@  r1 data pointer next byte to input
@
@  Changed: r2-r6
@
.align 8
__KeccakF1600_StateExtractBytesInLane:
	ldrd	r4, r5, [r0], #8
	fromBitInterleaving	r4, r5, r6
	push	{r4, r5}
	add		r2, sp, r2
__KeccakF1600_StateExtractBytesInLane_Loop:
	ldrb	r4, [r2], #1
	subs	r3, r3, #1
	strb	r4, [r1], #1
	bne		__KeccakF1600_StateExtractBytesInLane_Loop
	add		sp, #8
	bx		lr



.align 8
KeccakF1600_StatePermute_RoundConstantsWithTerminator:
	@		0			1
		.long 		0x00000001,	0x00000000
		.long 		0x00000000,	0x00000089
		.long 		0x00000000,	0x8000008b
		.long 		0x00000000,	0x80008080

		.long 		0x00000001,	0x0000008b
		.long 		0x00000001,	0x00008000
		.long 		0x00000001,	0x80008088
		.long 		0x00000001,	0x80000082

		.long 		0x00000000,	0x0000000b
		.long 		0x00000000,	0x0000000a
		.long 		0x00000001,	0x00008082
		.long 		0x00000000,	0x00008003

		.long 		0x00000001,	0x0000808b
		.long 		0x00000001,	0x8000000b
		.long 		0x00000001,	0x8000008a
		.long 		0x00000001,	0x80000081

		.long 		0x00000000,	0x80000081
		.long 		0x00000000,	0x80000008
		.long 		0x00000000,	0x00000083
		.long 		0x00000000,	0x80008003

		.long 		0x00000001,	0x80008088
		.long 		0x00000000,	0x80000088
		.long 		0x00000001,	0x00008000
		.long 		0x00000000,	0x80008082

		.long 		0x000000FF	@terminator

@----------------------------------------------------------------------------
@
@ void KeccakF1600_StatePermute( void *state )
@
.align 8
.global   KeccakF1600_StatePermute
.type     KeccakF1600_StatePermute, %function
KeccakF1600_StatePermute:
	adr		r1, KeccakF1600_StatePermute_RoundConstantsWithTerminator
	push	{ r4 - r12, lr }
	sub		sp, #mSize
	str		r1, [sp, #mRC]
KeccakF1600_StatePermute_RoundLoop:
	ldr.w r3, [r0, #60]
	ldr.w r11, [r0, #32]
	ldr.w r14, [r0, #20]
	ldr.w r10, [r0, #72]
	ldr.w r9, [r0, #100]
	ldr.w r8, [r0, #112]
	ldr r4, [r0, #128]
	eor r7, r14, r3
	ldr.w r3, [r0, #52]
	eor r6, r11, r10
	ldr.w r14, [r0, #12]
	eor r9, r7, r9
	ldr.w r7, [r0, #92]
	eor r11, r6, r8
	eor r6, r14, r3
	ldr.w r2, [r0, #48]
	ldr.w r3, [r0, #40]
	ldr r10, [r0, #132]
	eor r1, r6, r7
	ldr r12, [r0, #172]
	ldr.w r8, [r0, #0]
	ldr r7, [r0, #140]
	ldr.w r14, [r0, #8]
	eor r5, r1, r10
	eor r3, r8, r3
	ldr.w r1, [r0, #80]
	eor r5, r5, r12
	ldr r6, [r0, #120]
	eor r10, r14, r2
	ldr.w r14, [r0, #64]
	eor r12, r3, r1
	ldr r1, [r0, #152]
	ldr.w r2, [r0, #24]
	eor r6, r12, r6
	ldr r12, [r0, #180]
	ldr.w r3, [r0, #104]
	eor r9, r9, r7
	ldr.w r7, [r0, #88]
	eor r14, r2, r14
	eor r9, r9, r12
	ldr r8, [r0, #192]
	ldr.w r12, [r0, #28]
	eor r11, r11, r1
	eor r10, r10, r7
	ldr.w r2, [r0, #68]
	ldr r1, [r0, #160]
	eor r8, r11, r8
	eor r3, r14, r3
	ldr r11, [r0, #144]
	eor r2, r12, r2
	ldr.w r14, [r0, #108]
	eor r7, r8, r5, ror #31
	eor.w r8, r8, r9
	eor r12, r3, r11
	ldr r3, [r0, #148]
	str.w r7, [sp, #0]
	eor r14, r2, r14
	eor r2, r6, r1
	ldr r11, [r0, #188]
	eor r14, r14, r3
	ldr r1, [r0, #184]
	ldr r7, [r0, #168]
	eor r4, r10, r4
	eor r6, r14, r11
	ldr r11, [r0, #156]
	eor r3, r12, r1
	ldr.w r1, [r0, #76]
	eor r7, r4, r7
	eor r14, r6, r2
	eor r10, r2, r9, ror #31
	ldr r12, [r0, #196]
	eor.w r2, r5, r3
	ldr.w r5, [r0, #36]
	ldr.w r4, [r0, #56]
	eor r6, r7, r6, ror #31
	ldr.w r9, [r0, #16]
	eor r1, r5, r1
	ldr.w r5, [r0, #116]
	str.w r6, [sp, #16]
	ldr.w r6, [r0, #44]
	eor r4, r9, r4
	ldr.w r9, [r0, #4]
	eor r1, r1, r5
	ldr.w r5, [r0, #84]
	eor r9, r9, r6
	ldr.w r6, [r0, #96]
	eor r1, r1, r11
	ldr r11, [r0, #124]
	eor r9, r9, r5
	ldr r5, [r0, #136]
	eor r4, r4, r6
	ldr r6, [r0, #164]
	str.w r8, [sp, #12]
	eor r9, r9, r11
	eor r5, r4, r5
	ldr r8, [r0, #176]
	ldr.w r4, [r0, #180]
	eor r11, r9, r6
	eor r9, r1, r12
	ldr.w r1, [r0, #132]
	eor r5, r5, r8
	ldr.w r8, [r0, #84]
	eor r12, r3, r11, ror #31
	eor.w r7, r9, r7
	eor.w r8, r7, r8
	eor r11, r11, r5
	eor r9, r5, r9, ror #31
	eor.w r5, r11, r1
	bic r3, r5, r8, ror #23-2
	eor.w r1, r2, r4
	ldr.w r4, [r0, #24]
	bic r6, r1, r5, ror #31-23
	eor r6, r6, r8, ror #29
	eor.w r4, r9, r4
	str.w r6, [r0, #180]
	bic r6, r4, r1, ror #32+14-31
	eor r5, r6, r5, ror #23
	ldr.w r6, [r0, #72]
	str.w r7, [sp, #4]
	eor.w r6, r12, r6
	str.w r5, [r0, #24]
	bic r5, r6, r4, ror #32+10-14
	eor r1, r5, r1, ror #11
	ldr.w r5, [r0, #60]
	eor r3, r3, r6, ror #13
	eor.w r5, r2, r5
	str.w r1, [r0, #72]
	ldr.w r1, [r0, #8]
	str.w r3, [r0, #132]
	eor.w r3, r10, r1
	bic r6, r8, r6, ror #32+2-10
	ldr.w r8, [r0, #104]
	eor.w r1, r9, r8
	ldr.w r8, [r0, #164]
	eor.w r7, r7, r8
	bic r8, r1, r5, ror #12-3
	eor r4, r6, r4, ror #20
	ldr.w r6, [r0, #156]
	eor.w r6, r14, r6
	eor r8, r8, r3, ror #12
	str.w r4, [r0, #84]
	bic r4, r6, r1, ror #32+4-12
	str.w r8, [r0, #164]
	bic r8, r7, r6, ror #9-4
	str.w r9, [sp, #8]
	eor r4, r4, r5, ror #1
	eor r1, r8, r1, ror #29
	str.w r4, [r0, #8]
	bic r4, r5, r3, ror #3-0
	ldr.w r5, [r0, #88]
	eor.w r5, r10, r5
	bic r3, r3, r7, ror #32+0-9
	eor r6, r3, r6, ror #28
	str.w r1, [r0, #60]
	str.w r6, [r0, #104]
	ldr.w r8, [r0, #140]
	eor r1, r4, r7, ror #26
	ldr.w r7, [r0, #184]
	ldr.w r4, [r0, #40]
	str.w r1, [r0, #156]
	eor.w r1, r2, r8
	ldr r8, [sp, #0]
	eor.w r3, r9, r7
	eor.w r7, r8, r4
	ldr.w r6, [r0, #64]
	bic r4, r1, r5, ror #8-5
	eor r4, r4, r7, ror #22
	str.w r4, [r0, #88]
	eor.w r4, r9, r6
	bic r9, r3, r1, ror #28-8
	ldr.w r6, [r0, #36]
	eor r9, r9, r5, ror #23
	str.w r9, [r0, #140]
	eor.w r9, r14, r6
	bic r6, r9, r3, ror #32+14-28
	eor r1, r6, r1, ror #6
	ldr.w r6, [r0, #20]
	str.w r1, [r0, #184]
	bic r1, r7, r9, ror #18-14
	bic r7, r5, r7, ror #32+5-18
	ldr.w r5, [r0, #112]
	eor r9, r7, r9, ror #23
	str.w r9, [r0, #40]
	ldr.w r9, [r0, #120]
	eor.w r5, r12, r5
	eor r1, r1, r3, ror #22
	eor.w r7, r8, r9
	ldr.w r9, [r0, #172]
	bic r3, r7, r5, ror #20-19
	eor r3, r3, r4, ror #25
	str.w r3, [r0, #172]
	eor.w r3, r2, r6
	eor.w r6, r11, r9
	str.w r1, [r0, #36]
	ldr r1, [r0, #100]
	eor.w r1, r2, r1
	bic r9, r5, r4, ror #32+19-27
	bic r4, r4, r3, ror #32+27-31
	ldr r2, [r0, #48]
	eor r4, r4, r6, ror #26
	str.w r4, [r0, #112]
	eor.w r4, r10, r2
	bic r2, r3, r6, ror #31-1
	eor r9, r9, r3, ror #20
	ldr.w r3, [r0, #0]
	eor.w r3, r8, r3
	str.w r9, [r0, #120]
	eor r2, r2, r7, ror #11
	str.w r2, [r0, #64]
	bic r9, r6, r7, ror #32+1-20
	ldr r6, [r0, #148]
	eor r7, r9, r5, ror #14
	ldr r9, [sp, #12]
	bic r5, r1, r4, ror #22-22
	eor.w r6, r9, r6
	bic r2, r6, r1, ror #32+11-22
	str.w r7, [r0, #20]
	eor r2, r2, r4, ror #21
	ldr r7, [r0, #192]
	eor.w r7, r12, r7
	eor r5, r3, r5, ror #10
	str.w r2, [r0, #48]
	bic r2, r7, r6, ror #32+7-11
	eor r1, r2, r1, ror #17
	str.w r1, [r0, #100]
	bic r1, r3, r7, ror #32+0-7
	ldr.w r2, [sp, #16]
	eor r1, r1, r6, ror #21
	str.w r1, [r0, #148]
	bic r1, r4, r3, ror #22-0
	ldr r4, [sp, #20]
	ldr.w r3, [r0, #32]
	eor r1, r1, r7, ror #15
	ldr r6, [r4, #0]
	str.w r1, [r0, #192]
	eor.w r5, r6, r5
	str.w r5, [r0, #0]
	ldr.w r1, [r0, #108]
	ldr.w r6, [r0, #160]
	eor.w r5, r9, r1
	ldr.w r1, [r0, #152]
	eor.w r7, r12, r1
	eor.w r1, r8, r6
	eor.w r3, r12, r3
	bic r6, r7, r5, ror #32+4-13
	bic r4, r1, r7, ror #9-4
	ldr.w r12, [r0, #56]
	eor r4, r4, r5, ror #28
	str.w r4, [r0, #56]
	ldr.w r4, [r0, #80]
	eor.w r12, r2, r12
	eor.w r4, r8, r4
	ldr.w r8, [r0, #12]
	eor.w r8, r11, r8
	eor r6, r6, r12, ror #1
	str.w r6, [r0, #12]
	bic r5, r5, r12, ror #13-3
	ldr.w r6, [r0, #44]
	bic r12, r12, r8, ror #3-1
	eor r5, r5, r8, ror #12
	str.w r5, [r0, #160]
	ldr.w r5, [r0, #76]
	bic r8, r8, r1, ror #32+1-9
	eor r1, r12, r1, ror #26
	str.w r1, [r0, #152]
	eor r8, r8, r7, ror #29
	str.w r8, [r0, #108]
	eor.w r5, r14, r5
	ldr.w r12, [r0, #128]
	eor.w r1, r10, r12
	ldr.w r8, [r0, #176]
	eor.w r12, r2, r8
	bic r7, r1, r4, ror #22-1
	eor r8, r7, r5, ror #12
	str.w r8, [r0, #128]
	bic r8, r12, r1, ror #30-22
	ldr.w r7, [r0, #28]
	eor r8, r8, r4, ror #29
	eor.w r7, r9, r7
	str.w r8, [r0, #176]
	bic r8, r4, r5, ror #32+1-10
	eor r4, r8, r7, ror #19
	str.w r4, [r0, #80]
	bic r4, r7, r12, ror #32+14-30
	ldr r8, [sp, #4]
	eor r1, r4, r1, ror #24
	str.w r1, [r0, #28]
	eor.w r4, r8, r6
	bic r5, r5, r7, ror #32+10-14
	eor r12, r5, r12, ror #12
	ldr.w r7, [r0, #188]
	ldr.w r6, [r0, #136]
	ldr.w r1, [r0, #92]
	eor.w r6, r2, r6
	eor.w r5, r11, r1
	str.w r12, [r0, #76]
	bic r1, r5, r4, ror #32+5-18
	eor.w r7, r9, r7
	eor r1, r1, r3, ror #24
	str.w r1, [r0, #44]
	bic r1, r6, r5, ror #7-5
	ldr.w r12, [r0, #116]
	eor r1, r1, r4, ror #21
	str.w r1, [r0, #92]
	bic r1, r4, r3, ror #18-13
	ldr.w r4, [r0, #68]
	eor.w r4, r9, r4
	bic r9, r7, r6, ror #28-7
	eor r5, r9, r5, ror #23
	str.w r5, [r0, #136]
	bic r3, r3, r7, ror #32+13-28
	ldr.w r9, [r0, #124]
	eor r6, r3, r6, ror #6
	str.w r6, [r0, #188]
	eor r5, r1, r7, ror #22
	ldr.w r1, [r0, #16]
	eor.w r1, r2, r1
	ldr.w r7, [r0, #168]
	eor.w r12, r14, r12
	eor.w r3, r8, r9
	bic r9, r12, r4, ror #32+20-28
	eor.w r6, r10, r7
	eor r7, r9, r1, ror #21
	ldr r9, [r0, #144]
	bic r10, r1, r6, ror #31-1
	str.w r5, [r0, #32]
	str.w r7, [r0, #124]
	bic r7, r3, r12, ror #21-20
	eor r7, r7, r4, ror #25
	str.w r7, [r0, #168]
	eor r5, r10, r3, ror #10
	ldr r7, [r0, #96]
	eor.w r7, r2, r7
	bic r2, r4, r1, ror #32+28-31
	bic r3, r6, r3, ror #32+1-21
	ldr r10, [sp, #8]
	eor.w r9, r10, r9
	eor r10, r2, r6, ror #27
	eor r3, r3, r12, ror #13
	str.w r3, [r0, #16]
	str.w r5, [r0, #68]
	ldr r4, [r0, #196]
	eor.w r4, r14, r4
	ldr.w r14, [r0, #4]
	eor.w r6, r8, r14
	ldr r8, [r0, #52]
	eor.w r2, r11, r8
	str.w r10, [r0, #116]
	bic r12, r9, r7, ror #32+10-21
	ldr.w r5, [r0, #152]
	ldr r1, [sp, #20]
	bic r3, r6, r4, ror #32+0-7
	eor r14, r3, r9, ror #22
	str.w r14, [r0, #144]
	eor r14, r12, r2, ror #20
	str.w r14, [r0, #52]
	bic r14, r4, r9, ror #32+7-10
	ldr r11, [r1, #4]
	ldr.w r8, [r0, #192]
	eor r12, r14, r7, ror #18
	bic r14, r7, r2, ror #32+21-22
	str.w r12, [r0, #96]
	bic r10, r2, r6, ror #22-0
	ldr.w r7, [r0, #52]
	eor r4, r10, r4, ror #15
	str.w r4, [r0, #196]
	eor r6, r6, r14, ror #11
	ldr.w r9, [r0, #72]
	ldr.w r14, [r0, #96]
	ldr.w r1, [r0, #176]
	ldr.w r10, [r0, #60]
	eor r3, r8, r9, ror #12
	ldr.w r4, [r0, #128]
	ldr.w r9, [r0, #8]
	ldr.w r12, [r0, #132]
	eor.w r2, r11, r6
	ldr.w r11, [r0, #48]
	ldr.w r6, [r0, #84]
	eor r8, r3, r5, ror #19
	ldr.w r3, [r0, #12]
	ldr.w r5, [r0, #0]
	eor r12, r11, r12, ror #20
	str.w r2, [r0, #4]
	ldr r2, [r0, #88]
	ldr.w r11, [r0, #160]
	eor r3, r12, r3, ror #7
	eor r6, r5, r6, ror #30
	ldr r12, [r0, #168]
	eor r5, r3, r2, ror #3
	ldr.w r2, [r0, #156]
	eor r3, r6, r11, ror #19
	ldr r11, [r0, #36]
	eor r6, r5, r12, ror #22
	ldr.w r5, [r0, #196]
	ldr r12, [r0, #116]
	eor r7, r7, r4, ror #20
	eor r11, r8, r11, ror #4
	ldr.w r8, [r0, #76]
	eor r7, r7, r9, ror #6
	ror r6, #32-11
	ldr r9, [r0, #32]
	eor r4, r14, r1, ror #9
	eor r14, r5, r8, ror #12
	ldr.w r1, [r0, #28]
	ldr.w r8, [r0, #144]
	eor r4, r4, r10, ror #30
	ldr r5, [r0, #40]
	eor r2, r14, r2, ror #19
	eor r8, r8, r1, ror #18
	eor r9, r2, r9, ror #4
	ldr.w r2, [r0, #104]
	eor r10, r3, r5, ror #27
	ldr r1, [r0, #136]
	ldr r14, [r0, #188]
	eor r12, r11, r12, ror #26
	eor r5, r8, r2
	ldr r3, [r0, #112]
	ldr r8, [r0, #64]
	eor r2, r4, r1, ror #11
	ldr.w r11, [r0, #24]
	eor r14, r5, r14, ror #19
	eor r4, r9, r3, ror #27
	ldr.w r3, [r0, #148]
	ldr r1, [r0, #20]
	eor r5, r14, r8, ror #1
	ldr.w r9, [r0, #108]
	eor r3, r3, r11, ror #18
	ldr r14, [r0, #92]
	eor r8, r6, r4, ror #10
	ror r12, #32-22
	eor r2, r2, r1, ror #6
	eor r11, r3, r9, ror #31
	ldr r3, [r0, #124]
	eor r14, r7, r14, ror #3
	ldr r1, [r0, #172]
	eor r9, r12, r2, ror #25
	str.w r9, [sp, #12]
	ldr r9, [r0, #184]
	eor r10, r10, r3, ror #12
	eor r1, r14, r1, ror #22
	ldr.w r7, [r0, #100]
	eor r14, r5, r10
	eor r6, r6, r5, ror #31
	eor r5, r11, r9, ror #18
	ldr r3, [r0, #68]
	ldr.w r11, [r0, #180]
	eor r9, r12, r1, ror #21
	eor r10, r10, r2, ror #24
	str.w r9, [sp, #0]
	eor r3, r5, r3, ror #1
	ldr r12, [r0, #16]
	str.w r6, [sp, #16]
	ldr.w r5, [r0, #56]
	eor r7, r7, r11, ror #8
	ldr.w r6, [r0, #164]
	eor r2, r3, r1, ror #22
	ldr r11, [r0, #140]
	ldr.w r1, [r0, #80]
	eor r5, r7, r5, ror #30
	ldr.w r9, [r0, #4]
	eor r7, r8, r6, ror #20
	ldr.w r6, [r0, #164]
	eor r1, r9, r1, ror #31
	str.w r8, [sp, #4]
	eor r11, r5, r11, ror #11
	ldr r5, [r0, #44]
	eor r9, r1, r6, ror #20
	ldr.w r6, [r0, #20]
	eor r1, r11, r12, ror #6
	ldr r11, [r0, #120]
	eor r9, r9, r5, ror #27
	ldr.w r12, [r0, #120]
	eor r6, r2, r6, ror #31
	ror r1, #32-7
	eor r11, r9, r11, ror #13
	ldr.w r5, [r0, #92]
	eor r9, r1, r4, ror #9
	eor r4, r8, r12, ror #13
	ldr.w r8, [r0, #72]
	eor r12, r3, r11, ror #31
	eor r11, r11, r1
	eor r3, r11, r5, ror #25
	ldr.w r5, [r0, #148]
	eor r8, r12, r8, ror #22
	eor.w r1, r9, r5
	bic r5, r1, r6, ror #32+14-31
	eor r5, r5, r3, ror #23
	str.w r5, [r0, #148]
	bic r5, r7, r8, ror #32+2-10
	eor r5, r5, r1, ror #20
	str.w r5, [r0, #164]
	bic r1, r8, r1, ror #32+10-14
	eor r5, r1, r6, ror #11
	str.w r5, [r0, #72]
	bic r5, r6, r3, ror #31-23
	ldr.w r1, [r0, #32]
	eor r6, r5, r7, ror #29
	ldr.w r5, [r0, #176]
	bic r3, r3, r7, ror #23-2
	ldr.w r7, [r0, #108]
	str.w r6, [r0, #20]
	eor r6, r14, r1, ror #14
	eor r1, r2, r5, ror #2
	ldr.w r5, [r0, #48]
	eor r7, r9, r7, ror #31
	eor r3, r3, r8, ror #13
	str.w r3, [r0, #92]
	eor r3, r10, r5, ror #21
	ldr.w r8, [r0, #136]
	bic r5, r6, r7, ror #32+4-12
	eor r5, r5, r1, ror #1
	str.w r5, [r0, #48]
	bic r5, r4, r6, ror #9-4
	eor r5, r5, r7, ror #29
	str.w r5, [r0, #176]
	bic r7, r7, r1, ror #12-3
	str.w r9, [sp, #8]
	bic r1, r1, r3, ror #3-0
	ldr.w r5, [r0, #196]
	eor r7, r7, r3, ror #12
	str.w r7, [r0, #120]
	bic r7, r3, r4, ror #32+0-9
	eor r3, r14, r5, ror #10
	eor r1, r1, r4, ror #26
	ldr.w r4, [r0, #12]
	eor r7, r7, r6, ror #28
	str.w r7, [r0, #108]
	ldr.w r7, [r0, #68]
	str.w r1, [r0, #32]
	eor r6, r2, r8, ror #4
	eor r5, r10, r4, ror #28
	ldr.w r4, [r0, #84]
	eor r1, r9, r7, ror #1
	ldr r8, [sp, #0]
	eor r7, r8, r4, ror #30
	bic r4, r1, r6, ror #28-8
	eor r4, r4, r5, ror #23
	str.w r4, [r0, #136]
	bic r4, r5, r7, ror #32+5-18
	eor r4, r4, r3, ror #23
	str.w r4, [r0, #84]
	ldr.w r4, [r0, #24]
	bic r5, r6, r5, ror #8-5
	eor r5, r5, r7, ror #22
	str.w r5, [r0, #12]
	bic r5, r3, r1, ror #32+14-28
	eor r5, r5, r6, ror #6
	str.w r5, [r0, #68]
	bic r7, r7, r3, ror #18-14
	ldr.w r3, [r0, #172]
	eor r5, r9, r4, ror #18
	ldr.w r9, [r0, #40]
	ldr.w r4, [r0, #152]
	eor r1, r7, r1, ror #22
	eor r7, r11, r3, ror #12
	ldr.w r3, [r0, #96]
	eor r6, r8, r9, ror #27
	str.w r1, [r0, #196]
	eor r4, r12, r4, ror #29
	eor r3, r2, r3, ror #25
	bic r1, r7, r6, ror #32+1-20
	bic r9, r6, r4, ror #20-19
	eor r9, r9, r5, ror #25
	str.w r9, [r0, #172]
	eor r9, r1, r4, ror #14
	str.w r9, [r0, #96]
	bic r1, r4, r5, ror #32+19-27
	ldr r9, [r0, #60]
	eor r1, r1, r3, ror #20
	str.w r1, [r0, #40]
	ldr r4, [r0, #188]
	bic r5, r5, r3, ror #32+27-31
	eor r5, r5, r7, ror #26
	str.w r5, [r0, #152]
	bic r1, r3, r7, ror #31-1
	ldr r3, [r0, #116]
	eor r6, r1, r6, ror #11
	ldr.w r5, [r0, #160]
	eor r7, r2, r9, ror #23
	ldr r9, [sp, #12]
	str.w r6, [r0, #24]
	eor r6, r12, r3, ror #4
	ldr.w r1, [r0, #0]
	eor r4, r9, r4, ror #19
	eor r5, r8, r5, ror #19
	eor.w r2, r8, r1
	bic r3, r2, r6, ror #32+0-7
	ldr r1, [r0, #132]
	eor r3, r3, r4, ror #21
	str.w r3, [r0, #188]
	bic r3, r6, r4, ror #32+7-11
	eor r1, r10, r1, ror #9
	bic r4, r4, r7, ror #32+11-22
	eor r3, r3, r7, ror #17
	str.w r3, [r0, #60]
	eor r4, r4, r1, ror #21
	str.w r4, [r0, #132]
	bic r3, r7, r1, ror #22-22
	ldr.w r7, [r0, #16]
	bic r1, r1, r2, ror #22-0
	ldr.w r4, [r0, #88]
	eor r3, r2, r3, ror #10
	ldr.w r2, [sp, #16]
	eor r1, r1, r6, ror #15
	eor r6, r10, r4, ror #24
	ldr.w r4, [r0, #124]
	eor r7, r2, r7, ror #31
	str.w r1, [r0, #116]
	ldr r1, [sp, #20]
	eor r8, r8, r4, ror #12
	ldr r4, [r1, #8]
	ldr.w r1, [r0, #76]
	eor.w r4, r4, r3
	bic r3, r6, r5, ror #22-1
	str.w r4, [r0, #0]
	bic r4, r7, r6, ror #30-22
	eor r1, r14, r1, ror #22
	eor r4, r4, r5, ror #29
	str.w r4, [r0, #16]
	ldr.w r4, [r0, #144]
	eor r3, r3, r1, ror #12
	str.w r3, [r0, #88]
	bic r3, r5, r1, ror #32+1-10
	eor.w r4, r9, r4
	bic r5, r4, r7, ror #32+14-30
	eor r6, r5, r6, ror #24
	str.w r6, [r0, #144]
	eor r3, r3, r4, ror #19
	ldr.w r5, [r0, #180]
	bic r6, r1, r4, ror #32+10-14
	ldr.w r4, [r0, #52]
	eor r6, r6, r7, ror #12
	ldr.w r7, [r0, #36]
	str.w r6, [r0, #76]
	eor r6, r2, r5, ror #1
	eor r4, r11, r4, ror #22
	str.w r3, [r0, #160]
	eor r7, r12, r7, ror #14
	ldr.w r3, [r0, #104]
	bic r5, r4, r8, ror #32+1-9
	bic r1, r6, r4, ror #3-1
	eor.w r3, r9, r3
	eor r5, r5, r7, ror #29
	eor r1, r1, r8, ror #26
	str.w r1, [r0, #36]
	str.w r5, [r0, #104]
	bic r5, r3, r6, ror #13-3
	eor r4, r5, r4, ror #12
	ldr.w r5, [r0, #192]
	str.w r4, [r0, #124]
	bic r8, r8, r7, ror #9-4
	bic r4, r7, r3, ror #32+4-13
	ldr.w r7, [r0, #64]
	eor r1, r12, r5, ror #10
	eor r5, r8, r3, ror #28
	ldr.w r8, [r0, #8]
	str.w r5, [r0, #180]
	eor r7, r9, r7, ror #1
	eor r4, r4, r6, ror #1
	ldr.w r5, [r0, #140]
	ldr.w r12, [r0, #80]
	eor r6, r11, r8, ror #28
	bic r3, r1, r7, ror #32+13-28
	ldr r8, [sp, #4]
	str.w r4, [r0, #52]
	eor r4, r2, r5, ror #4
	eor r12, r8, r12, ror #31
	bic r5, r4, r6, ror #7-5
	eor r3, r3, r4, ror #6
	eor r5, r5, r12, ror #21
	str.w r5, [r0, #8]
	bic r5, r7, r4, ror #28-7
	ldr.w r4, [r0, #156]
	eor r5, r5, r6, ror #23
	str.w r5, [r0, #140]
	bic r5, r6, r12, ror #32+5-18
	ldr.w r6, [r0, #44]
	eor r5, r5, r1, ror #24
	str.w r5, [r0, #80]
	eor r5, r14, r4, ror #29
	eor r6, r8, r6, ror #27
	ldr.w r4, [r0, #28]
	str.w r3, [r0, #64]
	bic r1, r12, r1, ror #18-13
	bic r12, r6, r5, ror #21-20
	ldr.w r3, [r0, #168]
	eor r9, r9, r4, ror #18
	ldr.w r4, [r0, #4]
	eor r7, r1, r7, ror #22
	str.w r7, [r0, #192]
	eor r10, r10, r3, ror #11
	ldr.w r1, [r0, #100]
	eor r3, r12, r9, ror #25
	eor.w r12, r8, r4
	str.w r3, [r0, #168]
	bic r7, r10, r6, ror #32+1-21
	eor r7, r7, r5, ror #13
	str.w r7, [r0, #100]
	eor r8, r2, r1, ror #25
	ldr r1, [r0, #184]
	ldr r3, [r0, #112]
	bic r5, r5, r9, ror #32+20-28
	bic r4, r8, r10, ror #31-1
	ldr r7, [r0, #128]
	eor r5, r5, r8, ror #21
	str.w r5, [r0, #44]
	eor r5, r4, r6, ror #10
	ldr r6, [r0, #56]
	eor r3, r14, r3, ror #5
	ldr.w r14, [r0, #16]
	str.w r5, [r0, #28]
	eor r11, r11, r7, ror #10
	eor r2, r2, r6, ror #23
	ldr r6, [sp, #8]
	bic r5, r11, r12, ror #22-0
	ldr r4, [sp, #20]
	eor r5, r5, r3, ror #15
	str.w r5, [r0, #112]
	ldr r7, [r4, #12]
	bic r5, r9, r8, ror #32+28-31
	ldr.w r4, [r0, #72]
	bic r9, r2, r11, ror #32+21-22
	eor r5, r5, r10, ror #27
	str.w r5, [r0, #156]
	eor r8, r12, r9, ror #11
	ldr.w r5, [r0, #116]
	ldr.w r10, [r0, #88]
	eor r1, r6, r1, ror #18
	eor.w r8, r7, r8
	eor r9, r5, r4, ror #12
	ldr.w r4, [r0, #36]
	bic r5, r1, r2, ror #32+10-21
	eor r5, r5, r11, ror #20
	str.w r5, [r0, #128]
	ldr r7, [r0, #196]
	bic r5, r3, r1, ror #32+7-10
	eor r2, r5, r2, ror #18
	str.w r8, [r0, #4]
	str.w r2, [r0, #56]
	eor r9, r9, r4, ror #19
	bic r6, r12, r3, ror #32+0-7
	ldr.w r2, [r0, #128]
	eor r3, r9, r7, ror #4
	ldr.w r8, [r0, #48]
	eor r9, r2, r10, ror #20
	ldr r7, [r0, #8]
	eor r6, r6, r1, ror #22
	ldr.w r2, [r0, #56]
	eor r8, r9, r8, ror #6
	ldr.w r10, [r0, #176]
	str.w r6, [r0, #184]
	eor r5, r2, r14, ror #9
	ldr r11, [r0, #140]
	eor r7, r8, r7, ror #3
	ldr.w r4, [r0, #76]
	eor r8, r5, r10, ror #30
	ldr.w r6, [r0, #112]
	ldr.w r12, [r0, #92]
	ldr.w r9, [r0, #104]
	ldr.w r5, [r0, #132]
	eor r14, r6, r4, ror #12
	ldr.w r6, [r0, #52]
	eor r12, r5, r12, ror #20
	ldr.w r1, [r0, #148]
	ldr r5, [r0, #96]
	ldr.w r10, [r0, #188]
	ldr r2, [r0, #12]
	eor r12, r12, r6, ror #7
	eor r10, r10, r1, ror #18
	ldr.w r4, [r0, #60]
	eor r1, r8, r11, ror #11
	ldr r11, [r0, #156]
	eor r6, r12, r2, ror #3
	ldr.w r8, [r0, #20]
	eor r9, r10, r9, ror #31
	ldr r10, [r0, #68]
	eor r3, r3, r11, ror #26
	ldr.w r2, [r0, #32]
	eor r12, r4, r8, ror #8
	ldr r8, [r0, #172]
	eor r11, r9, r10, ror #18
	ldr.w r9, [r0, #180]
	ldr r4, [r0, #136]
	eor r10, r1, r5, ror #6
	ldr r1, [r0, #192]
	eor r5, r7, r8, ror #22
	eor r12, r12, r9, ror #30
	ldr.w r9, [r0, #164]
	eor r14, r14, r2, ror #19
	ror r3, #32-22
	eor r2, r12, r4, ror #11
	ldr.w r12, [r0, #0]
	ldr.w r8, [r0, #124]
	eor r7, r3, r10, ror #25
	ldr r4, [r0, #168]
	eor r9, r12, r9, ror #30
	eor r1, r14, r1, ror #4
	ldr r12, [r0, #84]
	eor r14, r9, r8, ror #19
	ldr r9, [r0, #152]
	eor r6, r6, r4, ror #22
	ldr r8, [r0, #44]
	eor r14, r14, r12, ror #27
	ldr.w r4, [r0, #144]
	eor r1, r1, r9, ror #27
	ldr.w r9, [r0, #184]
	eor r14, r14, r8, ror #12
	ldr.w r12, [r0, #108]
	eor r4, r9, r4, ror #18
	ldr r9, [r0, #28]
	ldr r8, [r0, #100]
	eor r10, r14, r10, ror #24
	str.w r7, [sp, #12]
	eor r4, r4, r12
	eor r7, r3, r5, ror #21
	ldr r12, [r0, #64]
	str.w r7, [sp, #0]
	eor r3, r11, r9, ror #1
	eor r7, r2, r8, ror #6
	ldr r9, [r0, #24]
	eor r12, r4, r12, ror #19
	ldr.w r11, [r0, #160]
	ror r7, #32-7
	eor r2, r3, r5, ror #22
	ldr.w r8, [r0, #4]
	eor r5, r12, r9, ror #1
	eor r9, r7, r1, ror #9
	ldr.w r4, [r0, #120]
	ror r6, #32-11
	eor r11, r8, r11, ror #31
	str.w r9, [sp, #8]
	eor r8, r6, r1, ror #10
	ldr.w r1, [r0, #16]
	eor r6, r6, r5, ror #31
	eor r14, r5, r14
	ldr r12, [r0, #40]
	eor r4, r11, r4, ror #20
	ldr r11, [r0, #80]
	ldr.w r5, [r0, #40]
	eor r1, r2, r1, ror #2
	str.w r6, [sp, #16]
	eor r4, r4, r11, ror #27
	ldr.w r11, [r0, #120]
	eor r5, r8, r5, ror #13
	ldr.w r6, [r0, #132]
	eor r12, r4, r12, ror #13
	str.w r8, [sp, #4]
	eor r4, r8, r11, ror #20
	ldr.w r8, [r0, #104]
	eor r11, r12, r7
	eor r6, r10, r6, ror #21
	eor r12, r3, r12, ror #31
	eor r3, r9, r8, ror #31
	ldr.w r8, [r0, #192]
	bic r7, r1, r6, ror #3-0
	eor r7, r7, r5, ror #26
	eor r8, r14, r8, ror #14
	str.w r7, [r0, #192]
	bic r7, r3, r1, ror #12-3
	eor r7, r7, r6, ror #12
	str.w r7, [r0, #40]
	bic r7, r5, r8, ror #9-4
	eor r7, r7, r3, ror #29
	str.w r7, [r0, #16]
	bic r7, r8, r3, ror #32+4-12
	bic r3, r6, r5, ror #32+0-9
	ldr.w r5, [r0, #72]
	eor r6, r7, r1, ror #1
	ldr.w r7, [r0, #8]
	eor r1, r3, r8, ror #28
	ldr.w r8, [r0, #96]
	eor r5, r12, r5, ror #22
	str.w r6, [r0, #132]
	eor r3, r11, r7, ror #25
	ldr.w r6, [r0, #188]
	eor r8, r2, r8, ror #31
	eor.w r6, r9, r6
	str.w r1, [r0, #104]
	bic r7, r4, r5, ror #32+2-10
	eor r7, r7, r6, ror #20
	str.w r7, [r0, #120]
	bic r7, r5, r6, ror #32+10-14
	ldr.w r1, [r0, #112]
	eor r7, r7, r8, ror #11
	str.w r7, [r0, #72]
	bic r7, r8, r3, ror #31-23
	bic r8, r6, r8, ror #32+14-31
	ldr.w r6, [r0, #140]
	eor r7, r7, r4, ror #29
	str.w r7, [r0, #96]
	bic r4, r3, r4, ror #23-2
	ldr.w r7, [r0, #52]
	eor r3, r8, r3, ror #23
	ldr r8, [sp, #0]
	eor r5, r4, r5, ror #13
	ldr.w r4, [r0, #164]
	str.w r5, [r0, #8]
	eor r6, r2, r6, ror #4
	eor r5, r10, r7, ror #28
	ldr.w r7, [r0, #28]
	str.w r3, [r0, #188]
	eor r4, r8, r4, ror #30
	eor r3, r14, r1, ror #10
	eor r7, r9, r7, ror #1
	bic r1, r5, r4, ror #32+5-18
	eor r1, r1, r3, ror #23
	str.w r1, [r0, #164]
	bic r1, r6, r5, ror #8-5
	eor r1, r1, r4, ror #22
	str.w r1, [r0, #52]
	bic r1, r7, r6, ror #28-8
	eor r1, r1, r5, ror #23
	str.w r1, [r0, #140]
	bic r4, r4, r3, ror #18-14
	ldr.w r1, [r0, #148]
	bic r3, r3, r7, ror #32+14-28
	ldr.w r5, [r0, #36]
	eor r6, r3, r6, ror #6
	str.w r6, [r0, #28]
	eor r1, r9, r1, ror #18
	ldr.w r9, [r0, #84]
	eor r6, r12, r5, ror #29
	ldr.w r5, [r0, #56]
	eor r3, r4, r7, ror #22
	ldr.w r4, [r0, #172]
	str.w r3, [r0, #112]
	eor r7, r8, r9, ror #27
	eor r9, r2, r5, ror #25
	eor r5, r11, r4, ror #12
	bic r3, r6, r1, ror #32+19-27
	eor r4, r3, r9, ror #20
	str.w r4, [r0, #84]
	bic r4, r5, r7, ror #32+1-20
	eor r4, r4, r6, ror #14
	str.w r4, [r0, #56]
	bic r3, r9, r5, ror #31-1
	ldr r4, [r0, #92]
	eor r3, r3, r7, ror #11
	str.w r3, [r0, #148]
	bic r6, r7, r6, ror #20-19
	ldr r7, [r0, #176]
	eor r6, r6, r1, ror #25
	str.w r6, [r0, #172]
	bic r9, r1, r9, ror #32+27-31
	ldr r1, [sp, #20]
	eor r3, r10, r4, ror #9
	ldr r6, [r0, #64]
	eor r7, r2, r7, ror #23
	ldr.w r2, [r0, #0]
	eor r9, r9, r5, ror #26
	ldr r4, [r1, #16]
	str.w r9, [r0, #36]
	bic r1, r7, r3, ror #22-22
	eor.w r5, r8, r2
	ldr r9, [sp, #12]
	eor r2, r5, r1, ror #10
	ldr r1, [r0, #156]
	eor r6, r9, r6, ror #19
	eor.w r4, r4, r2
	bic r2, r3, r5, ror #22-0
	eor r1, r12, r1, ror #4
	str.w r4, [r0, #0]
	bic r4, r6, r7, ror #32+11-22
	eor r3, r4, r3, ror #21
	ldr.w r4, [r0, #76]
	bic r5, r5, r1, ror #32+0-7
	str.w r3, [r0, #92]
	eor r2, r2, r1, ror #15
	str.w r2, [r0, #156]
	eor r4, r14, r4, ror #22
	ldr.w r2, [r0, #12]
	eor r3, r5, r6, ror #21
	ldr.w r5, [r0, #124]
	str.w r3, [r0, #64]
	bic r3, r1, r6, ror #32+7-11
	ldr.w r6, [r0, #184]
	eor r1, r3, r7, ror #17
	str.w r1, [r0, #176]
	eor r5, r8, r5, ror #19
	eor.w r3, r9, r6
	eor r6, r10, r2, ror #24
	bic r1, r5, r4, ror #32+1-10
	ldr.w r7, [r0, #100]
	eor r1, r1, r3, ror #19
	ldr.w r2, [sp, #16]
	str.w r1, [r0, #124]
	bic r1, r6, r5, ror #22-1
	eor r7, r2, r7, ror #31
	eor r1, r1, r4, ror #12
	str.w r1, [r0, #12]
	bic r1, r4, r3, ror #32+10-14
	ldr.w r4, [r0, #44]
	eor r1, r1, r7, ror #12
	str.w r1, [r0, #76]
	bic r1, r3, r7, ror #32+14-30
	ldr.w r3, [r0, #196]
	eor r1, r1, r6, ror #24
	str.w r1, [r0, #184]
	ldr.w r1, [r0, #20]
	bic r6, r7, r6, ror #30-22
	ldr.w r7, [r0, #116]
	eor r5, r6, r5, ror #29
	eor r8, r8, r4, ror #12
	ldr.w r6, [r0, #128]
	str.w r5, [r0, #100]
	eor r3, r12, r3, ror #14
	ldr.w r4, [r0, #108]
	eor r5, r2, r1, ror #1
	eor r1, r11, r6, ror #22
	eor.w r4, r9, r4
	bic r6, r8, r3, ror #9-4
	eor r6, r6, r4, ror #28
	str.w r6, [r0, #20]
	eor r12, r12, r7, ror #10
	ldr.w r7, [r0, #168]
	bic r6, r3, r4, ror #32+4-13
	bic r4, r4, r5, ror #13-3
	eor r4, r4, r1, ror #12
	str.w r4, [r0, #44]
	eor r7, r10, r7, ror #11
	ldr.w r4, [r0, #144]
	bic r10, r1, r8, ror #32+1-9
	bic r1, r5, r1, ror #3-1
	eor r8, r1, r8, ror #26
	ldr.w r1, [r0, #24]
	eor r4, r9, r4, ror #18
	str.w r8, [r0, #196]
	eor r10, r10, r3, ror #29
	ldr.w r8, [r0, #48]
	eor r1, r9, r1, ror #1
	ldr.w r3, [r0, #136]
	str.w r10, [r0, #108]
	eor r5, r6, r5, ror #1
	ldr.w r10, [r0, #160]
	eor r9, r11, r8, ror #28
	ldr r8, [sp, #4]
	eor r6, r2, r3, ror #4
	bic r3, r12, r1, ror #32+13-28
	str.w r5, [r0, #128]
	eor r10, r8, r10, ror #31
	eor r5, r3, r6, ror #6
	str.w r5, [r0, #24]
	bic r5, r1, r6, ror #28-7
	bic r3, r10, r12, ror #18-13
	eor r1, r3, r1, ror #22
	ldr.w r3, [r0, #60]
	str.w r1, [r0, #116]
	eor r5, r5, r9, ror #23
	bic r6, r6, r9, ror #7-5
	ldr.w r1, [r0, #80]
	str.w r5, [r0, #136]
	eor r6, r6, r10, ror #21
	eor r3, r2, r3, ror #25
	ldr.w r5, [r0, #32]
	str.w r6, [r0, #48]
	eor r6, r8, r1, ror #27
	bic r10, r9, r10, ror #32+5-18
	eor r5, r14, r5, ror #29
	eor r12, r10, r12, ror #24
	ldr r10, [r0, #180]
	bic r9, r6, r5, ror #21-20
	eor r1, r9, r4, ror #25
	str.w r1, [r0, #168]
	ldr r9, [sp, #8]
	bic r1, r5, r4, ror #32+20-28
	str.w r12, [r0, #160]
	bic r12, r7, r6, ror #32+1-21
	eor r12, r12, r5, ror #13
	str.w r12, [r0, #60]
	bic r12, r4, r3, ror #32+28-31
	ldr r4, [r0, #88]
	eor r12, r12, r7, ror #27
	str.w r12, [r0, #32]
	eor r5, r2, r10, ror #23
	ldr r2, [r0, #68]
	eor r1, r1, r3, ror #21
	str.w r1, [r0, #80]
	bic r1, r3, r7, ror #31-1
	ldr.w r7, [r0, #156]
	eor r1, r1, r6, ror #10
	ldr r6, [r0, #152]
	eor r9, r9, r2, ror #18
	ldr.w r12, [r0, #4]
	eor r3, r11, r4, ror #10
	ldr.w r11, [r0, #72]
	eor r14, r14, r6, ror #5
	eor.w r12, r8, r12
	bic r8, r9, r5, ror #32+10-21
	ldr.w r10, [r0, #196]
	eor r2, r7, r11, ror #12
	ldr r11, [r0, #32]
	bic r7, r12, r14, ror #32+0-7
	str.w r1, [r0, #144]
	eor r4, r7, r9, ror #22
	str.w r4, [r0, #68]
	eor r6, r2, r10, ror #19
	ldr.w r7, [r0, #100]
	bic r1, r3, r12, ror #22-0
	ldr r10, [r0, #112]
	eor r2, r1, r14, ror #15
	str.w r2, [r0, #152]
	bic r1, r14, r9, ror #32+7-10
	ldr.w r2, [r0, #12]
	eor r8, r8, r3, ror #20
	str.w r8, [r0, #88]
	eor r4, r1, r5, ror #18
	str.w r4, [r0, #180]
	bic r5, r5, r3, ror #32+21-22
	ldr r3, [r0, #48]
	eor r10, r6, r10, ror #4
	ldr r8, [sp, #20]
	eor r5, r12, r5, ror #11
	ldr.w r14, [r0, #88]
	ldr.w r1, [r0, #16]
	ldr.w r12, [r0, #132]
	eor r9, r14, r2, ror #20
	ldr r2, [r8, #20]
	eor r8, r10, r11, ror #26
	ldr.w r14, [r0, #180]
	eor r12, r9, r12, ror #6
	ldr r9, [r0, #172]
	eor r10, r14, r7, ror #9
	ror r8, #32-22
	eor r6, r12, r3, ror #3
	eor.w r3, r2, r5
	eor r14, r10, r1, ror #30
	ldr r4, [r0, #136]
	ldr r2, [r0, #56]
	eor r7, r6, r9, ror #22
	str.w r3, [r0, #4]
	ldr r11, [r0, #28]
	ldr.w r5, [r0, #108]
	ldr.w r1, [r0, #188]
	eor r6, r8, r7, ror #21
	eor r3, r14, r4, ror #11
	ldr r12, [r0, #144]
	ldr.w r10, [r0, #4]
	ldr.w r14, [r0, #8]
	ldr.w r9, [r0, #124]
	eor r4, r3, r2, ror #6
	ldr.w r2, [r0, #64]
	str.w r6, [sp, #0]
	ldr.w r3, [r0, #152]
	ldr.w r6, [r0, #76]
	eor r1, r2, r1, ror #18
	eor r10, r10, r9, ror #31
	ldr.w r9, [r0, #92]
	eor r2, r1, r5, ror #31
	ldr.w r5, [r0, #184]
	eor r14, r9, r14, ror #20
	ldr.w r1, [r0, #128]
	eor r6, r3, r6, ror #12
	ldr.w r3, [r0, #68]
	eor r2, r2, r11, ror #18
	ldr.w r11, [r0, #40]
	eor r9, r3, r5, ror #18
	ldr.w r5, [r0, #192]
	eor r8, r8, r4, ror #25
	str.w r8, [sp, #12]
	eor r11, r10, r11, ror #20
	ldr.w r10, [r0, #104]
	eor r6, r6, r5, ror #19
	ldr r5, [r0, #52]
	eor r8, r14, r1, ror #7
	ldr r14, [r0, #160]
	eor r1, r9, r10
	ldr r3, [r0, #168]
	ldr.w r9, [r0, #96]
	eor r8, r8, r5, ror #3
	eor r10, r2, r12, ror #1
	ldr r5, [r0, #84]
	eor r14, r11, r14, ror #27
	ldr r11, [r0, #116]
	eor r8, r8, r3, ror #22
	ldr.w r12, [r0, #176]
	ldr.w r3, [r0, #120]
	eor r2, r10, r7, ror #22
	eor r12, r12, r9, ror #8
	ldr r9, [r0, #24]
	eor r7, r6, r11, ror #4
	ldr.w r6, [r0, #20]
	eor r11, r14, r5, ror #13
	ldr.w r5, [r0, #0]
	eor r14, r1, r9, ror #19
	ldr r9, [r0, #140]
	eor r6, r12, r6, ror #30
	ldr r1, [r0, #164]
	eor r12, r10, r11, ror #31
	ldr.w r10, [r0, #44]
	eor r5, r5, r3, ror #30
	ldr r3, [r0, #148]
	ror r8, #32-11
	eor r9, r6, r9, ror #11
	eor r5, r5, r10, ror #19
	ldr r10, [r0, #36]
	eor r6, r14, r3, ror #1
	ldr r3, [r0, #80]
	eor r5, r5, r1, ror #27
	ldr r14, [r0, #60]
	eor r1, r7, r10, ror #27
	ldr.w r7, [r0, #56]
	eor r10, r5, r3, ror #12
	ldr.w r5, [r0, #40]
	ldr.w r3, [r0, #72]
	eor r9, r9, r14, ror #6
	eor r14, r6, r10
	eor r6, r8, r6, ror #31
	eor r7, r2, r7, ror #31
	str.w r6, [sp, #16]
	eor r10, r10, r4, ror #24
	ror r9, #32-7
	eor r4, r12, r3, ror #22
	ldr.w r3, [r0, #64]
	ldr.w r6, [r0, #48]
	eor r8, r8, r1, ror #10
	eor r11, r11, r9
	eor r9, r9, r1, ror #9
	str.w r8, [sp, #4]
	eor r1, r11, r6, ror #25
	eor.w r3, r9, r3
	eor r6, r8, r5, ror #20
	bic r5, r3, r7, ror #32+14-31
	eor r5, r5, r1, ror #23
	ror r5, r5, #32-14
	str.w r5, [r0, #64]
	bic r5, r1, r6, ror #23-2
	eor r5, r5, r4, ror #13
	bic r1, r7, r1, ror #31-23
	ror r5, r5, #32-23
	eor r1, r1, r6, ror #29
	str.w r5, [r0, #48]
	bic r5, r6, r4, ror #32+2-10
	ror r1, r1, #32-31
	eor r6, r5, r3, ror #20
	bic r3, r4, r3, ror #32+10-14
	ldr.w r5, [r0, #84]
	str.w r1, [r0, #56]
	ldr.w r1, [r0, #116]
	eor r3, r3, r7, ror #11
	ldr.w r7, [r0, #108]
	eor r4, r8, r5, ror #13
	ldr.w r8, [r0, #92]
	ror r3, r3, #32-10
	eor r1, r14, r1, ror #14
	str.w r3, [r0, #72]
	eor r5, r9, r7, ror #31
	eor r3, r10, r8, ror #21
	ldr.w r7, [r0, #100]
	ror r8, r6, #32-2
	bic r6, r4, r1, ror #9-4
	str.w r8, [r0, #40]
	eor r6, r6, r5, ror #29
	eor r7, r2, r7, ror #2
	ror r6, r6, #32-9
	bic r8, r3, r4, ror #32+0-9
	str.w r6, [r0, #100]
	eor r6, r8, r1, ror #28
	str.w r6, [r0, #108]
	bic r6, r7, r3, ror #3-0
	eor r6, r6, r4, ror #26
	ldr.w r4, [r0, #120]
	bic r1, r1, r5, ror #32+4-12
	ldr.w r8, [r0, #128]
	ror r6, r6, #32-3
	eor r1, r1, r7, ror #1
	str.w r6, [r0, #116]
	ldr.w r6, [r0, #136]
	bic r7, r5, r7, ror #12-3
	ror r1, r1, #32-4
	eor r5, r10, r8, ror #28
	ldr r8, [sp, #0]
	str.w r1, [r0, #92]
	eor r6, r2, r6, ror #4
	eor r4, r8, r4, ror #30
	eor r3, r7, r3, ror #12
	ldr.w r7, [r0, #152]
	bic r1, r6, r5, ror #8-5
	ror r3, r3, #32-12
	eor r1, r1, r4, ror #22
	str.w r3, [r0, #84]
	eor r3, r14, r7, ror #10
	ror r1, r1, #32-8
	ldr.w r7, [r0, #144]
	str.w r1, [r0, #128]
	bic r1, r5, r4, ror #32+5-18
	eor r1, r1, r3, ror #23
	eor r7, r9, r7, ror #1
	ror r1, r1, #32-5
	bic r4, r4, r3, ror #18-14
	str.w r1, [r0, #120]
	bic r1, r7, r6, ror #28-8
	eor r1, r1, r5, ror #23
	ldr.w r5, [r0, #188]
	bic r3, r3, r7, ror #32+14-28
	str.w r9, [sp, #8]
	eor r3, r3, r6, ror #6
	ror r6, r1, #32-28
	eor r9, r9, r5, ror #18
	ldr.w r1, [r0, #196]
	eor r4, r4, r7, ror #22
	ldr.w r7, [r0, #164]
	str.w r6, [r0, #136]
	ldr.w r5, [r0, #180]
	ror r4, r4, #32-18
	eor r1, r12, r1, ror #29
	str.w r4, [r0, #152]
	eor r6, r8, r7, ror #27
	eor r7, r2, r5, ror #25
	ldr.w r5, [r0, #172]
	ror r3, r3, #32-14
	bic r4, r6, r1, ror #20-19
	eor r4, r4, r9, ror #25
	str.w r3, [r0, #144]
	bic r3, r1, r9, ror #32+19-27
	ror r4, r4, #32-20
	eor r3, r3, r7, ror #20
	eor r5, r11, r5, ror #12
	str.w r4, [r0, #172]
	ror r3, r3, #32-19
	bic r4, r9, r7, ror #32+27-31
	str.w r3, [r0, #164]
	bic r3, r5, r6, ror #32+1-20
	eor r3, r3, r1, ror #14
	ldr r1, [r0, #8]
	bic r9, r7, r5, ror #31-1
	ldr r7, [r0, #32]
	eor r6, r9, r6, ror #11
	ror r3, r3, #32-1
	str.w r3, [r0, #180]
	ldr r3, [r0, #16]
	eor r5, r4, r5, ror #26
	ldr r4, [r0, #24]
	eor r1, r10, r1, ror #9
	ldr r9, [sp, #12]
	eor r3, r2, r3, ror #23
	ror r2, r5, #32-27
	ror r5, r6, #32-31
	eor r6, r9, r4, ror #19
	str.w r2, [r0, #196]
	eor r2, r12, r7, ror #4
	str.w r5, [r0, #188]
	bic r4, r6, r3, ror #32+11-22
	eor r5, r4, r1, ror #21
	ldr.w r4, [r0, #0]
	eor.w r4, r8, r4
	bic r7, r2, r6, ror #32+7-11
	eor r7, r7, r3, ror #17
	ror r5, r5, #32-11
	str.w r5, [r0, #8]
	bic r3, r3, r1, ror #22-22
	ror r7, r7, #32-7
	str.w r7, [r0, #16]
	bic r5, r4, r2, ror #32+0-7
	ldr.w r7, [r0, #60]
	eor r6, r5, r6, ror #21
	ldr.w r5, [r0, #44]
	bic r1, r1, r4, ror #22-0
	str.w r6, [r0, #24]
	eor r1, r1, r2, ror #15
	ldr.w r2, [sp, #16]
	eor r5, r8, r5, ror #19
	ldr.w r6, [r0, #52]
	eor r7, r2, r7, ror #31
	ror r1, r1, #32-22
	str.w r1, [r0, #32]
	eor r3, r4, r3, ror #10
	eor r6, r10, r6, ror #24
	ldr r1, [sp, #20]
	ldr r4, [r1, #24]
	ldr.w r1, [r0, #76]
	eor.w r3, r4, r3
	bic r4, r7, r6, ror #30-22
	eor r4, r4, r5, ror #29
	str.w r3, [r0, #0]
	eor r1, r14, r1, ror #22
	ror r3, r4, #32-30
	str.w r3, [r0, #60]
	bic r3, r6, r5, ror #22-1
	ldr.w r4, [r0, #68]
	eor.w r4, r9, r4
	eor r3, r3, r1, ror #12
	bic r5, r5, r1, ror #32+1-10
	ror r3, r3, #32-22
	eor r5, r5, r4, ror #19
	bic r1, r1, r4, ror #32+10-14
	str.w r3, [r0, #52]
	ror r3, r5, #32-1
	eor r5, r1, r7, ror #12
	bic r7, r4, r7, ror #32+14-30
	ldr.w r1, [r0, #80]
	eor r6, r7, r6, ror #24
	ldr.w r4, [r0, #88]
	ldr.w r7, [r0, #96]
	str.w r3, [r0, #44]
	eor r1, r8, r1, ror #12
	ror r6, r6, #32-14
	ldr.w r8, [r0, #112]
	eor r4, r11, r4, ror #22
	eor r3, r2, r7, ror #1
	ror r7, r5, #32-10
	str.w r7, [r0, #76]
	ldr.w r7, [r0, #104]
	str.w r6, [r0, #68]
	bic r5, r3, r4, ror #3-1
	eor.w r6, r9, r7
	eor r5, r5, r1, ror #26
	bic r7, r6, r3, ror #13-3
	ror r5, r5, #32-3
	eor r7, r7, r4, ror #12
	str.w r5, [r0, #112]
	eor r5, r12, r8, ror #14
	ror r8, r7, #32-13
	bic r4, r4, r1, ror #32+1-9
	bic r7, r5, r6, ror #32+4-13
	str.w r8, [r0, #80]
	bic r1, r1, r5, ror #9-4
	ldr r8, [sp, #4]
	eor r7, r7, r3, ror #1
	ldr.w r3, [r0, #156]
	eor r5, r4, r5, ror #29
	ldr.w r4, [r0, #124]
	eor r1, r1, r6, ror #28
	ldr.w r6, [r0, #132]
	eor r3, r12, r3, ror #10
	ror r5, r5, #32-1
	ror r1, r1, #32-9
	eor r12, r8, r4, ror #31
	str.w r5, [r0, #104]
	eor r5, r11, r6, ror #28
	str.w r1, [r0, #96]
	ldr.w r1, [r0, #140]
	ror r6, r7, #32-4
	bic r4, r5, r12, ror #32+5-18
	eor r4, r4, r3, ror #24
	str.w r6, [r0, #88]
	eor r6, r2, r1, ror #4
	ror r1, r4, #32-5
	ldr.w r4, [r0, #148]
	str.w r1, [r0, #124]
	bic r1, r6, r5, ror #7-5
	eor r1, r1, r12, ror #21
	eor r7, r9, r4, ror #1
	ror r1, r1, #32-7
	bic r4, r12, r3, ror #18-13
	bic r12, r7, r6, ror #28-7
	str.w r1, [r0, #132]
	eor r5, r12, r5, ror #23
	ldr.w r1, [r0, #176]
	bic r3, r3, r7, ror #32+13-28
	ldr r12, [r0, #12]
	ror r5, r5, #32-28
	eor r4, r4, r7, ror #22
	eor r7, r3, r6, ror #6
	str.w r5, [r0, #140]
	eor r3, r2, r1, ror #25
	ldr r6, [r0, #20]
	ror r1, r7, #32-13
	ldr r5, [r0, #36]
	eor r7, r11, r12, ror #10
	ldr.w r12, [r0, #184]
	eor r6, r2, r6, ror #23
	ldr.w r11, [r0, #168]
	eor r5, r14, r5, ror #5
	ldr.w r2, [r0, #192]
	eor r9, r9, r12, ror #18
	ldr.w r12, [r0, #160]
	eor r10, r10, r11, ror #11
	str.w r1, [r0, #148]
	eor r11, r14, r2, ror #29
	ror r14, r4, #32-18
	str.w r14, [r0, #156]
	eor r2, r8, r12, ror #27
	bic r12, r11, r9, ror #32+20-28
	ldr.w r14, [r0, #4]
	eor.w r8, r8, r14
	eor r12, r12, r3, ror #21
	ldr r1, [r0, #28]
	bic r14, r9, r3, ror #32+28-31
	ror r4, r12, #32-20
	eor r12, r14, r10, ror #27
	bic r14, r7, r8, ror #22-0
	str.w r4, [r0, #160]
	eor r14, r14, r5, ror #15
	ror r12, r12, #32-28
	bic r4, r2, r11, ror #21-20
	str.w r12, [r0, #192]
	ror r12, r14, #32-22
	bic r14, r3, r10, ror #31-1
	eor r3, r14, r2, ror #10
	str.w r12, [r0, #36]
	bic r14, r10, r2, ror #32+1-21
	ldr r12, [sp, #8]
	eor r11, r14, r11, ror #13
	ror r14, r3, #32-31
	eor r2, r12, r1, ror #18
	ldr r1, [sp, #20]
	str.w r14, [r0, #184]
	bic r10, r6, r7, ror #32+21-22
	bic r12, r8, r5, ror #32+0-7
	ror r14, r11, #32-1
	eor r12, r12, r2, ror #22
	str.w r14, [r0, #176]
	eor r14, r4, r9, ror #25
	ldr r3, [r1, #28]
	str.w r12, [r0, #28]
	bic r4, r2, r6, ror #32+10-21
	ror r12, r14, #32-21
	bic r14, r5, r2, ror #32+7-10
	eor r14, r14, r6, ror #18
	ldr r11, [r1, #32]!
	eor r2, r4, r7, ror #20
	str.w r12, [r0, #168]
	eor r12, r8, r10, ror #11
	ror r14, r14, #32-7
	ror r6, r2, #32-10
	str.w r6, [r0, #12]
	str r1, [sp, #20]
	cmp r11, #0xFF
	eor.w r1, r3, r12
	str.w r14, [r0, #20]
	str.w r1, [r0, #4]
	bne		KeccakF1600_StatePermute_RoundLoop
	add		sp, #mSize
	pop		{ r4 - r12, pc }
.size KeccakF1600_StatePermute, .-KeccakF1600_StatePermute

