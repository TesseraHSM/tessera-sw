/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

/*
 * The HSP debug-log messages of the tessera-sw CP1 firmware, for the
 * decoder. Generated from the message map, fw/plat/uno/fw/pal/log_map.tsv,
 * by `cargo xtask log-map` in fw/plat/uno. Do not edit.
 *
 * A record is three little-endian 32-bit words: the descriptor, then two
 * values. The descriptor holds the severity, the component, and the message
 * number, one byte each from the lowest up, then a zero byte. Each message
 * below is a printf format for the record's two values, in order. A
 * deprecated message is one that no image built by `cargo xtask log-map`
 * logs anymore, test-hook images included; its number keeps its meaning.
 */

#ifndef TSRA_LOG_MESSAGES_H
#define TSRA_LOG_MESSAGES_H

/* Provisional until the decoder and HSP owners allocate the values. */
#define TSRA_LOG_COMPONENT_CORE 0xF9
#define TSRA_LOG_COMPONENT_UNO 0xFA

static const char *const tsra_log_core_messages[256] = {
    [0] = "[core] failed to fault the IO's poisoned partition [err:%08x]",
    [1] = "[core] undo walk poisoned the IO's partition [err:%08x]",
    [2] = "[core] handle_op failed [err:%08x]",
};

static const char *const tsra_log_uno_messages[256] = {
    [0] = "[app] Tessera Integrated HSM firmware starting up...",
    [1] = "[app] boot complete, spawning poll_io",
    [2] = "[fips] #### FIPS error state #### [err:%08x]",
    [3] = "[fips] crypto command timed out [err:%08x]",
    [4] = "[selftest] periodic self-test %u failed [err:%08x]",
    [5] = "[idfu] malformed shutdown request [err:%08x]",
    [6] = "[idfu] shutdown requested with PKA cleanup pending; failing closed [err:%08x]",
    [7] = "[idfu] shutdown requested with %u IO in flight; failing closed [err:%08x]",
    [8] = "[io] detached CQE post failed for slot %u [err:%08x]",
    [9] = "[selftest] AES-CBC decrypt KAT mismatch [err:%08x]",
    [10] = "[selftest] AES-CBC encrypt KAT mismatch [err:%08x]",
    [11] = "[selftest] AES-ECB decrypt KAT mismatch [err:%08x]",
    [12] = "[selftest] AES-KWP unwrap KAT mismatch [err:%08x]",
    [13] = "[selftest] ECDH P-384 KAT mismatch on engine [err:%08x]",
    [14] = "[selftest] ECDSA P-384 sign KAT mismatch on engine [err:%08x]",
    [15] = "[selftest] HKDF KAT mismatch [err:%08x]",
    [16] = "[selftest] KBKDF KAT mismatch [err:%08x]",
    [17] = "[selftest] RSA-2K CRT mod-exp KAT mismatch on engine [err:%08x]",
    [18] = "[selftest] RSA-2K OAEP KEK mismatch on engine [err:%08x]",
    [19] = "[selftest] RSA-2K OAEP lHash mismatch on engine [err:%08x]",
    [20] = "[selftest] RSA-2K OAEP leading byte nonzero on engine [err:%08x]",
    [21] = "[selftest] RSA-2K OAEP separator invalid on engine [err:%08x]",
    [22] = "[selftest] RSA-2K mod-exp KAT mismatch on engine [err:%08x]",
    [23] = "[selftest] pre-operational self-test FAILED [err:%08x]",
    [24] = "[boot] ACK'd NormalBoot, phase -> WaitStart",
    [25] = "[boot] init: boot_status=Done published",
    [26] = "[boot] init: reset=POR -> partition store init_default",
    [27] = "[boot] init: reset=warm/fwupdate -> keep store, rearm gate1",
    [28] = "[boot] phase -> Running, status=Run",
    [29] = "[selftest] pre-operational self-test PASSED",
    [30] = "[boot] non-StateChange msg while waiting for state %u",
    [31] = "[boot] unexpected state %u while waiting for state %u",
    [32] = "[pcie] ignoring unexpected admin event 0x%x",
    [33] = "[pcie] reset event %u: %u partition(s) failed to free and were faulted",
    [34] = "[pqc] pal: mldsa_gen_keypair bad seed_len=%u [err:%08x]",
    [35] = "[pqc] pal: mldsa_gen_keypair short buffers sk_len=%u [err:%08x]",
    [36] = "[pqc] pal: mlkem_gen_keypair bad seed_len=%u [err:%08x]",
    [37] = "[pqc] pal: mlkem_gen_keypair short buffers sk_len=%u [err:%08x]",
    [38] = "[gdma] SRAM scrub for slot %u fell back to CPU (GDMA wipe failed)",
    [39] = "[iic] ALREADY ENABLED before full init: ch=%u",
    [40] = "[iic] recv FAILED: addr=0x%x axi_id=%u",
    [41] = "[iic] recv FAILED: ch=%u slot=%u",
    [42] = "[oic] ALREADY ENABLED before full init: ch=%u",
    [43] = "[fault]   BusFault:  IBUSERR   instruction prefetch bus error [err:%08x]",
    [44] = "[fault]   BusFault:  IMPRECISERR imprecise data bus error (BFAR unreliable) [err:%08x]",
    [45] = "[fault]   BusFault:  LSPERR    bus fault during FP lazy state preservation [err:%08x]",
    [46] = "[fault]   BusFault:  PRECISERR precise data bus error (BFAR valid) [err:%08x]",
    [47] = "[fault]   BusFault:  STKERR    bus fault on exception entry stacking [err:%08x]",
    [48] = "[fault]   BusFault:  UNSTKERR  bus fault on exception return unstacking [err:%08x]",
    [49] = "[fault]   MemManage: DACCVIOL  data access violation [err:%08x]",
    [50] = "[fault]   MemManage: IACCVIOL  instruction-fetch access violation [err:%08x]",
    [51] = "[fault]   MemManage: MLSPERR   fault during FP lazy state preservation [err:%08x]",
    [52] = "[fault]   MemManage: MSTKERR   fault on exception entry stacking [err:%08x]",
    [53] = "[fault]   MemManage: MUNSTKERR fault on exception return unstacking [err:%08x]",
    [54] = "[fault]   UsageFault: DIVBYZERO divide-by-zero trap [err:%08x]",
    [55] = "[fault]   UsageFault: INVPC     invalid PC load (exception return) [err:%08x]",
    [56] = "[fault]   UsageFault: INVSTATE  invalid EPSR/Thumb state [err:%08x]",
    [57] = "[fault]   UsageFault: NOCP      coprocessor access denied/absent [err:%08x]",
    [58] = "[fault]   UsageFault: UNALIGNED unaligned access trap [err:%08x]",
    [59] = "[fault]   UsageFault: UNDEFINSTR undefined instruction [err:%08x]",
    [60] = "[fault] #### HardFault #### [err:%08x]",
    [61] = "[fault] #### Unexpected exception %u #### [err:%08x]",
    [62] = "[fault] BFAR=0x%08x  (faulting bus address) [err:%08x]",
    [63] = "[fault] MMFAR=0x%08x (faulting memory address) [err:%08x]",
    [64] = "[fault] cause: stack overflow (exception frame unreliable) [err:%08x]",
    [65] = "[fault] stack overflow: MSP=0x%08x [err:%08x]",
    [66] = "[panic] #### PANIC #### [err:%08x]",
    [67] = "[pcie] reset event: partition %u free failed; faulted [err:%08x]",
    [68] = "[pcie] reset event %u: all partitions reset",
    [69] = "[explicit_crash] #### EXPLICIT CRASH #### [err:%08x]",
    [70] = "[pqc] FP crash: FP%u [err:%08x]",
    [71] = "[pqc] FP crash: bfar=0x%08x [err:%08x]",
    [72] = "[pqc] FP crash: cfsr=0x%08x [err:%08x]",
    [73] = "[pqc] FP crash: hfsr=0x%08x [err:%08x]",
    [74] = "[pqc] FP crash: mmfar=0x%08x [err:%08x]",
    [75] = "[pqc] FP crash: pc=0x%08x [err:%08x]",
    [76] = "[pqc] FP crash: sp=0x%08x [err:%08x]",
    [77] = "[pqc] FP crash: stack overflowed by %u B [err:%08x]",
    [78] = "[pqc] FP crash: stack_free=%u [err:%08x]",
    [79] = "[pqc] engine did not answer: FP%u [err:%08x]",
    [80] = "[pqc] engine did not answer: seq=%u [err:%08x]",
    [81] = "[fault] stack overflow: CFSR=0x%08x [err:%08x]",
    [82] = "[fault] stack overflow: HFSR=0x%08x [err:%08x]",
    [83] = "[pqc] pal: mldsa_gen_keypair bad seed_len (want %u) [err:%08x]",
    [84] = "[pqc] pal: mldsa_gen_keypair short buffers pk_len (want %u) [err:%08x]",
    [85] = "[pqc] pal: mldsa_gen_keypair short buffers pk_len=%u [err:%08x]",
    [86] = "[pqc] pal: mldsa_gen_keypair short buffers sk_len (want %u) [err:%08x]",
    [87] = "[pqc] pal: mlkem_gen_keypair bad seed_len (want %u) [err:%08x]",
    [88] = "[pqc] pal: mlkem_gen_keypair short buffers pk_len (want %u) [err:%08x]",
    [89] = "[pqc] pal: mlkem_gen_keypair short buffers pk_len=%u [err:%08x]",
    [90] = "[pqc] pal: mlkem_gen_keypair short buffers sk_len (want %u) [err:%08x]",
    [91] = "[iic] ALREADY ENABLED before full init: icq_ctrl=0x%x isq_ctrl=0x%x",
    [92] = "[iic] recv FAILED: qid=%u cause=0x%08x",
    [93] = "[oic] ALREADY ENABLED before full init: ocq_ctrl=0x%x osq_ctrl=0x%x",
    [94] = "[pqc] FP crash: kind=%u [err:%08x]",
    [95] = "[pqc] engine did not answer: engine=%u [err:%08x]",
    [96] = "[fault] HardFault: CFSR=0x%08x [err:%08x]",
    [97] = "[fault] HardFault: HFSR=0x%08x [err:%08x]",
    [98] = "[fault] HardFault: MSP=0x%08x [err:%08x]",
};

#endif /* TSRA_LOG_MESSAGES_H */
