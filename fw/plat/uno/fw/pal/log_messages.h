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
    [0x00] = "[core] failed to fault the IO's poisoned partition [err:%08x]",
    [0x01] = "[core] undo walk poisoned the IO's partition [err:%08x]",
    [0x02] = "[core] handle_op failed [err:%08x]",
};

static const char *const tsra_log_uno_messages[256] = {
    [0x00] = "[app] Tessera Integrated HSM firmware starting up...",
    [0x01] = "[app] boot complete, spawning poll_io",
    [0x02] = "[fips] #### FIPS error state #### [err:%08x]",
    [0x03] = "[fips] crypto command timed out [err:%08x]",
    [0x04] = "[selftest] periodic self-test %u failed [err:%08x]",
    [0x05] = "[idfu] malformed shutdown request [err:%08x]",
    [0x06] = "[idfu] shutdown requested with PKA cleanup pending; failing closed [err:%08x]",
    [0x07] = "[idfu] shutdown requested with %u IO in flight; failing closed [err:%08x]",
    [0x08] = "[io] detached CQE post failed for slot %u [err:%08x]",
    [0x09] = "[selftest] AES-CBC decrypt KAT mismatch [err:%08x]",
    [0x0a] = "[selftest] AES-CBC encrypt KAT mismatch [err:%08x]",
    [0x0b] = "[selftest] AES-ECB decrypt KAT mismatch [err:%08x]",
    [0x0c] = "[selftest] AES-KWP unwrap KAT mismatch [err:%08x]",
    [0x0d] = "[selftest] ECDH P-384 KAT mismatch on engine [err:%08x]",
    [0x0e] = "[selftest] ECDSA P-384 sign KAT mismatch on engine [err:%08x]",
    [0x0f] = "[selftest] HKDF KAT mismatch [err:%08x]",
    [0x10] = "[selftest] KBKDF KAT mismatch [err:%08x]",
    [0x11] = "[selftest] RSA-2K CRT mod-exp KAT mismatch on engine [err:%08x]",
    [0x12] = "[selftest] RSA-2K OAEP KEK mismatch on engine [err:%08x]",
    [0x13] = "[selftest] RSA-2K OAEP lHash mismatch on engine [err:%08x]",
    [0x14] = "[selftest] RSA-2K OAEP leading byte nonzero on engine [err:%08x]",
    [0x15] = "[selftest] RSA-2K OAEP separator invalid on engine [err:%08x]",
    [0x16] = "[selftest] RSA-2K mod-exp KAT mismatch on engine [err:%08x]",
    [0x17] = "[selftest] pre-operational self-test FAILED [err:%08x]",
    [0x18] = "[boot] ACK'd NormalBoot, phase -> WaitStart",
    [0x19] = "[boot] init: boot_status=Done published",
    [0x1a] = "[boot] init: reset=POR -> partition store init_default",
    [0x1b] = "[boot] init: reset=warm/fwupdate -> keep store, rearm gate1",
    [0x1c] = "[boot] phase -> Running, status=Run",
    [0x1d] = "[selftest] pre-operational self-test PASSED",
    [0x1e] = "[boot] non-StateChange msg while waiting for state %u",
    [0x1f] = "[boot] unexpected state %u while waiting for state %u",
    [0x20] = "[pcie] ignoring unexpected admin event 0x%x",
    [0x21] = "[pcie] reset event %u: %u partition(s) failed to free and were faulted",
    [0x22] = "[pqc] pal: mldsa_gen_keypair bad seed_len=%u [err:%08x]",
    [0x23] = "[pqc] pal: mldsa_gen_keypair short buffers sk_len=%u [err:%08x]",
    [0x24] = "[pqc] pal: mlkem_gen_keypair bad seed_len=%u [err:%08x]",
    [0x25] = "[pqc] pal: mlkem_gen_keypair short buffers sk_len=%u [err:%08x]",
    [0x26] = "[gdma] SRAM scrub for slot %u fell back to CPU (GDMA wipe failed)",
    [0x27] = "[iic] ALREADY ENABLED before full init: ch=%u",
    [0x28] = "[iic] recv FAILED: addr=0x%x axi_id=%u",
    [0x29] = "[iic] recv FAILED: ch=%u slot=%u",
    [0x2a] = "[oic] ALREADY ENABLED before full init: ch=%u",
    [0x2b] = "[fault]   BusFault:  IBUSERR   instruction prefetch bus error [err:%08x]",
    [0x2c] = "[fault]   BusFault:  IMPRECISERR imprecise data bus error (BFAR unreliable) [err:%08x]",
    [0x2d] = "[fault]   BusFault:  LSPERR    bus fault during FP lazy state preservation [err:%08x]",
    [0x2e] = "[fault]   BusFault:  PRECISERR precise data bus error (BFAR valid) [err:%08x]",
    [0x2f] = "[fault]   BusFault:  STKERR    bus fault on exception entry stacking [err:%08x]",
    [0x30] = "[fault]   BusFault:  UNSTKERR  bus fault on exception return unstacking [err:%08x]",
    [0x31] = "[fault]   MemManage: DACCVIOL  data access violation [err:%08x]",
    [0x32] = "[fault]   MemManage: IACCVIOL  instruction-fetch access violation [err:%08x]",
    [0x33] = "[fault]   MemManage: MLSPERR   fault during FP lazy state preservation [err:%08x]",
    [0x34] = "[fault]   MemManage: MSTKERR   fault on exception entry stacking [err:%08x]",
    [0x35] = "[fault]   MemManage: MUNSTKERR fault on exception return unstacking [err:%08x]",
    [0x36] = "[fault]   UsageFault: DIVBYZERO divide-by-zero trap [err:%08x]",
    [0x37] = "[fault]   UsageFault: INVPC     invalid PC load (exception return) [err:%08x]",
    [0x38] = "[fault]   UsageFault: INVSTATE  invalid EPSR/Thumb state [err:%08x]",
    [0x39] = "[fault]   UsageFault: NOCP      coprocessor access denied/absent [err:%08x]",
    [0x3a] = "[fault]   UsageFault: UNALIGNED unaligned access trap [err:%08x]",
    [0x3b] = "[fault]   UsageFault: UNDEFINSTR undefined instruction [err:%08x]",
    [0x3c] = "[fault] #### HardFault #### [err:%08x]",
    [0x3d] = "[fault] #### Unexpected exception %u #### [err:%08x]",
    [0x3e] = "[fault] BFAR=0x%08x  (faulting bus address) [err:%08x]",
    [0x3f] = "[fault] MMFAR=0x%08x (faulting memory address) [err:%08x]",
    [0x40] = "[fault] cause: stack overflow (exception frame unreliable) [err:%08x]",
    [0x41] = "[fault] stack overflow: MSP=0x%08x [err:%08x]",
    [0x42] = "[panic] #### PANIC #### [err:%08x]",
    [0x43] = "[pcie] reset event: partition %u free failed; faulted [err:%08x]",
    [0x44] = "[pcie] reset event %u: all partitions reset",
    [0x45] = "[explicit_crash] #### EXPLICIT CRASH #### [err:%08x]",
    [0x46] = "[pqc] FP crash: FP%u [err:%08x]",
    [0x47] = "[pqc] FP crash: bfar=0x%08x [err:%08x]",
    [0x48] = "[pqc] FP crash: cfsr=0x%08x [err:%08x]",
    [0x49] = "[pqc] FP crash: hfsr=0x%08x [err:%08x]",
    [0x4a] = "[pqc] FP crash: mmfar=0x%08x [err:%08x]",
    [0x4b] = "[pqc] FP crash: pc=0x%08x [err:%08x]",
    [0x4c] = "[pqc] FP crash: sp=0x%08x [err:%08x]",
    [0x4d] = "[pqc] FP crash: stack overflowed by %u B [err:%08x]",
    [0x4e] = "[pqc] FP crash: stack_free=%u [err:%08x]",
    [0x4f] = "[pqc] engine did not answer: FP%u [err:%08x]",
    [0x50] = "[pqc] engine did not answer: seq=%u [err:%08x]",
    [0x51] = "[fault] stack overflow: CFSR=0x%08x [err:%08x]",
    [0x52] = "[fault] stack overflow: HFSR=0x%08x [err:%08x]",
    [0x53] = "[pqc] pal: mldsa_gen_keypair bad seed_len (want %u) [err:%08x]",
    [0x54] = "[pqc] pal: mldsa_gen_keypair short buffers pk_len (want %u) [err:%08x]",
    [0x55] = "[pqc] pal: mldsa_gen_keypair short buffers pk_len=%u [err:%08x]",
    [0x56] = "[pqc] pal: mldsa_gen_keypair short buffers sk_len (want %u) [err:%08x]",
    [0x57] = "[pqc] pal: mlkem_gen_keypair bad seed_len (want %u) [err:%08x]",
    [0x58] = "[pqc] pal: mlkem_gen_keypair short buffers pk_len (want %u) [err:%08x]",
    [0x59] = "[pqc] pal: mlkem_gen_keypair short buffers pk_len=%u [err:%08x]",
    [0x5a] = "[pqc] pal: mlkem_gen_keypair short buffers sk_len (want %u) [err:%08x]",
    [0x5b] = "[iic] ALREADY ENABLED before full init: icq_ctrl=0x%x isq_ctrl=0x%x",
    [0x5c] = "[iic] recv FAILED: qid=%u cause=0x%08x",
    [0x5d] = "[oic] ALREADY ENABLED before full init: ocq_ctrl=0x%x osq_ctrl=0x%x",
    [0x5e] = "[pqc] FP crash: kind=%u [err:%08x]",
    [0x5f] = "[pqc] engine did not answer: engine=%u [err:%08x]",
    [0x60] = "[fault] HardFault: CFSR=0x%08x [err:%08x]",
    [0x61] = "[fault] HardFault: HFSR=0x%08x [err:%08x]",
    [0x62] = "[fault] HardFault: MSP=0x%08x [err:%08x]",
};

#endif /* TSRA_LOG_MESSAGES_H */
