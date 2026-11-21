/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

/*
 * The HSP debug-log messages of the tessera-sw CP1 firmware, for the
 * decoder. Generated from the message map, which has one file per component
 * in fw/plat/uno/fw/pal/log_map/, by `cargo xtask log-map` in fw/plat/uno.
 * Do not edit.
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
    [35] = "[pqc] pal: mlkem_gen_keypair bad seed_len=%u [err:%08x]",
    [36] = "[gdma] SRAM scrub for slot %u fell back to CPU (GDMA wipe failed)",
    [37] = "[fault] #### Unexpected exception %u #### [err:%08x]",
    [38] = "[pcie] reset event: partition %u free failed; faulted [err:%08x]",
    [39] = "[pcie] reset event %u: all partitions reset",
    [40] = "[iic] Disabling: icq_ctrl=0x%x isq_ctrl=0x%x",
    [41] = "[iic] recv FAILED: ch=%u cause=0x%08x",
    [42] = "[oic] Disabling: ocq_ctrl=0x%x osq_ctrl=0x%x",
    [43] = "[pqc] FP crash: kind=%u [err:%08x]",
    [44] = "[pqc] engine did not answer: engine=%u [err:%08x]",
    [45] = "[pqc] pal: mldsa_gen_keypair buffer too short [err:%08x]",
    [46] = "[pqc] pal: mlkem_gen_keypair buffer too short [err:%08x]",
    [47] = "[iic] ch=%u enabled before full init",
    [48] = "[oic] ch=%u enabled before full init",
    [49] = "[pcie] reset: failed to recycle IO received during reset [err:%08x]",
    [50] = "[selftest] bulk AES-GCM decrypt KAT mismatch [err:%08x]",
    [51] = "[selftest] bulk AES-GCM encrypt KAT mismatch [err:%08x]",
    [52] = "[selftest] bulk AES-XTS decrypt KAT mismatch [err:%08x]",
    [53] = "[selftest] bulk AES-XTS encrypt KAT mismatch [err:%08x]",
};

#endif /* TSRA_LOG_MESSAGES_H */
