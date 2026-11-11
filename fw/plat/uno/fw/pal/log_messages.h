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
    0,
};

static const char *const tsra_log_uno_messages[256] = {
    0,
};

#endif /* TSRA_LOG_MESSAGES_H */
