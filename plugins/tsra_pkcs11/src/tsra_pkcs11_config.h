// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define P11_CREDS_ID_LEN 16
#define P11_CREDS_PIN_LEN 16
#define P11_OBK_LEN 48
#define P11_CONFIG_ERROR_LEN 128

/* The C_Login PIN range (C_GetTokenInfo). A PIN is zero-padded to the 16-byte
 * credential PIN, see tsra_pkcs11_pin_normalise. */
#define TSRA_PKCS11_MIN_PIN_LEN 4
#define TSRA_PKCS11_MAX_PIN_LEN P11_CREDS_PIN_LEN

/* Credentials, from the environment only: never from the configuration file. */
#define TSRA_PKCS11_ENV_ID "TSRA_PKCS11_ID"
#define TSRA_PKCS11_ENV_PIN "TSRA_PKCS11_PIN"

/* The configuration file, and the environment variable of each of its keys,
 * which wins over the file. */
#define TSRA_PKCS11_ENV_CONF "TSRA_PKCS11_CONF"
#define TSRA_PKCS11_ENV_STORE_DIR "TSRA_PKCS11_STORE_DIR"
#define TSRA_PKCS11_ENV_PERSIST "TSRA_PKCS11_PERSIST"
#define TSRA_PKCS11_ENV_DEBUG "TSRA_PKCS11_DEBUG"
#define TSRA_PKCS11_ENV_OBK_PATH "TSRA_PKCS11_OBK_PATH"

#define TSRA_PKCS11_PATH_LEN 4096
#define TSRA_PKCS11_DEFAULT_STORE_DIR "/var/lib/tsra/pkcs11"

/*
 * Module settings: the provisioning inputs for the first login after power-on,
 * and the host object-store settings. The per-login PIN comes from C_Login;
 * `default_pin` serves a login without one.
 */
typedef struct
{
    CK_BYTE id[P11_CREDS_ID_LEN];           /* partition ID of the credential */
    CK_BYTE default_pin[P11_CREDS_PIN_LEN]; /* credential PIN of a login without a PIN */
    bool id_set;                            /* id is configured, or built into the emulator */
    bool default_pin_set;                   /* default_pin is configured */
    char store_dir[TSRA_PKCS11_PATH_LEN];   /* persistent object-store root */
    char obk_path[TSRA_PKCS11_PATH_LEN];    /* owner backup key file; empty if none */
    bool store_persist;                     /* select the file backend over in-memory */
    bool debug;                             /* trace to stderr */
    char error[P11_CONFIG_ERROR_LEN];       /* why tsra_pkcs11_config_load failed */
} tsra_pkcs11_config;

/*
 * Populate `cfg`: the defaults, then the file TSRA_PKCS11_CONF names (when
 * set), then the environment variable of every file key, which wins over the
 * file. Credentials come from the environment only: TSRA_PKCS11_ID and
 * TSRA_PKCS11_PIN, 32 hex characters each. Every HSM-backed build
 * (TSRA_WITH_HSM) requires TSRA_PKCS11_ID and an obk_path; the key
 * file itself is not read here (tsra_pkcs11_config_obk). A malformed setting
 * fails closed instead of falling back to a default: CKR_GENERAL_ERROR with
 * the reason in cfg->error for a missing, empty or unreadable file, a line that
 * is not a known "key = value", a credential that is not 32 hex characters, a
 * boolean other than 1, 0, true or false, a path that is not absolute,
 * contains "..", or does not fit, or an HSM-backed build missing the partition ID
 * or the obk_path. cfg->debug is set even then, so the reason can be traced.
 * The caller clears `cfg` on either outcome.
 */
CK_RV tsra_pkcs11_config_load(tsra_pkcs11_config *cfg);

/*
 * Apply configuration file text to `cfg`, on top of what it holds: `len` bytes,
 * one "key = value" per line. Blanks around keys and values and a CR before
 * the line end are ignored; a blank line or a line starting with '#' is
 * skipped. Keys: store_dir and obk_path (absolute paths, a "file:" prefix is
 * stripped), persist and debug (booleans). Credentials are not keys.
 * CKR_GENERAL_ERROR, with the line in cfg->error, for anything else, including
 * a NUL byte. CKR_ARGUMENTS_BAD for a NULL `cfg`, or a NULL `text` with a
 * length. No I/O and no environment.
 */
CK_RV tsra_pkcs11_config_parse(tsra_pkcs11_config *cfg, const char *text, size_t len);

/*
 * Copy C_Login's PIN into the 16-byte credential PIN `out`, zero-padded: 4 to
 * 16 bytes, none of them NUL, so "1234" and "1234\0" cannot be one credential.
 * No hashing: the OpenSSL provider presents the raw 16 bytes to the same
 * partition. CKR_ARGUMENTS_BAD for a NULL `pin` with a length,
 * CKR_PIN_LEN_RANGE for any other length (an empty PIN included),
 * CKR_PIN_INVALID for a NUL byte. `out` is written only on success.
 */
CK_RV tsra_pkcs11_pin_normalise(
    const CK_UTF8CHAR *pin,
    CK_ULONG pin_len,
    CK_BYTE out[P11_CREDS_PIN_LEN]
);

/*
 * Read the owner backup key: the file cfg->obk_path, or without one the emulator
 * build's built-in key. C_Login reads it at every login and hands it to the
 * device only when the login provisions. A build without either fails closed.
 * CKR_FUNCTION_FAILED for that, and for a file that is missing, a symbolic
 * link, not a regular file or not exactly 48 bytes. The caller wipes `obk`.
 */
CK_RV tsra_pkcs11_config_obk(const tsra_pkcs11_config *cfg, CK_BYTE obk[P11_OBK_LEN]);

/*
 * Wipe `cfg` (credential id and PIN bytes). Callers must clear a loaded config
 * as soon as it is no longer needed, on success and error paths alike; the
 * wipe is not elided for stack objects about to leave scope.
 */
void tsra_pkcs11_config_clear(tsra_pkcs11_config *cfg);

#ifdef __cplusplus
}
#endif
