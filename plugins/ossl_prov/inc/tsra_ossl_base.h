// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdbool.h>
#include <stdint.h>
#include <tsra.h>

#include "tsra_ossl_helpers.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Value provided by CMake, defined in top level CMakeLists.txt
#define TSRA_OSSL_VERSION ""
#define TSRA_OSSL_NAME "tsra"

#ifndef _Return_type_success_
#define _Return_type_success_(expr)
#endif

typedef _Return_type_success_(return == 1) int OSSL_STATUS;
#define OSSL_SUCCESS (1)
#define OSSL_FAILURE (0)

typedef struct
{
    tsra_handle priv;
} TSRA_KEY_OBJ;

typedef struct
{
    tsra_handle pub;
    tsra_handle priv;
} TSRA_KEY_PAIR_OBJ;

/* Maximum file path length for key and config file paths */
#define TSRA_MAX_FILE_PATH 4096

/* Default file paths for partition keys, credentials, and POTA keys.
 * These are relative to the current working directory so that the provider
 * works out of the box without any system-wide setup. Override via openssl.cnf
 * (key material) or environment variables (credentials). */
#define TSRA_DEFAULT_BMK_PATH "./bmk.bin"
#define TSRA_DEFAULT_MUK_PATH "./muk.bin"
#define TSRA_DEFAULT_OBK_PATH "./obk.bin"
#define TSRA_DEFAULT_MOBK_PATH "./mobk.bin"
#define TSRA_DEFAULT_CREDENTIALS_ID_PATH "./credentials_id.bin"
#define TSRA_DEFAULT_CREDENTIALS_PIN_PATH "./credentials_pin.bin"
#define TSRA_DEFAULT_POTA_PRIVATE_KEY_PATH "./pota_private_key.der"
#define TSRA_DEFAULT_POTA_PUBLIC_KEY_PATH "./pota_public_key.der"

/* Size of binary credentials (ID and PIN) in bytes */
#define TSRA_CREDENTIALS_SIZE 16

/* Length of hex-encoded credential strings (2 hex chars per byte) */
#define TSRA_CREDENTIALS_HEX_SIZE (TSRA_CREDENTIALS_SIZE * 2)

/* Configuration parameter names for openssl.cnf */
#define TSRA_CFG_BMK_PATH "tsra-bmk-path"
#define TSRA_CFG_MUK_PATH "tsra-muk-path"
#define TSRA_CFG_OBK_PATH "tsra-obk-path"
#define TSRA_CFG_MOBK_PATH "tsra-mobk-path"
#define TSRA_CFG_OBK_SOURCE "tsra-obk-source"
#define TSRA_CFG_POTA_SOURCE "tsra-pota-source"
#define TSRA_CFG_POTA_PRIVATE_KEY_PATH "tsra-pota-private-key-path"
#define TSRA_CFG_POTA_PUBLIC_KEY_PATH "tsra-pota-public-key-path"
#define TSRA_CFG_API_REVISION "tsra-api-revision"

/* Environment variable names for hex-encoded credentials (not in openssl.cnf for security).
 * Each value must be exactly TSRA_CREDENTIALS_HEX_SIZE hex characters (0-9, a-f, A-F).
 * If unset, the provider falls back to reading the default credential files in CWD. */
#define TSRA_ENV_CREDENTIALS_ID "TSRA_CREDENTIALS_ID"
#define TSRA_ENV_CREDENTIALS_PIN "TSRA_CREDENTIALS_PIN"

/* Supported API revision range */
#define TSRA_API_REVISION_MIN_MAJOR 1
#define TSRA_API_REVISION_MIN_MINOR 0
#define TSRA_API_REVISION_MAX_MAJOR 1
#define TSRA_API_REVISION_MAX_MINOR 0
#define TSRA_API_REVISION_DEFAULT_MAJOR 1
#define TSRA_API_REVISION_DEFAULT_MINOR 0

/* Forward declaration — defined in tsra_ossl_resiliency.c */
struct tsra_resiliency_ctx;

typedef struct
{
    char bmk_path[TSRA_MAX_FILE_PATH];
    char muk_path[TSRA_MAX_FILE_PATH];
    char obk_path[TSRA_MAX_FILE_PATH];
    char mobk_path[TSRA_MAX_FILE_PATH];
    char pota_private_key_path[TSRA_MAX_FILE_PATH];
    char pota_public_key_path[TSRA_MAX_FILE_PATH];
    uint8_t credentials_id[TSRA_CREDENTIALS_SIZE];
    uint8_t credentials_pin[TSRA_CREDENTIALS_SIZE];
    uint16_t api_revision_major;
    uint16_t api_revision_minor;
    bool credentials_id_from_env;
    bool credentials_pin_from_env;
    bool use_tpm_obk;
    bool use_tpm_pota;
    bool resiliency_enabled;
    char resiliency_storage_dir[4096];
} TSRA_CONFIG;

typedef struct
{
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *handle;
    OSSL_PROVIDER *default_provider; /* Ref to default provider in the NULL ctx;
                                      * kept alive so the Rust library's bare
                                      * EVP calls (RAND_bytes, EC keygen, …)
                                      * always have a provider to service them. */
    tsra_handle device;
    tsra_handle session;
    CRYPTO_RWLOCK *session_lock; /* serializes lazy session-open */
    TSRA_CONFIG config;
    struct
    {
        CRYPTO_RWLOCK *lock;
        tsra_handle pub;
        tsra_handle priv;
    } unwrapping_key;                           /* Cached UK handles (thread-safe) */
    struct tsra_resiliency_ctx *resiliency_ctx; /* NULL when resiliency disabled */
} TSRA_OSSL_PROV_CTX;

static const OSSL_PARAM tsra_ossl_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END
};

// EVP_MD_CTX_dup is a helpful function for the provider, but was not added until OpenSSL 3.1
// This function is copied from 3.1 to allow its use when the provider is built against 3.0
#if OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0
EVP_MD_CTX *EVP_MD_CTX_dup(const EVP_MD_CTX *in);

#endif // OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR == 0

#ifdef __cplusplus
}
#endif
