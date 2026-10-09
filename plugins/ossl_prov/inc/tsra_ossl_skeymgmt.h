// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <openssl/core_dispatch.h>
#include <stdbool.h>
#include <stddef.h>
#include <tsra.h>

#include "tsra_ossl_base.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * OpenSSL 3.5 SKEYMGMT (EVP_SKEY) is required for the opaque AES symmetric key
 * object.  All of this is compiled out on older OpenSSL where the dispatch ids
 * and OSSL_SKEY_* params do not exist.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L

/* Maximum length of the decimal key-id string surfaced via get_key_id. */
#define TSRA_SKEY_KEY_ID_MAX 24

/*
 * Provider-private keydata object behind an EVP_SKEY.
 *
 * It holds ONLY an opaque HSM key handle plus metadata — never raw key
 * material.  For AES-XTS the single handle internally references the HSM key
 * pair (the pair is opaque below the FFI boundary), so one handle is enough
 * for all three modes.
 *
 * Produced by tsra_ossl_aes_skeymgmt_{import,generate}; consumed by the AES
 * cipher's *_skey_init hooks (which copy out key_handle / key_kind); freed by
 * tsra_ossl_aes_skeymgmt_free.
 */
typedef struct tsra_skey_st
{
    TSRA_OSSL_PROV_CTX *provctx;
    tsra_handle key_handle;            /* opaque HSM key handle (owned)        */
    tsra_key_kind key_kind;            /* AES / AES_GCM / AES_XTS              */
    size_t key_bytes;                  /* raw key length in bytes, 0 = unknown */
    char key_id[TSRA_SKEY_KEY_ID_MAX]; /* decimal handle, for get_key_id       */
} TSRA_SKEY;

/* SKEYMGMT dispatch table for the "AES" opaque symmetric key. */
extern const OSSL_DISPATCH tsra_ossl_aes_skeymgmt_functions[];

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

#ifdef __cplusplus
}
#endif
