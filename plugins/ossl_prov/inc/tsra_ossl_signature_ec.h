// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>

#include "tsra_ossl_base.h"
#include "tsra_ossl_ec.h"

/* Signature context for ECDSA operations */
typedef struct
{
    TSRA_OSSL_PROV_CTX *provctx; /* Provider context */
    TSRA_EC_KEY *key;            /* EC key (public or private) */
    const EVP_MD *md;            /* Hash algorithm (SHA1, SHA256, etc.) */
    int operation;               /* Sign (1) or Verify (0) */
    tsra_handle sign_ctx;        /* HSM streaming sign/verify context */
} tsra_ec_sig_ctx;

/* Dispatch tables */
extern const OSSL_DISPATCH tsra_ossl_ecdsa_signature_functions[];
