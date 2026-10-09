// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <tsra.h>

#include <openssl/obj_mac.h>

#include "tsra_ossl_base.h"
#include "tsra_ossl_pkey_param.h"

/*
 * EC-specific definitions which are shared
 * between multiple subsystems like keymgmt, encoder, ...
 * */

/* EC curve key sizes in bits */
#define TSRA_EC_P256_KEY_BITS 256
#define TSRA_EC_P384_KEY_BITS 384
#define TSRA_EC_P521_KEY_BITS 521

/* EC curve coordinate sizes in bytes (ceil(bits/8)) */
#define TSRA_EC_P256_COORD_SIZE 32
#define TSRA_EC_P384_COORD_SIZE 48
#define TSRA_EC_P521_COORD_SIZE 66

/*
 * Raw ECDSA signature sizes (r || s concatenated, no DER encoding).
 * The HSM uses raw format and expects exact buffer sizes.
 */
#define TSRA_EC_P256_SIG_SIZE 64
#define TSRA_EC_P384_SIG_SIZE 96
#define TSRA_EC_P521_SIG_SIZE 132

typedef struct
{
    tsra_ecc_curve ec_curve_id;
    TSRA_KEY_USAGE_TYPE key_usage;
    tsra_handle session;
    TSRA_OSSL_PROV_CTX *provctx;
    bool session_flag;
    char masked_key_file[TSRA_MAX_FILE_PATH];
    char input_key_file[TSRA_MAX_FILE_PATH];
    char wrapped_key_file[TSRA_MAX_FILE_PATH];
} TSRA_EC_GEN_CTX;

typedef struct
{
    TSRA_KEY_PAIR_OBJ key;
    TSRA_EC_GEN_CTX genctx;
    bool has_public, has_private;

    unsigned char *pub_key_data; /* Imported peer public key */
    size_t pub_key_data_len;
    char group_name[64];
    bool is_imported;
} TSRA_EC_KEY;

static inline int tsra_ossl_ec_curve_id_to_nid(int curve_id)
{
    switch (curve_id)
    {
    case TSRA_ECC_CURVE_P256:
        return NID_X9_62_prime256v1;
    case TSRA_ECC_CURVE_P384:
        return NID_secp384r1;
    case TSRA_ECC_CURVE_P521:
        return NID_secp521r1;
    default:
        return NID_undef;
    }
}

static inline int tsra_ossl_ec_curve_id_to_bits(int curve_id)
{
    switch (curve_id)
    {
    case TSRA_ECC_CURVE_P256:
        return TSRA_EC_P256_KEY_BITS;
    case TSRA_ECC_CURVE_P384:
        return TSRA_EC_P384_KEY_BITS;
    case TSRA_ECC_CURVE_P521:
        return TSRA_EC_P521_KEY_BITS;
    default:
        return 0;
    }
}

#ifdef __cplusplus
}
#endif
