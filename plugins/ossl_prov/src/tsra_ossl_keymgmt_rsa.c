// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "tsra_ossl_base.h"
#include "tsra_ossl_file_io.h"
#include "tsra_ossl_helpers.h"
#include "tsra_ossl_hsm.h"
#include "tsra_ossl_masked_key.h"
#include "tsra_ossl_pkey_param.h"
#include "tsra_ossl_rsa.h"

/*
 * RSA/RSA-PSS KeyManagement
 *
 * NOTE: The HSM is not capable of generating RSA keys natively.
 * All RSA keys must be provided externally and imported into the HSM
 * via the tsra.input_key parameter.
 *
 * supported parameters (pkeyopt):
 *
 *   @rsa_keygen_bits
 *   Description: RSA public key bit length
 *   Accepted values: 2048, 3072, 4096
 *   Default: 2048
 *   Example:
 *      -pkeyopt rsa_keygen_bits:2048
 *
 *   @tsra.key_usage
 *   Description: Key usage type for the key pair
 *   Accepted values: digitalSignature (private: sign, public: verify)
 *                    keyWrapping (export HSM's internal unwrapping public key;
 *                                rsa_keygen_bits must be 2048 or omitted)
 *   Default value: digitalSignature
 *   Example:
 *      -pkeyopt tsra.key_usage:digitalSignature
 *      -pkeyopt tsra.key_usage:keyWrapping
 *
 *   @tsra.session
 *   Description: Whether to create a session key or persistent key
 *   Accepted values: true, false, 1, 0, yes, no
 *   Default value: false
 *   Example:
 *      -pkeyopt tsra.session:true
 *
 *   @tsra.input_key
 *   Description: Path to an external DER-encoded RSA private key to import.
 *   When set, the key is wrapped (RSA-AES) and unwrapped into the HSM.
 *   THIS PARAMETER IS REQUIRED - the HSM cannot generate RSA keys natively.
 *   Example:
 *      -pkeyopt tsra.input_key:/path/to/rsa_key.der
 *
 *   @tsra.key_kind
 *   Description: Key form to import: plain RSA or RSA-CRT (the HSM keeps the
 *   CRT components for faster private-key operations). The imported key must
 *   carry the CRT components (PKCS#1 makes them mandatory) unless RSA is
 *   selected explicitly.
 *   Accepted values: RSA, RSA-CRT
 *   Default value: RSA-CRT
 *   Example:
 *      -pkeyopt tsra.key_kind:RSA
 *
 *   @tsra.masked_key
 *   Description: Path to write the masked key blob for later reload via store
 *   Example:
 *      -pkeyopt tsra.masked_key:/path/to/masked.bin
 *
 *   @tsra.wrapped_key
 *   Description: Path to a pre-wrapped key blob (produced by the wrap_key tool).
 *   When set, the blob is unwrapped directly into the HSM without DER normalization.
 *   Mutually exclusive with tsra.input_key.
 *   Example:
 *      -pkeyopt tsra.wrapped_key:/path/to/wrapped.bin
 *
 * */

#define TSRA_RSA_POSSIBLE_SELECTIONS                                                               \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define TSRA_RSA_PUBKEY_BITS_MIN 2048
#define TSRA_RSA_PUBKEY_BITS_DEFAULT TSRA_RSA_PUBKEY_BITS_MIN
#define TSRA_RSA_WRAPPING_KEY_BITS 2048

#define TSRA_KEY_USAGE_DEFAULT KEY_USAGE_DIGITAL_SIGNATURE

/* Key Management Functions */

/*
 * Import a plaintext DER key file into the HSM.
 * Delegates to the shared tsra_import_key_pair() helper.
 */
static tsra_status tsra_ossl_rsa_keymgmt_gen_import(
    TSRA_RSA_GEN_CTX *genctx,
    const struct tsra_key_prop_list *priv_key_prop_list,
    const struct tsra_key_prop_list *pub_key_prop_list,
    tsra_handle *out_priv,
    tsra_handle *out_pub
)
{
    return tsra_import_key_pair(
        genctx->provctx,
        genctx->input_key_file,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );
}

static TSRA_RSA_KEY *tsra_ossl_keymgmt_gen(
    TSRA_RSA_GEN_CTX *genctx,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    TSRA_RSA_KEY *rsa_key;
    tsra_handle public = 0, private = 0;
    tsra_status status = TSRA_STATUS_INTERNAL_ERROR;
    const bool enable = true;
    const tsra_key_class priv_class = TSRA_KEY_CLASS_PRIVATE;
    const tsra_key_class pub_class = TSRA_KEY_CLASS_PUBLIC;
    /* The public half of a CRT pair is still a plain RSA public key. */
    const tsra_key_kind pub_key_kind = TSRA_KEY_KIND_RSA;
    const tsra_key_kind priv_key_kind = genctx->key_kind;

    /*
     * keyWrapping usage: retrieve the HSM's internal unwrapping key pair.
     * This key is generated and cached by the HSM — we only expose the public half
     * so callers can export it for offline key wrapping (RSA-AES Key Wrap).
     */
    if (genctx->key_usage == KEY_USAGE_KEY_WRAPPING)
    {
        tsra_handle wrap_pub = 0, wrap_priv = 0;

        /* The HSM's unwrapping key is fixed at 2048 bits. Reject mismatched sizes
         * so that keymgmt_get_params() reports the correct bit length. */
        if (genctx->pubkey_bits != TSRA_RSA_WRAPPING_KEY_BITS)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_KEY_SIZE_TOO_SMALL,
                "keyWrapping usage requires rsa_keygen_bits=%u "
                "(the HSM unwrapping key is fixed at %u bits)",
                TSRA_RSA_WRAPPING_KEY_BITS,
                TSRA_RSA_WRAPPING_KEY_BITS
            );
            return NULL;
        }

        status = tsra_get_unwrapping_key(genctx->provctx, &wrap_pub, &wrap_priv);
        if (status != TSRA_STATUS_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            return NULL;
        }

        if ((rsa_key = OPENSSL_zalloc(sizeof(TSRA_RSA_KEY))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }

        rsa_key->genctx = *genctx;
        rsa_key->key.pub = wrap_pub;
        rsa_key->has_public = true;
        rsa_key->key.priv = 0;
        rsa_key->has_private = false;

        return rsa_key;
    }

    /*
     * The HSM cannot generate RSA keys natively.
     * RSA keys must be provided externally via tsra.input_key or tsra.wrapped_key.
     */
    if (genctx->input_key_file[0] == '\0' && genctx->wrapped_key_file[0] == '\0')
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "tsra: RSA key generation requires tsra.input_key or tsra.wrapped_key parameter. "
            "The HSM cannot generate RSA keys natively. "
            "Please provide an external DER-encoded RSA private key: "
            "-pkeyopt tsra.input_key:/path/to/rsa_key.der "
            "or a pre-wrapped blob: "
            "-pkeyopt tsra.wrapped_key:/path/to/wrapped.bin"
        );
        return NULL;
    }

    /* RSA key properties: class, kind, bit_len, usage, and optionally session */
#define TSRA_RSA_KEY_PROPS_SIZE 5
    struct tsra_key_prop pub_key_props[TSRA_RSA_KEY_PROPS_SIZE] = {
        [0] = { .id = TSRA_KEY_PROP_ID_CLASS, .val = (void *)&pub_class, .len = sizeof(pub_class) },
        [1] = { .id = TSRA_KEY_PROP_ID_KIND,
                .val = (void *)&pub_key_kind,
                .len = sizeof(pub_key_kind) },
        [2] = { .id = TSRA_KEY_PROP_ID_BIT_LEN,
                .val = (void *)&genctx->pubkey_bits,
                .len = sizeof(genctx->pubkey_bits) },
        [3] = { .id = (tsra_key_prop_id)tsra_ossl_get_pub_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool) },
    };

    struct tsra_key_prop priv_key_props[TSRA_RSA_KEY_PROPS_SIZE] = {
        [0] = { .id = TSRA_KEY_PROP_ID_CLASS,
                .val = (void *)&priv_class,
                .len = sizeof(priv_class) },
        [1] = { .id = TSRA_KEY_PROP_ID_KIND,
                .val = (void *)&priv_key_kind,
                .len = sizeof(priv_key_kind) },
        [2] = { .id = TSRA_KEY_PROP_ID_BIT_LEN,
                .val = (void *)&genctx->pubkey_bits,
                .len = sizeof(genctx->pubkey_bits) },
        [3] = { .id = (tsra_key_prop_id)tsra_ossl_get_priv_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool) },
    };

    uint32_t pub_key_prop_count = 4;
    uint32_t priv_key_prop_count = 4;

    /* Add SESSION property if requested */
    if (genctx->session_flag)
    {
        pub_key_props[4] = (struct tsra_key_prop){
            .id = TSRA_KEY_PROP_ID_SESSION,
            .val = (void *)&enable,
            .len = sizeof(bool),
        };
        pub_key_prop_count++;

        priv_key_props[4] = (struct tsra_key_prop){
            .id = TSRA_KEY_PROP_ID_SESSION,
            .val = (void *)&enable,
            .len = sizeof(bool),
        };
        priv_key_prop_count++;
    }

    struct tsra_key_prop_list pub_key_prop_list = {
        .props = pub_key_props,
        .count = pub_key_prop_count,
    };

    struct tsra_key_prop_list priv_key_prop_list = {
        .props = priv_key_props,
        .count = priv_key_prop_count,
    };

    rsa_key = OPENSSL_zalloc(sizeof(TSRA_RSA_KEY));
    if (rsa_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (genctx->wrapped_key_file[0] != '\0')
    {
        /* Pre-wrapped blob path: unwrap directly into HSM */
        status = tsra_unwrap_key_pair(
            genctx->provctx,
            genctx->wrapped_key_file,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }
    else
    {
        /* Import external DER key via wrap-unwrap */
        status = tsra_ossl_rsa_keymgmt_gen_import(
            genctx,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }

    if (status != TSRA_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        goto cleanup;
    }

    rsa_key->genctx = *genctx;
    rsa_key->key.pub = public;
    rsa_key->has_public = true;
    rsa_key->key.priv = private;
    rsa_key->has_private = true;

    /* Handle masked key file output if requested */
    if (genctx->masked_key_file[0] != '\0')
    {
        /* First call to get required buffer size */
        struct tsra_key_prop prop = { .id = TSRA_KEY_PROP_ID_MASKED_KEY, .val = NULL, .len = 0 };

        tsra_status retrieve_status = tsra_key_get_prop(private, &prop);

        if (retrieve_status == TSRA_STATUS_BUFFER_TOO_SMALL && prop.len > 0)
        {
            /* Allocate buffer of exact size */
            uint32_t masked_key_buffer_size = prop.len;
            uint8_t *masked_key_buffer = OPENSSL_malloc(masked_key_buffer_size);
            if (masked_key_buffer == NULL)
            {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                status = TSRA_STATUS_INTERNAL_ERROR;
                goto cleanup;
            }

            /* Second call to retrieve the masked key */
            prop.val = masked_key_buffer;
            retrieve_status = tsra_key_get_prop(private, &prop);

            if (retrieve_status != TSRA_STATUS_SUCCESS)
            {
                OPENSSL_clear_free(masked_key_buffer, masked_key_buffer_size);
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                status = TSRA_STATUS_INTERNAL_ERROR;
                goto cleanup;
            }

            /* Write masked key to file with restricted permissions (owner-only) */
            if (tsra_ossl_write_masked_key_to_file(
                    masked_key_buffer,
                    prop.len,
                    genctx->masked_key_file
                ) != OSSL_SUCCESS)
            {
                OPENSSL_clear_free(masked_key_buffer, masked_key_buffer_size);
                ERR_raise_data(
                    ERR_LIB_PROV,
                    ERR_R_OPERATION_FAIL,
                    "failed to write masked key to '%s'",
                    genctx->masked_key_file
                );
                status = TSRA_STATUS_INTERNAL_ERROR;
                goto cleanup;
            }

            OPENSSL_clear_free(masked_key_buffer, masked_key_buffer_size);
        }
        else if (retrieve_status != TSRA_STATUS_PROPERTY_NOT_PRESENT)
        {
            /* Unexpected error - not BUFFER_TOO_SMALL and not PROPERTY_NOT_PRESENT */
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            status = TSRA_STATUS_INTERNAL_ERROR;
            goto cleanup;
        }
        /* If PROPERTY_NOT_PRESENT, continue without masked key */
    }

    /* Success — prevent cleanup from freeing the result */
    private = 0;
    public = 0;

cleanup:
    if (private != 0)
        tsra_key_delete(private);
    if (public != 0)
        tsra_key_delete(public);
    if (status != TSRA_STATUS_SUCCESS)
    {
        OPENSSL_free(rsa_key);
        rsa_key = NULL;
    }
    return rsa_key;
}

static TSRA_RSA_KEY *tsra_ossl_keymgmt_new(ossl_unused void *provctx)
{
    TSRA_RSA_KEY *key = OPENSSL_zalloc(sizeof(TSRA_RSA_KEY));
    if (key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return key;
}

static void tsra_ossl_keymgmt_free(TSRA_RSA_KEY *rsa_key)
{
    if (rsa_key == NULL)
    {
        return;
    }

    if (rsa_key->key.pub != 0)
    {
        tsra_key_delete(rsa_key->key.pub);
    }
    if (rsa_key->key.priv != 0)
    {
        tsra_key_delete(rsa_key->key.priv);
    }

    OPENSSL_free(rsa_key);
}

static void tsra_ossl_keymgmt_gen_cleanup(TSRA_RSA_GEN_CTX *genctx)
{
    if (genctx == NULL)
    {
        return;
    }

    OPENSSL_clear_free(genctx, sizeof(TSRA_RSA_GEN_CTX));
}

/*
 * Parse the tsra.key_kind string into an HSM key kind.
 * Returns 1 on success, 0 on failure.
 */
static int tsra_rsa_kind_from_str(const char *s, tsra_key_kind *kind)
{
    if (s == NULL)
    {
        return 0;
    }
    if (OPENSSL_strcasecmp(s, "RSA") == 0)
    {
        *kind = TSRA_KEY_KIND_RSA;
        return 1;
    }
    if (OPENSSL_strcasecmp(s, "RSA-CRT") == 0)
    {
        *kind = TSRA_KEY_KIND_RSA_CRT;
        return 1;
    }
    return 0;
}

/* Fits the longest accepted key usage, session and key kind value. */
#define TSRA_RSA_PARAM_STR_MAX 64

static int tsra_ossl_keymgmt_gen_set_params(TSRA_RSA_GEN_CTX *genctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    char str_val[TSRA_RSA_PARAM_STR_MAX];

    if (params == NULL)
    {
        return OSSL_SUCCESS;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL)
    {
        uint32_t bits;

        if (!OSSL_PARAM_get_uint32(p, &bits))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (bits < TSRA_RSA_PUBKEY_BITS_MIN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            return OSSL_FAILURE;
        }

        genctx->pubkey_bits = bits;
    }

    switch (
        tsra_ossl_get_str_param(params, TSRA_OSSL_PKEY_PARAM_KEY_USAGE, str_val, sizeof(str_val))
    )
    {
    case 1:
        if (tsra_ossl_key_usage_from_str(str_val, &genctx->key_usage) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return OSSL_FAILURE;
        }
        break;
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    switch (tsra_ossl_get_str_param(params, TSRA_OSSL_PKEY_PARAM_SESSION, str_val, sizeof(str_val)))
    {
    case 1: {
        int session_result = tsra_ossl_session_from_str(str_val);

        if (session_result < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        genctx->session_flag = (bool)session_result;
        break;
    }
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    switch (tsra_ossl_get_str_param(
        params,
        TSRA_OSSL_PKEY_PARAM_MASKED_KEY,
        genctx->masked_key_file,
        sizeof(genctx->masked_key_file)
    ))
    {
    case 1:
        if (tsra_ossl_masked_key_filepath_validate(genctx->masked_key_file) < 0)
        {
            genctx->masked_key_file[0] = '\0';
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        break;
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    switch (tsra_ossl_get_str_param(
        params,
        TSRA_OSSL_PKEY_PARAM_INPUT_KEY,
        genctx->input_key_file,
        sizeof(genctx->input_key_file)
    ))
    {
    case 1:
        if (tsra_ossl_input_key_filepath_validate(genctx->input_key_file) < 0)
        {
            genctx->input_key_file[0] = '\0';
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        break;
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    switch (tsra_ossl_get_str_param(
        params,
        TSRA_OSSL_PKEY_PARAM_WRAPPED_KEY,
        genctx->wrapped_key_file,
        sizeof(genctx->wrapped_key_file)
    ))
    {
    case 1:
        if (tsra_ossl_input_key_filepath_validate(genctx->wrapped_key_file) < 0)
        {
            genctx->wrapped_key_file[0] = '\0';
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        break;
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    switch (tsra_ossl_get_str_param(params, TSRA_OSSL_PKEY_PARAM_KEY_KIND, str_val, sizeof(str_val))
    )
    {
    case 1:
        if (!tsra_rsa_kind_from_str(str_val, &genctx->key_kind))
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_INVALID_KEY,
                "tsra: tsra.key_kind must be 'RSA' or 'RSA-CRT'"
            );
            return OSSL_FAILURE;
        }
        break;
    case -1:
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return OSSL_FAILURE;
    default: /* absent */
        break;
    }

    /* Reject if both input_key and wrapped_key are set */
    if (genctx->input_key_file[0] != '\0' && genctx->wrapped_key_file[0] != '\0')
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY,
            "tsra: tsra.input_key and tsra.wrapped_key are mutually exclusive"
        );
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static TSRA_RSA_GEN_CTX *tsra_ossl_keymgmt_gen_init_common(
    void *ctx,
    int selection,
    const OSSL_PARAM params[],
    int key_type
)
{
    TSRA_RSA_GEN_CTX *genctx;
    TSRA_OSSL_PROV_CTX *provctx = ctx;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return NULL;
    }

    genctx = OPENSSL_zalloc(sizeof(TSRA_RSA_GEN_CTX));

    if (genctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Lazy HSM session open is deferred from query_operation to here so
     * libcrypto can finish its own initialisation (e.g. DRBG bootstrap)
     * without us re-entering it. */
    if (tsra_ensure_session(provctx) != TSRA_STATUS_SUCCESS)
    {
        OPENSSL_free(genctx);
        return NULL;
    }

    genctx->session = provctx->session;
    genctx->provctx = provctx;
    genctx->key_type = key_type;
    genctx->pubkey_bits = TSRA_RSA_PUBKEY_BITS_DEFAULT;
    genctx->key_usage = TSRA_KEY_USAGE_DEFAULT;
    genctx->session_flag = false;
    genctx->masked_key_file[0] = '\0';
    genctx->input_key_file[0] = '\0';
    genctx->wrapped_key_file[0] = '\0';
    genctx->key_kind = TSRA_KEY_KIND_RSA_CRT;

    if (tsra_ossl_keymgmt_gen_set_params(genctx, params) == 0)
    {
        tsra_ossl_keymgmt_gen_cleanup(genctx);
        return NULL;
    }

    return genctx;
}

static TSRA_RSA_GEN_CTX *tsra_ossl_keymgmt_gen_init_rsa(
    void *ctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    return tsra_ossl_keymgmt_gen_init_common(ctx, selection, params, TSRA_KEY_TYPE_RSA);
}

static TSRA_RSA_GEN_CTX *tsra_ossl_keymgmt_gen_init_rsa_pss(
    void *ctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    return tsra_ossl_keymgmt_gen_init_common(ctx, selection, params, TSRA_KEY_TYPE_RSA_PSS);
}

static int tsra_ossl_keymgmt_has(const TSRA_RSA_KEY *rsa_key, int selection)
{
    int has_selection = 1;

    if (rsa_key == NULL)
    {
        return OSSL_FAILURE;
    }

    if ((selection & TSRA_RSA_POSSIBLE_SELECTIONS) == 0)
    {
        return OSSL_SUCCESS;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        has_selection &= rsa_key->has_private;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        has_selection &= rsa_key->has_public;
    }

    return has_selection ? OSSL_SUCCESS : OSSL_FAILURE;
}

static int tsra_ossl_keymgmt_match(
    const TSRA_RSA_KEY *rsa_key1,
    const TSRA_RSA_KEY *rsa_key2,
    int selection
)
{
    if (rsa_key1 == NULL || rsa_key2 == NULL)
    {
        return OSSL_FAILURE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (rsa_key1->key.pub != rsa_key2->key.pub)
        {
            return OSSL_FAILURE;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (rsa_key1->key.priv != rsa_key2->key.priv)
        {
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static void *tsra_ossl_keymgmt_load(const void *reference, size_t reference_sz)
{
    TSRA_RSA_KEY *dst_key;

    /* Validate reference size matches our key object */
    if (reference == NULL || reference_sz != sizeof(TSRA_RSA_KEY))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    /* Create a copy of the key - reference contains the raw bytes of TSRA_RSA_KEY */
    dst_key = OPENSSL_zalloc(sizeof(TSRA_RSA_KEY));
    if (dst_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy the key structure from reference */
    memcpy(dst_key, reference, sizeof(TSRA_RSA_KEY));

    return dst_key;
}

static int tsra_ossl_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    TSRA_RSA_KEY *rsa_key = keydata;

    if (rsa_key == NULL || params == NULL)
    {
        return OSSL_FAILURE;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        const OSSL_PARAM *p;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
        if (p != NULL)
        {
            if (!OSSL_PARAM_get_uint32(p, &rsa_key->genctx.pubkey_bits))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return OSSL_FAILURE;
            }
        }

        rsa_key->has_public = true;
    }

    return OSSL_SUCCESS;
}

static int tsra_ossl_keymgmt_export(
    ossl_unused const void *keydata,
    ossl_unused int selection,
    ossl_unused OSSL_CALLBACK *param_cb,
    ossl_unused void *cbarg
)
{
    return OSSL_FAILURE;
}

static const OSSL_PARAM *tsra_ossl_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
                                               OSSL_PARAM_END };

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return import_types;
    }

    return NULL;
}

static const OSSL_PARAM *tsra_ossl_keymgmt_export_types(ossl_unused int selection)
{
    // TODO: Return exportable parameter types
    return NULL;
}

static int tsra_ossl_keymgmt_get_params(TSRA_RSA_KEY *key, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_uint32(p, key->genctx.pubkey_bits))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
    {
        /* RSA signature size equals key size in bytes */
        size_t sig_size = key->genctx.pubkey_bits / 8;
        if (!OSSL_PARAM_set_size_t(p, sig_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *tsra_ossl_keymgmt_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM gettable_params[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_BITS, NULL),
                                                  OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
                                                  OSSL_PARAM_END };

    return gettable_params;
}

static const OSSL_PARAM *tsra_ossl_keymgmt_gen_settable_params(
    ossl_unused void *genctx,
    ossl_unused void *ctx
)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_SESSION, NULL, 0),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_MASKED_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_INPUT_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_WRAPPED_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(TSRA_OSSL_PKEY_PARAM_KEY_KIND, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

static const char *tsra_ossl_keymgmt_rsa_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "RSA";
    case OSSL_OP_ASYM_CIPHER:
        return "RSA";
    }
    return "RSA";
}

static const char *tsra_ossl_keymgmt_rsa_pss_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "RSA-PSS";
    }
    return "RSA-PSS";
}

/* RSA Key Management */
const OSSL_DISPATCH tsra_ossl_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tsra_ossl_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))tsra_ossl_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tsra_ossl_keymgmt_gen_init_rsa },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))tsra_ossl_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))tsra_ossl_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))tsra_ossl_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tsra_ossl_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tsra_ossl_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tsra_ossl_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tsra_ossl_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))tsra_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tsra_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tsra_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tsra_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))tsra_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))tsra_ossl_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))tsra_ossl_keymgmt_rsa_query_operation_name },
    { 0, NULL }
};

const OSSL_DISPATCH tsra_ossl_rsa_pss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tsra_ossl_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))tsra_ossl_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tsra_ossl_keymgmt_gen_init_rsa_pss },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))tsra_ossl_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))tsra_ossl_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))tsra_ossl_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tsra_ossl_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tsra_ossl_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tsra_ossl_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tsra_ossl_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))tsra_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tsra_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tsra_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tsra_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))tsra_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))tsra_ossl_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))tsra_ossl_keymgmt_rsa_pss_query_operation_name },
    { 0, NULL }
};
