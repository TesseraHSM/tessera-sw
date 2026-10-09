// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>

#include "tsra_ossl_base.h"
#include "tsra_ossl_ec.h"
#include "tsra_ossl_helpers.h"
#include "tsra_ossl_hsm.h"

typedef struct
{
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    tsra_handle session;
} TSRA_ENCODER_CTX;

static const char *curve_id_to_str(tsra_ecc_curve curve_id)
{
    switch (curve_id)
    {

    case TSRA_ECC_CURVE_P256:
        return "P256";
    case TSRA_ECC_CURVE_P384:
        return "P384";
    case TSRA_ECC_CURVE_P521:
        return "P521";
    default:
        break;
    }

    return "unknown";
}

/* --- ENCODER (TEXT) --- */

static TSRA_ENCODER_CTX *tsra_ossl_encoder_newctx(TSRA_OSSL_PROV_CTX *provctx)
{
    TSRA_ENCODER_CTX *ectx;

    if ((ectx = OPENSSL_zalloc(sizeof(TSRA_ENCODER_CTX))) == NULL)
    {
        return NULL;
    }

    /* Lazy HSM session open is deferred from query_operation to here so
     * libcrypto can finish its own initialisation (e.g. DRBG bootstrap)
     * without us re-entering it. */
    if (tsra_ensure_session(provctx) != TSRA_STATUS_SUCCESS)
    {
        OPENSSL_free(ectx);
        return NULL;
    }

    ectx->handle = provctx->handle;
    ectx->libctx = provctx->libctx;
    ectx->session = provctx->session;

    return ectx;
}

static void tsra_ossl_encoder_freectx(TSRA_ENCODER_CTX *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    OPENSSL_clear_free(ctx, sizeof(TSRA_ENCODER_CTX));
}

static int tsra_ossl_encoder_encode(
    TSRA_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const TSRA_EC_KEY *ec_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;
    const TSRA_EC_GEN_CTX *genctx = &ec_key->genctx;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    const char *key_usage_str = tsra_ossl_key_usage_to_str(genctx->key_usage);

    BIO_printf(bio, "\n");
    BIO_printf(bio, "==== Key Generation Details ====\n");
    BIO_printf(bio, "provider             : tsra\n");
    BIO_printf(bio, "algorithm            : EC\n");
    BIO_printf(bio, "curve                : %s\n", curve_id_to_str(genctx->ec_curve_id));
    BIO_printf(bio, "session              : %s\n", genctx->session_flag ? "yes" : "no");
    if (genctx->masked_key_file[0] != '\0')
    {
        BIO_printf(bio, "masked-key file      : %s\n", genctx->masked_key_file);
    }
    BIO_printf(bio, "key usage            : %s\n", key_usage_str);
    BIO_printf(bio, "handle (public-key)  : %" PRIu32 "\n", ec_key->key.pub);
    BIO_printf(bio, "handle (private-key) : %" PRIu32 "\n", ec_key->key.priv);

    BIO_free(bio);
    return 1;
}

const OSSL_DISPATCH tsra_ossl_ec_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tsra_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tsra_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tsra_ossl_encoder_encode },
    { 0, NULL }
};

/* --- ENCODER (DER) --- */

static uint8_t *tsra_ossl_get_der_spki(
    tsra_handle session,
    tsra_handle key_handle,
    uint32_t *nbytes
)
{
    void *spki;
    const uint32_t spki_max_len = 2048;

    if ((spki = OPENSSL_zalloc(spki_max_len)) == NULL)
    {
        return NULL;
    }

    struct tsra_key_prop prop = { .id = TSRA_KEY_PROP_ID_PUB_KEY_INFO,
                                  .val = spki,
                                  .len = spki_max_len };

    if (tsra_key_get_prop(key_handle, &prop) != TSRA_STATUS_SUCCESS)
    {
        OPENSSL_free(spki);
        return NULL;
    }

    *nbytes = prop.len;
    return (uint8_t *)prop.val;
}

static int tsra_ossl_encoder_der_spki_encode(
    TSRA_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const TSRA_EC_KEY *ec_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;
    uint8_t *spki;
    uint32_t nbytes = 0;
    int rc = 0;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {

        if ((spki = tsra_ossl_get_der_spki(ctx->session, ec_key->key.pub, &nbytes)) != NULL)
        {
            BIO_write(bio, (const void *)spki, (int)nbytes);
            OPENSSL_clear_free(spki, nbytes);
            rc = 1;
        }
    }
    else if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {

        BIO_printf(bio, "info: DER-encoded SPKI not available for private keys\n");
        rc = 1;
    }

    BIO_free(bio);
    return rc;
}

static int tsra_ossl_encoder_der_spki_does_selection(ossl_unused void *provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        /*
         * technically, there is no SPKI for private keys,
         * but we still have to advertise it since OpenSSL requires it.
         *
         * If the encoding of OSSL_KEYMGMT_SELECT_PRIVATE_KEY
         * is ever requested, we will notify the caller.
         * */
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH tsra_ossl_ec_der_spki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tsra_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tsra_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))tsra_ossl_encoder_der_spki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tsra_ossl_encoder_der_spki_encode },
    { 0, NULL }
};

static int tsra_ossl_encoder_der_pki_encode(
    TSRA_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const TSRA_EC_KEY *ec_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;
    const TSRA_EC_GEN_CTX *genctx = &ec_key->genctx;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {

        const char *key_usage_str = tsra_ossl_key_usage_to_str(genctx->key_usage);

        BIO_printf(bio, "\n");
        BIO_printf(bio, "==== PrivateKeyInfo (PKCS#8) ====\n");
        BIO_printf(bio, "provider             : tsra\n");
        BIO_printf(bio, "algorithm            : EC\n");
        BIO_printf(bio, "curve                : %s\n", curve_id_to_str(genctx->ec_curve_id));
        BIO_printf(bio, "session              : %s\n", genctx->session_flag ? "yes" : "no");
        if (genctx->masked_key_file[0] != '\0')
        {
            BIO_printf(bio, "masked-key file      : %s\n", genctx->masked_key_file);
        }
        BIO_printf(bio, "key usage            : %s\n", key_usage_str);
        BIO_printf(bio, "handle (public-key)  : %" PRIu32 "\n", ec_key->key.pub);
        BIO_printf(bio, "handle (private-key) : %" PRIu32 "\n", ec_key->key.priv);
        BIO_printf(bio, "\n");
        BIO_printf(bio, "NOTE: Full PKCS#8 DER encoding is not implemented.\n");
        BIO_printf(bio, "      Keys remain in HSM and cannot be exported.\n");
    }
    else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        BIO_printf(bio, "info: DER-encoded PrivateKeyInfo not available for public keys\n");
    }

    BIO_free(bio);
    return 1;
}

static int tsra_ossl_encoder_der_pki_does_selection(ossl_unused void *provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH tsra_ossl_ec_der_pki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tsra_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tsra_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))tsra_ossl_encoder_der_pki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tsra_ossl_encoder_der_pki_encode },
    { 0, NULL }
};

/* --- ENCODER (PEM) --- */

static int tsra_ossl_encoder_pem_encode(
    TSRA_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const TSRA_EC_KEY *ec_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;
    const TSRA_EC_GEN_CTX *genctx = &ec_key->genctx;
    int rc = 0;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        uint8_t *spki;
        uint32_t nbytes = 0;

        if ((spki = tsra_ossl_get_der_spki(ctx->session, ec_key->key.pub, &nbytes)) != NULL)
        {
            PEM_write_bio(bio, "PUBLIC KEY", "", spki, nbytes);
            OPENSSL_clear_free(spki, nbytes);
            rc = 1;
        }
    }
    else if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        BIO_printf(bio, "-----BEGIN TSRA PRIVATE KEY-----\n");
        BIO_printf(bio, "HSM-backed private key - not exportable\n");
        BIO_printf(bio, "\n");
        BIO_printf(bio, "algorithm            : EC\n");
        BIO_printf(bio, "curve                : %s\n", curve_id_to_str(genctx->ec_curve_id));
        if (genctx->masked_key_file[0] != '\0')
        {
            BIO_printf(bio, "\n");
            BIO_printf(bio, "A masked key blob has been saved to:\n");
            BIO_printf(bio, "  %s\n", genctx->masked_key_file);
            BIO_printf(bio, "\n");
            BIO_printf(bio, "Use the store URI to reload this key:\n");
            BIO_printf(bio, "  tsra://%s;type=ec\n", genctx->masked_key_file);
        }
        BIO_printf(bio, "-----END TSRA PRIVATE KEY-----\n");
        rc = 1;
    }

    BIO_free(bio);
    return rc;
}

static int tsra_ossl_encoder_pem_does_selection(ossl_unused void *provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH tsra_ossl_ec_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tsra_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tsra_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))tsra_ossl_encoder_pem_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tsra_ossl_encoder_pem_encode },
    { 0, NULL }
};
