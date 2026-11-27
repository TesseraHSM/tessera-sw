// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Prepares the RSA key pkcs11test's KeyPair fixture unwraps
 * (rsa-fixture.patch): a fresh RSA-2048 key as PKCS#8, wrapped with
 * CKM_RSA_AES_KEY_WRAP for the token's RSA unwrapping key, whose public half
 * it reads through the module. The token generates no RSA keys, so this is
 * how the signature tests get one. The blob is RSA-OAEP (SHA-256, MGF1 with
 * SHA-256, no label) of a random AES-256 key-encryption key, then the key
 * wrapped under it with RFC 5649.
 *
 *   rsa_blob <module.so> <pin> <out-file>
 *
 * The module takes its device and store settings from the environment, as in
 * every process that loads it. The partition's unwrapping key is the same for
 * every process until the device is provisioned afresh, so one blob serves
 * every run of the gate against one device.
 */

#include "tsra_pkcs11_compat.h"

#include <dlfcn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* The fixture's key size, and the AES-256 key-encryption key. */
#define RSA_BITS 2048
#define KEK_BYTES 32
/* The partition's unwrapping key: RSA-2048, so its modulus fits this. */
#define UNWRAP_MODULUS_MAX 256
#define EXPONENT_MAX 8
/* What RFC 5649 adds at most: padding to a semiblock, and one semiblock. */
#define KWP_GROWTH 16

/* Run one PKCS#11 call; on failure name it and stop. */
#define P11_CALL(call)                                                                             \
    do                                                                                             \
    {                                                                                              \
        rv = (call);                                                                               \
        if (rv != CKR_OK)                                                                          \
        {                                                                                          \
            fprintf(stderr, "rsa_blob: %s: 0x%lx\n", #call, (unsigned long)rv);                    \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

/* Fail with the step's name when `ok` is false. */
#define SSL_CALL(ok, what)                                                                         \
    do                                                                                             \
    {                                                                                              \
        if (!(ok))                                                                                 \
        {                                                                                          \
            fprintf(stderr, "rsa_blob: %s failed\n", (what));                                      \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <module.so> <pin> <out-file>\n", argv[0]);
        return 2;
    }
    int status = 1;
    CK_RV rv = CKR_OK;
    bool initialized = false;
    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST_PTR p11 = NULL;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY *wrapping = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_CIPHER *kwp = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
    unsigned char *blob = NULL;
    size_t blob_len = 0;
    unsigned char kek[KEK_BYTES];
    FILE *out = NULL;

    void *dl = dlopen(argv[1], RTLD_NOW);
    if (dl == NULL)
    {
        fprintf(stderr, "rsa_blob: %s\n", dlerror());
        return 1;
    }
    CK_C_GetFunctionList get_list = (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
    if ((get_list == NULL) || (get_list(&p11) != CKR_OK))
    {
        fprintf(stderr, "rsa_blob: no function list in %s\n", argv[1]);
        dlclose(dl);
        return 1;
    }

    /* The partition's unwrapping key, as the module hands it out. */
    CK_BYTE modulus[UNWRAP_MODULUS_MAX];
    CK_BYTE exponent[EXPONENT_MAX];
    CK_ULONG bits = RSA_BITS;
    CK_BBOOL yes = CK_TRUE;
    CK_MECHANISM gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_ATTRIBUTE pub_tmpl[] = { { CKA_MODULUS_BITS, &bits, sizeof(bits) },
                                { CKA_WRAP, &yes, sizeof(yes) } };
    CK_ATTRIBUTE priv_tmpl[] = { { CKA_UNWRAP, &yes, sizeof(yes) } };
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ATTRIBUTE read[] = { { CKA_MODULUS, modulus, sizeof(modulus) },
                            { CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent) } };
    P11_CALL(p11->C_Initialize(NULL));
    initialized = true;
    P11_CALL(p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s));
    P11_CALL(p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)argv[2], (CK_ULONG)strlen(argv[2])));
    P11_CALL(p11->C_GenerateKeyPair(s, &gen, pub_tmpl, 2, priv_tmpl, 1, &pub, &priv));
    P11_CALL(p11->C_GetAttributeValue(s, pub, read, 2));

    /* OpenSSL in a context of its own: the module's process shares libcrypto. */
    ctx = OSSL_LIB_CTX_new();
    prov = (ctx != NULL) ? OSSL_PROVIDER_load(ctx, "default") : NULL;
    SSL_CALL(prov != NULL, "the default provider");
    n = BN_bin2bn(modulus, (int)read[0].ulValueLen, NULL);
    e = BN_bin2bn(exponent, (int)read[1].ulValueLen, NULL);
    bld = OSSL_PARAM_BLD_new();
    SSL_CALL(
        (n != NULL) && (e != NULL) && (bld != NULL) &&
            (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1) &&
            (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1) &&
            ((params = OSSL_PARAM_BLD_to_param(bld)) != NULL),
        "the unwrapping key's parameters"
    );
    pctx = EVP_PKEY_CTX_new_from_name(ctx, "RSA", NULL);
    SSL_CALL(
        (pctx != NULL) && (EVP_PKEY_fromdata_init(pctx) == 1) &&
            (EVP_PKEY_fromdata(pctx, &wrapping, EVP_PKEY_PUBLIC_KEY, params) == 1),
        "the unwrapping key"
    );
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    /* The key the fixture signs with, as PKCS#8. */
    key = EVP_PKEY_Q_keygen(ctx, NULL, "RSA", (size_t)RSA_BITS);
    p8 = (key != NULL) ? EVP_PKEY2PKCS8(key) : NULL;
    der_len = (p8 != NULL) ? i2d_PKCS8_PRIV_KEY_INFO(p8, &der) : -1;
    SSL_CALL(der_len > 0, "the RSA key");

    /* OAEP block of the KEK, then the key wrapped under it. */
    SSL_CALL(RAND_bytes_ex(ctx, kek, sizeof(kek), 0) == 1, "the key-encryption key");
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, wrapping, NULL);
    size_t oaep_len = 0;
    SSL_CALL(
        (pctx != NULL) && (EVP_PKEY_encrypt_init(pctx) == 1) &&
            (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) == 1) &&
            (EVP_PKEY_CTX_set_rsa_oaep_md_name(pctx, "SHA256", NULL) == 1) &&
            (EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL) == 1) &&
            (EVP_PKEY_encrypt(pctx, NULL, &oaep_len, kek, sizeof(kek)) == 1),
        "OAEP sizing"
    );
    blob = OPENSSL_malloc(oaep_len + (size_t)der_len + KWP_GROWTH);
    SSL_CALL(blob != NULL, "the blob buffer");
    blob_len = oaep_len;
    SSL_CALL(EVP_PKEY_encrypt(pctx, blob, &blob_len, kek, sizeof(kek)) == 1, "OAEP");
    kwp = EVP_CIPHER_fetch(ctx, "AES-256-WRAP-PAD", NULL);
    cctx = EVP_CIPHER_CTX_new();
    int part = 0;
    int last = 0;
    SSL_CALL(kwp != NULL, "AES-256-WRAP-PAD");
    SSL_CALL(cctx != NULL, "a cipher context");
    EVP_CIPHER_CTX_set_flags(cctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    SSL_CALL(
        (EVP_EncryptInit_ex2(cctx, kwp, kek, NULL, NULL) == 1) &&
            (EVP_EncryptUpdate(cctx, blob + blob_len, &part, der, der_len) == 1) &&
            (EVP_EncryptFinal_ex(cctx, blob + blob_len + part, &last) == 1),
        "RFC 5649"
    );
    blob_len += (size_t)part + (size_t)last;

    out = fopen(argv[3], "wb");
    SSL_CALL((out != NULL) && (fwrite(blob, 1, blob_len, out) == blob_len), argv[3]);
    status = 0;

cleanup:
    if ((out != NULL) && (fclose(out) != 0))
    {
        status = 1;
    }
    OPENSSL_cleanse(kek, sizeof(kek));
    OPENSSL_clear_free(der, (size_t)((der_len > 0) ? der_len : 0));
    OPENSSL_free(blob);
    PKCS8_PRIV_KEY_INFO_free(p8);
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(kwp);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(key);
    EVP_PKEY_free(wrapping);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(ctx);
    if (s != CK_INVALID_HANDLE)
    {
        (void)p11->C_CloseSession(s); /* the pair objects are session objects */
    }
    if (initialized)
    {
        (void)p11->C_Finalize(NULL);
    }
    dlclose(dl);
    return ((status == 0) && (rv == CKR_OK)) ? 0 : 1;
}
