// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the mechanism table (src/tsra_pkcs11_mech.c) against the
 * dispatch arms that run the mechanisms: the digest table
 * (src/tsra_pkcs11_digest.c), the cipher and sign tables and the
 * key-generation template check (src/tsra_pkcs11_template.c), the EC
 * key-pair template check (src/tsra_pkcs11_ec_template.c), and the unwrapping
 * key pair and unwrap checks (src/tsra_pkcs11_unwrap_params.c), and the derive
 * check (src/tsra_pkcs11_derive_params.c). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src mech_table_test.c \
 *       ../src/tsra_pkcs11_mech.c ../src/tsra_pkcs11_template.c \
 *       ../src/tsra_pkcs11_attr_types.c ../src/tsra_pkcs11_digest.c \
 *       ../src/tsra_pkcs11_ec_template.c ../src/tsra_pkcs11_unwrap_params.c \
 *       ../src/tsra_pkcs11_derive_params.c \
 *       -o mech_table_test && ./mech_table_test
 *
 * Both directions: every row advertises exactly the flags its arms implement,
 * and every mechanism an arm implements has a row. A row without its arm, or
 * an arm without its row, fails here.
 */

#include "tsra_pkcs11_derive_params.h"
#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_mech.h"
#include "tsra_pkcs11_template.h"
#include "tsra_pkcs11_unwrap_params.h"

#include <stdio.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

/* Every standard CKM_* value lies below this; the sweep looks for arms there. */
#define SWEEP_END 0x10000

/* The flags the dispatch arms implement for `t`, with the EC capability flags
 * for an EC arm. */
static CK_FLAGS arm_flags(CK_MECHANISM_TYPE t)
{
    CK_FLAGS f = 0;
    if (tsra_pkcs11_digest_mech_len(t) != 0)
    {
        f |= CKF_DIGEST;
    }
    if (tsra_pkcs11_cipher_mech_find(t) != NULL)
    {
        f |= CKF_ENCRYPT | CKF_DECRYPT;
    }
    const tsra_pkcs11_sign_mech *sm = tsra_pkcs11_sign_mech_find(t);
    if (sm != NULL)
    {
        f |= CKF_SIGN | CKF_VERIFY;
    }
    const tsra_pkcs11_keygen_policy *policy = NULL;
    CK_ULONG len = 0;
    CK_BBOOL token = CK_FALSE;
    if (tsra_pkcs11_keygen_check_template(t, NULL, 0, &policy, &len, &token) !=
        CKR_MECHANISM_INVALID)
    {
        f |= CKF_GENERATE;
    }
    tsra_pkcs11_ec_keygen kg;
    bool ec_keygen =
        tsra_pkcs11_ec_keygen_check(t, NULL, 0, NULL, 0, &kg, NULL) != CKR_MECHANISM_INVALID;
    CK_BBOOL priv_token = CK_FALSE;
    if (ec_keygen || (tsra_pkcs11_unwrapping_pair_check(t, NULL, 0, NULL, 0, &token, &priv_token) !=
                      CKR_MECHANISM_INVALID))
    {
        f |= CKF_GENERATE_KEY_PAIR;
    }
    /* An EC mechanism also reports what EC it handles. */
    if (ec_keygen || ((sm != NULL) && (sm->key_type == CKK_EC)))
    {
        f |= EC_MECH_FLAGS;
    }
    CK_MECHANISM m = { t, NULL, 0 };
    tsra_pkcs11_rsa_aes_params params;
    if (tsra_pkcs11_unwrap_params_check(&m, &params) != CKR_MECHANISM_INVALID)
    {
        f |= CKF_UNWRAP;
    }
    tsra_pkcs11_derive_params derive;
    if (tsra_pkcs11_derive_params_check(&m, &derive) != CKR_MECHANISM_INVALID)
    {
        /* A derivation from an EC key also reports what EC it handles. */
        f |= CKF_DERIVE | ((derive.base_key_type == CKK_EC) ? EC_MECH_FLAGS : 0);
    }
    return f;
}

/* Whether C_GenerateKey with `t` accepts CKA_VALUE_LEN = `len`. */
static bool keygen_accepts(CK_MECHANISM_TYPE t, CK_ULONG len)
{
    CK_ATTRIBUTE a = { CKA_VALUE_LEN, &len, sizeof(len) };
    const tsra_pkcs11_keygen_policy *policy = NULL;
    CK_ULONG value_len = 0;
    CK_BBOOL token = CK_FALSE;
    return tsra_pkcs11_keygen_check_template(t, &a, 1, &policy, &value_len, &token) == CKR_OK;
}

static void test_rows(void)
{
    printf("== every row is backed by its dispatch arms ==\n");
    char msg[128];
    for (CK_ULONG i = 0; i < TSRA_PKCS11_MECH_COUNT; i++)
    {
        const tsra_pkcs11_mech_t *m = &tsra_pkcs11_mechs[i];
        unsigned long t = (unsigned long)m->type;

        snprintf(msg, sizeof(msg), "0x%lx: flags 0x%lx match its arms", t, (unsigned long)m->flags);
        CHECK((m->flags != 0) && (m->flags == arm_flags(m->type)), msg);

        snprintf(msg, sizeof(msg), "0x%lx: found as its own row (no duplicate)", t);
        CHECK(tsra_pkcs11_mech_find(m->type) == m, msg);

        if ((m->flags & CKF_GENERATE) != 0)
        {
            snprintf(
                msg,
                sizeof(msg),
                "0x%lx: generates keys of %lu and %lu bytes",
                t,
                (unsigned long)m->min_key,
                (unsigned long)m->max_key
            );
            CHECK(keygen_accepts(m->type, m->min_key) && keygen_accepts(m->type, m->max_key), msg);
        }
    }
}

static void test_sweep(void)
{
    printf("== every implemented mechanism has a row ==\n");
    int missing = 0;
    for (CK_MECHANISM_TYPE t = 0; t < SWEEP_END; t++)
    {
        if ((arm_flags(t) != 0) && (tsra_pkcs11_mech_find(t) == NULL))
        {
            printf("  no row for 0x%lx\n", (unsigned long)t);
            missing++;
        }
    }
    CHECK(missing == 0, "no dispatch arm below 0x10000 lacks a row");
    CHECK(tsra_pkcs11_mech_find(CKM_AES_ECB) == NULL, "CKM_AES_ECB is not advertised");
    CHECK(tsra_pkcs11_mech_find(CKM_RSA_PKCS) == NULL, "CKM_RSA_PKCS is not advertised");
    CHECK(
        tsra_pkcs11_mech_find(CKM_GENERIC_SECRET_KEY_GEN) == NULL,
        "CKM_GENERIC_SECRET_KEY_GEN is not advertised"
    );
    CHECK(
        tsra_pkcs11_mech_find(CKM_SP800_108_COUNTER_KDF) == NULL,
        "CKM_SP800_108_COUNTER_KDF is not advertised"
    );
    const tsra_pkcs11_mech_t *hkdf = tsra_pkcs11_mech_find(CKM_HKDF_DERIVE);
    CHECK(
        (hkdf != NULL) && (hkdf->min_key == tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_P256)) &&
            (hkdf->max_key == tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_P521)),
        "CKM_HKDF_DERIVE takes the ECDH secrets, 32 to 66 bytes"
    );
    const tsra_pkcs11_mech_t *ec = tsra_pkcs11_mech_find(CKM_ECDSA_SHA256);
    CHECK(
        (ec != NULL) && ((ec->flags & CKF_EC_F_P) != 0) && ((ec->flags & CKF_EC_OID) != 0) &&
            ((ec->flags & CKF_EC_UNCOMPRESS) != 0),
        "an EC row names prime-field curves, by OID, with uncompressed points"
    );
    const tsra_pkcs11_mech_t *pss = tsra_pkcs11_mech_find(CKM_SHA256_RSA_PKCS_PSS);
    CHECK(
        (pss != NULL) && (pss->min_key == RSA_MIN_KEY_BITS) && (pss->max_key == RSA_MAX_KEY_BITS) &&
            ((pss->flags & EC_MECH_FLAGS) == 0),
        "an RSA row takes the unwrapped key sizes, 2048 to 4096 bits, and has no EC flags"
    );
    const tsra_pkcs11_mech_t *oaep = tsra_pkcs11_mech_find(CKM_RSA_PKCS_OAEP);
    CHECK(
        (oaep != NULL) && (oaep->flags == (CKF_ENCRYPT | CKF_DECRYPT)),
        "CKM_RSA_PKCS_OAEP encrypts and decrypts, and wraps nothing"
    );
    const tsra_pkcs11_mech_t *aes = tsra_pkcs11_mech_find(CKM_AES_CBC);
    CHECK((aes != NULL) && ((aes->flags & EC_MECH_FLAGS) == 0), "an AES row has no EC flags");
}

int main(void)
{
    test_rows();
    test_sweep();
    printf(
        g_fail ? "\nmech_table_test: FAILED (%d checks)\n"
               : "\nmech_table_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
