// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the mechanism table (src/tsra_pkcs11_mech.c) against the
 * dispatch arms that run the mechanisms: the digest table
 * (src/tsra_pkcs11_digest.c), the cipher table and the key-generation
 * template check (src/tsra_pkcs11_template.c). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src mech_table_test.c \
 *       ../src/tsra_pkcs11_mech.c ../src/tsra_pkcs11_template.c \
 *       ../src/tsra_pkcs11_attr_types.c ../src/tsra_pkcs11_digest.c \
 *       -o mech_table_test && ./mech_table_test
 *
 * Both directions: every row advertises exactly the flags its arms implement,
 * and every mechanism an arm implements has a row. A row without its arm, or
 * an arm without its row, fails here.
 */

#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_mech.h"
#include "tsra_pkcs11_template.h"

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

/* The entry-point flags the dispatch arms implement for `t`. */
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
    const tsra_pkcs11_keygen_policy *policy = NULL;
    CK_ULONG len = 0;
    CK_BBOOL token = CK_FALSE;
    if (tsra_pkcs11_keygen_check_template(t, NULL, 0, &policy, &len, &token) !=
        CKR_MECHANISM_INVALID)
    {
        f |= CKF_GENERATE;
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
