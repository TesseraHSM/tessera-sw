// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the RSA mechanism parameters (src/tsra_pkcs11_rsa_params.c).
 * No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src rsa_params_test.c \
 *       ../src/tsra_pkcs11_rsa_params.c ../src/tsra_pkcs11_digest.c \
 *       -o rsa_params_test && ./rsa_params_test
 *
 * Covers the sign parameter check over every PSS mechanism, hash and MGF
 * (the hashing mechanisms take their own hash only, the pre-hashed one any
 * hash of MGF1), a parameter on a mechanism that takes none, wrong sizes, NULL
 * arguments and a misaligned block; the PSS salt limit at its edges for every
 * hash and key size and for moduli that are not whole bytes; the OAEP
 * parameter check over every hash and MGF, the source and label rules and a
 * misaligned block; and the longest OAEP message.
 */

#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_rsa_params.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* The RFC 8017 bytes PSS and OAEP add to the hash lengths. */
#define PAD_FIXED 2

/* The RSA sizes the device takes, in bits. */
static const CK_ULONG SIZES[] = { 2048, 3072, 4096 };

/* The hashes and their MGF1, SHA-224 as one the module refuses. */
static const struct
{
    CK_MECHANISM_TYPE hash;
    CK_RSA_PKCS_MGF_TYPE mgf;
    CK_ULONG len;
} HASHES[] = {
    { CKM_SHA_1, CKG_MGF1_SHA1, TSRA_PKCS11_SHA1_DIGEST_LEN },
    { CKM_SHA224, CKG_MGF1_SHA224, 28 },
    { CKM_SHA256, CKG_MGF1_SHA256, TSRA_PKCS11_SHA256_DIGEST_LEN },
    { CKM_SHA384, CKG_MGF1_SHA384, TSRA_PKCS11_SHA384_DIGEST_LEN },
    { CKM_SHA512, CKG_MGF1_SHA512, TSRA_PKCS11_SHA512_DIGEST_LEN },
};

/* The PSS mechanisms and their hash; 0 for the pre-hashed one. */
static const struct
{
    CK_MECHANISM_TYPE mech;
    CK_MECHANISM_TYPE hash;
} PSS[] = {
    { CKM_RSA_PKCS_PSS, 0 },
    { CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1 },
    { CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256 },
    { CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384 },
    { CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512 },
};

/* emLen = ceil((modBits - 1) / 8) at moduli that are not whole bytes, with
 * SHA-256: a salt fits up to emLen - 32 - 2. */
static const struct
{
    CK_ULONG bits;
    CK_ULONG salt;
    bool fits;
} EM_EDGES[] = {
    { 2049, 222, true },                     /* emLen 256 */
    { 2042, 222, true },                     /* emLen 256 */
    { 2041, 222, false },                    /* emLen 255 */
    { 2041, 221, true },  { 256, 0, false }, /* emLen 32: shorter than the hash and the padding */
};

static CK_RV sign_check(CK_MECHANISM_TYPE mech, const void *param, CK_ULONG len, bool *is_pss)
{
    CK_MECHANISM m = { mech, (void *)param, len };
    CK_RSA_PKCS_PSS_PARAMS out;
    return tsra_pkcs11_sign_params_check(&m, &out, is_pss);
}

static void test_sign_params(void)
{
    printf("== sign_params_check ==\n");
    bool is_pss = true;
    CK_RSA_PKCS_PSS_PARAMS out;
    CK_RSA_PKCS_PSS_PARAMS p = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS_PSS, &p, sizeof(p) };
    CHECK(
        (tsra_pkcs11_sign_params_check(&m, &out, &is_pss) == CKR_OK) && is_pss &&
            (out.hashAlg == CKM_SHA256) && (out.mgf == CKG_MGF1_SHA256) && (out.sLen == 32),
        "PSS-SHA256 with its parameters -> CKR_OK, copied out"
    );
    CHECK(
        tsra_pkcs11_sign_params_check(NULL, &out, &is_pss) == CKR_ARGUMENTS_BAD,
        "NULL mechanism"
    );
    CHECK(tsra_pkcs11_sign_params_check(&m, NULL, &is_pss) == CKR_ARGUMENTS_BAD, "NULL output");
    CHECK(tsra_pkcs11_sign_params_check(&m, &out, NULL) == CKR_ARGUMENTS_BAD, "NULL flag");

    CHECK(
        (sign_check(CKM_SHA256_RSA_PKCS, NULL, 0, &is_pss) == CKR_OK) && !is_pss,
        "PKCS#1 v1.5 without a parameter -> CKR_OK, not PSS"
    );
    CHECK(
        (sign_check(CKM_ECDSA_SHA256, NULL, 0, &is_pss) == CKR_OK) && !is_pss,
        "ECDSA without a parameter -> CKR_OK"
    );
    CHECK(
        sign_check(CKM_SHA256_RSA_PKCS, &p, sizeof(p), &is_pss) == CKR_MECHANISM_PARAM_INVALID,
        "PKCS#1 v1.5 with a parameter -> PARAM_INVALID"
    );
    CHECK(
        sign_check(CKM_ECDSA, &p, 0, &is_pss) == CKR_MECHANISM_PARAM_INVALID,
        "a parameter pointer of length 0 on a parameterless mechanism -> PARAM_INVALID"
    );
    CHECK(
        sign_check(CKM_ECDSA, NULL, 1, &is_pss) == CKR_MECHANISM_PARAM_INVALID,
        "a length without a parameter -> PARAM_INVALID"
    );
    for (size_t i = 0; i < COUNT(PSS); i++)
    {
        char msg[160];
        snprintf(
            msg,
            sizeof(msg),
            "0x%lx: no, short or long parameter -> PARAM_INVALID",
            PSS[i].mech
        );
        CHECK(
            (sign_check(PSS[i].mech, NULL, 0, &is_pss) == CKR_MECHANISM_PARAM_INVALID) &&
                (sign_check(PSS[i].mech, NULL, sizeof(p), &is_pss) == CKR_MECHANISM_PARAM_INVALID
                ) &&
                (sign_check(PSS[i].mech, &p, sizeof(p) - 1, &is_pss) == CKR_MECHANISM_PARAM_INVALID
                ) &&
                (sign_check(PSS[i].mech, &p, sizeof(p) + 1, &is_pss) == CKR_MECHANISM_PARAM_INVALID
                ),
            msg
        );
        /* Every hash with every MGF: OK only for the mechanism's hash (any
         * SHA-1/2 hash but SHA-224 for the pre-hashed one) and its MGF1. */
        bool all = true;
        for (size_t h = 0; h < COUNT(HASHES); h++)
        {
            for (size_t g = 0; g < COUNT(HASHES); g++)
            {
                CK_RSA_PKCS_PSS_PARAMS q = { HASHES[h].hash, HASHES[g].mgf, 0 };
                bool hash_ok = (PSS[i].hash == 0) ? (HASHES[h].hash != CKM_SHA224)
                                                  : (HASHES[h].hash == PSS[i].hash);
                CK_RV want = (hash_ok && (g == h)) ? CKR_OK : CKR_MECHANISM_PARAM_INVALID;
                all = all && (sign_check(PSS[i].mech, &q, sizeof(q), &is_pss) == want) &&
                      ((want != CKR_OK) || is_pss);
            }
        }
        snprintf(msg, sizeof(msg), "0x%lx: the hash and MGF matrix", PSS[i].mech);
        CHECK(all, msg);
    }
    /* pParameter carries no alignment guarantee. */
    CK_BYTE raw[sizeof(p) + 1];
    memcpy(raw + 1, &p, sizeof(p));
    CHECK(
        sign_check(CKM_SHA256_RSA_PKCS_PSS, raw + 1, sizeof(p), &is_pss) == CKR_OK,
        "a misaligned parameter block -> CKR_OK"
    );
}

static void test_salt(void)
{
    printf("== pss_salt_ok ==\n");
    for (size_t s = 0; s < COUNT(SIZES); s++)
    {
        for (size_t h = 0; h < COUNT(HASHES); h++)
        {
            if (HASHES[h].hash == CKM_SHA224)
            {
                continue;
            }
            CK_ULONG longest = (SIZES[s] / CHAR_BIT) - HASHES[h].len - PAD_FIXED;
            CK_RSA_PKCS_PSS_PARAMS p = { HASHES[h].hash, HASHES[h].mgf, longest };
            bool fits = tsra_pkcs11_pss_salt_ok(SIZES[s], &p);
            p.sLen = longest + 1;
            bool over = tsra_pkcs11_pss_salt_ok(SIZES[s], &p);
            p.sLen = 0;
            bool none = tsra_pkcs11_pss_salt_ok(SIZES[s], &p);
            char msg[128];
            snprintf(
                msg,
                sizeof(msg),
                "%lu bits, hash 0x%lx: salt 0 and %lu fit, %lu does not",
                SIZES[s],
                HASHES[h].hash,
                longest,
                longest + 1
            );
            CHECK(fits && !over && none, msg);
        }
    }
    for (size_t i = 0; i < COUNT(EM_EDGES); i++)
    {
        CK_RSA_PKCS_PSS_PARAMS q = { CKM_SHA256, CKG_MGF1_SHA256, EM_EDGES[i].salt };
        char msg[128];
        snprintf(
            msg,
            sizeof(msg),
            "%lu bits: salt %lu %s",
            EM_EDGES[i].bits,
            EM_EDGES[i].salt,
            EM_EDGES[i].fits ? "fits" : "does not fit"
        );
        CHECK(tsra_pkcs11_pss_salt_ok(EM_EDGES[i].bits, &q) == EM_EDGES[i].fits, msg);
    }
    CK_RSA_PKCS_PSS_PARAMS p = { CKM_SHA256, CKG_MGF1_SHA256, 0 };
    CHECK(!tsra_pkcs11_pss_salt_ok(2048, NULL), "NULL parameters -> false");
    CHECK(!tsra_pkcs11_pss_salt_ok(0, &p), "no modulus -> false");
    p.hashAlg = CKM_SHA224;
    CHECK(!tsra_pkcs11_pss_salt_ok(2048, &p), "a hash the module has no length for -> false");
}

static CK_RV oaep_check(
    CK_MECHANISM_TYPE hash,
    CK_RSA_PKCS_MGF_TYPE mgf,
    tsra_pkcs11_oaep_params *out
)
{
    CK_RSA_PKCS_OAEP_PARAMS p = { hash, mgf, CKZ_DATA_SPECIFIED, NULL, 0 };
    return tsra_pkcs11_oaep_params_check(&p, sizeof(p), out);
}

static void test_oaep_params(void)
{
    printf("== oaep_params_check ==\n");
    tsra_pkcs11_oaep_params out;
    bool all = true;
    for (size_t h = 0; h < COUNT(HASHES); h++)
    {
        for (size_t g = 0; g < COUNT(HASHES); g++)
        {
            bool sha2 = (HASHES[h].hash == CKM_SHA256) || (HASHES[h].hash == CKM_SHA384) ||
                        (HASHES[h].hash == CKM_SHA512);
            CK_RV want = (sha2 && (g == h)) ? CKR_OK : CKR_MECHANISM_PARAM_INVALID;
            CK_RV got = oaep_check(HASHES[h].hash, HASHES[g].mgf, &out);
            all = all && (got == want) && ((got != CKR_OK) || (out.hash == HASHES[h].hash));
        }
    }
    CHECK(all, "SHA-256, SHA-384 or SHA-512 with MGF1 of the same hash only (SHA-1 refused)");

    CK_BYTE label[] = { 'l', 'a', 'b', 'e', 'l' };
    CK_RSA_PKCS_OAEP_PARAMS p = { CKM_SHA384, CKG_MGF1_SHA384, CKZ_DATA_SPECIFIED, label, 5 };
    CHECK(
        (tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_OK) && (out.label == label) &&
            (out.label_len == 5),
        "a label is passed through"
    );
    p.ulSourceDataLen = 0;
    CHECK(
        (tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_OK) && (out.label == NULL) &&
            (out.label_len == 0),
        "a label pointer with length 0 is no label"
    );
    p.pSourceData = NULL;
    CHECK(tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_OK, "no label -> CKR_OK");
    p.ulSourceDataLen = 1;
    CHECK(
        tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a NULL label with a length -> PARAM_INVALID"
    );
    p.ulSourceDataLen = 0;
    p.source = 0;
    CHECK(
        tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a source other than CKZ_DATA_SPECIFIED -> PARAM_INVALID"
    );
    p.source = CKZ_DATA_SPECIFIED;
#if ULONG_MAX > UINT32_MAX
    p.pSourceData = label;
    p.ulSourceDataLen = (CK_ULONG)UINT32_MAX + 1;
    CHECK(
        tsra_pkcs11_oaep_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a label beyond 32 bits -> PARAM_INVALID"
    );
    p.pSourceData = NULL;
    p.ulSourceDataLen = 0;
#endif
    CHECK(
        (tsra_pkcs11_oaep_params_check(NULL, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID) &&
            (tsra_pkcs11_oaep_params_check(&p, sizeof(p) - 1, &out) == CKR_MECHANISM_PARAM_INVALID
            ) &&
            (tsra_pkcs11_oaep_params_check(&p, sizeof(p) + 1, &out) == CKR_MECHANISM_PARAM_INVALID),
        "no parameter, or one of the wrong size -> PARAM_INVALID"
    );
    CHECK(tsra_pkcs11_oaep_params_check(&p, sizeof(p), NULL) == CKR_ARGUMENTS_BAD, "NULL output");
    CK_BYTE raw[sizeof(p) + 1];
    memcpy(raw + 1, &p, sizeof(p));
    CHECK(
        tsra_pkcs11_oaep_params_check(raw + 1, sizeof(p), &out) == CKR_OK,
        "a misaligned parameter block -> CKR_OK"
    );
}

static void test_oaep_max(void)
{
    printf("== oaep_max_msg ==\n");
    bool all = true;
    for (size_t s = 0; s < COUNT(SIZES); s++)
    {
        for (size_t h = 0; h < COUNT(HASHES); h++)
        {
            if (HASHES[h].hash == CKM_SHA224)
            {
                continue;
            }
            CK_ULONG k = SIZES[s] / CHAR_BIT;
            all = all && (tsra_pkcs11_oaep_max_msg(k, HASHES[h].hash) ==
                          (k - (2 * HASHES[h].len) - PAD_FIXED));
        }
    }
    CHECK(all, "every size and hash -> k - 2hLen - 2");
    CHECK(
        tsra_pkcs11_oaep_max_msg(SIZES[0] / CHAR_BIT, CKM_SHA224) == 0,
        "a hash without a length -> 0"
    );
    CHECK(
        tsra_pkcs11_oaep_max_msg((2 * TSRA_PKCS11_SHA512_DIGEST_LEN) + 1, CKM_SHA512) == 0,
        "a modulus too short for the padding -> 0"
    );
}

int main(void)
{
    test_sign_params();
    test_salt();
    test_oaep_params();
    test_oaep_max();
    printf(
        g_fail ? "\nrsa_params_test: FAILED (%d checks)\n"
               : "\nrsa_params_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
