// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the attribute type table (src/tsra_pkcs11_attr_types.c). No
 * device, no store, no module load:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src attr_types_test.c \
 *       ../src/tsra_pkcs11_attr_types.c -o attr_types_test && ./attr_types_test
 *
 * Covers every CK_BBOOL and CK_ULONG attribute of PKCS#11 v3.1 at the lengths
 * a caller gets wrong (only the exact width passes, and no value is read at a
 * wrong length), dates, mechanism lists, the attribute arrays, NULL values,
 * the count and byte ceilings including a sum that would wrap, first failure
 * wins over a template, values at odd addresses, and the key-material and
 * token-set predicates. The type lists here are written from the spec, not
 * copied from the table, so a table row with the wrong shape fails a check.
 */

#include "tsra_pkcs11_attr_types.h"

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

/* Lengths a caller gets wrong; the exact width is checked separately. */
static const CK_ULONG BAD_LENS[] = { 0, 1, 2, 7, 8, 9, 0xFFFFFFFFUL };

static const CK_ATTRIBUTE_TYPE BOOL_TYPES[] = {
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_TRUSTED,
    CKA_SENSITIVE,
    CKA_ENCRYPT,
    CKA_DECRYPT,
    CKA_WRAP,
    CKA_UNWRAP,
    CKA_SIGN,
    CKA_SIGN_RECOVER,
    CKA_VERIFY,
    CKA_VERIFY_RECOVER,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_LOCAL,
    CKA_NEVER_EXTRACTABLE,
    CKA_ALWAYS_SENSITIVE,
    CKA_MODIFIABLE,
    CKA_COPYABLE,
    CKA_DESTROYABLE,
    CKA_SECONDARY_AUTH,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_WRAP_WITH_TRUSTED,
    CKA_OTP_USER_FRIENDLY_MODE,
    CKA_RESET_ON_INIT,
    CKA_HAS_RESET,
    CKA_COLOR,
    CKA_X2RATCHET_BOBS1STMSG,
    CKA_X2RATCHET_ISALICE,
};

static const CK_ATTRIBUTE_TYPE ULONG_TYPES[] = {
    CKA_CLASS,
    CKA_CERTIFICATE_TYPE,
    CKA_CERTIFICATE_CATEGORY,
    CKA_JAVA_MIDP_SECURITY_DOMAIN,
    CKA_NAME_HASH_ALGORITHM,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PRIME_BITS,
    CKA_SUBPRIME_BITS,
    CKA_VALUE_BITS,
    CKA_VALUE_LEN,
    CKA_KEY_GEN_MECHANISM,
    CKA_AUTH_PIN_FLAGS,
    CKA_OTP_FORMAT,
    CKA_OTP_LENGTH,
    CKA_OTP_TIME_INTERVAL,
    CKA_OTP_CHALLENGE_REQUIREMENT,
    CKA_OTP_TIME_REQUIREMENT,
    CKA_OTP_COUNTER_REQUIREMENT,
    CKA_OTP_PIN_REQUIREMENT,
    CKA_HW_FEATURE_TYPE,
    CKA_PIXEL_X,
    CKA_PIXEL_Y,
    CKA_RESOLUTION,
    CKA_CHAR_ROWS,
    CKA_CHAR_COLUMNS,
    CKA_BITS_PER_PIXEL,
    CKA_MECHANISM_TYPE,
    CKA_PROFILE_ID,
    CKA_X2RATCHET_BAGSIZE,
    CKA_X2RATCHET_NR,
    CKA_X2RATCHET_NS,
    CKA_X2RATCHET_PNS,
    CKA_HSS_LEVELS,
    CKA_HSS_LMS_TYPE,
    CKA_HSS_LMOTS_TYPE,
    CKA_HSS_KEYS_REMAINING,
};

/* Byte-array attributes, any length; the material ones among them too. */
static const CK_ATTRIBUTE_TYPE BYTES_TYPES[] = {
    CKA_LABEL,    CKA_VALUE,     CKA_ID,          CKA_SUBJECT,
    CKA_MODULUS,  CKA_EC_PARAMS, CKA_EC_POINT,    CKA_PUBLIC_EXPONENT,
    CKA_PRIME_1,  CKA_UNIQUE_ID, CKA_CHECK_VALUE, CKA_HSS_LMS_TYPES,
    CKA_OTP_TIME, CKA_PRIME,     CKA_APPLICATION, CKA_VENDOR_DEFINED,
    0x7FFFF00FUL, /* undefined */
};

static const CK_ATTRIBUTE_TYPE MATERIAL_TYPES[] = {
    CKA_VALUE,      CKA_PRIVATE_EXPONENT, CKA_PRIME_1,     CKA_PRIME_2,
    CKA_EXPONENT_1, CKA_EXPONENT_2,       CKA_COEFFICIENT,
};

static const CK_ATTRIBUTE_TYPE TOKEN_SET_TYPES[] = {
    CKA_LOCAL,   CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM,
    CKA_TRUSTED, CKA_UNIQUE_ID,
};

/* Large enough for every value below; no check reads past what it names. */
static unsigned char g_buf[64];

/* Whether `t` at `len` earns `want`; names the row when it does not. */
static int len_gives(CK_ATTRIBUTE_TYPE t, CK_ULONG len, CK_RV want)
{
    CK_ATTRIBUTE a = { t, g_buf, len };
    CK_RV rv = tsra_pkcs11_attr_check(&a);
    if (rv != want)
    {
        printf("         type 0x%lx, length %lu -> 0x%lx\n", t, len, rv);
    }
    return rv == want;
}

static void test_scalars(void)
{
    printf("== CK_BBOOL and CK_ULONG attributes: exact width only ==\n");
    int bool_ok = 1;
    for (size_t i = 0; i < COUNT(BOOL_TYPES); i++)
    {
        bool_ok &= len_gives(BOOL_TYPES[i], sizeof(CK_BBOOL), CKR_OK);
        for (size_t j = 0; j < COUNT(BAD_LENS); j++)
        {
            if (BAD_LENS[j] != sizeof(CK_BBOOL))
            {
                bool_ok &= len_gives(BOOL_TYPES[i], BAD_LENS[j], CKR_ATTRIBUTE_VALUE_INVALID);
            }
        }
    }
    CHECK(bool_ok, "every CK_BBOOL attribute: 1 byte passes, 0/2/7/8/9/0xFFFFFFFF do not");

    int ulong_ok = 1;
    for (size_t i = 0; i < COUNT(ULONG_TYPES); i++)
    {
        ulong_ok &= len_gives(ULONG_TYPES[i], sizeof(CK_ULONG), CKR_OK);
        for (size_t j = 0; j < COUNT(BAD_LENS); j++)
        {
            if (BAD_LENS[j] != sizeof(CK_ULONG))
            {
                ulong_ok &= len_gives(ULONG_TYPES[i], BAD_LENS[j], CKR_ATTRIBUTE_VALUE_INVALID);
            }
        }
    }
    CHECK(ulong_ok, "every CK_ULONG attribute: sizeof(CK_ULONG) passes, the rest does not");

    int bytes_ok = 1;
    for (size_t i = 0; i < COUNT(BYTES_TYPES); i++)
    {
        for (size_t j = 0; j < COUNT(BAD_LENS); j++)
        {
            bytes_ok &= len_gives(BYTES_TYPES[i], BAD_LENS[j], CKR_OK);
        }
    }
    CHECK(bytes_ok, "byte arrays and unknown types take any length, unread");
}

static void test_null_values(void)
{
    printf("== NULL values ==\n");
    static const CK_ATTRIBUTE_TYPE one_of_each[] = {
        CKA_TOKEN, CKA_CLASS, CKA_START_DATE, CKA_ALLOWED_MECHANISMS, CKA_LABEL,
    };
    int ok = 1;
    for (size_t i = 0; i < COUNT(one_of_each); i++)
    {
        CK_ATTRIBUTE a = { one_of_each[i], NULL, 1 };
        ok &= (tsra_pkcs11_attr_check(&a) == CKR_ATTRIBUTE_VALUE_INVALID);
    }
    CHECK(ok, "a NULL value with a non-zero length -> CKR_ATTRIBUTE_VALUE_INVALID, any shape");
    CK_ATTRIBUTE empty_label = { CKA_LABEL, NULL, 0 };
    CHECK(tsra_pkcs11_attr_check(&empty_label) == CKR_OK, "an empty byte array may be NULL");
    CK_ATTRIBUTE empty_bool = { CKA_TOKEN, NULL, 0 };
    CHECK(
        tsra_pkcs11_attr_check(&empty_bool) == CKR_ATTRIBUTE_VALUE_INVALID,
        "an empty CK_BBOOL is no CK_BBOOL"
    );
    CHECK(tsra_pkcs11_attr_check(NULL) == CKR_ATTRIBUTE_VALUE_INVALID, "a NULL attribute");
}

#define DATE(y, m, d)                                                                              \
    {                                                                                              \
        { (y)[0], (y)[1], (y)[2], (y)[3] }, { (m)[0], (m)[1] },                                    \
        {                                                                                          \
            (d)[0], (d)[1]                                                                         \
        }                                                                                          \
    }

static void test_dates(void)
{
    printf("== CK_DATE attributes ==\n");
    static const CK_DATE good[] = { DATE("1900", "01", "01"),
                                    DATE("2026", "11", "04"),
                                    DATE("9999", "12", "31") };
    static const CK_DATE bad[] = {
        DATE("2026", "00", "15"), DATE("2026", "13", "15"),  DATE("2026", "06", "00"),
        DATE("2026", "06", "32"), DATE("1899", "12", "31"),  DATE("20x6", "06", "15"),
        DATE("2026", " 6", "15"), DATE("2026", "06", "1\0"),
    };
    static const CK_ATTRIBUTE_TYPE date_types[] = { CKA_START_DATE, CKA_END_DATE };
    int ok = 1;
    for (size_t t = 0; t < COUNT(date_types); t++)
    {
        for (size_t i = 0; i < COUNT(good); i++)
        {
            CK_ATTRIBUTE a = { date_types[t], (void *)&good[i], sizeof(CK_DATE) };
            ok &= (tsra_pkcs11_attr_check(&a) == CKR_OK);
        }
        for (size_t i = 0; i < COUNT(bad); i++)
        {
            CK_ATTRIBUTE a = { date_types[t], (void *)&bad[i], sizeof(CK_DATE) };
            ok &= (tsra_pkcs11_attr_check(&a) == CKR_ATTRIBUTE_VALUE_INVALID);
        }
        CK_ATTRIBUTE none = { date_types[t], NULL, 0 };
        ok &= (tsra_pkcs11_attr_check(&none) == CKR_OK);
        for (size_t j = 0; j < COUNT(BAD_LENS); j++)
        {
            if (BAD_LENS[j] != 0)
            {
                ok &= len_gives(date_types[t], BAD_LENS[j], CKR_ATTRIBUTE_VALUE_INVALID);
            }
        }
    }
    CHECK(ok, "START/END_DATE: valid dates and empty pass; bad fields and lengths do not");

    /* At an odd address the date is copied out, not dereferenced (UBSan). */
    static unsigned char raw[sizeof(CK_DATE) + 1];
    memcpy(raw + 1, &good[1], sizeof(CK_DATE));
    CK_ATTRIBUTE odd = { CKA_START_DATE, raw + 1, sizeof(CK_DATE) };
    CHECK(tsra_pkcs11_attr_check(&odd) == CKR_OK, "a date at an odd address decodes");
}

static void test_arrays(void)
{
    printf("== mechanism lists and attribute arrays ==\n");
    int ok = 1;
    for (CK_ULONG n = 0; n <= 3; n++)
    {
        ok &= len_gives(CKA_ALLOWED_MECHANISMS, n * sizeof(CK_MECHANISM_TYPE), CKR_OK);
    }
    CHECK(ok, "CKA_ALLOWED_MECHANISMS: 0 to 3 whole entries pass");
    CHECK(
        len_gives(
            CKA_ALLOWED_MECHANISMS,
            sizeof(CK_MECHANISM_TYPE) - 1,
            CKR_ATTRIBUTE_VALUE_INVALID
        ) &&
            len_gives(
                CKA_ALLOWED_MECHANISMS,
                sizeof(CK_MECHANISM_TYPE) + 1,
                CKR_ATTRIBUTE_VALUE_INVALID
            ),
        "CKA_ALLOWED_MECHANISMS: a partial entry -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    static const CK_ATTRIBUTE_TYPE templates[] = {
        CKA_WRAP_TEMPLATE,
        CKA_UNWRAP_TEMPLATE,
        CKA_DERIVE_TEMPLATE,
    };
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE inner[] = { { CKA_ENCRYPT, &yes, sizeof(yes) } };
    ok = 1;
    for (size_t i = 0; i < COUNT(templates); i++)
    {
        CK_ATTRIBUTE a = { templates[i], inner, sizeof(inner) };
        CK_ATTRIBUTE empty = { templates[i], NULL, 0 };
        ok &= (tsra_pkcs11_attr_check(&a) == CKR_ATTRIBUTE_TYPE_INVALID);
        ok &= (tsra_pkcs11_attr_check(&empty) == CKR_ATTRIBUTE_TYPE_INVALID);
    }
    CHECK(ok, "WRAP/UNWRAP/DERIVE_TEMPLATE -> CKR_ATTRIBUTE_TYPE_INVALID, even empty");
}

static void test_bounds(void)
{
    printf("== ceilings ==\n");
    CHECK(tsra_pkcs11_tmpl_check_bounds(NULL, 0) == CKR_OK, "NULL template with count 0");
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(NULL, 1) == CKR_ARGUMENTS_BAD,
        "NULL template with count 1 -> CKR_ARGUMENTS_BAD"
    );
    static CK_ATTRIBUTE many[TEMPLATE_MAX_ATTRS + 1];
    for (size_t i = 0; i < COUNT(many); i++)
    {
        many[i] = (CK_ATTRIBUTE){ CKA_VENDOR_DEFINED + i, g_buf, 1 };
    }
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(many, TEMPLATE_MAX_ATTRS) == CKR_OK,
        "TEMPLATE_MAX_ATTRS entries pass"
    );
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(many, TEMPLATE_MAX_ATTRS + 1) == CKR_ARGUMENTS_BAD,
        "TEMPLATE_MAX_ATTRS + 1 -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(many, 0xFFFFFFFFUL) == CKR_ARGUMENTS_BAD,
        "ulCount 0xFFFFFFFF -> CKR_ARGUMENTS_BAD before any entry is read"
    );

    /* Lengths only: the bounds read no value. */
    CK_ATTRIBUTE at_max[] = { { CKA_LABEL, g_buf, TEMPLATE_MAX_VALUE_BYTES - 1 },
                              { CKA_ID, g_buf, 1 } };
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(at_max, 2) == CKR_OK,
        "values summing to TEMPLATE_MAX_VALUE_BYTES pass"
    );
    at_max[1].ulValueLen = 2;
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(at_max, 2) == CKR_ATTRIBUTE_VALUE_INVALID,
        "one byte more -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_ATTRIBUTE huge[] = { { CKA_LABEL, g_buf, 0xFFFFFFFFUL } };
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(huge, 1) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a 0xFFFFFFFF label -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_ATTRIBUTE wrap[] = { { CKA_LABEL, g_buf, 16 }, { CKA_ID, g_buf, (CK_ULONG)-16 } };
    CHECK(
        tsra_pkcs11_tmpl_check_bounds(wrap, 2) == CKR_ATTRIBUTE_VALUE_INVALID,
        "lengths whose sum wraps to 0 -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
}

static void test_template(void)
{
    printf("== tmpl_check: bounds, then every entry in order ==\n");
    CK_BBOOL b = CK_TRUE;
    CK_ULONG wide = 1;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE inner[] = { { CKA_ENCRYPT, &yes, sizeof(yes) } };
    CK_ATTRIBUTE good[] = { { CKA_TOKEN, &b, sizeof(b) }, { CKA_LABEL, g_buf, 3 } };
    CHECK(tsra_pkcs11_tmpl_check(good, 2) == CKR_OK, "a well-formed template passes");
    CHECK(tsra_pkcs11_tmpl_check(NULL, 0) == CKR_OK, "an empty template passes");
    CK_ATTRIBUTE order1[] = { { CKA_TOKEN, &wide, sizeof(wide) },
                              { CKA_WRAP_TEMPLATE, inner, sizeof(inner) } };
    CK_ATTRIBUTE order2[] = { { CKA_WRAP_TEMPLATE, inner, sizeof(inner) },
                              { CKA_TOKEN, &wide, sizeof(wide) } };
    CHECK(
        tsra_pkcs11_tmpl_check(order1, 2) == CKR_ATTRIBUTE_VALUE_INVALID,
        "[wide bool, wrap template] -> the bool verdict"
    );
    CHECK(
        tsra_pkcs11_tmpl_check(order2, 2) == CKR_ATTRIBUTE_TYPE_INVALID,
        "[wrap template, wide bool] -> the array verdict"
    );
    CK_ATTRIBUTE late_huge[] = { { CKA_WRAP_TEMPLATE, inner, sizeof(inner) },
                                 { CKA_LABEL, g_buf, 0xFFFFFFFFUL } };
    CHECK(
        tsra_pkcs11_tmpl_check(late_huge, 2) == CKR_ATTRIBUTE_VALUE_INVALID,
        "the ceilings come before any entry"
    );
}

/* tsra_pkcs11_attr_is_token_set for `t` with the one-byte value `b`. */
static bool token_set(CK_ATTRIBUTE_TYPE t, CK_BBOOL b)
{
    CK_ATTRIBUTE a = { t, &b, sizeof(b) };
    return tsra_pkcs11_attr_is_token_set(&a);
}

static void test_predicates(void)
{
    printf("== key material and token-set attributes ==\n");
    int ok = 1;
    for (size_t i = 0; i < COUNT(MATERIAL_TYPES); i++)
    {
        ok &= tsra_pkcs11_attr_is_key_material(MATERIAL_TYPES[i]);
        ok &= !token_set(MATERIAL_TYPES[i], CK_TRUE);
    }
    CHECK(ok, "CKA_VALUE and the RSA private components are key material");
    ok = 1;
    for (size_t i = 0; i < COUNT(TOKEN_SET_TYPES); i++)
    {
        ok &= token_set(TOKEN_SET_TYPES[i], CK_TRUE);
        ok &= !tsra_pkcs11_attr_is_key_material(TOKEN_SET_TYPES[i]);
    }
    CHECK(ok, "provenance, CKA_TRUSTED=TRUE and CKA_UNIQUE_ID are token-set");
    ok = 1;
    for (size_t i = 0; i < COUNT(TOKEN_SET_TYPES); i++)
    {
        ok &= (token_set(TOKEN_SET_TYPES[i], CK_FALSE) == (TOKEN_SET_TYPES[i] != CKA_TRUSTED));
    }
    CHECK(ok, "CKA_TRUSTED=FALSE is not token-set, the others are at any value");
    static const CK_ATTRIBUTE_TYPE neither[] = {
        CKA_CLASS,     CKA_LABEL, CKA_MODULUS,   CKA_PUBLIC_EXPONENT, CKA_EC_POINT,       CKA_PRIME,
        CKA_SENSITIVE, CKA_TOKEN, CKA_VALUE_LEN, CKA_SUBJECT,         CKA_VENDOR_DEFINED,
    };
    ok = 1;
    for (size_t i = 0; i < COUNT(neither); i++)
    {
        ok &= !tsra_pkcs11_attr_is_key_material(neither[i]);
        ok &= !token_set(neither[i], CK_TRUE);
    }
    CHECK(ok, "public components and caller attributes are neither");
}

int main(void)
{
    test_scalars();
    test_null_values();
    test_dates();
    test_arrays();
    test_bounds();
    test_template();
    test_predicates();
    printf(
        g_fail ? "\nattr_types_test: FAILED (%d checks)\n"
               : "\nattr_types_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
