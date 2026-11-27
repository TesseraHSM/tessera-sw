// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the secret-byte helpers of src/tsra_pkcs11_wipe.h, which are
 * header-static. No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src wipe_test.c \
 *       -o wipe_test && ./wipe_test
 *
 * Covers the wipe of a range and nothing beyond it, and the constant-time
 * compare that checks HMAC tags: equal ranges, every single-bit difference at
 * every position of the longest tag, differences that cancel in a plain XOR
 * sum, the same pointer, misaligned ranges, the empty range and NULL ranges.
 */

#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_wipe.h"

#include <limits.h>
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

/* The longest HMAC tag the module compares. */
#define TAG_LEN TSRA_PKCS11_DIGEST_MAX_LEN

/* The byte the wipe test fills with, and a tag byte pattern. */
#define FILL 0xA5
#define PATTERN_STEP 37

/* One change made at two positions: its byte differences XOR to zero. */
#define TWICE 0x03

static void fill_tag(unsigned char *p)
{
    for (size_t i = 0; i < TAG_LEN; i++)
    {
        p[i] = (unsigned char)(i * PATTERN_STEP);
    }
}

static void test_wipe(void)
{
    printf("== wipe ==\n");
    unsigned char buf[TAG_LEN + 2];
    memset(buf, FILL, sizeof(buf));
    tsra_pkcs11_wipe(buf + 1, TAG_LEN);
    bool zero = true;
    for (size_t i = 1; i <= TAG_LEN; i++)
    {
        zero = zero && (buf[i] == 0);
    }
    CHECK(zero, "wipe: the range is zero");
    CHECK((buf[0] == FILL) && (buf[TAG_LEN + 1] == FILL), "wipe: nothing beyond it changes");
    tsra_pkcs11_wipe(NULL, TAG_LEN);
    CHECK(true, "wipe: NULL is a no-op");
}

static void test_equal_ct(void)
{
    printf("== constant-time compare ==\n");
    unsigned char a[TAG_LEN];
    unsigned char b[TAG_LEN];
    fill_tag(a);
    fill_tag(b);
    CHECK(tsra_pkcs11_equal_ct(a, b, TAG_LEN), "compare: equal ranges are equal");
    CHECK(tsra_pkcs11_equal_ct(a, a, TAG_LEN), "compare: a range equals itself");
    CHECK(tsra_pkcs11_equal_ct(a, b, 0), "compare: empty ranges are equal");
    CHECK(
        !tsra_pkcs11_equal_ct(NULL, b, TAG_LEN) && !tsra_pkcs11_equal_ct(a, NULL, TAG_LEN) &&
            !tsra_pkcs11_equal_ct(NULL, NULL, TAG_LEN),
        "compare: a NULL range with a length is equal to nothing"
    );

    int missed = 0;
    for (size_t i = 0; i < TAG_LEN; i++)
    {
        for (unsigned bit = 0; bit < CHAR_BIT; bit++)
        {
            b[i] ^= (unsigned char)(1u << bit);
            missed += tsra_pkcs11_equal_ct(a, b, TAG_LEN) ? 1 : 0;
            missed += tsra_pkcs11_equal_ct(b, a, TAG_LEN) ? 1 : 0;
            b[i] ^= (unsigned char)(1u << bit);
        }
    }
    CHECK(missed == 0, "compare: every one-bit difference at every position is found");

    /* A plain XOR sum of the byte differences misses this; the OR finds it. */
    b[0] ^= TWICE;
    b[TAG_LEN - 1] ^= TWICE;
    CHECK(!tsra_pkcs11_equal_ct(a, b, TAG_LEN), "compare: differences that cancel are found");
    fill_tag(b);
    b[TAG_LEN - 1] ^= 1;
    CHECK(tsra_pkcs11_equal_ct(a, b, TAG_LEN - 1), "compare: bytes past `n` do not count");

    unsigned char ma[TAG_LEN + 1];
    unsigned char mb[TAG_LEN + 1];
    fill_tag(ma + 1);
    fill_tag(mb + 1);
    CHECK(tsra_pkcs11_equal_ct(ma + 1, mb + 1, TAG_LEN), "compare: misaligned equal ranges");
    mb[TAG_LEN / 2] ^= 1;
    CHECK(!tsra_pkcs11_equal_ct(ma + 1, mb + 1, TAG_LEN), "compare: misaligned differing ranges");
}

int main(void)
{
    test_wipe();
    test_equal_ct();
    printf(
        g_fail ? "\nwipe_test: FAILED (%d checks)\n" : "\nwipe_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
