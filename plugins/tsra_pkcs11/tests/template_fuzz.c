// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * libFuzzer target over the device-free template decoders: the attribute type
 * table and its ceilings (src/tsra_pkcs11_attr_types.c), the C_CreateObject
 * and C_SetAttributeValue policy (src/tsra_pkcs11_attr_policy.c), the AES
 * key-generation template check and build (src/tsra_pkcs11_template.c), and
 * the unwrap and unwrapping key pair templates
 * (src/tsra_pkcs11_unwrap_params.c). The input becomes a template whose values
 * are slices of the input itself, so every ulValueLen is honest and a finding
 * is the module's, never caller UB. The same template doubles as the object
 * the C_SetAttributeValue check reads.
 *
 *   clang-18 -g -O1 -fsanitize=fuzzer,address,undefined -I ../include/pkcs11-v3.1 \
 *       -I ../src template_fuzz.c ../src/tsra_pkcs11_attr_types.c \
 *       ../src/tsra_pkcs11_attr_policy.c ../src/tsra_pkcs11_template.c \
 *       ../src/tsra_pkcs11_ec_template.c \
 *       ../src/tsra_pkcs11_unwrap_params.c ../src/tsra_pkcs11_digest.c \
 *       -o template_fuzz && ./template_fuzz -max_total_time=60
 *
 * Besides the sanitizers it traps when the checks disagree: a template the
 * C_CreateObject policy, the keygen or the unwrap check accepts must also pass
 * the type table, a built keygen or unwrap template never outgrows its
 * documented headroom, and no template asks for both halves of the unwrapping
 * key pair at once (one wraps, the other unwraps).
 */

#include "tsra_pkcs11_attr_policy.h"
#include "tsra_pkcs11_template.h"
#include "tsra_pkcs11_unwrap_params.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The types an input byte picks by index; other indexes become vendor types. */
static const CK_ATTRIBUTE_TYPE TYPES[] = {
    CKA_CLASS,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_LABEL,
    CKA_VALUE,
    CKA_KEY_TYPE,
    CKA_VALUE_LEN,
    CKA_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_ENCRYPT,
    CKA_DECRYPT,
    CKA_MODIFIABLE,
    CKA_LOCAL,
    CKA_TRUSTED,
    CKA_KEY_GEN_MECHANISM,
    CKA_ALLOWED_MECHANISMS,
    CKA_WRAP_TEMPLATE,
    CKA_START_DATE,
    CKA_END_DATE,
    CKA_PRIVATE_EXPONENT,
    CKA_ID,
    CKA_WRAP_WITH_TRUSTED,
    CKA_ALWAYS_SENSITIVE,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_WRAP,
    CKA_UNWRAP,
    CKA_SIGN,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
};

#define TYPE_INDEX_MASK 0x7Fu
#define NULL_VALUE_BIT 0x80u /* the entry keeps its length but has no value */

typedef struct
{
    const CK_ATTRIBUTE *attrs;
    CK_ULONG count;
} fuzz_obj;

/* The store's get_attr for one attribute, over the template as an object. */
static CK_RV read_obj(void *ctx, CK_ATTRIBUTE *a)
{
    const fuzz_obj *o = (const fuzz_obj *)ctx;
    for (CK_ULONG i = 0; i < o->count; i++)
    {
        const CK_ATTRIBUTE *s = &o->attrs[i];
        if ((s->type != a->type) || ((s->pValue == NULL) && (s->ulValueLen > 0)))
        {
            continue;
        }
        if (a->pValue == NULL)
        {
            a->ulValueLen = s->ulValueLen;
            return CKR_OK;
        }
        if (a->ulValueLen < s->ulValueLen)
        {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        if (s->ulValueLen > 0)
        {
            memcpy(a->pValue, s->pValue, s->ulValueLen);
        }
        a->ulValueLen = s->ulValueLen;
        return CKR_OK;
    }
    a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
    {
        return 0;
    }
    size_t pos = 0;
    /* One more than the ceiling, so the count check is reached too. */
    CK_ULONG count = data[pos++] % (TEMPLATE_MAX_ATTRS + 2);
    uint8_t flags = data[pos++];
    CK_ATTRIBUTE tmpl[TEMPLATE_MAX_ATTRS + 1];
    for (CK_ULONG i = 0; i < count; i++)
    {
        uint8_t t = (pos < size) ? data[pos++] : 0;
        size_t len = (pos < size) ? data[pos++] : 0;
        size_t idx = t & TYPE_INDEX_MASK;
        tmpl[i].type =
            (idx < (sizeof(TYPES) / sizeof(TYPES[0]))) ? TYPES[idx] : (CKA_VENDOR_DEFINED | idx);
        if ((t & NULL_VALUE_BIT) != 0)
        {
            tmpl[i].pValue = NULL;
        }
        else
        {
            len = (len <= (size - pos)) ? len : (size - pos);
            tmpl[i].pValue = (len > 0) ? (void *)(data + pos) : NULL;
            pos += len;
        }
        tmpl[i].ulValueLen = len;
    }

    CK_RV shapes = tsra_pkcs11_tmpl_check(tmpl, count);
    CK_BBOOL token = CK_FALSE;
    if ((tsra_pkcs11_create_check(tmpl, count, CK_TRUE, &token) == CKR_OK) && (shapes != CKR_OK))
    {
        __builtin_trap();
    }

    static const CK_MECHANISM_TYPE KEYGEN[] = { CKM_AES_KEY_GEN, CKM_AES_XTS_KEY_GEN };
    for (size_t m = 0; m < (sizeof(KEYGEN) / sizeof(KEYGEN[0])); m++)
    {
        const tsra_pkcs11_keygen_policy *pol = NULL;
        CK_ULONG value_len = 0;
        CK_BBOOL tok = CK_FALSE;
        if (tsra_pkcs11_keygen_check_template(KEYGEN[m], tmpl, count, &pol, &value_len, &tok) !=
            CKR_OK)
        {
            continue;
        }
        if (shapes != CKR_OK)
        {
            __builtin_trap();
        }
        tsra_pkcs11_keygen_fill fill;
        CK_ATTRIBUTE full[TEMPLATE_MAX_ATTRS + KEYGEN_APPENDED_ATTRS];
        CK_ULONG n = 0;
        if ((tsra_pkcs11_keygen_build_template(pol, tmpl, count, true, &fill, full, &n) != CKR_OK
            ) ||
            (n > (count + KEYGEN_APPENDED_ATTRS)))
        {
            __builtin_trap();
        }
    }

    /* A blob length up to 1020 bytes reaches every length the unwrap takes. */
    static tsra_pkcs11_unwrap_target target;
    if ((tsra_pkcs11_unwrap_check_template(tmpl, count, (CK_ULONG)flags * 4u, &target) == CKR_OK) &&
        ((shapes != CKR_OK) || (target.count > (count + 1))))
    {
        __builtin_trap();
    }
    CK_BBOOL pub_token = CK_FALSE;
    CK_BBOOL priv_token = CK_FALSE;
    CK_RV pair = tsra_pkcs11_unwrapping_pair_check(
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        tmpl,
        count,
        tmpl,
        count,
        &pub_token,
        &priv_token
    );
    if (pair == CKR_OK)
    {
        __builtin_trap();
    }

    fuzz_obj obj = { tmpl, count };
    (void)tsra_pkcs11_setattr_check(tmpl, count, (flags & 1u) ? CK_TRUE : CK_FALSE, read_obj, &obj);
    return 0;
}
