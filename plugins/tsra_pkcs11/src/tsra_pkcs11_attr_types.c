// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * The attribute type table (see tsra_pkcs11_attr_types.h).
 */

#include "tsra_pkcs11_attr_types.h"

#include <stddef.h>
#include <string.h>

typedef enum
{
    P11_SHAPE_BYTES = 0, /* any length */
    P11_SHAPE_BOOL,      /* exactly a CK_BBOOL */
    P11_SHAPE_ULONG,     /* exactly a CK_ULONG (CK_OBJECT_CLASS, CK_KEY_TYPE, ...) */
    P11_SHAPE_DATE,      /* a CK_DATE, or empty for no date */
    P11_SHAPE_MECHS,     /* whole CK_MECHANISM_TYPE entries */
    P11_SHAPE_ATTRS,     /* a CK_ATTRIBUTE array: not supported */
} attr_shape;

#define P11_ATTR_KEY_MATERIAL 0x01u /* never taken or revealed in clear */
#define P11_ATTR_TOKEN_SET 0x02u    /* set by the token, never by a caller */

typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    attr_shape shape;
    unsigned flags;
} attr_type;

/* The v3.1 types whose value is not plain bytes, plus the key-material ones. */
static const attr_type ATTR_TYPES[] = {
    { CKA_CLASS, P11_SHAPE_ULONG, 0 },
    { CKA_TOKEN, P11_SHAPE_BOOL, 0 },
    { CKA_PRIVATE, P11_SHAPE_BOOL, 0 },
    { CKA_UNIQUE_ID, P11_SHAPE_BYTES, P11_ATTR_TOKEN_SET },
    { CKA_VALUE, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_CERTIFICATE_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_TRUSTED, P11_SHAPE_BOOL, P11_ATTR_TOKEN_SET },
    { CKA_CERTIFICATE_CATEGORY, P11_SHAPE_ULONG, 0 },
    { CKA_JAVA_MIDP_SECURITY_DOMAIN, P11_SHAPE_ULONG, 0 },
    { CKA_NAME_HASH_ALGORITHM, P11_SHAPE_ULONG, 0 },
    { CKA_KEY_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_SENSITIVE, P11_SHAPE_BOOL, 0 },
    { CKA_ENCRYPT, P11_SHAPE_BOOL, 0 },
    { CKA_DECRYPT, P11_SHAPE_BOOL, 0 },
    { CKA_WRAP, P11_SHAPE_BOOL, 0 },
    { CKA_UNWRAP, P11_SHAPE_BOOL, 0 },
    { CKA_SIGN, P11_SHAPE_BOOL, 0 },
    { CKA_SIGN_RECOVER, P11_SHAPE_BOOL, 0 },
    { CKA_VERIFY, P11_SHAPE_BOOL, 0 },
    { CKA_VERIFY_RECOVER, P11_SHAPE_BOOL, 0 },
    { CKA_DERIVE, P11_SHAPE_BOOL, 0 },
    { CKA_START_DATE, P11_SHAPE_DATE, 0 },
    { CKA_END_DATE, P11_SHAPE_DATE, 0 },
    { CKA_MODULUS_BITS, P11_SHAPE_ULONG, 0 },
    { CKA_PRIVATE_EXPONENT, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_PRIME_1, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_PRIME_2, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_EXPONENT_1, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_EXPONENT_2, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_COEFFICIENT, P11_SHAPE_BYTES, P11_ATTR_KEY_MATERIAL },
    { CKA_PRIME_BITS, P11_SHAPE_ULONG, 0 },
    { CKA_SUBPRIME_BITS, P11_SHAPE_ULONG, 0 },
    { CKA_VALUE_BITS, P11_SHAPE_ULONG, 0 },
    { CKA_VALUE_LEN, P11_SHAPE_ULONG, 0 },
    { CKA_EXTRACTABLE, P11_SHAPE_BOOL, 0 },
    { CKA_LOCAL, P11_SHAPE_BOOL, P11_ATTR_TOKEN_SET },
    { CKA_NEVER_EXTRACTABLE, P11_SHAPE_BOOL, P11_ATTR_TOKEN_SET },
    { CKA_ALWAYS_SENSITIVE, P11_SHAPE_BOOL, P11_ATTR_TOKEN_SET },
    { CKA_KEY_GEN_MECHANISM, P11_SHAPE_ULONG, P11_ATTR_TOKEN_SET },
    { CKA_MODIFIABLE, P11_SHAPE_BOOL, 0 },
    { CKA_COPYABLE, P11_SHAPE_BOOL, 0 },
    { CKA_DESTROYABLE, P11_SHAPE_BOOL, 0 },
    { CKA_SECONDARY_AUTH, P11_SHAPE_BOOL, 0 },
    { CKA_AUTH_PIN_FLAGS, P11_SHAPE_ULONG, 0 },
    { CKA_ALWAYS_AUTHENTICATE, P11_SHAPE_BOOL, 0 },
    { CKA_WRAP_WITH_TRUSTED, P11_SHAPE_BOOL, 0 },
    { CKA_WRAP_TEMPLATE, P11_SHAPE_ATTRS, 0 },
    { CKA_UNWRAP_TEMPLATE, P11_SHAPE_ATTRS, 0 },
    { CKA_DERIVE_TEMPLATE, P11_SHAPE_ATTRS, 0 },
    { CKA_OTP_FORMAT, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_LENGTH, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_TIME_INTERVAL, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_USER_FRIENDLY_MODE, P11_SHAPE_BOOL, 0 },
    { CKA_OTP_CHALLENGE_REQUIREMENT, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_TIME_REQUIREMENT, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_COUNTER_REQUIREMENT, P11_SHAPE_ULONG, 0 },
    { CKA_OTP_PIN_REQUIREMENT, P11_SHAPE_ULONG, 0 },
    { CKA_HW_FEATURE_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_RESET_ON_INIT, P11_SHAPE_BOOL, 0 },
    { CKA_HAS_RESET, P11_SHAPE_BOOL, 0 },
    { CKA_PIXEL_X, P11_SHAPE_ULONG, 0 },
    { CKA_PIXEL_Y, P11_SHAPE_ULONG, 0 },
    { CKA_RESOLUTION, P11_SHAPE_ULONG, 0 },
    { CKA_CHAR_ROWS, P11_SHAPE_ULONG, 0 },
    { CKA_CHAR_COLUMNS, P11_SHAPE_ULONG, 0 },
    { CKA_COLOR, P11_SHAPE_BOOL, 0 },
    { CKA_BITS_PER_PIXEL, P11_SHAPE_ULONG, 0 },
    { CKA_MECHANISM_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_ALLOWED_MECHANISMS, P11_SHAPE_MECHS, 0 },
    { CKA_PROFILE_ID, P11_SHAPE_ULONG, 0 },
    { CKA_X2RATCHET_BAGSIZE, P11_SHAPE_ULONG, 0 },
    { CKA_X2RATCHET_BOBS1STMSG, P11_SHAPE_BOOL, 0 },
    { CKA_X2RATCHET_ISALICE, P11_SHAPE_BOOL, 0 },
    { CKA_X2RATCHET_NR, P11_SHAPE_ULONG, 0 },
    { CKA_X2RATCHET_NS, P11_SHAPE_ULONG, 0 },
    { CKA_X2RATCHET_PNS, P11_SHAPE_ULONG, 0 },
    { CKA_HSS_LEVELS, P11_SHAPE_ULONG, 0 },
    { CKA_HSS_LMS_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_HSS_LMOTS_TYPE, P11_SHAPE_ULONG, 0 },
    { CKA_HSS_KEYS_REMAINING, P11_SHAPE_ULONG, 0 },
};

static const attr_type *find_type(CK_ATTRIBUTE_TYPE t)
{
    for (size_t i = 0; i < sizeof(ATTR_TYPES) / sizeof(ATTR_TYPES[0]); i++)
    {
        if (ATTR_TYPES[i].type == t)
        {
            return &ATTR_TYPES[i];
        }
    }
    return NULL;
}

/* Parse `n` ASCII digits; -1 if any is not a digit. */
static int parse_digits(const CK_CHAR *p, size_t n)
{
    int v = 0;
    for (size_t i = 0; i < n; i++)
    {
        if ((p[i] < '0') || (p[i] > '9'))
        {
            return -1;
        }
        v = (v * 10) + (p[i] - '0');
    }
    return v;
}

/*
 * An empty value (no date), or a CK_DATE whose fields are in the ranges
 * pkcs11t.h gives: year 1900-9999, month 01-12, day 01-31. The day is not
 * checked against the month; the spec defines only the ranges.
 */
static bool date_ok(const CK_ATTRIBUTE *a)
{
    if (a->ulValueLen == 0)
    {
        return true;
    }
    if (a->ulValueLen != sizeof(CK_DATE))
    {
        return false;
    }
    CK_DATE d;
    memcpy(&d, a->pValue, sizeof(d));
    int year = parse_digits(d.year, sizeof(d.year));
    int month = parse_digits(d.month, sizeof(d.month));
    int day = parse_digits(d.day, sizeof(d.day));
    return (year >= 1900) && (month >= 1) && (month <= 12) && (day >= 1) && (day <= 31);
}

CK_RV tsra_pkcs11_tmpl_check_bounds(const CK_ATTRIBUTE *tmpl, CK_ULONG count)
{
    if (((tmpl == NULL) && (count > 0)) || (count > TEMPLATE_MAX_ATTRS))
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_ULONG total = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        /* Compared against what is left, so the sum never wraps. */
        if (tmpl[i].ulValueLen > (TEMPLATE_MAX_VALUE_BYTES - total))
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        total += tmpl[i].ulValueLen;
    }
    return CKR_OK;
}

CK_RV tsra_pkcs11_attr_check(const CK_ATTRIBUTE *a)
{
    if ((a == NULL) || ((a->ulValueLen > 0) && (a->pValue == NULL)))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    const attr_type *t = find_type(a->type);
    bool ok = true;
    switch ((t != NULL) ? t->shape : P11_SHAPE_BYTES)
    {
    case P11_SHAPE_BYTES:
        break;
    case P11_SHAPE_BOOL:
        ok = (a->ulValueLen == sizeof(CK_BBOOL));
        break;
    case P11_SHAPE_ULONG:
        ok = (a->ulValueLen == sizeof(CK_ULONG));
        break;
    case P11_SHAPE_DATE:
        ok = date_ok(a);
        break;
    case P11_SHAPE_MECHS:
        ok = ((a->ulValueLen % sizeof(CK_MECHANISM_TYPE)) == 0);
        break;
    case P11_SHAPE_ATTRS:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    return ok ? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
}

CK_RV tsra_pkcs11_tmpl_check(const CK_ATTRIBUTE *tmpl, CK_ULONG count)
{
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    for (CK_ULONG i = 0; (rv == CKR_OK) && (i < count); i++)
    {
        rv = tsra_pkcs11_attr_check(&tmpl[i]);
    }
    return rv;
}

bool tsra_pkcs11_attr_is_key_material(CK_ATTRIBUTE_TYPE t)
{
    const attr_type *a = find_type(t);
    return (a != NULL) && ((a->flags & P11_ATTR_KEY_MATERIAL) != 0);
}

bool tsra_pkcs11_attr_is_token_set(const CK_ATTRIBUTE *a)
{
    const attr_type *t = find_type(a->type);
    if ((t == NULL) || ((t->flags & P11_ATTR_TOKEN_SET) == 0))
    {
        return false;
    }
    /* The shape check left exactly one CK_BBOOL to read. */
    return (a->type != CKA_TRUSTED) || (*(const CK_BBOOL *)a->pValue != CK_FALSE);
}
