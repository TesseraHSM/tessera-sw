// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * The attribute type table every template entry point checks a caller's
 * template against before any value is read, stored or matched: the value
 * shape of each CKA_* type of PKCS#11 v3.1 (CK_BBOOL, CK_ULONG, CK_DATE, a
 * mechanism list, an attribute array, or bytes of any length for every type
 * not listed), and which types are key material or set only by the token.
 * Device-free, unit-tested on its own (tests/attr_types_test.c) and fuzzed
 * with the template decoders (tests/template_fuzz.c).
 */

/*
 * Ceiling on a caller template's ulCount. PKCS#11 defines some forty
 * attributes for any one object, so anything longer is a bogus count, refused
 * before an O(n²) duplicate scan or a buffer sized from it.
 */
#define TEMPLATE_MAX_ATTRS 64

/*
 * Ceiling on the sum of a template's value lengths, which the object store
 * copies. Far above any certificate or public key, low enough that a bogus
 * ulValueLen is refused before an allocation is sized from it.
 */
#define TEMPLATE_MAX_VALUE_BYTES (1024 * 1024)

/*
 * The ceilings a template is held to before any value is read or copied:
 * CKR_ARGUMENTS_BAD for a NULL tmpl with count > 0 or count above
 * TEMPLATE_MAX_ATTRS, CKR_ATTRIBUTE_VALUE_INVALID for value lengths summing to
 * more than TEMPLATE_MAX_VALUE_BYTES.
 */
CK_RV tsra_pkcs11_tmpl_check_bounds(const CK_ATTRIBUTE *tmpl, CK_ULONG count);

/*
 * Check one caller attribute against the type table. Reads the value only
 * when its length is right for the type. Returns:
 *   CKR_ATTRIBUTE_VALUE_INVALID   NULL `a`, a NULL value with a non-zero
 *                                 length, a CK_BBOOL or CK_ULONG value not
 *                                 exactly that wide, a CK_DATE value neither
 *                                 empty nor a valid date (sizeof(CK_DATE)
 *                                 wide, digits only, year 1900-9999, month
 *                                 01-12, day 01-31), or a mechanism list that
 *                                 is not a whole number of entries
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute array (CKA_WRAP_TEMPLATE,
 *                                 CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE):
 *                                 its entries point into the caller's memory
 *   CKR_OK                        otherwise
 */
CK_RV tsra_pkcs11_attr_check(const CK_ATTRIBUTE *a);

/* tsra_pkcs11_tmpl_check_bounds, then tsra_pkcs11_attr_check on every entry
 * in template order; the first failure wins. */
CK_RV tsra_pkcs11_tmpl_check(const CK_ATTRIBUTE *tmpl, CK_ULONG count);

/* Whether `t` is key material (CKA_VALUE and the RSA private components): the
 * token never takes it in clear and a sensitive object never reveals it. */
bool tsra_pkcs11_attr_is_key_material(CK_ATTRIBUTE_TYPE t);

/* Whether `a`, an entry tsra_pkcs11_attr_check accepted, sets what only the
 * token sets: how a key came to be, CKA_UNIQUE_ID, or CKA_TRUSTED = TRUE,
 * which needs the Security Officer this token does not have. CKA_TRUSTED =
 * FALSE is its default, and any caller may state it. */
bool tsra_pkcs11_attr_is_token_set(const CK_ATTRIBUTE *a);

#ifdef __cplusplus
}
#endif
