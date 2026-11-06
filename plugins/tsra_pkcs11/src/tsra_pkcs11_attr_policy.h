// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_attr_types.h"
#include "tsra_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Object policy: what C_CreateObject may create, which attributes of an
 * existing object C_SetAttributeValue may change, and to what, and whether
 * C_DestroyObject may destroy an object. The object store applies whatever it
 * is handed, so this is the only gate between a caller and a stored object. It
 * depends on neither the device nor the store (the object is read through a
 * callback), so it is unit-tested on its own (tests/attr_policy_test.c). Value
 * shapes and the template ceilings come from the attribute type table
 * (tsra_pkcs11_attr_types.h).
 *
 * The C_SetAttributeValue rules are PKCS#11 v3.1's footnote-8 attributes
 * ("may be modified after the object is created"), per object class, and
 * nothing else: an attribute is modifiable only if it is listed for the
 * object's class. Keys exist on the device only as masked blobs, so the latches
 * matter here: CKA_SENSITIVE and CKA_WRAP_WITH_TRUSTED can only become TRUE,
 * CKA_EXTRACTABLE only FALSE.
 */

/*
 * Decide whether C_CreateObject may create an object from `tmpl` in a session
 * that is read/write or not (`rw_session`), and whether it is a token object
 * (*token, CK_FALSE when CKA_TOKEN is absent; meaningful on CKR_OK only). Keys
 * enter this token only by generation or unwrap, so a secret or private key is
 * never created here. Returns, checking in this order:
 *   CKR_ARGUMENTS_BAD             NULL `token`, NULL tmpl with count > 0, or
 *                                 count > TEMPLATE_MAX_ATTRS
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES
 *   then per attribute, in template order, first failure wins:
 *   (tsra_pkcs11_attr_check)      a value of the wrong shape, an attribute
 *                                 array
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute only the token sets
 *                                 (tsra_pkcs11_attr_is_token_set)
 *   then over the whole template:
 *   CKR_SESSION_READ_ONLY         a token object and !rw_session; ahead of
 *                                 the class rules, so the caller learns about
 *                                 the session even for a template this token
 *                                 would refuse anyway
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_CLASS
 *   CKR_ATTRIBUTE_VALUE_INVALID   a class other than data, certificate,
 *                                 secret, private or public key
 *   CKR_TEMPLATE_INCONSISTENT     a secret, private or public key carrying key
 *                                 material (tsra_pkcs11_attr_is_key_material)
 *   CKR_TEMPLATE_INCOMPLETE       a secret or private key without it, which
 *                                 PKCS#11 requires
 */
CK_RV tsra_pkcs11_create_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    CK_BBOOL *token
);

/*
 * Reads one attribute of the target object, with C_GetAttributeValue semantics
 * for a single-entry template: CKR_OK fills a->pValue (or only a->ulValueLen
 * when pValue is NULL), CKR_ATTRIBUTE_TYPE_INVALID means the object does not
 * carry the type, and CKR_ATTRIBUTE_SENSITIVE means it does but will not reveal
 * it. Any other result (CKR_OBJECT_HANDLE_INVALID above all) is passed through.
 */
typedef CK_RV (*tsra_pkcs11_attr_reader)(void *ctx, CK_ATTRIBUTE *a);

/*
 * Decide whether `tmpl` may be applied to the object `read` sees. Nothing is
 * changed; on CKR_OK the whole template is acceptable. Returns, checking in
 * this order:
 *   CKR_ARGUMENTS_BAD             NULL `read`, NULL tmpl with count > 0, or
 *                                 count > TEMPLATE_MAX_ATTRS
 *   CKR_ATTRIBUTE_VALUE_INVALID   values over TEMPLATE_MAX_VALUE_BYTES
 *   (from `read`)                 e.g. CKR_OBJECT_HANDLE_INVALID
 *   CKR_SESSION_READ_ONLY         a token object and !rw_session
 *   CKR_ACTION_PROHIBITED         the object has CKA_MODIFIABLE = FALSE
 *   then per attribute, in template order, first failure wins:
 *   (tsra_pkcs11_attr_check)      a value of the wrong shape (an invalid
 *                                 CK_DATE among them), an attribute array
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute the class defines as fixed
 *                                 (CKA_CLASS, CKA_TOKEN, CKA_PRIVATE,
 *                                 CKA_VALUE, CKA_KEY_TYPE, ...), any other
 *                                 attribute the object carries but its class
 *                                 does not let change, or a latch moved back
 *                                 (SENSITIVE / WRAP_WITH_TRUSTED to FALSE,
 *                                 EXTRACTABLE to TRUE)
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute the object neither carries nor
 *                                 may gain
 * A stored value the store accepted malformed (a CK_BBOOL of the wrong width,
 * say) is read as its most restrictive meaning.
 */
CK_RV tsra_pkcs11_setattr_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    tsra_pkcs11_attr_reader read,
    void *ctx
);

/*
 * Decide whether C_DestroyObject may destroy the object `read` sees. Nothing is
 * changed. Returns, checking in this order:
 *   CKR_ARGUMENTS_BAD             NULL `read`
 *   (from `read`)                 e.g. CKR_OBJECT_HANDLE_INVALID
 *   CKR_SESSION_READ_ONLY         a token object and !rw_session
 *   CKR_ACTION_PROHIBITED         the object has CKA_DESTROYABLE = FALSE
 * A malformed stored value is read as its most restrictive meaning.
 */
CK_RV tsra_pkcs11_destroy_check(CK_BBOOL rw_session, tsra_pkcs11_attr_reader read, void *ctx);

#ifdef __cplusplus
}
#endif
