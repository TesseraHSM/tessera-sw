// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Sign and verify: C_SignInit / C_Sign / C_SignUpdate / C_SignFinal and their
 * C_Verify* counterparts, for the mechanisms of tsra_pkcs11_sign_mech_find.
 * The operation knows the mechanism only through that table: the init binds
 * the key object's masked body to device handles by key type and learns the
 * signature length there, and the data calls follow the lifetime rules of the
 * cipher operations (tsra_pkcs11_crypt.c): a NULL output buffer or a
 * too-small one keeps the operation for the retry, every other outcome ends
 * it, and one operation does not mix one-shot and multi-part calls.
 */

#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_template.h"

#include <stdint.h>
#include <stdlib.h>

/* Per-operation state (s->op_ctx while op is P11_OP_SIGN / P11_OP_VERIFY). */
typedef struct
{
    const tsra_pkcs11_sign_mech *sm;
    uint32_t hsm_key;   /* the device key that signs or verifies; owned */
    uint32_t hsm_other; /* the other half of an unmasked pair; owned, unused */
    uint32_t stream;    /* SDK stream context once a multi-part call ran; 0 = none */
    CK_ULONG sig_len;   /* the signature length for this key and mechanism */
} sign_op;

void tsra_pkcs11_sign_op_free(void *op_ctx)
{
    sign_op *op = (sign_op *)op_ctx;
    if (op == NULL)
    {
        return;
    }
    tsra_pkcs11_key_sign_stream_free(op->stream); /* before the key it references */
    tsra_pkcs11_key_release(op->hsm_key);
    tsra_pkcs11_key_release(op->hsm_other);
    free(op);
}

/* Read the fixed-size attribute `type` of key `h` into `value`. */
static CK_RV key_attr(
    const tsra_pkcs11_session_t *s,
    CK_OBJECT_HANDLE h,
    CK_ATTRIBUTE_TYPE type,
    void *value,
    CK_ULONG len
)
{
    CK_ATTRIBUTE a = { type, value, len };
    CK_RV rv =
        g_tsra_pkcs11.store.ops->get_attr(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, h, &a, 1);
    return (rv == CKR_OBJECT_HANDLE_INVALID) ? CKR_KEY_HANDLE_INVALID : rv;
}

/*
 * Whether key `h` may run `sm` in the direction `sign`: a key of the
 * mechanism's type, a private key with CKA_SIGN or a public key with
 * CKA_VERIFY, and the mechanism on its CKA_ALLOWED_MECHANISMS if it has one.
 * A missing or malformed attribute permits nothing.
 */
static CK_RV check_key(
    const tsra_pkcs11_session_t *s,
    CK_OBJECT_HANDLE h,
    const tsra_pkcs11_sign_mech *sm,
    bool sign
)
{
    CK_KEY_TYPE kt = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_CLASS cls = CK_UNAVAILABLE_INFORMATION;
    CK_BBOOL allowed = CK_FALSE;
    CK_RV rv = key_attr(s, h, CKA_KEY_TYPE, &kt, sizeof(kt));
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = key_attr(s, h, CKA_CLASS, &cls, sizeof(cls));
    }
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = key_attr(s, h, sign ? CKA_SIGN : CKA_VERIFY, &allowed, sizeof(allowed));
    }
    /* Only an absent attribute is a policy verdict; a store failure is
     * reported as itself. */
    if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID))
    {
        return rv;
    }
    if (kt != sm->key_type)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if ((cls != (sign ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY)) || !allowed)
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_ALLOWED_MECHS];
    CK_ATTRIBUTE list = { CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs) };
    rv = g_tsra_pkcs11.store.ops->get_attr(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, h, &list, 1);
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        return CKR_OK; /* no list: every mechanism of the key type */
    }
    if ((rv != CKR_OK) && (rv != CKR_BUFFER_TOO_SMALL))
    {
        return (rv == CKR_OBJECT_HANDLE_INVALID) ? CKR_KEY_HANDLE_INVALID : rv;
    }
    return tsra_pkcs11_key_mech_permitted(rv, mechs, list.ulValueLen, sm->mech)
               ? CKR_OK
               : CKR_KEY_FUNCTION_NOT_PERMITTED;
}

/*
 * Unmask the key object's masked `body` into the operation's device handles
 * and set the signature length, by the key type the mechanism takes. A key
 * type that joins the sign table gets its arm here.
 */
static CK_RV bind_key(
    sign_op *op,
    uint32_t hsm_session,
    bool sign,
    const CK_BYTE *body,
    CK_ULONG body_len
)
{
    switch (op->sm->key_type)
    {
    case CKK_EC: {
        uint32_t priv = 0;
        uint32_t pub = 0;
        tsra_pkcs11_ec_curve_t curve = TSRA_PKCS11_CURVE_NONE;
        CK_RV rv = tsra_pkcs11_key_ec_unmask(hsm_session, body, body_len, &priv, &pub, &curve);
        if (rv != CKR_OK)
        {
            return rv;
        }
        op->hsm_key = sign ? priv : pub;
        op->hsm_other = sign ? pub : priv;
        op->sig_len = 2 * tsra_pkcs11_ec_coord_len(curve); /* r || s */
        return CKR_OK;
    }
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }
}

static CK_RV sign_init(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey,
    tsra_pkcs11_op_type_t want
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pMechanism == NULL_PTR)
    {
        tsra_pkcs11_session_cancel_op(s, want);
        tsra_pkcs11_unlock();
        return CKR_OK;
    }
    /* Precedence as in C_EncryptInit: handle, the NULL-mechanism cancel above,
     * operation state, mechanism and its parameter, then login state. */
    CK_RV rv = CKR_OK;
    const tsra_pkcs11_sign_mech *sm = NULL;
    if (s->op != P11_OP_NONE)
    {
        rv = CKR_OPERATION_ACTIVE;
    }
    else if ((sm = tsra_pkcs11_sign_mech_find(pMechanism->mechanism)) == NULL)
    {
        rv = CKR_MECHANISM_INVALID;
    }
    else if ((pMechanism->pParameter != NULL_PTR) || (pMechanism->ulParameterLen != 0))
    {
        rv = CKR_MECHANISM_PARAM_INVALID;
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    if (!slot->user_logged_in || (slot->hsm_session == 0))
    {
        tsra_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN; /* unmasking needs the device session */
    }

    CK_BYTE *body = NULL;
    CK_ULONG body_len = 0;
    sign_op *op = NULL;
    rv = g_tsra_pkcs11.store.ops
             ->get_key_body(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, NULL, &body_len);
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* the handle names a key at this entry point */
    }
    if ((rv == CKR_OK) && (body_len == 0))
    {
        /* An object with no masked body (a data object, or a public key made
         * with C_CreateObject) backs no device key. */
        rv = CKR_KEY_HANDLE_INVALID;
    }
    if (rv == CKR_OK)
    {
        rv = check_key(s, hKey, sm, want == P11_OP_SIGN);
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    body = (CK_BYTE *)malloc(body_len);
    op = (sign_op *)calloc(1, sizeof(sign_op)); /* zeroed: no handles to release yet */
    if ((body == NULL) || (op == NULL))
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    rv = g_tsra_pkcs11.store.ops
             ->get_key_body(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, body, &body_len);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    op->sm = sm;
    rv = bind_key(op, slot->hsm_session, want == P11_OP_SIGN, body, body_len);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    s->op_ctx = op;
    s->op = want;
    op = NULL; /* ownership moved to the session */

cleanup:
    if (body != NULL)
    {
        tsra_pkcs11_wipe(body, body_len);
        free(body);
    }
    tsra_pkcs11_sign_op_free(op);
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return sign_init(hSession, pMechanism, hKey, P11_OP_SIGN);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return sign_init(hSession, pMechanism, hKey, P11_OP_VERIFY);
}

/*
 * Take the lock and look up the session with an active operation of kind
 * `want`. NULL with *rv set (and the lock released again) when there is none:
 * then there is nothing to terminate.
 */
static tsra_pkcs11_session_t *active_session(
    CK_SESSION_HANDLE hSession,
    tsra_pkcs11_op_type_t want,
    CK_RV *rv
)
{
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    *rv = CKR_OK;
    if (s == NULL)
    {
        *rv = CKR_SESSION_HANDLE_INVALID;
    }
    else if ((s->op != want) || (s->op_ctx == NULL))
    {
        *rv = CKR_OPERATION_NOT_INITIALIZED;
    }
    if (*rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return NULL;
    }
    return s;
}

/* Release the lock active_session took, ending the operation unless `keep`. */
static CK_RV op_done(tsra_pkcs11_session_t *s, bool keep, CK_RV rv)
{
    if (!keep)
    {
        tsra_pkcs11_session_reset_op(s);
    }
    tsra_pkcs11_unlock();
    return rv;
}

/* The length verdict on the data of a one-shot call: the device buffers are
 * 32-bit, and CKM_ECDSA takes only the hash lengths the SDK recognises. */
static CK_RV data_len_check(const sign_op *op, CK_ULONG len)
{
    if ((len > (CK_ULONG)UINT32_MAX) ||
        ((op->sm->mech == CKM_ECDSA) && !tsra_pkcs11_ecdsa_raw_len_ok(len)))
    {
        return CKR_DATA_LEN_RANGE;
    }
    return CKR_OK;
}

/* Open the operation's SDK stream unless a multi-part call already did. */
static CK_RV stream_open(sign_op *op, bool sign)
{
    if (op->stream != 0)
    {
        return CKR_OK;
    }
    return tsra_pkcs11_key_sign_stream_new(sign, op->sm->mech, op->hsm_key, &op->stream);
}

/*
 * The sizing half of C_Sign and C_SignFinal: a NULL buffer learns the length
 * and a too-small one CKR_BUFFER_TOO_SMALL, both keeping the operation (*keep).
 * CKR_OK with *keep false means: sign into `sig`.
 */
static CK_RV sig_size(const sign_op *op, const CK_BYTE *sig, CK_ULONG_PTR sig_len, bool *keep)
{
    *keep = (sig == NULL_PTR) || (*sig_len < op->sig_len);
    if (*keep)
    {
        CK_RV rv = (sig == NULL_PTR) ? CKR_OK : CKR_BUFFER_TOO_SMALL;
        *sig_len = op->sig_len;
        return rv;
    }
    return CKR_OK;
}

CK_RV C_Sign(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    tsra_pkcs11_session_t *s = active_session(hSession, P11_OP_SIGN, &rv);
    if (s == NULL)
    {
        return rv;
    }
    sign_op *op = (sign_op *)s->op_ctx;
    if ((pulSignatureLen == NULL_PTR) || ((pData == NULL_PTR) && (ulDataLen > 0)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_MULTIPART)
    {
        rv = CKR_OPERATION_ACTIVE; /* only C_SignFinal may finish it now */
    }
    else
    {
        rv = data_len_check(op, ulDataLen);
    }
    if (rv != CKR_OK)
    {
        return op_done(s, false, rv);
    }
    s->op_mode = P11_OP_MODE_ONESHOT;
    bool keep = false;
    rv = sig_size(op, pSignature, pulSignatureLen, &keep);
    if (keep)
    {
        return op_done(s, true, rv);
    }
    CK_ULONG n = op->sig_len;
    rv = tsra_pkcs11_key_sign(op->sm->mech, op->hsm_key, pData, ulDataLen, pSignature, &n);
    *pulSignatureLen = (rv == CKR_OK) ? n : 0;
    return op_done(s, false, rv);
}

/* Shared C_SignUpdate / C_VerifyUpdate body. */
static CK_RV sign_update(
    CK_SESSION_HANDLE hSession,
    bool sign,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    tsra_pkcs11_session_t *s = active_session(hSession, sign ? P11_OP_SIGN : P11_OP_VERIFY, &rv);
    if (s == NULL)
    {
        return rv;
    }
    sign_op *op = (sign_op *)s->op_ctx;
    if ((pPart == NULL_PTR) && (ulPartLen > 0))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE; /* a one-shot call is in progress */
    }
    else if (!op->sm->multipart)
    {
        rv = CKR_FUNCTION_NOT_SUPPORTED; /* the SDK streams no caller-made hash */
    }
    else if (ulPartLen > (CK_ULONG)UINT32_MAX)
    {
        rv = CKR_DATA_LEN_RANGE;
    }
    else
    {
        s->op_mode = P11_OP_MODE_MULTIPART;
        rv = stream_open(op, sign);
        if ((rv == CKR_OK) && (ulPartLen > 0))
        {
            rv = tsra_pkcs11_key_sign_stream_update(sign, op->stream, pPart, ulPartLen);
        }
    }
    return op_done(s, rv == CKR_OK, rv);
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return sign_update(hSession, true, pPart, ulPartLen);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    tsra_pkcs11_session_t *s = active_session(hSession, P11_OP_SIGN, &rv);
    if (s == NULL)
    {
        return rv;
    }
    sign_op *op = (sign_op *)s->op_ctx;
    if (pulSignatureLen == NULL_PTR)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE;
    }
    else if (!op->sm->multipart)
    {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }
    if (rv != CKR_OK)
    {
        return op_done(s, false, rv);
    }
    /* Straight after the init this is the (allowed) zero-part case. */
    s->op_mode = P11_OP_MODE_MULTIPART;
    bool keep = false;
    rv = sig_size(op, pSignature, pulSignatureLen, &keep);
    if (keep)
    {
        return op_done(s, true, rv);
    }
    CK_ULONG n = op->sig_len;
    rv = stream_open(op, true);
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_key_sign_stream_final(op->stream, pSignature, &n);
    }
    *pulSignatureLen = (rv == CKR_OK) ? n : 0;
    return op_done(s, false, rv);
}

CK_RV C_Verify(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    tsra_pkcs11_session_t *s = active_session(hSession, P11_OP_VERIFY, &rv);
    if (s == NULL)
    {
        return rv;
    }
    sign_op *op = (sign_op *)s->op_ctx;
    if (((pData == NULL_PTR) && (ulDataLen > 0)) ||
        ((pSignature == NULL_PTR) && (ulSignatureLen > 0)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_MULTIPART)
    {
        rv = CKR_OPERATION_ACTIVE; /* only C_VerifyFinal may finish it now */
    }
    else
    {
        rv = data_len_check(op, ulDataLen);
    }
    if ((rv == CKR_OK) && (ulSignatureLen != op->sig_len))
    {
        rv = CKR_SIGNATURE_LEN_RANGE;
    }
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_key_verify(
            op->sm->mech,
            op->hsm_key,
            pData,
            ulDataLen,
            pSignature,
            ulSignatureLen
        );
    }
    return op_done(s, false, rv);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return sign_update(hSession, false, pPart, ulPartLen);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    tsra_pkcs11_session_t *s = active_session(hSession, P11_OP_VERIFY, &rv);
    if (s == NULL)
    {
        return rv;
    }
    sign_op *op = (sign_op *)s->op_ctx;
    if ((pSignature == NULL_PTR) && (ulSignatureLen > 0))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (!op->sm->multipart)
    {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }
    else if (ulSignatureLen != op->sig_len)
    {
        rv = CKR_SIGNATURE_LEN_RANGE;
    }
    else
    {
        rv = stream_open(op, false);
    }
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_key_verify_stream_final(op->stream, pSignature, ulSignatureLen);
    }
    return op_done(s, false, rv);
}
