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
 * it, and one operation does not mix one-shot and multi-part calls. An HMAC
 * runs on one secret key in both directions, and its verify compares the tag
 * here (mac_verify) rather than in the SDK.
 */

#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_rsa_params.h"
#include "tsra_pkcs11_template.h"
#include "tsra_pkcs11_wipe.h"

#include <limits.h>
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
    bool is_pss;        /* a PSS mechanism, whose parameters are `pss` */
    CK_RSA_PKCS_PSS_PARAMS pss;
    bool mac;         /* an HMAC mechanism */
    CK_ULONG mac_fed; /* HMAC: the message bytes the multi-part calls fed so far */
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

/* The HMAC key types: the device kind to unmask a key as, and the tag length,
 * which is the hash length (api/lib HsmHmacKey::validate_props makes the key
 * as long as the hash). */
typedef struct
{
    CK_KEY_TYPE key_type;
    tsra_pkcs11_key_kind_t kind;
    CK_ULONG tag_len;
} hmac_info;

static const hmac_info HMAC_KEYS[] = {
    { CKK_SHA256_HMAC, TSRA_PKCS11_KIND_HMAC_SHA256, TSRA_PKCS11_SHA256_DIGEST_LEN },
    { CKK_SHA384_HMAC, TSRA_PKCS11_KIND_HMAC_SHA384, TSRA_PKCS11_SHA384_DIGEST_LEN },
    { CKK_SHA512_HMAC, TSRA_PKCS11_KIND_HMAC_SHA512, TSRA_PKCS11_SHA512_DIGEST_LEN },
};

/* The HMAC_KEYS row of `kt`, or NULL for a key type that is not HMAC. */
static const hmac_info *find_hmac(CK_KEY_TYPE kt)
{
    for (size_t i = 0; i < (sizeof(HMAC_KEYS) / sizeof(HMAC_KEYS[0])); i++)
    {
        if (HMAC_KEYS[i].key_type == kt)
        {
            return &HMAC_KEYS[i];
        }
    }
    return NULL;
}

/* The mechanism and direction check_key decides on. */
typedef struct
{
    const tsra_pkcs11_sign_mech *sm;
    bool sign;
} key_check_ctx;

/* Read the fixed-size attribute `type` of the record into `value`. */
static CK_RV key_attr(
    tsra_pkcs11_objstore_reader read,
    void *rctx,
    CK_ATTRIBUTE_TYPE type,
    void *value,
    CK_ULONG len
)
{
    CK_ATTRIBUTE a = { type, value, len };
    return read(rctx, &a);
}

/*
 * Whether the key may run the mechanism in the direction asked: a key of the
 * mechanism's type, a private key with CKA_SIGN or a public key with
 * CKA_VERIFY (for HMAC, a secret key with the same flag), and the mechanism
 * on its CKA_ALLOWED_MECHANISMS if it has one.
 * A missing or malformed attribute permits nothing. The store runs it on the
 * record it returns the body from, so a record rewritten in between cannot
 * pass the check with one version and supply the body from another.
 */
static CK_RV check_key(void *cctx, tsra_pkcs11_objstore_reader read, void *rctx)
{
    const tsra_pkcs11_sign_mech *sm = ((const key_check_ctx *)cctx)->sm;
    bool sign = ((const key_check_ctx *)cctx)->sign;
    CK_KEY_TYPE kt = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_CLASS cls = CK_UNAVAILABLE_INFORMATION;
    CK_BBOOL allowed = CK_FALSE;
    CK_RV rv = key_attr(read, rctx, CKA_KEY_TYPE, &kt, sizeof(kt));
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = key_attr(read, rctx, CKA_CLASS, &cls, sizeof(cls));
    }
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = key_attr(read, rctx, sign ? CKA_SIGN : CKA_VERIFY, &allowed, sizeof(allowed));
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
    CK_OBJECT_CLASS want = sign ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    if (find_hmac(kt) != NULL)
    {
        want = CKO_SECRET_KEY; /* one key for both directions */
    }
    if ((cls != want) || !allowed)
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_ALLOWED_MECHS];
    CK_ATTRIBUTE list = { CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs) };
    rv = read(rctx, &list);
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        return CKR_OK; /* no list: every mechanism of the key type */
    }
    if ((rv != CKR_OK) && (rv != CKR_BUFFER_TOO_SMALL))
    {
        return rv;
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
    case CKK_RSA: {
        uint32_t priv = 0;
        uint32_t pub = 0;
        CK_ULONG bits = 0;
        CK_RV rv = tsra_pkcs11_key_rsa_unmask(hsm_session, body, body_len, &priv, &pub, &bits);
        if (rv != CKR_OK)
        {
            return rv;
        }
        op->hsm_key = sign ? priv : pub;
        op->hsm_other = sign ? pub : priv;
        op->sig_len = bits / CHAR_BIT; /* the device's sizes are whole bytes */
        return CKR_OK;
    }
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC: {
        const hmac_info *h = find_hmac(op->sm->key_type);
        if (h == NULL)
        {
            return CKR_KEY_TYPE_INCONSISTENT; /* defensive: HMAC_KEYS lists all three */
        }
        op->mac = true;
        op->sig_len = h->tag_len;
        return tsra_pkcs11_key_hmac_unmask(hsm_session, h->kind, body, body_len, &op->hsm_key);
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
    CK_RSA_PKCS_PSS_PARAMS pss;
    bool is_pss = false;
    if (s->op != P11_OP_NONE)
    {
        rv = CKR_OPERATION_ACTIVE;
    }
    else if ((sm = tsra_pkcs11_sign_mech_find(pMechanism->mechanism)) == NULL)
    {
        rv = CKR_MECHANISM_INVALID;
    }
    else
    {
        rv = tsra_pkcs11_sign_params_check(pMechanism, &pss, &is_pss);
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
    CK_ULONG body_cap = 0; /* the read may report a larger body_len if the record changed */
    sign_op *op = NULL;
    key_check_ctx kc = { sm, want == P11_OP_SIGN };
    rv = g_tsra_pkcs11.store.ops->get_key_body(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        CK_TRUE,
        hKey,
        NULL,
        &body_len,
        NULL,
        NULL
    );
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* the handle names a key at this entry point */
    }
    if ((rv == CKR_OK) && (body_len == 0))
    {
        /* An object with no masked body (a data object, a public key made with
         * C_CreateObject, the unwrapping key pair) backs no device key. A key
         * that lacks the usage is told so rather than about its handle; both
         * reads end in a refusal, so no decision rests on two reads. */
        CK_RV check = g_tsra_pkcs11.store.ops->get_key_body(
            g_tsra_pkcs11.store.ctx,
            s->slot,
            CK_TRUE,
            hKey,
            NULL,
            &body_len,
            check_key,
            &kc
        );
        rv = (check == CKR_KEY_FUNCTION_NOT_PERMITTED) ? check : CKR_KEY_HANDLE_INVALID;
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    body_cap = body_len;
    body = (CK_BYTE *)malloc(body_cap);
    op = (sign_op *)calloc(1, sizeof(sign_op)); /* zeroed: no handles to release yet */
    if ((body == NULL) || (op == NULL))
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    /* The key's policy is checked on the record the body comes from. */
    rv = g_tsra_pkcs11.store.ops->get_key_body(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        CK_TRUE,
        hKey,
        body,
        &body_len,
        check_key,
        &kc
    );
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* removed since the length was read */
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    op->sm = sm;
    op->is_pss = is_pss;
    op->pss = pss;
    rv = bind_key(op, slot->hsm_session, want == P11_OP_SIGN, body, body_len);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    /* The PSS salt is a parameter error, but only the key tells whether it
     * fits (the mechanism checks above ran before the key was read). */
    if (is_pss && !tsra_pkcs11_pss_salt_ok(op->sig_len * CHAR_BIT, &pss))
    {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto cleanup;
    }
    s->op_ctx = op;
    s->op = want;
    op = NULL; /* ownership moved to the session */

cleanup:
    if (body != NULL)
    {
        tsra_pkcs11_wipe(body, body_cap);
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
 * 32-bit, CKM_ECDSA takes only the hash lengths the SDK recognises,
 * CKM_RSA_PKCS_PSS exactly one hash of its parameters' hashAlg, and an HMAC
 * at most HMAC_MAX_DATA_LEN bytes (checked here: the SDK's refusal,
 * INDEX_OUT_OF_RANGE, would reach the caller as CKR_ARGUMENTS_BAD). */
static CK_RV data_len_check(const sign_op *op, CK_ULONG len)
{
    bool raw_ecdsa = (op->sm->mech == CKM_ECDSA) && !tsra_pkcs11_ecdsa_raw_len_ok(len);
    bool pre_hashed =
        (op->sm->mech == CKM_RSA_PKCS_PSS) && (len != tsra_pkcs11_digest_mech_len(op->pss.hashAlg));
    bool mac_long = op->mac && (len > HMAC_MAX_DATA_LEN);
    return ((len > (CK_ULONG)UINT32_MAX) || raw_ecdsa || pre_hashed || mac_long)
               ? CKR_DATA_LEN_RANGE
               : CKR_OK;
}

/* The PSS parameters for the binding layer, NULL for a mechanism without them. */
static const CK_RSA_PKCS_PSS_PARAMS *pss_of(const sign_op *op)
{
    return op->is_pss ? &op->pss : NULL;
}

/* Open the operation's SDK stream unless a multi-part call already did. An
 * HMAC verify opens a sign stream (mac_verify). */
static CK_RV stream_open(sign_op *op, bool sign)
{
    if (op->stream != 0)
    {
        return CKR_OK;
    }
    return tsra_pkcs11_key_sign_stream_new(
        sign || op->mac,
        op->sm->mech,
        pss_of(op),
        op->hsm_key,
        &op->stream
    );
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
    rv = tsra_pkcs11_key_sign(
        op->sm->mech,
        pss_of(op),
        op->hsm_key,
        pData,
        ulDataLen,
        pSignature,
        &n
    );
    *pulSignatureLen = (rv == CKR_OK) ? n : 0;
    return op_done(s, false, rv);
}

/*
 * The HMAC verify: the device computes the tag, one-shot over `in` or by
 * finishing the operation's sign stream (`stream`), and it is compared with
 * the caller's `sig` here, in constant time. The SDK's HMAC verify compares
 * with `==`, which may stop at the first byte that differs. Signing is open
 * to every key that verifies: an HMAC key's device key carries both usages
 * (tsra_pkcs11_key_hkdf derives it so), and CKA_VERIFY was checked at the
 * init. The caller checked `sig_len` against op->sig_len.
 */
static CK_RV mac_verify(
    sign_op *op,
    bool stream,
    const CK_BYTE *in,
    CK_ULONG in_len,
    const CK_BYTE *sig,
    CK_ULONG sig_len
)
{
    CK_BYTE tag[TSRA_PKCS11_DIGEST_MAX_LEN]; /* the longest tag, HMAC-SHA-512's */
    CK_ULONG n = sizeof(tag);
    CK_RV rv = stream ? tsra_pkcs11_key_sign_stream_final(op->stream, tag, &n)
                      : tsra_pkcs11_key_sign(op->sm->mech, NULL, op->hsm_key, in, in_len, tag, &n);
    if ((rv == CKR_OK) && (n != sig_len))
    {
        rv = CKR_FUNCTION_FAILED; /* the device's tag is not as long as the key's */
    }
    if ((rv == CKR_OK) && !tsra_pkcs11_equal_ct(tag, sig, n))
    {
        rv = CKR_SIGNATURE_INVALID;
    }
    tsra_pkcs11_wipe(tag, sizeof(tag)); /* the valid tag would forge this message */
    return rv;
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
    else if ((ulPartLen > (CK_ULONG)UINT32_MAX) ||
             (op->mac && (ulPartLen > HMAC_MAX_DATA_LEN - op->mac_fed)))
    {
        rv = CKR_DATA_LEN_RANGE; /* for HMAC, the parts so far plus this one */
    }
    else
    {
        s->op_mode = P11_OP_MODE_MULTIPART;
        rv = stream_open(op, sign);
        if ((rv == CKR_OK) && (ulPartLen > 0))
        {
            bool signs = sign || op->mac; /* an HMAC verify feeds a sign stream */
            rv = tsra_pkcs11_key_sign_stream_update(signs, op->stream, pPart, ulPartLen);
        }
        if ((rv == CKR_OK) && op->mac)
        {
            op->mac_fed += ulPartLen; /* at most HMAC_MAX_DATA_LEN, checked above */
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
    if ((rv == CKR_OK) && op->mac)
    {
        rv = mac_verify(op, false, pData, ulDataLen, pSignature, ulSignatureLen);
    }
    else if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_key_verify(
            op->sm->mech,
            pss_of(op),
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
    if ((rv == CKR_OK) && op->mac)
    {
        rv = mac_verify(op, true, NULL, 0, pSignature, ulSignatureLen);
    }
    else if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_key_verify_stream_final(op->stream, pSignature, ulSignatureLen);
    }
    return op_done(s, false, rv);
}
