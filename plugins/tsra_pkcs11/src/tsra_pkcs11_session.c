// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Session lifecycle, login, the object entry points (which delegate to the
 * object-store seam), and the host-side digests (see tsra_pkcs11_digest.h).
 * The digests need no partition provisioning, so they are the operations the
 * validation tools can drive end-to-end while the key-backed mechanisms are
 * still unimplemented.
 */

#include "tsra_pkcs11_attr_policy.h"
#include "tsra_pkcs11_config.h"
#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_hsm.h"
#include "tsra_pkcs11_internal.h"

#include <stdlib.h>

/* ========================================================================= */
/* Operation state                                                           */
/* ========================================================================= */

CK_RV tsra_pkcs11_session_reset_op(tsra_pkcs11_session_t *s)
{
    if (s->op == P11_OP_DIGEST && s->op_ctx != NULL)
    {
        tsra_pkcs11_digest_op_free(s->op_ctx);
    }
    if (((s->op == P11_OP_ENCRYPT) || (s->op == P11_OP_DECRYPT)) && (s->op_ctx != NULL))
    {
        tsra_pkcs11_cipher_op_free(s->op_ctx);
    }
    if (((s->op == P11_OP_SIGN) || (s->op == P11_OP_VERIFY)) && (s->op_ctx != NULL))
    {
        tsra_pkcs11_sign_op_free(s->op_ctx);
    }
    s->op_ctx = NULL;
    if (s->op == P11_OP_FIND && s->find_cursor != NULL)
    {
        g_tsra_pkcs11.store.ops->find_final(g_tsra_pkcs11.store.ctx, s->find_cursor);
    }
    s->find_cursor = NULL;
    s->op = P11_OP_NONE;
    s->op_mode = P11_OP_MODE_UNSET;
    return CKR_OK;
}

void tsra_pkcs11_session_cancel_op(tsra_pkcs11_session_t *s, tsra_pkcs11_op_type_t op)
{
    if ((s != NULL) && (s->op == op))
    {
        tsra_pkcs11_session_reset_op(s);
    }
}

/* The C_SessionCancel flag naming operation `op`; 0 for none. */
static CK_FLAGS op_cancel_flag(tsra_pkcs11_op_type_t op)
{
    switch (op)
    {
    case P11_OP_FIND:
        return CKF_FIND_OBJECTS;
    case P11_OP_ENCRYPT:
        return CKF_ENCRYPT;
    case P11_OP_DECRYPT:
        return CKF_DECRYPT;
    case P11_OP_DIGEST:
        return CKF_DIGEST;
    case P11_OP_SIGN:
        return CKF_SIGN;
    case P11_OP_VERIFY:
        return CKF_VERIFY;
    default:
        return 0;
    }
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
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
    /* The spec ignores a flag whose operation is not active, so flags naming
     * operations this module lacks need no check. Every operation here can be
     * cancelled, so CKR_OPERATION_CANCEL_FAILED never arises. */
    if ((flags & op_cancel_flag(s->op)) != 0)
    {
        tsra_pkcs11_session_reset_op(s);
    }
    tsra_pkcs11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Session objects (destroyed with their session — the C_CloseSession rule)   */
/* ========================================================================= */

/* First allocation of a session's owned-object list; doubles from there. */
#define OWNED_OBJECTS_INITIAL_CAP 8

CK_RV tsra_pkcs11_session_own_object(tsra_pkcs11_session_t *s, CK_OBJECT_HANDLE h)
{
    if (s == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (s->owned_count == s->owned_cap)
    {
        CK_ULONG cap = (s->owned_cap == 0) ? OWNED_OBJECTS_INITIAL_CAP : (s->owned_cap * 2);
        CK_OBJECT_HANDLE *grown = (CK_OBJECT_HANDLE *)realloc(s->owned, cap * sizeof(*grown));
        if (grown == NULL)
        {
            return CKR_HOST_MEMORY;
        }
        s->owned = grown;
        s->owned_cap = cap;
    }
    s->owned[s->owned_count++] = h;
    return CKR_OK;
}

void tsra_pkcs11_session_disown_object(CK_SLOT_ID slot, CK_OBJECT_HANDLE h)
{
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        tsra_pkcs11_session_t *s = &g_tsra_pkcs11.sessions[i];
        if (!s->in_use || (s->slot != slot))
        {
            continue;
        }
        for (CK_ULONG j = 0; j < s->owned_count; j++)
        {
            if (s->owned[j] == h)
            {
                s->owned_count--;
                s->owned[j] = s->owned[s->owned_count]; /* order is irrelevant */
                return;
            }
        }
    }
}

void tsra_pkcs11_session_destroy_owned(tsra_pkcs11_session_t *s)
{
    if (s == NULL)
    {
        return;
    }
    for (CK_ULONG i = 0; i < s->owned_count; i++)
    {
        /* A session reaps its own objects whatever the login state is, hence
         * CK_TRUE. An object a sibling session destroyed meanwhile is simply
         * gone: store handles are never reused, so nothing else can be hit. */
        (void)g_tsra_pkcs11.store.ops
            ->destroy(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, s->owned[i], NULL, NULL);
    }
    free(s->owned);
    s->owned = NULL;
    s->owned_count = 0;
    s->owned_cap = 0;
}

/* The C_Logout rule: destroy the private session objects `s` owns and keep
 * the public ones. */
static void destroy_private_owned(tsra_pkcs11_session_t *s)
{
    CK_ULONG kept = 0;
    for (CK_ULONG i = 0; i < s->owned_count; i++)
    {
        CK_OBJECT_HANDLE h = s->owned[i];
        /* Private as the store judges it: hidden from a logged-out caller. */
        CK_RV seen = g_tsra_pkcs11.store.ops
                         ->get_attr(g_tsra_pkcs11.store.ctx, s->slot, CK_FALSE, h, NULL, 0);
        if (seen == CKR_OBJECT_HANDLE_INVALID)
        {
            (void)g_tsra_pkcs11.store.ops
                ->destroy(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, h, NULL, NULL);
        }
        else
        {
            s->owned[kept++] = h;
        }
    }
    s->owned_count = kept;
}

/* ========================================================================= */
/* Sessions                                                                  */
/* ========================================================================= */

CK_RV C_OpenSession(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    CK_VOID_PTR pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phSession == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if ((flags & CKF_SERIAL_SESSION) == 0)
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = NULL;
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        if (!g_tsra_pkcs11.sessions[i].in_use)
        {
            s = &g_tsra_pkcs11.sessions[i];
            break;
        }
    }
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_COUNT;
    }
    memset(s, 0, sizeof(*s));
    s->in_use = true;
    s->handle = g_tsra_pkcs11.next_session_handle++;
    s->slot = slotID;
    s->flags = flags;
    s->app = pApplication;
    s->notify = Notify;
    s->op = P11_OP_NONE;
    *phSession = s->handle;
    tsra_pkcs11_unlock();
    return CKR_OK;
}

static bool slot_has_sessions(CK_SLOT_ID slot)
{
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_tsra_pkcs11.sessions[i].in_use && g_tsra_pkcs11.sessions[i].slot == slot)
        {
            return true;
        }
    }
    return false;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
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
    CK_SLOT_ID slot_id = s->slot;
    tsra_pkcs11_session_reset_op(s);
    tsra_pkcs11_session_destroy_owned(s);
    s->in_use = false;
    /* The HSM login is token-wide: close it only when the last session on the
     * slot goes away, not whenever any one session closes. */
    if (!slot_has_sessions(slot_id))
    {
        tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[slot_id];
        tsra_pkcs11_hsm_logout(slot->hsm_session);
        slot->hsm_session = 0;
        slot->user_logged_in = false;
    }
    tsra_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    tsra_pkcs11_lock();
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_tsra_pkcs11.sessions[i].in_use && g_tsra_pkcs11.sessions[i].slot == slotID)
        {
            tsra_pkcs11_session_reset_op(&g_tsra_pkcs11.sessions[i]);
            tsra_pkcs11_session_destroy_owned(&g_tsra_pkcs11.sessions[i]);
            g_tsra_pkcs11.sessions[i].in_use = false;
        }
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[slotID];
    tsra_pkcs11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    tsra_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    bool rw = (s->flags & CKF_RW_SESSION) != 0;

    CK_STATE state;
    if (slot->user_logged_in)
    {
        state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    }
    else
    {
        state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    }

    pInfo->slotID = s->slot;
    pInfo->state = state;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    tsra_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_Login(
    CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen
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
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    CK_RV rv = CKR_OK;
    switch (userType)
    {
    case CKU_USER: {
        /*
         * The PIN rules come before the login state, so a malformed PIN gets
         * the same answer in every state. An empty PIN means the configured
         * default PIN (CKF_PROTECTED_AUTHENTICATION_PATH) and is out of range
         * without one.
         */
        CK_BYTE pin[P11_CREDS_PIN_LEN];
        bool use_default = (ulPinLen == 0) && g_tsra_pkcs11.default_pin;
        if (!use_default)
        {
            rv = tsra_pkcs11_pin_normalise(pPin, ulPinLen, pin);
        }
        if ((rv == CKR_OK) && slot->user_logged_in)
        {
            rv = CKR_USER_ALREADY_LOGGED_IN;
        }
        if (rv == CKR_OK)
        {
            uint32_t hs = 0;
            rv = tsra_pkcs11_hsm_login(s->slot, use_default ? NULL : pin, &hs);
            if (rv == CKR_OK)
            {
                slot->hsm_session = hs;
                slot->user_logged_in = true;
            }
        }
        tsra_pkcs11_wipe(pin, sizeof(pin));
        break;
    }
    case CKU_SO:
        /*
         * The TSRA DDI has no security-officer credential, so an SO login
         * cannot be authenticated. Accepting it unconditionally would let any
         * caller put the token into SO mode and lock out RO sessions, so reject
         * it until SO is backed by a real credential.
         */
        rv = CKR_USER_TYPE_INVALID;
        break;
    case CKU_CONTEXT_SPECIFIC:
        /*
         * Per-operation re-authentication (for CKA_ALWAYS_AUTHENTICATE keys).
         * No such operation can be active yet, so there is nothing to
         * re-authenticate.
         */
        rv = CKR_OPERATION_NOT_INITIALIZED;
        break;
    default:
        rv = CKR_USER_TYPE_INVALID;
        break;
    }
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
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
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    if (!slot->user_logged_in)
    {
        tsra_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }
    /* Logout closes the token's device session, and cipher and sign
     * operations hold device key handles scoped to it: release them first,
     * while the session they belong to is still alive. A search collected its
     * handles while logged in, so it ends too, or it would hand out private
     * ones. Only a digest, which needs no device, outlives the logout. */
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        tsra_pkcs11_session_t *t = &g_tsra_pkcs11.sessions[i];
        if (!t->in_use || (t->slot != s->slot))
        {
            continue;
        }
        if (t->op != P11_OP_DIGEST)
        {
            tsra_pkcs11_session_reset_op(t);
        }
        destroy_private_owned(t);
    }
    /* Login is token-wide, so log the token out regardless of which session
     * calls C_Logout — including one that never called C_Login itself. */
    tsra_pkcs11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    tsra_pkcs11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Random numbers                                                            */
/* ========================================================================= */

/* The device offers the host no random-number generator and the token does not
 * set CKF_RNG, so both entry points answer CKR_RANDOM_NO_RNG for any valid
 * session. */
static CK_RV no_rng(CK_SESSION_HANDLE hSession)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    tsra_pkcs11_lock();
    bool known = (tsra_pkcs11_session_lookup(hSession) != NULL);
    tsra_pkcs11_unlock();
    return known ? CKR_RANDOM_NO_RNG : CKR_SESSION_HANDLE_INVALID;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    (void)pSeed;
    (void)ulSeedLen;
    return no_rng(hSession);
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    (void)RandomData;
    (void)ulRandomLen;
    return no_rng(hSession);
}

/* ========================================================================= */
/* Objects (delegated to the object-store seam)                              */
/*                                                                           */
/* Each entry point validates its arguments and session, then hands off to   */
/* g_tsra_pkcs11.store; slot isolation and private-object login-gating are enforced  */
/* by the store (see tsra_pkcs11_objstore.h).                                        */
/* ========================================================================= */

CK_RV C_CreateObject(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || (pTemplate == NULL_PTR && ulCount > 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* The store keeps whatever it is handed, so the policy decides first. Its
     * CKA_TOKEN decides where the store puts the object and whether this
     * session owns it. */
    CK_BBOOL token = CK_FALSE;
    CK_BBOOL rw_session = ((s->flags & CKF_RW_SESSION) != 0) ? CK_TRUE : CK_FALSE;
    CK_RV rv = tsra_pkcs11_create_check(pTemplate, ulCount, rw_session, &token);
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }

    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    rv = g_tsra_pkcs11.store.ops
             ->create(g_tsra_pkcs11.store.ctx, s->slot, logged_in, pTemplate, ulCount, phObject);
    if ((rv == CKR_OK) && !token)
    {
        /* CKA_TOKEN defaults to FALSE, so this is a session object: it dies
         * with the session that created it (the C_CloseSession rule). */
        rv = tsra_pkcs11_session_own_object(s, *phObject);
        if (rv != CKR_OK)
        {
            /* Untracked objects are not handed out. */
            (void)g_tsra_pkcs11.store.ops
                ->destroy(g_tsra_pkcs11.store.ctx, s->slot, CK_TRUE, *phObject, NULL, NULL);
            *phObject = CK_INVALID_HANDLE;
        }
    }
    tsra_pkcs11_unlock();
    return rv;
}

static CK_RV destroy_check(void *cctx, tsra_pkcs11_objstore_reader read, void *rctx)
{
    return tsra_pkcs11_destroy_check(*(const CK_BBOOL *)cctx, read, rctx);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
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
    /* Judged under the store lock, as in C_SetAttributeValue. */
    CK_BBOOL rw_session = ((s->flags & CKF_RW_SESSION) != 0) ? CK_TRUE : CK_FALSE;
    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv = g_tsra_pkcs11.store.ops->destroy(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        logged_in,
        hObject,
        destroy_check,
        &rw_session
    );
    if (rv == CKR_OK)
    {
        tsra_pkcs11_session_disown_object(s->slot, hObject);
    }
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_GetAttributeValue(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* The output lengths are capacities, so only the count has a ceiling. */
    if (((pTemplate == NULL_PTR) && (ulCount > 0)) || (ulCount > TEMPLATE_MAX_ATTRS))
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_tsra_pkcs11.store.ops
            ->get_attr(g_tsra_pkcs11.store.ctx, s->slot, logged_in, hObject, pTemplate, ulCount);
    tsra_pkcs11_unlock();
    return rv;
}

/* The request C_SetAttributeValue hands the store to decide under its lock. */
typedef struct
{
    const CK_ATTRIBUTE *tmpl;
    CK_ULONG count;
    CK_BBOOL rw_session;
} setattr_request;

static CK_RV setattr_check(void *cctx, tsra_pkcs11_objstore_reader read, void *rctx)
{
    const setattr_request *r = (const setattr_request *)cctx;
    return tsra_pkcs11_setattr_check(r->tmpl, r->count, r->rw_session, read, rctx);
}

CK_RV C_SetAttributeValue(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if ((pTemplate == NULL_PTR) && (ulCount > 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /*
     * The store applies whatever it is given, so the policy decides over the
     * whole template first. It runs inside set_attr rather than before it: the
     * module lock serialises this process only, and the file backend's token
     * objects are shared with other processes, so the latches must be judged
     * on the object as locked for the write.
     */
    setattr_request req = { pTemplate,
                            ulCount,
                            ((s->flags & CKF_RW_SESSION) != 0) ? CK_TRUE : CK_FALSE };
    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv = g_tsra_pkcs11.store.ops->set_attr(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        logged_in,
        hObject,
        pTemplate,
        ulCount,
        setattr_check,
        &req
    );
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulSize == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv = g_tsra_pkcs11.store.ops
                   ->get_size(g_tsra_pkcs11.store.ctx, s->slot, logged_in, hObject, pulSize);
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pTemplate == NULL_PTR && ulCount > 0)
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_NONE)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    CK_RV rv = tsra_pkcs11_tmpl_check(pTemplate, ulCount);
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }
    CK_BBOOL logged_in = g_tsra_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    rv = g_tsra_pkcs11.store.ops->find_init(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        logged_in,
        pTemplate,
        ulCount,
        &s->find_cursor
    );
    if (rv == CKR_OK)
    {
        s->op = P11_OP_FIND;
    }
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjects(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_FIND)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = g_tsra_pkcs11.store.ops->find(
        g_tsra_pkcs11.store.ctx,
        s->find_cursor,
        phObject,
        ulMaxObjectCount,
        pulObjectCount
    );
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
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
    if (s->op != P11_OP_FIND)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    tsra_pkcs11_session_reset_op(s);
    tsra_pkcs11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Digest (host-side; see tsra_pkcs11_digest.h)                            */
/* ========================================================================= */

/*
 * Precedence in the digest entry points, in line with the spec's operation
 * rules and what conformance tooling checks: a bad session handle is reported
 * before anything else. C_DigestInit then takes a NULL mechanism as the v3.0
 * request to end the active digest, and otherwise checks operation state
 * before the mechanism. The data calls check operation state first, since with
 * no operation there is nothing to terminate and CKR_OPERATION_NOT_INITIALIZED
 * is the answer, then arguments and the one-shot/multi-part mode; from there on
 * every failure terminates the operation, and only a successful sizing probe
 * and CKR_BUFFER_TOO_SMALL keep it alive.
 */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
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
        tsra_pkcs11_session_cancel_op(s, P11_OP_DIGEST);
        tsra_pkcs11_unlock();
        return CKR_OK;
    }
    if (s->op != P11_OP_NONE)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    if (tsra_pkcs11_digest_mech_len(pMechanism->mechanism) == 0)
    {
        tsra_pkcs11_unlock();
        return CKR_MECHANISM_INVALID;
    }
    /* All supported digest mechanisms are parameterless. */
    if (pMechanism->pParameter != NULL_PTR || pMechanism->ulParameterLen != 0)
    {
        tsra_pkcs11_unlock();
        return CKR_MECHANISM_PARAM_INVALID;
    }
    tsra_pkcs11_digest_op_t *op = NULL;
    CK_RV rv = tsra_pkcs11_digest_op_new(pMechanism->mechanism, &op);
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }
    s->op_ctx = op;
    s->op = P11_OP_DIGEST;
    tsra_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
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
    if (s->op != P11_OP_DIGEST)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    if ((ulPartLen > 0) && (pPart == NULL_PTR))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE; /* a one-shot C_Digest is in progress */
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_session_reset_op(s);
        tsra_pkcs11_unlock();
        return rv;
    }
    s->op_mode = P11_OP_MODE_MULTIPART;
    if (ulPartLen > 0)
    {
        tsra_pkcs11_digest_op_update(s->op_ctx, pPart, ulPartLen);
    }
    tsra_pkcs11_unlock();
    return CKR_OK;
}

static CK_RV digest_output(tsra_pkcs11_session_t *s, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_ULONG len = tsra_pkcs11_digest_op_len(s->op_ctx);
    if (pDigest == NULL_PTR)
    {
        *pulDigestLen = len; /* two-call: report length, keep op active */
        return CKR_OK;
    }
    if (*pulDigestLen < len)
    {
        *pulDigestLen = len;
        return CKR_BUFFER_TOO_SMALL; /* op stays active for retry */
    }
    tsra_pkcs11_digest_op_final(s->op_ctx, pDigest);
    *pulDigestLen = len;
    tsra_pkcs11_session_reset_op(s);
    return CKR_OK;
}

CK_RV C_Digest(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
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
    if (s->op != P11_OP_DIGEST)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    if ((pulDigestLen == NULL_PTR) || ((ulDataLen > 0) && (pData == NULL_PTR)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_MULTIPART)
    {
        rv = CKR_OPERATION_ACTIVE; /* only C_DigestFinal may finish it now */
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_session_reset_op(s);
        tsra_pkcs11_unlock();
        return rv;
    }
    s->op_mode = P11_OP_MODE_ONESHOT;
    /* Absorb the data only on the call that will complete: a sizing probe or a
     * too-small buffer keeps the operation, and the retry supplies it again. */
    if ((pDigest != NULL_PTR) && (*pulDigestLen >= tsra_pkcs11_digest_op_len(s->op_ctx)) &&
        (ulDataLen > 0))
    {
        tsra_pkcs11_digest_op_update(s->op_ctx, pData, ulDataLen);
    }
    rv = digest_output(s, pDigest, pulDigestLen);
    tsra_pkcs11_unlock();
    return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
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
    if (s->op != P11_OP_DIGEST)
    {
        tsra_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = CKR_OK;
    if (pulDigestLen == NULL_PTR)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE; /* a one-shot C_Digest is in progress */
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_session_reset_op(s);
        tsra_pkcs11_unlock();
        return rv;
    }
    /* Straight after C_DigestInit this is the (allowed) zero-part case. */
    s->op_mode = P11_OP_MODE_MULTIPART;
    rv = digest_output(s, pDigest, pulDigestLen);
    tsra_pkcs11_unlock();
    return rv;
}
