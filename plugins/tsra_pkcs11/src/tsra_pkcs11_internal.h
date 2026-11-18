// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_objstore.h"
#include "tsra_pkcs11_wipe.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Module identity                                                           */
/* ------------------------------------------------------------------------- */

#define TSRA_PKCS11_MANUFACTURER "Microsoft Corporation"
#define TSRA_PKCS11_LIBRARY_DESC "TSRA PKCS#11"
#define TSRA_PKCS11_TOKEN_MODEL "TSRA"
#define TSRA_PKCS11_SLOT_DESC "Azure Integrated HSM partition"

/* Cryptoki version reported from C_GetInfo and the default interface. */
#define TSRA_PKCS11_CK_MAJOR 3
#define TSRA_PKCS11_CK_MINOR 1
/* Legacy version reported through the classic CK_FUNCTION_LIST. */
#define TSRA_PKCS11_CK_LEGACY_MAJOR 2
#define TSRA_PKCS11_CK_LEGACY_MINOR 40
/* This module's own version. */
#define TSRA_PKCS11_LIB_MAJOR 0
#define TSRA_PKCS11_LIB_MINOR 1

#define TSRA_PKCS11_MAX_SLOTS 16
#define TSRA_PKCS11_MAX_SESSIONS 256

/* ------------------------------------------------------------------------- */
/* Logging (enabled by the debug setting; off by default)                    */
/* ------------------------------------------------------------------------- */

void tsra_pkcs11_log(const char *fmt, ...);
#define TSRA_PKCS11_LOG(...) tsra_pkcs11_log(__VA_ARGS__)

/* ------------------------------------------------------------------------- */
/* Sessions                                                                  */
/* ------------------------------------------------------------------------- */

/* PKCS#11 allows at most one active operation of each kind per session. */
typedef enum
{
    P11_OP_NONE = 0,
    P11_OP_FIND,
    P11_OP_ENCRYPT,
    P11_OP_DECRYPT,
    P11_OP_DIGEST,
    P11_OP_SIGN,
    P11_OP_VERIFY,
} tsra_pkcs11_op_type_t;

/*
 * How the active operation is being driven. PKCS#11 forbids mixing the
 * one-shot call (C_Digest, C_Encrypt, ...) with the multi-part calls
 * (C_DigestUpdate / C_DigestFinal, ...) within one operation: the first data
 * call fixes the mode, and a call from the other family then fails with
 * CKR_OPERATION_ACTIVE and terminates the operation.
 */
typedef enum
{
    P11_OP_MODE_UNSET = 0, /* no data call yet: either family may start */
    P11_OP_MODE_ONESHOT,   /* a one-shot sizing probe / retry is pending */
    P11_OP_MODE_MULTIPART, /* an *Update or *Final call has been made */
} tsra_pkcs11_op_mode_t;

typedef struct
{
    bool in_use;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    CK_FLAGS flags; /* CKF_SERIAL_SESSION | CKF_RW_SESSION */
    CK_VOID_PTR app;
    CK_NOTIFY notify;

    tsra_pkcs11_op_type_t op;
    tsra_pkcs11_op_mode_t op_mode; /* reset together with op */
    void *op_ctx;                  /* digest state (P11_OP_DIGEST), cipher operation state
                                    * (P11_OP_ENCRYPT / P11_OP_DECRYPT, owned by
                                    * tsra_pkcs11_crypt.c) or sign operation state
                                    * (P11_OP_SIGN / P11_OP_VERIFY, owned by
                                    * tsra_pkcs11_sign.c) */
    void *find_cursor;             /* object-store cursor while op == P11_OP_FIND */

    /*
     * Session objects (CKA_TOKEN = FALSE) this session created. C_CloseSession
     * destroys them with the session, C_Logout the private ones, and the object
     * store knows nothing about sessions, so the framework keeps the list: grown
     * on demand, drained and freed when the session closes.
     */
    CK_OBJECT_HANDLE *owned;
    CK_ULONG owned_count;
    CK_ULONG owned_cap;
} tsra_pkcs11_session_t;

/* ------------------------------------------------------------------------- */
/* Slots / tokens                                                            */
/* ------------------------------------------------------------------------- */

typedef struct
{
    bool present;           /* an TSRA partition exists for this slot */
    bool token_initialized; /* CKF_TOKEN_INITIALIZED */
    char device_path[512];  /* TSRA partition OS path (from part_get_info) */
    char label[64];
    char serial[24];
    uint16_t api_rev_major;
    uint16_t api_rev_minor;

    /* Login state lives on the token so it is shared across sessions. */
    bool user_logged_in;

    /* TSRA partition handle, opened lazily at first login and reused; closed
     * at C_Finalize. 0 = not open. */
    uint32_t hsm_dev;

    /*
     * TSRA session handle for the token-wide login. PKCS#11 login state is
     * per-token, not per-session: this is opened by the C_Login that logs the
     * token in and closed by C_Logout, C_Finalize, or the close of the last
     * session on the slot — regardless of which session drives those calls.
     * 0 = not logged in.
     */
    uint32_t hsm_session;
} tsra_pkcs11_slot_t;

/* ------------------------------------------------------------------------- */
/* Global module state                                                       */
/* ------------------------------------------------------------------------- */

typedef struct
{
    bool initialized;
    pthread_mutex_t lock; /* one coarse module lock; held across store calls */
    bool os_locking_ok;   /* from CK_C_INITIALIZE_ARGS */
    bool default_pin;     /* a default PIN is configured: CKF_PROTECTED_AUTHENTICATION_PATH */

    tsra_pkcs11_slot_t slots[TSRA_PKCS11_MAX_SLOTS];
    CK_ULONG slot_count;

    tsra_pkcs11_session_t sessions[TSRA_PKCS11_MAX_SESSIONS];
    CK_ULONG next_session_handle; /* monotonic, never reused */

    tsra_pkcs11_objstore store; /* host object store behind the seam */
} tsra_pkcs11_module_t;

extern tsra_pkcs11_module_t g_tsra_pkcs11;

/* Acquire / release the module lock (g_tsra_pkcs11.lock). */
void tsra_pkcs11_lock(void);
void tsra_pkcs11_unlock(void);

/* ------------------------------------------------------------------------- */
/* Shared helpers                                                            */
/* ------------------------------------------------------------------------- */

/* Resolve a session handle to its table entry; NULL if invalid or closed. */
tsra_pkcs11_session_t *tsra_pkcs11_session_lookup(CK_SESSION_HANDLE h);

/* Abandon the session's active operation, releasing its digest state, cipher
 * or sign state (including the unmasked device keys), or find cursor. */
CK_RV tsra_pkcs11_session_reset_op(tsra_pkcs11_session_t *s);

/* Abandon the session's active operation if it is of kind `op` (the v3.0
 * C_*Init call with a NULL mechanism); any other operation stays. NULL-safe. */
void tsra_pkcs11_session_cancel_op(tsra_pkcs11_session_t *s, tsra_pkcs11_op_type_t op);

/* Record `h` as a session object created by `s`. CKR_HOST_MEMORY if the list
 * cannot grow (CKR_ARGUMENTS_BAD for a NULL session) — the caller then destroys
 * the object rather than leak it. */
CK_RV tsra_pkcs11_session_own_object(tsra_pkcs11_session_t *s, CK_OBJECT_HANDLE h);

/* Forget `h` on whichever session of `slot` owns it (it has been destroyed
 * explicitly; any session of the token may do that). No-op if none does. */
void tsra_pkcs11_session_disown_object(CK_SLOT_ID slot, CK_OBJECT_HANDLE h);

/* Destroy every session object `s` still owns and release the list. Called on
 * every path that ends the session (close, close-all, finalize). */
void tsra_pkcs11_session_destroy_owned(tsra_pkcs11_session_t *s);

/* Free a cipher operation context (releases its SDK stream and unmasked device
 * key first). NULL-safe no-op. Defined in tsra_pkcs11_crypt.c, which owns the
 * type. */
void tsra_pkcs11_cipher_op_free(void *op_ctx);

/* Free a sign or verify operation context (releases its SDK stream and
 * unmasked device keys first). NULL-safe no-op. Defined in
 * tsra_pkcs11_sign.c, which owns the type. */
void tsra_pkcs11_sign_op_free(void *op_ctx);

/* Fill a fixed-width, space-padded CK_UTF8CHAR string field. */
void tsra_pkcs11_pad_str(CK_UTF8CHAR *dst, size_t dstlen, const char *src);
