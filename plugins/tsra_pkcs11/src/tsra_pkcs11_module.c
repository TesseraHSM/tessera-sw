// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Module-global state, the general-purpose functions (C_Initialize / C_Finalize
 * / C_GetInfo), and small shared helpers.
 */

#include "tsra_pkcs11_hsm.h"
#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_key.h"

#include <stdarg.h>

tsra_pkcs11_module_t g_tsra_pkcs11 = {
    .initialized = false,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .next_session_handle = 1, /* 0 is CK_INVALID_HANDLE; handles are never reused */
};

void tsra_pkcs11_lock(void)
{
    pthread_mutex_lock(&g_tsra_pkcs11.lock);
}

void tsra_pkcs11_unlock(void)
{
    pthread_mutex_unlock(&g_tsra_pkcs11.lock);
}

/* The configuration's debug setting, applied by C_Initialize. */
static bool log_enabled = false;

void tsra_pkcs11_log(const char *fmt, ...)
{
    if (!log_enabled)
    {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[tsra-pkcs11] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void tsra_pkcs11_pad_str(CK_UTF8CHAR *dst, size_t dstlen, const char *src)
{
    size_t n = src ? strlen(src) : 0;
    if (n > dstlen)
    {
        n = dstlen;
    }
    if (n > 0)
    {
        memcpy(dst, src, n); /* skip when n == 0: memcpy(_, NULL, 0) with src == NULL is UB */
    }
    memset(dst + n, ' ', dstlen - n); /* PKCS#11 fixed-width fields are space-padded */
}

tsra_pkcs11_session_t *tsra_pkcs11_session_lookup(CK_SESSION_HANDLE h)
{
    if (h == CK_INVALID_HANDLE)
    {
        return NULL;
    }
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_tsra_pkcs11.sessions[i].in_use && g_tsra_pkcs11.sessions[i].handle == h)
        {
            return &g_tsra_pkcs11.sessions[i];
        }
    }
    return NULL;
}

/* The device's only AES-GCM key size. */
#define P11_STORE_KEY_BITS 256

/* Every record key encrypts one record only, so a fixed IV never repeats under a key. */
static const CK_BYTE P11_STORE_IV[AES_GCM_IV_LEN] = { 0 };

/* The device session of `slot`'s login, which every record key call runs in. */
static uint32_t store_session(CK_SLOT_ID slot)
{
    return (slot < TSRA_PKCS11_MAX_SLOTS) ? g_tsra_pkcs11.slots[slot].hsm_session : 0;
}

static CK_RV store_key_generate(CK_SLOT_ID slot, CK_BYTE **blob, CK_ULONG *blob_len)
{
    uint32_t session = store_session(slot);
    if (session == 0)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    return tsra_pkcs11_key_aes_generate(
        session,
        TSRA_PKCS11_KIND_AES_GCM,
        P11_STORE_KEY_BITS,
        TSRA_PKCS11_SCOPE_PARTITION,
        blob,
        blob_len
    );
}

static CK_RV store_gcm(
    CK_SLOT_ID slot,
    bool encrypt,
    const CK_BYTE *key,
    CK_ULONG key_len,
    const CK_BYTE *aad,
    CK_ULONG aad_len,
    CK_BYTE *data,
    CK_ULONG data_len,
    CK_BYTE *tag
)
{
    uint32_t session = store_session(slot);
    if (session == 0)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    uint32_t hkey = 0;
    CK_RV rv = tsra_pkcs11_key_aes_unmask(session, TSRA_PKCS11_KIND_AES_GCM, key, key_len, &hkey);
    if (rv == CKR_OK)
    {
        CK_ULONG out_len = data_len;
        rv = tsra_pkcs11_key_aes_gcm(
            encrypt,
            hkey,
            P11_STORE_IV,
            aad,
            aad_len,
            data,
            data_len,
            tag,
            data,
            &out_len
        );
        tsra_pkcs11_key_release(hkey);
    }
    return rv;
}

static const tsra_pkcs11_store_cipher STORE_CIPHER = {
    .key_generate = store_key_generate,
    .gcm = store_gcm,
};

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    bool os_locking_ok = true;
    if (pInitArgs != NULL_PTR)
    {
        CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
        if (args->pReserved != NULL_PTR)
        {
            return CKR_ARGUMENTS_BAD;
        }
        /* The four mutex callbacks must be all-NULL or all-set. */
        int n = (args->CreateMutex != NULL) + (args->DestroyMutex != NULL) +
                (args->LockMutex != NULL) + (args->UnlockMutex != NULL);
        if (n != 0 && n != 4)
        {
            return CKR_ARGUMENTS_BAD;
        }
        /* We always use native pthread locking, which covers the NULL and
         * CKF_OS_LOCKING_OK cases. Honouring caller-supplied mutexes with
         * CKF_OS_LOCKING_OK clear is a conformance follow-up. */
        os_locking_ok = (args->flags & CKF_OS_LOCKING_OK) != 0 || n == 0;
    }

    tsra_pkcs11_lock();
    if (g_tsra_pkcs11.initialized)
    {
        tsra_pkcs11_unlock();
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    /* Commit global state only after we hold the lock and know we are the
     * initializing caller. */
    g_tsra_pkcs11.os_locking_ok = os_locking_ok;

    memset(g_tsra_pkcs11.slots, 0, sizeof(g_tsra_pkcs11.slots));
    memset(g_tsra_pkcs11.sessions, 0, sizeof(g_tsra_pkcs11.sessions));
    g_tsra_pkcs11.slot_count = 0;
    g_tsra_pkcs11.next_session_handle = 1;

    /* Load the configuration before building the store: the persistent file
     * backend is opt-in and needs its root dir; without it the store stays in
     * memory. */
    tsra_pkcs11_config cfg;
    CK_RV rv = tsra_pkcs11_config_load(&cfg);
    log_enabled = cfg.debug;
    g_tsra_pkcs11.default_pin = cfg.default_pin_set;
    if (rv != CKR_OK)
    {
        TSRA_PKCS11_LOG("C_Initialize: configuration refused: %s", cfg.error);
    }
    else if (cfg.store_persist)
    {
        rv = tsra_pkcs11_objstore_file_create(&g_tsra_pkcs11.store, &cfg, &STORE_CIPHER);
        if (rv != CKR_OK)
        {
            TSRA_PKCS11_LOG(
                "C_Initialize: store dir %s unusable (rv 0x%lx): it must be a directory this "
                "user owns with mode 0700, or absent with an existing parent",
                cfg.store_dir,
                (unsigned long)rv
            );
        }
    }
    else
    {
        rv = tsra_pkcs11_objstore_mem_create(&g_tsra_pkcs11.store);
    }
    /* The config carries credential bytes and is only needed to select and seed
     * the store; wipe it before any return (error paths included). */
    tsra_pkcs11_config_clear(&cfg);
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }

    int32_t n_slots = tsra_pkcs11_hsm_enumerate_slots();
    if (n_slots < 0)
    {
        g_tsra_pkcs11.store.ops->teardown(g_tsra_pkcs11.store.ctx);
        g_tsra_pkcs11.store.ctx = NULL;
        tsra_pkcs11_unlock();
        TSRA_PKCS11_LOG("C_Initialize: slot enumeration failed");
        return CKR_FUNCTION_FAILED;
    }
    g_tsra_pkcs11.slot_count = (CK_ULONG)n_slots;
    g_tsra_pkcs11.initialized = true;
    tsra_pkcs11_unlock();

    TSRA_PKCS11_LOG(
        "C_Initialize: OK (%d slot(s), os_locking=%d)",
        n_slots,
        (int)g_tsra_pkcs11.os_locking_ok
    );
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    if (pReserved != NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    tsra_pkcs11_lock();
    if (!g_tsra_pkcs11.initialized)
    {
        tsra_pkcs11_unlock();
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_tsra_pkcs11.sessions[i].in_use)
        {
            tsra_pkcs11_session_reset_op(&g_tsra_pkcs11.sessions[i]);
            /* The store is torn down below anyway; this frees the lists. */
            tsra_pkcs11_session_destroy_owned(&g_tsra_pkcs11.sessions[i]);
            g_tsra_pkcs11.sessions[i].in_use = false;
        }
    }
    /* HSM login sessions are token-wide; close them per slot before closing the
     * partitions. */
    for (CK_ULONG i = 0; i < g_tsra_pkcs11.slot_count; i++)
    {
        tsra_pkcs11_hsm_logout(g_tsra_pkcs11.slots[i].hsm_session);
        g_tsra_pkcs11.slots[i].hsm_session = 0;
        g_tsra_pkcs11.slots[i].user_logged_in = false;
    }
    tsra_pkcs11_hsm_close_all();
    if (g_tsra_pkcs11.store.ctx != NULL)
    {
        /* Flush the store before tearing it down. Backends that write through
         * (or hold nothing durable) have nothing to do; persist is NULL on the
         * in-memory backend. It is a barrier, so its result does not change the
         * C_Finalize outcome. */
        if (g_tsra_pkcs11.store.ops->persist != NULL)
        {
            (void)g_tsra_pkcs11.store.ops->persist(g_tsra_pkcs11.store.ctx);
        }
        g_tsra_pkcs11.store.ops->teardown(g_tsra_pkcs11.store.ctx);
        g_tsra_pkcs11.store.ctx = NULL;
    }
    g_tsra_pkcs11.initialized = false;
    tsra_pkcs11_unlock();
    TSRA_PKCS11_LOG("C_Finalize: OK");
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = TSRA_PKCS11_CK_MAJOR;
    pInfo->cryptokiVersion.minor = TSRA_PKCS11_CK_MINOR;
    tsra_pkcs11_pad_str(
        pInfo->manufacturerID,
        sizeof(pInfo->manufacturerID),
        TSRA_PKCS11_MANUFACTURER
    );
    pInfo->flags = 0;
    tsra_pkcs11_pad_str(
        pInfo->libraryDescription,
        sizeof(pInfo->libraryDescription),
        TSRA_PKCS11_LIBRARY_DESC
    );
    pInfo->libraryVersion.major = TSRA_PKCS11_LIB_MAJOR;
    pInfo->libraryVersion.minor = TSRA_PKCS11_LIB_MINOR;
    return CKR_OK;
}
