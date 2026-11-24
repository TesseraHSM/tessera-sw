// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Slot / token / mechanism enumeration over g_tsra_pkcs11.slots[] (populated by
 * the HSM binding) and the mechanism table (tsra_pkcs11_mech.c).
 */

#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_mech.h"

/* ------------------------------------------------------------------------- */
/* Slot / token functions                                                    */
/* ------------------------------------------------------------------------- */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    (void)tokenPresent; /* every discovered partition has a token present */

    CK_ULONG n = g_tsra_pkcs11.slot_count;
    if (pSlotList == NULL_PTR)
    {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n)
    {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < n; i++)
    {
        pSlotList[i] = i; /* slot id == index */
    }
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[slotID];
    memset(pInfo, 0, sizeof(*pInfo));

    char desc[600];
    snprintf(desc, sizeof(desc), "%s [%s]", TSRA_PKCS11_SLOT_DESC, slot->device_path);
    tsra_pkcs11_pad_str(pInfo->slotDescription, sizeof(pInfo->slotDescription), desc);
    tsra_pkcs11_pad_str(
        pInfo->manufacturerID,
        sizeof(pInfo->manufacturerID),
        TSRA_PKCS11_MANUFACTURER
    );
    pInfo->flags = CKF_HW_SLOT;
    if (slot->present)
    {
        pInfo->flags |= CKF_TOKEN_PRESENT;
    }
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (CK_BYTE)slot->api_rev_major;
    pInfo->firmwareVersion.minor = (CK_BYTE)slot->api_rev_minor;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[slotID];
    if (!slot->present)
    {
        return CKR_TOKEN_NOT_PRESENT;
    }
    memset(pInfo, 0, sizeof(*pInfo));

    tsra_pkcs11_pad_str(pInfo->label, sizeof(pInfo->label), slot->label);
    tsra_pkcs11_pad_str(
        pInfo->manufacturerID,
        sizeof(pInfo->manufacturerID),
        TSRA_PKCS11_MANUFACTURER
    );
    tsra_pkcs11_pad_str(pInfo->model, sizeof(pInfo->model), TSRA_PKCS11_TOKEN_MODEL);
    tsra_pkcs11_pad_str(pInfo->serialNumber, sizeof(pInfo->serialNumber), slot->serial);

    /*
     * The first C_Login after power-on provisions the partition with its PIN,
     * so the token has no initialisation step of its own (C_InitToken and
     * C_InitPIN are not supported) and is initialised, with a user PIN, from
     * the start. No CKF_RNG: the device offers the host no random-number
     * generator.
     */
    pInfo->flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    if (slot->token_initialized)
    {
        pInfo->flags |= CKF_TOKEN_INITIALIZED;
    }
    /* A login without a PIN uses the configured default PIN. */
    if (g_tsra_pkcs11.default_pin)
    {
        pInfo->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
    }

    /* The session table is module-wide, so its size bounds every token. */
    pInfo->ulMaxSessionCount = TSRA_PKCS11_MAX_SESSIONS;
    pInfo->ulMaxRwSessionCount = TSRA_PKCS11_MAX_SESSIONS;
    tsra_pkcs11_lock();
    for (size_t i = 0; i < TSRA_PKCS11_MAX_SESSIONS; i++)
    {
        const tsra_pkcs11_session_t *s = &g_tsra_pkcs11.sessions[i];
        if (s->in_use && (s->slot == slotID))
        {
            pInfo->ulSessionCount++;
            if ((s->flags & CKF_RW_SESSION) != 0)
            {
                pInfo->ulRwSessionCount++;
            }
        }
    }
    tsra_pkcs11_unlock();
    /* TSRA credentials PIN is a fixed 16-byte value. */
    pInfo->ulMaxPinLen = TSRA_PKCS11_MAX_PIN_LEN;
    pInfo->ulMinPinLen = TSRA_PKCS11_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (CK_BYTE)slot->api_rev_major;
    pInfo->firmwareVersion.minor = (CK_BYTE)slot->api_rev_minor;
    /* No on-token clock: leave utcTime blank (space-padded). */
    tsra_pkcs11_pad_str(pInfo->utcTime, sizeof(pInfo->utcTime), "");
    return CKR_OK;
}

CK_RV C_GetMechanismList(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    CK_ULONG n = TSRA_PKCS11_MECH_COUNT;
    if (pMechanismList == NULL_PTR)
    {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n)
    {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < n; i++)
    {
        pMechanismList[i] = tsra_pkcs11_mechs[i].type;
    }
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_tsra_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    const tsra_pkcs11_mech_t *m = tsra_pkcs11_mech_find(type);
    if (m == NULL)
    {
        return CKR_MECHANISM_INVALID;
    }
    pInfo->ulMinKeySize = m->min_key;
    pInfo->ulMaxKeySize = m->max_key;
    pInfo->flags = m->flags;
    return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* pReserved is reserved and must be NULL, pSlot is the required output, and
     * CKF_DONT_BLOCK is the only defined flag. */
    if (pReserved != NULL_PTR || pSlot == NULL_PTR || (flags & ~(CK_FLAGS)CKF_DONT_BLOCK) != 0)
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* TSRA partitions are not hot-pluggable, so no slot event ever occurs. */
    if (flags & CKF_DONT_BLOCK)
    {
        return CKR_NO_EVENT;
    }
    return CKR_FUNCTION_NOT_SUPPORTED;
}
