// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * HSM-binding layer: the only place that calls tsra_* and the only place that
 * translates tsra_status into CK_RV (via tsra_pkcs11_status.h). Compiled against the
 * SDK under TSRA_WITH_HSM; the no-device build provides stubs so the framework
 * still loads and the object/digest paths remain testable.
 */

/*
 * Enumerate TSRA partitions into g_tsra_pkcs11.slots[] and set g_tsra_pkcs11.slot_count.
 * Returns the number of slots (>= 0), or -1 on error. A partition that fails to
 * describe itself is skipped rather than failing the whole enumeration.
 */
int32_t tsra_pkcs11_hsm_enumerate_slots(void);

/*
 * Log a user into `slot`: open the partition, provision it lazily (only if the
 * device reports it is not yet provisioned: provisioning is one-shot per power
 * cycle), then open a session. `pin` is the 16-byte credential PIN
 * (tsra_pkcs11_pin_normalise), or NULL for the configured default PIN. On
 * success writes the TSRA session handle to *out_session. Reloads the
 * configuration and reads the owner backup key before the device session
 * opens, and fails closed with CKR_FUNCTION_FAILED when either is unusable
 * (tsra_pkcs11_config.h), even on a provisioned partition.
 */
CK_RV tsra_pkcs11_hsm_login(CK_SLOT_ID slot, const CK_BYTE *pin, uint32_t *out_session);

/* Close a previously opened TSRA session (no-op if 0). */
void tsra_pkcs11_hsm_logout(uint32_t hsm_session);

/* Close every open partition handle. Called from C_Finalize. */
void tsra_pkcs11_hsm_close_all(void);

#ifdef __cplusplus
}
#endif
