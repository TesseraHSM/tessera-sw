// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno PIN-policy clock and persistent-state adapter.

use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_drivers_part_store::PartStore;
use tsra_fw_uno_drivers_part_store::pin_policy::DELAY_INCREMENT_SECONDS;
use tsra_fw_uno_drivers_tcon::Tcon;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

impl UnoHsmPal {
    pub(crate) fn check_pin_policy(&self, io: &UnoHsmIo) -> HsmResult<()> {
        if PartStore::partition(io.pid())?
            .pin_policy()
            .can_login(Tcon::tsc())
        {
            Ok(())
        } else {
            Err(HsmError::LoginFailed)
        }
    }

    pub(crate) fn record_pin_auth(&self, io: &UnoHsmIo, valid: bool) -> HsmResult<()> {
        let part = PartStore::partition(io.pid())?;
        let mut policy = part.pin_policy();
        let increment = DELAY_INCREMENT_SECONDS;
        #[cfg(feature = "tsra_test_hooks")]
        let increment = self
            .pin_delay_increment
            .get(usize::from(u8::from(io.pid())))
            .ok_or(HsmError::InvalidArg)?
            .get()
            .unwrap_or(increment);
        let result = policy.record_auth(
            valid,
            Tcon::tsc(),
            u64::from(increment) * u64::from(Tcon::tsc_freq_hz()),
        );
        if result.is_ok() || result == Err(HsmError::InvalidAppCredentials) {
            part.set_pin_policy(policy);
        }
        result
    }
}
