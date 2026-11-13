// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only PIN-policy overrides with reference application order.

use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_ddi_mbor_derive::Ddi;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_drivers_part_store::PartStore;
use tsra_fw_uno_drivers_part_store::PinPolicy;
use tsra_fw_uno_drivers_part_store::PinPolicyState;
use tsra_fw_uno_drivers_part_store::pin_policy::DELAY_INCREMENT_SECONDS;
use tsra_fw_uno_drivers_part_store::pin_policy::MAX_DELAY_FACTOR;
use tsra_fw_uno_drivers_part_store::pin_policy::MAX_PIN_AUTH_ATTEMPTS;
use tsra_fw_uno_drivers_tcon::Tcon;

use super::common::ReqHdr;
use super::test_action::decode_payload;
use super::test_action::encode_success;
use super::test_action::expect_empty_payload;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

#[derive(Debug, Ddi)]
#[ddi(map)]
struct PinPolicyConfig {
    #[ddi(id = 1)]
    delay_increment: Option<u16>,
    #[ddi(id = 2)]
    state: Option<bool>,
    #[ddi(id = 3)]
    delay: Option<u16>,
    #[ddi(id = 4)]
    allowed_attempts: Option<u16>,
    #[ddi(id = 5)]
    lockout_delay: Option<u32>,
}

pub(super) async fn override_policy<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    field_count: u8,
    request_len: usize,
) -> HsmResult<&'p HsmDmaBuf> {
    let config: PinPolicyConfig = decode_payload(decoder, field_count, request_len)?;
    if config.delay.is_some_and(|factor| factor > MAX_DELAY_FACTOR)
        || config
            .allowed_attempts
            .is_some_and(|count| count >= MAX_PIN_AUTH_ATTEMPTS)
    {
        return Err(HsmError::InvalidArg);
    }

    let _lock = pal.partition_lock(io).await?;
    let part = PartStore::partition(io.pid())?;
    let override_slot = pal
        .pin_delay_increment
        .get(usize::from(u8::from(io.pid())))
        .ok_or(HsmError::InvalidArg)?;
    let mut increment = override_slot.get();
    let mut policy = part.pin_policy();
    let now = Tcon::tsc();
    if let Some(value) = config.delay_increment {
        increment = Some(value);
        set_factor_delay(&mut policy, now, value)?;
    }
    if let Some(ready) = config.state {
        policy.state = if ready {
            PinPolicyState::Ready
        } else {
            PinPolicyState::Lockout
        };
    }
    if let Some(factor) = config.delay {
        policy.delay_factor = factor;
        set_factor_delay(
            &mut policy,
            now,
            increment.unwrap_or(DELAY_INCREMENT_SECONDS),
        )?;
    }
    if let Some(count) = config.allowed_attempts {
        policy.allowed_attempts = count;
    }
    if let Some(seconds) = config.lockout_delay {
        policy.set_lockout_delay(now, u64::from(seconds) * u64::from(Tcon::tsc_freq_hz()))?;
    }

    // Neither decoding/arithmetic nor response allocation may partially apply an override.
    let resp = encode_success(pal, io, hdr)?;
    part.set_pin_policy(policy);
    override_slot.set(increment);
    Ok(resp)
}

fn set_factor_delay(policy: &mut PinPolicy, now: u64, increment: u16) -> HsmResult<()> {
    let delay =
        u64::from(policy.delay_factor) * u64::from(increment) * u64::from(Tcon::tsc_freq_hz());
    policy.set_lockout_delay(now, delay)
}

pub(super) async fn clear_policy<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    field_count: u8,
    request_len: usize,
) -> HsmResult<&'p HsmDmaBuf> {
    expect_empty_payload(decoder, field_count, request_len)?;
    let _lock = pal.partition_lock(io).await?;
    let part = PartStore::partition(io.pid())?;
    let override_slot = pal
        .pin_delay_increment
        .get(usize::from(u8::from(io.pid())))
        .ok_or(HsmError::InvalidArg)?;
    let resp = encode_success(pal, io, hdr)?;
    part.set_pin_policy(PinPolicy::default());
    override_slot.set(None);
    Ok(resp)
}
