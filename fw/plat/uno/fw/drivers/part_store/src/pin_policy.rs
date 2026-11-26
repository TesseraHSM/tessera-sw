// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure transitions for the reference-compatible persistent PIN policy.

use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::PinPolicy;
use crate::PinPolicyState;

/// Failed authentications per delay-factor increment.
pub const MAX_PIN_AUTH_ATTEMPTS: u16 = 1000;
/// Largest delay factor before the reference policy rolls over.
pub const MAX_DELAY_FACTOR: u16 = 32;
/// Default duration of one delay-factor step, in seconds.
pub const DELAY_INCREMENT_SECONDS: u16 = 60;

impl PinPolicy {
    /// Whether a credential attempt may start at the supplied timestamp.
    pub fn can_login(&self, now: u64) -> bool {
        self.state == PinPolicyState::Ready || now >= u64::from_le_bytes(self.lockout_time)
    }

    /// Record a credential result, independent of subsequent command success.
    ///
    /// An admitted failure updates the context and returns
    /// [`HsmError::InvalidAppCredentials`]. Rejected attempts leave it unchanged.
    pub fn record_auth(
        &mut self,
        valid: bool,
        now: u64,
        delay_increment_ticks: u64,
    ) -> HsmResult<()> {
        if !self.can_login(now) {
            return Err(HsmError::LoginFailed);
        }
        if valid {
            if self.state == PinPolicyState::Lockout {
                self.allowed_attempts = 0;
                self.delay_factor = 0;
                self.lockout_time = [0; 8];
            }
            return Ok(());
        }
        if self.allowed_attempts >= MAX_PIN_AUTH_ATTEMPTS || self.delay_factor > MAX_DELAY_FACTOR {
            return Err(HsmError::InternalError);
        }

        let mut next = *self;
        next.state = PinPolicyState::Lockout;
        next.allowed_attempts += 1;
        if next.allowed_attempts == MAX_PIN_AUTH_ATTEMPTS {
            next.allowed_attempts = 0;
            next.delay_factor += 1;
            if next.delay_factor > MAX_DELAY_FACTOR {
                next.delay_factor = 0;
            }
        }
        let delay = u64::from(next.delay_factor)
            .checked_mul(delay_increment_ticks)
            .ok_or(HsmError::InternalError)?;
        next.set_lockout_delay(now, delay)?;
        *self = next;
        Err(HsmError::InvalidAppCredentials)
    }

    /// Replace the absolute deadline using a delay in hardware timestamp ticks.
    pub fn set_lockout_delay(&mut self, now: u64, delay_ticks: u64) -> HsmResult<()> {
        let deadline = now
            .checked_add(delay_ticks)
            .ok_or(HsmError::InternalError)?;
        self.lockout_time = deadline.to_le_bytes();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail(policy: &mut PinPolicy, now: u64, step: u64) {
        assert_eq!(
            policy.record_auth(false, now, step),
            Err(HsmError::InvalidAppCredentials)
        );
    }

    #[test]
    fn first_failure_enters_lockout_without_a_delay() {
        let mut policy = PinPolicy::default();
        fail(&mut policy, 100, 60);
        assert_eq!(policy.state, PinPolicyState::Lockout);
        assert_eq!(policy.allowed_attempts, 1);
        assert_eq!(policy.delay_factor, 0);
        assert_eq!(u64::from_le_bytes(policy.lockout_time), 100);
        assert!(policy.can_login(100));
    }

    #[test]
    fn threshold_adds_a_step_and_every_admitted_failure_renews_it() {
        let mut policy = PinPolicy::default();
        for _ in 0..MAX_PIN_AUTH_ATTEMPTS {
            fail(&mut policy, 100, 60);
        }
        assert_eq!(policy.allowed_attempts, 0);
        assert_eq!(policy.delay_factor, 1);
        assert_eq!(u64::from_le_bytes(policy.lockout_time), 160);
        assert!(!policy.can_login(159));
        assert!(policy.can_login(160));
        fail(&mut policy, 160, 60);
        assert_eq!(policy.allowed_attempts, 1);
        assert_eq!(u64::from_le_bytes(policy.lockout_time), 220);
    }

    #[test]
    fn locked_attempts_change_nothing_including_with_correct_credentials() {
        let mut policy = PinPolicy {
            state: PinPolicyState::Lockout,
            delay_factor: 8,
            allowed_attempts: 23,
            lockout_time: 1000u64.to_le_bytes(),
        };
        let before = policy;
        for valid in [false, true] {
            assert_eq!(
                policy.record_auth(valid, 999, 60),
                Err(HsmError::LoginFailed)
            );
            assert_eq!(policy, before);
        }
    }

    #[test]
    fn success_at_the_deadline_clears_context_but_keeps_lockout_state() {
        let mut policy = PinPolicy {
            state: PinPolicyState::Lockout,
            delay_factor: 32,
            allowed_attempts: 999,
            lockout_time: 1000u64.to_le_bytes(),
        };
        assert_eq!(policy.record_auth(true, 1000, 60), Ok(()));
        assert_eq!(
            policy,
            PinPolicy {
                state: PinPolicyState::Lockout,
                ..PinPolicy::default()
            }
        );
        fail(&mut policy, 1001, 60);
        assert_eq!(policy.allowed_attempts, 1);
        assert_eq!(policy.delay_factor, 0);
    }

    #[test]
    fn factors_increase_linearly_and_roll_over_after_the_maximum() {
        let mut policy = PinPolicy::default();
        let mut now = 100;
        for factor in 1..=MAX_DELAY_FACTOR + 1 {
            for _ in 0..MAX_PIN_AUTH_ATTEMPTS {
                fail(&mut policy, now, 60);
                now = u64::from_le_bytes(policy.lockout_time);
            }
            assert_eq!(policy.delay_factor, factor % (MAX_DELAY_FACTOR + 1));
            assert_eq!(policy.allowed_attempts, 0);
            assert_eq!(policy.state, PinPolicyState::Lockout);
        }
        assert!(policy.can_login(now));
    }

    #[test]
    fn zero_delay_override_preserves_accounting_without_waiting() {
        let mut policy = PinPolicy::default();
        for _ in 0..MAX_PIN_AUTH_ATTEMPTS * 2 {
            fail(&mut policy, 500, 0);
        }
        assert_eq!(policy.delay_factor, 2);
        assert_eq!(u64::from_le_bytes(policy.lockout_time), 500);
    }

    #[test]
    fn invalid_context_or_deadline_overflow_does_not_partially_update() {
        for (attempts, factor, now, step) in [
            (MAX_PIN_AUTH_ATTEMPTS, 0, 1, 60),
            (0, MAX_DELAY_FACTOR + 1, 1, 60),
            (0, 1, u64::MAX, 60),
            (0, 2, 1, u64::MAX),
        ] {
            let mut policy = PinPolicy {
                allowed_attempts: attempts,
                delay_factor: factor,
                ..PinPolicy::default()
            };
            let before = policy;
            assert_eq!(
                policy.record_auth(false, now, step),
                Err(HsmError::InternalError)
            );
            assert_eq!(policy, before);
        }
    }
}
