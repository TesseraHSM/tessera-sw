// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pairwise consistency tests (PCTs) for the partition's RSA unwrapping key.
//!
//! The unwrapping key reaches the vault two ways, and FIPS 140-3 requires a
//! PCT on both before the key is used:
//!
//! - **Published by the SP:** The SP generates the key, writes it into
//!   the partition's GSRAM slot, and marks the slot `PendingPct`.
//!   [`UnoHsmPal::certify_pending_unwrapping_key`] runs the PCT on a copy of
//!   the slot bytes, then marks the slot `PctPassed` only if it still holds
//!   those bytes. The existing first-use import
//!   (`ensure_unwrapping_key_imported`) imports only a `PctPassed` slot, so
//!   the key never enters the vault untested.
//! - **Restored from its masked backup:** `EstablishCredential` restores
//!   the key after a live migration. `vault_key_create` runs the PCT before
//!   it stores the key.
//!
//! In `fips_validation_hooks` builds, the `RawKeyImport` test hook can also
//! install a host-supplied key as the unwrapping key. It stores the key with
//! `vault_key_create`, so the key gets the same PCT as a restored key.
//!
//! The PCT is the encrypt/decrypt form, because the key only unwraps
//! ([`UnoHsmPal::unwrapping_key_pct`]). Both paths run it through the PAL's
//! RSA PCT runner (see [`crate::pct`]). A key that fails it sends the module
//! to the FIPS error state. A failed SP-published key is first discarded from
//! its slot, if the slot still holds it.

use core::cell::Cell;
use core::future::Future;

use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_drivers_part_store::PartStore;
use tsra_fw_uno_drivers_part_store::UnwrappingKeySlot;
use tsra_fw_uno_pct::ct_eq;
use tsra_fw_uno_pct::scratch;
use tsra_fw_uno_pct::wipe;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Returns `true` for the partition's RSA unwrapping key.
///
/// It's the only `Rsa2kPrivate` key with both `internal` and `unwrap` set.
/// Only the device sets `internal`, except that the `RawKeyImport` test hook
/// in `fips_validation_hooks` builds sets it on the host-supplied key that it
/// installs as the unwrapping key.
pub(crate) fn is_unwrapping_key(kind: HsmVaultKeyKind, attrs: HsmVaultKeyAttrs) -> bool {
    kind == HsmVaultKeyKind::Rsa2kPrivate && attrs.internal() && attrs.unwrap()
}

/// A partition's claim on its unwrapping-key PCT, so only one IO tests the
/// slot at a time. Dropping it releases the claim, on every exit path.
struct PctReservation<'a> {
    busy: &'a Cell<bool>,
}

impl<'a> PctReservation<'a> {
    /// Claims the PCT for `pid`, or returns `None` if another IO holds it.
    fn acquire(pal: &'a UnoHsmPal, pid: HsmPartId) -> Option<Self> {
        let busy = pal.unwrap_pct_busy.get(usize::from(u8::from(pid)))?;
        if busy.replace(true) {
            return None;
        }
        Some(Self { busy })
    }
}

impl Drop for PctReservation<'_> {
    fn drop(&mut self) {
        self.busy.set(false);
    }
}

impl UnoHsmPal {
    /// Runs the unwrapping key's PCT on `key`: the encrypt/decrypt form for an
    /// RSA-2048 key in the PKA's layout, `d ‖ n ‖ e`. Negative-PCT test builds
    /// run it with failure injection (`neg_pct_unwrapping_key_pct`), so every
    /// unwrapping-key PCT can consume an `UnwrappingKey` arm.
    ///
    /// Returns the PCT's future directly. An `async fn` that awaited it would
    /// wrap it in another state machine, which makes the release image larger.
    pub(crate) fn unwrapping_key_pct<'a>(
        &'a self,
        io: &'a UnoHsmIo,
        key: &'a HsmDmaBuf,
    ) -> impl Future<Output = HsmResult<bool>> + 'a {
        #[cfg(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks"))]
        let pct = self.neg_pct_unwrapping_key_pct(io, key);
        #[cfg(not(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks")))]
        let pct = self.rsa_key_pct(
            io,
            key,
            tsra_fw_hsm_pal_traits::HsmRsaKey::Rsa2048Priv,
            tsra_fw_hsm_pal_traits::HsmRsaPct::EncryptDecrypt,
        );
        pct
    }

    /// Certifies the SP-published unwrapping key of `io`'s partition.
    ///
    /// The Uno app calls this for each host IO before the HSM core handles
    /// it. When the slot holds a `PendingPct` key that isn't imported yet,
    /// this copies the key into the IO's scratch and runs the PCT on the
    /// copy. The result applies only if the slot still holds the tested
    /// bytes: a pass marks the slot `PctPassed`, so a command in this or a
    /// later IO can import the key, and a failure discards the key. A failed
    /// PCT always enters the FIPS error state.
    ///
    /// It leaves the slot unchanged when the partition isn't serving host
    /// traffic, when another IO is testing the slot, when an operation such
    /// as an allocation fails, or when the test passes but the slot changed
    /// during it. Until a later IO certifies the key, `GetUnwrappingKey`
    /// reports it as still pending (`PendingKeyGeneration`), and the host
    /// retries.
    pub async fn certify_pending_unwrapping_key(&self, io: &UnoHsmIo) {
        let pid = io.pid();
        let Ok(part) = PartStore::partition(pid) else {
            return;
        };
        // The same admission rule that the core applies to host traffic.
        if !matches!(
            part.state(),
            Ok(HsmPartState::Enabled | HsmPartState::Initializing | HsmPartState::Initialized)
        ) {
            return;
        }
        let slot = part.unwrapping_key_slot();
        let pct_due =
            slot == Some(UnwrappingKeySlot::PendingPct) && part.unwrapping_key_id().is_none();
        // Negative-PCT test builds can also ask for the unwrapping key to be
        // tested again. An imported key is tested from the vault, because the
        // `RawKeyImport` hook can install one that the slot doesn't hold.
        #[cfg(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks"))]
        if !pct_due
            && self.neg_pct_retest(pid)
            && let Some(key_id) = part.unwrapping_key_id()
        {
            self.retest_imported_unwrapping_key(io, key_id).await;
            return;
        }
        // Otherwise a staged key is tested again, even one that already passed.
        #[cfg(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks"))]
        let pct_due = pct_due
            || (self.neg_pct_retest(pid)
                && matches!(
                    slot,
                    Some(UnwrappingKeySlot::PendingPct | UnwrappingKeySlot::PctPassed)
                ));
        if !pct_due {
            return;
        }
        let Some(_reservation) = PctReservation::acquire(self, pid) else {
            return;
        };

        // Test a copy. The slot can change while the test waits on the PKA,
        // for example when a teardown wipes it and the SP publishes a new key.
        self.alloc_scoped_async(io, async |alloc| {
            let Ok(key) = scratch(alloc, part.unwrapping_key_bk().len()) else {
                return;
            };
            key.copy_from_slice(part.unwrapping_key_bk());
            let result = self.unwrapping_key_pct(io, key).await;

            // Nothing below awaits, so no teardown can run before the slot is
            // marked or discarded, and the SP doesn't write an occupied slot.
            let same = part.unwrapping_key_slot() == slot && ct_eq(part.unwrapping_key_bk(), key);
            wipe(key);
            match result {
                Ok(true) if same => {
                    if slot == Some(UnwrappingKeySlot::PendingPct) {
                        part.mark_unwrapping_key_pct_passed();
                    }
                    #[cfg(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks"))]
                    self.neg_pct_retest_passed(pid);
                }
                Ok(false) => {
                    // Discard the failed key before entering the error
                    // state. A slot that now holds a different key is left
                    // alone.
                    if same {
                        part.discard_unwrapping_key();
                    }
                    tsra_fw_uno_fault::enter_error_state(
                        HsmError::PctValidationUnwrappingKeyFailed,
                    );
                }
                // The test didn't finish, or it passed bytes that the slot no
                // longer holds. Leave the slot for a later IO to test.
                _ => {}
            }
        })
        .await;
    }

    /// Runs the negative-PCT retest of `io`'s partition's imported
    /// unwrapping key `key_id`, testing a copy of the vault key.
    ///
    /// Covers every way the key reached the vault, including a key the
    /// `RawKeyImport` hook installed while the slot is empty or holds a
    /// different staged key. A pass applies only if the partition still has
    /// the same key; a failed PCT always enters the FIPS error state.
    #[cfg(all(feature = "tsra_test_hooks", feature = "fips_validation_hooks"))]
    async fn retest_imported_unwrapping_key(
        &self,
        io: &UnoHsmIo,
        key_id: tsra_fw_hsm_pal_traits::HsmKeyId,
    ) {
        use tsra_fw_hsm_pal_traits::HsmVault;

        let pid = io.pid();
        let Ok(part) = PartStore::partition(pid) else {
            return;
        };
        let Some(_reservation) = PctReservation::acquire(self, pid) else {
            return;
        };
        self.alloc_scoped_async(io, async |alloc| {
            let Ok(active) = self.vault_key(io, key_id) else {
                return;
            };
            let Ok(key) = scratch(alloc, active.len()) else {
                return;
            };
            key.copy_from_slice(active);
            let result = self.unwrapping_key_pct(io, key).await;

            // Nothing below awaits, so the partition can't change before the
            // result is applied.
            let same = part.unwrapping_key_id() == Some(key_id)
                && self
                    .vault_key(io, key_id)
                    .is_ok_and(|active| ct_eq(active, key));
            wipe(key);
            match result {
                Ok(true) if same => self.neg_pct_retest_passed(pid),
                Ok(false) => {
                    tsra_fw_uno_fault::enter_error_state(HsmError::PctValidationUnwrappingKeyFailed)
                }
                // The test didn't finish, or the partition's key changed during
                // it. Leave the retest for a later IO.
                _ => {}
            }
        })
        .await;
    }
}
