// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time layout assertions for the partition-store [`Storage`] slot.
//!
//! These are `const` assertions evaluated in *every* build (including the
//! firmware target), locking the on-storage layout to the reference format.
//! They are not `#[cfg(test)]` unit tests — keeping them in a plain child
//! module preserves that always-on compile-time coverage while keeping the
//! layout checks out of the main source file.

use super::*;

// Lock the layout to the reference 3072-byte slot. The whole partition-store
// GSRAM region (`PART_STORE_T_BASE`..key vault) is sized for exactly
// `NUM_PARTITIONS` of these.
const _: () = assert!(core::mem::size_of::<Storage>() == STORE_SIZE);
const _: () = assert!(STRIDE == STORE_SIZE);
// The ECC keygen engine writes the public keys directly into these fields
// via DMA, which requires 4-byte alignment (see `Storage` field ordering).
const _: () = assert!(core::mem::offset_of!(Storage, ec_pub_key) % 4 == 0);
const _: () = assert!(core::mem::offset_of!(Storage, se_pub_key) % 4 == 0);

// Pin the SP<->CP gate-byte offsets so the SP's ephemeral-key monitor and this
// slot agree (must match the reference `HsmPartPersistentStore`): Gate 1 at 22,
// the validity byte at 23, and the 516-byte key payload at 24.
const _: () = assert!(core::mem::offset_of!(Storage, unwrapping_key_required) == 22);
const _: () = assert!(core::mem::offset_of!(Storage, unwrapping_key_bk_valid) == 23);
const _: () = assert!(core::mem::offset_of!(Storage, unwrapping_key_bk) == 24);

// The `Shadow` runs: each is word-aligned, holds the fields it shadows, and
// lies within the slot.
const _: () = assert!(SHADOW_HEAD.is_multiple_of(4) && SHADOW_TAIL.is_multiple_of(4));
const _: () = assert!(core::mem::offset_of!(Storage, generation) == SHADOW_HEAD + 4);
// Shadowed 16-bit handles sit within one word each.
const _: () = assert!((core::mem::offset_of!(Storage, id_key_id) - SHADOW_TAIL).is_multiple_of(2));
const _: () =
    assert!(core::mem::offset_of!(Storage, res_mask) + RES_MASK_LEN == SHADOW_HEAD + SHADOW_RUN);
const _: () = assert!(core::mem::offset_of!(Storage, sd_mk_key_id) + 2 <= SHADOW_TAIL + SHADOW_RUN);
const _: () = assert!(core::mem::offset_of!(Storage, valid_flags) < SHADOW_TAIL + SHADOW_RUN);
const _: () = assert!(SHADOW_HEAD + SHADOW_RUN <= SHADOW_TAIL);
// The front run holds the whole session table, its 16-bit slot ids each
// within one word, and the tail run the session metadata.
const _: () = assert!(SHADOW_FRONT + SHADOW_RUN <= SHADOW_HEAD);
const _: () = assert!(
    core::mem::offset_of!(Storage, session_table) + SESSION_TABLE_LEN <= SHADOW_FRONT + SHADOW_RUN
);
const _: () =
    assert!((core::mem::offset_of!(Storage, session_table) - SHADOW_FRONT).is_multiple_of(2));
const _: () = assert!(core::mem::offset_of!(Storage, session_meta) + 2 <= SHADOW_TAIL + SHADOW_RUN);
const _: () = assert!(SHADOW_TAIL + SHADOW_RUN <= STORE_SIZE);
