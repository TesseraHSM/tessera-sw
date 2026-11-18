// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Emulated hardware drivers: the platform-independent ones come from
//! `tsra_fw_hsm_std_common`; the IO and vault drivers, which use this
//! crate's IO and session types, are shared via `#[path]`.

pub use tsra_fw_hsm_std_common::drivers::*;

#[path = "../../../../common/pal_src/drivers/iic.rs"]
pub mod iic;
#[path = "../../../../common/pal_src/drivers/oic.rs"]
pub mod oic;
#[path = "../../../../common/pal_src/drivers/vault.rs"]
pub mod vault;
