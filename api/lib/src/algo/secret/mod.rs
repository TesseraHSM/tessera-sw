// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Secret key algorithms and types.
//!
//! This module defines the HSM-managed shared-secret wrapper used by ECDH and KDF
//! operations. It also carries AES/HMAC derivation outputs before conversion to
//! their concrete key wrappers.
//! Imported generic secrets are distinct keys used only as KBKDF inputs.

mod key;

pub use key::*;

use super::*;
