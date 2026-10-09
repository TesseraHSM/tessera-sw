// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Key encode / decode for the TSRA firmware.
//!
//! A constrained profile of RFC 9052 `COSE_Key`, matching the internal
//! *COSE Key Definition Format* specification.  This crate currently
//! supports **elliptic-curve (EC2) private keys only** — the shape the
//! TBOR `DarcKeyUnwrap` command imports.
//!
//! It is `no_std` and takes no allocations: decoding walks the CBOR with
//! a `minicbor` cursor only to locate the coordinate / scalar spans and
//! returns zero-copy [`DmaBuf`](tsra_fw_hsm_pal_traits::DmaBuf)
//! sub-views borrowing from the input buffer.
//!
//! Every code path is **no-panic across the trust boundary**: any
//! malformed, ambiguous, or out-of-profile input returns
//! [`HsmError::InvalidArg`](tsra_fw_hsm_pal_traits::HsmError::InvalidArg).

#![no_std]

mod ec2;

pub use ec2::encode_ec2_private_cose_key;
pub use ec2::key_op;
pub use ec2::parse_ec2_private_cose_key;
pub use ec2::CoseKeyOps;
pub use ec2::Ec2PrivateCoseKey;

#[cfg(test)]
extern crate std;
