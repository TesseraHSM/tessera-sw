// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `MlKemDecapsulate` command.
//!
//! `MlKemDecapsulate` is an in-session command that decapsulates an ML-KEM ciphertext using a caller-held
//! **masked** decapsulation key and returns the shared secret as a
//! **masked** blob under the requested scope's masking key.
//!
//! There is intentionally no `key_kind` request field: the masked blob is
//! self-describing.  Its authenticated key kind already tells the firmware
//! which parameter set the seed belongs to.
//!
//! Requests are bound to an active session.

use alloc::vec::Vec;

pub use crate::mlkem_generate_key::MASKED_MLKEM_KEY_MAX_LEN;
pub use crate::mlkem_generate_key::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
pub use crate::mlkem_generate_key::MLKEM_CIPHERTEXT_MAX_LEN;
use crate::tbor;

/// TBOR opcode for `MlKemDecapsulate`.
pub const TBOR_OP_MLKEM_DECAPSULATE: u8 = 0x2B;

/// Host-facing TBOR `MlKemDecapsulate` request.
#[tbor(opcode = TBOR_OP_MLKEM_DECAPSULATE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlKemDecapsulateReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// The masked ML-KEM decapsulation key (from `MlKemGenerateKey`).
    /// Carries the seed and expanded decapsulation key. See
    /// [`MASKED_MLKEM_KEY_MAX_LEN`].
    #[tbor(align = 4, max_len = 3464)]
    pub masked_key: Vec<u8>,

    /// ML-KEM ciphertext bytes.
    #[tbor(max_len = 1568)]
    pub ciphertext: Vec<u8>,
}

/// Host-facing TBOR `MlKemDecapsulate` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborMlKemDecapsulateResp {
    /// The 32-byte shared secret, masked under the requested scope's masking key.
    #[tbor(align = 4, max_len = 264)]
    pub masked_shared_secret: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_ciphertext() {
        let req = TborMlKemDecapsulateReq {
            session_id: 7,
            scope: 0b100,
            masked_key: alloc::vec![0x11u8; MASKED_MLKEM_KEY_MAX_LEN],
            ciphertext: alloc::vec![0x22u8; 64],
        };
        let mut buf = [0u8; 8192];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the ciphertext bytes",
        );
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(3464 == MASKED_MLKEM_KEY_MAX_LEN);
        const _: () = assert!(1568 == MLKEM_CIPHERTEXT_MAX_LEN);
        const _: () = assert!(264 == MASKED_MLKEM_SHARED_SECRET_MAX_LEN);
    }
}
