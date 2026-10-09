// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire format for HSM → FP PQC requests.
//!
//! Messages are arrays of `u32` because that is what the IPC rings carry.
//! The layout is deliberately fixed-size and small: the ring entry stride
//! is tens of bytes, so bulk operands cannot travel inline.
//!
//! # Operand passing (unresolved)
//!
//! An FP core has 32 KB of DTCM, and an ML-DSA-87 public key alone is
//! 2,592 bytes while a signature is 4,627 — so neither the ring nor FP's
//! local memory can hold a working set of operands comfortably.  The
//! request therefore carries *addresses* rather than payloads, and the
//! window those addresses point into still has to be settled:
//!
//! * The Admin↔HSM rings live in IO GSRAM (`0x6100_0000`), but it is not
//!   established that an FP core can reach that aperture.
//! * The legacy Admin↔FP channels used PSRAM (around `0xA3E0_xxxx`),
//!   which FP demonstrably can reach, but the PSRAM map is nearly full —
//!   roughly 1.2 KB spare, plus about 3.5 KB reclaimable from the retired
//!   legacy Admin↔FP regions.
//!
//! Until that is decided the address fields are populated but never sent.

/// Operation selector in a PQC request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PqcOp {
    /// Generate an ML-DSA keypair.
    MlDsaGenerateKey = 1,

    /// Sign a message with a caller-supplied seed.
    MlDsaSign = 2,

    /// Verify a signature under a supplied public key.
    MlDsaVerify = 3,

    /// Generate an ML-KEM key pair.
    MlKemGenerateKey = 4,

    /// Encapsulate to an ML-KEM public key.
    MlKemEncapsulate = 5,

    /// Decapsulate an ML-KEM ciphertext.
    MlKemDecapsulate = 6,
}

/// Number of `u32` words in a request message.
pub const REQUEST_WORDS: usize = 5;

/// A PQC request as it goes onto the wire.
#[derive(Debug, Clone, Copy)]
pub struct PqcRequest {
    /// Operation to perform.
    pub op: PqcOp,

    /// Key kind, as the `HsmVaultKeyKind` discriminant.  Carries the
    /// parameter set; for seed kinds it is the only thing that does,
    /// since every ML-DSA seed is 32 bytes regardless of parameter set.
    pub key_kind: u32,

    /// Address FP writes the private seed to.
    pub seed_addr: u32,

    /// Address FP writes the public key to.
    pub pub_key_addr: u32,

    /// Length of the public-key output buffer.
    pub pub_key_len: u32,
}

impl PqcRequest {
    /// Encode into the fixed-size word array carried by the IPC ring.
    pub fn encode(&self) -> [u32; REQUEST_WORDS] {
        [
            self.op as u32,
            self.key_kind,
            self.seed_addr,
            self.pub_key_addr,
            self.pub_key_len,
        ]
    }
}

/// Number of `u32` words in a response message.
pub const RESPONSE_WORDS: usize = 2;

/// A PQC response from an FP core.
#[derive(Debug, Clone, Copy)]
pub struct PqcResponse {
    /// Zero on success, otherwise an FP-defined failure code.
    pub status: u32,

    /// Bytes written to the public-key buffer.
    pub pub_key_len: u32,
}

impl PqcResponse {
    /// Decode from the words read out of the IPC ring.
    pub fn decode(words: &[u32]) -> Option<Self> {
        if words.len() < RESPONSE_WORDS {
            return None;
        }
        Some(Self {
            status: words[0],
            pub_key_len: words[1],
        })
    }
}
