// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The ML-DSA hashes this core computes on the fastpath cores' behalf.
//!
//! A fastpath core spends the first 10-20 Keccak permutations of a
//! verification hashing the public key into `tr`, and the last ones of a
//! key generation doing the same, while this core mostly waits on it. So
//! the hashes that need nothing but a request's own operands are done here
//! instead, with the cores' own Keccak, and the cores are handed the
//! results:
//!
//! * key generation: `tr = H(pk)`, written into the expanded secret key,
//!   which the core returns without it;
//! * signing and verification: the message representative
//!   `mu = H(tr || 0 || |ctx| || ctx || msg)` of pure ML-DSA (FIPS 204),
//!   staged where the message would go.
//!
//! Hashing yields after every block absorbed, so a public key hashed here
//! holds up no engine's completion for longer than one permutation.

use pqc_ml::keccak::shake256_init;
use pqc_ml::keccak::SHAKE256_RATE;

/// Length of `tr` and of `mu`.
pub(crate) const HASH_LEN: usize = 64;

/// Where `tr` sits in an expanded ML-DSA secret key, after `rho` and `K`.
pub(crate) const SEC_KEY_TR: core::ops::Range<usize> = 64..64 + HASH_LEN;

/// SHAKE256 of the concatenation of `parts`, squeezed into `out`.
async fn shake256(parts: &[&[u8]], out: &mut [u8; HASH_LEN]) {
    let mut ctx = shake256_init();
    let mut unyielded = 0;
    for part in parts {
        for chunk in part.chunks(SHAKE256_RATE) {
            ctx.absorb(chunk);
            unyielded += chunk.len();
            if unyielded >= SHAKE256_RATE {
                unyielded -= SHAKE256_RATE;
                embassy_futures::yield_now().await;
            }
        }
    }
    ctx.finalize();
    ctx.squeeze(out);
}

/// The public-key hash `tr = H(pk)`.
pub(crate) async fn public_key_hash(pk: &[u8], tr: &mut [u8; HASH_LEN]) {
    shake256(&[pk], tr).await;
}

/// Pure ML-DSA's message representative `mu = H(tr || 0 || |ctx| || ctx ||
/// msg)`; `ctx` is at most 255 bytes.
pub(crate) async fn message_representative(
    tr: &[u8],
    ctx: &[u8],
    msg: &[u8],
    mu: &mut [u8; HASH_LEN],
) {
    shake256(&[tr, &[0, ctx.len() as u8], ctx, msg], mu).await;
}
