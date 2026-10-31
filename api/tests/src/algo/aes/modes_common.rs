// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the AES ECB, CFB, OFB and CTR tests.
//!
//! Generated keys never leave the HSM, so known-answer checks use the HSM's
//! own AES-ECB (single block encryption) to build reference CFB, OFB and CTR
//! output from the SP 800-38A definitions.

// Most helpers are only used by the extended-session tests.
#![cfg_attr(not(feature = "session-ex-tests"), allow(dead_code))]

use tsra_api::HsmAesEcbAlgo;
use tsra_api::HsmAesKey;
use tsra_api::HsmAesKeyGenAlgo;
use tsra_api::HsmDecryptContext;
use tsra_api::HsmDecryptOp;
use tsra_api::HsmDecryptStreamingOp;
use tsra_api::HsmEncryptContext;
use tsra_api::HsmEncryptOp;
use tsra_api::HsmEncryptStreamingOp;
use tsra_api::HsmError;
use tsra_api::HsmKeyClass;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmKeyPropsBuilder;
use tsra_api::HsmResult;
use tsra_api::HsmSession;

pub const AES_BLOCK: usize = 16;

/// Generates a session AES key with the given usage permissions.
pub fn mode_key(
    session: &HsmSession,
    bits: u32,
    can_encrypt: bool,
    can_decrypt: bool,
) -> HsmResult<HsmAesKey> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bits)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(can_encrypt)
        .can_decrypt(can_decrypt)
        .is_session(true)
        .build()
        .expect("Failed to build key properties");
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props)
}

/// Generates a session AES key that can encrypt and decrypt.
pub fn mode_key_all(session: &HsmSession, bits: u32) -> HsmAesKey {
    mode_key(session, bits, true, true).expect("Failed to generate AES key")
}

/// Deterministic, non-repeating test data.
pub fn mode_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Single-shot encrypt with a size query first.
pub fn one_shot_encrypt<A>(algo: &mut A, key: &HsmAesKey, input: &[u8]) -> HsmResult<Vec<u8>>
where
    A: HsmEncryptOp<Key = HsmAesKey, Error = HsmError>,
{
    let len = algo.encrypt(key, input, None)?;
    let mut out = vec![0u8; len];
    let written = algo.encrypt(key, input, Some(&mut out))?;
    out.truncate(written);
    Ok(out)
}

/// Single-shot decrypt with a size query first.
pub fn one_shot_decrypt<A>(algo: &mut A, key: &HsmAesKey, input: &[u8]) -> HsmResult<Vec<u8>>
where
    A: HsmDecryptOp<Key = HsmAesKey, Error = HsmError>,
{
    let len = algo.decrypt(key, input, None)?;
    let mut out = vec![0u8; len];
    let written = algo.decrypt(key, input, Some(&mut out))?;
    out.truncate(written);
    Ok(out)
}

/// Splits `len` into chunks cycling through `sizes`.
fn chunk_ranges(len: usize, sizes: &[usize]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < len {
        let size = sizes[i % sizes.len()].min(len - offset);
        ranges.push(offset..offset + size);
        offset += size;
        i += 1;
    }
    ranges
}

/// Streaming encrypt in `sizes` chunks; returns output and the algorithm.
pub fn stream_encrypt<A>(
    algo: A,
    key: &HsmAesKey,
    input: &[u8],
    sizes: &[usize],
) -> HsmResult<(Vec<u8>, A)>
where
    A: HsmEncryptStreamingOp<Key = HsmAesKey, Error = HsmError>,
{
    let mut ctx = algo.encrypt_init(key.clone())?;
    let mut out = Vec::new();
    for range in chunk_ranges(input.len(), sizes) {
        let chunk = &input[range];
        let len = ctx.update(chunk, None)?;
        let mut buf = vec![0u8; len];
        let written = ctx.update(chunk, Some(&mut buf))?;
        out.extend_from_slice(&buf[..written]);
    }
    let len = ctx.finish(None)?;
    let mut buf = vec![0u8; len];
    let written = ctx.finish(Some(&mut buf))?;
    out.extend_from_slice(&buf[..written]);
    Ok((out, ctx.into_algo()))
}

/// Streaming decrypt in `sizes` chunks; returns output and the algorithm.
pub fn stream_decrypt<A>(
    algo: A,
    key: &HsmAesKey,
    input: &[u8],
    sizes: &[usize],
) -> HsmResult<(Vec<u8>, A)>
where
    A: HsmDecryptStreamingOp<Key = HsmAesKey, Error = HsmError>,
{
    let mut ctx = algo.decrypt_init(key.clone())?;
    let mut out = Vec::new();
    for range in chunk_ranges(input.len(), sizes) {
        let chunk = &input[range];
        let len = ctx.update(chunk, None)?;
        let mut buf = vec![0u8; len];
        let written = ctx.update(chunk, Some(&mut buf))?;
        out.extend_from_slice(&buf[..written]);
    }
    let len = ctx.finish(None)?;
    let mut buf = vec![0u8; len];
    let written = ctx.finish(Some(&mut buf))?;
    out.extend_from_slice(&buf[..written]);
    Ok((out, ctx.into_algo()))
}

/// Feedback mode used to build reference output.
#[derive(Clone, Copy)]
pub enum RefMode {
    Cfb,
    Ofb,
    Ctr,
}

/// Encrypts one block with the HSM key in ECB mode (the AES forward cipher).
pub fn aes_block(key: &HsmAesKey, block: &[u8]) -> [u8; AES_BLOCK] {
    let out = one_shot_encrypt(&mut HsmAesEcbAlgo, key, block).expect("ECB block encrypt");
    out.try_into().expect("ECB block length")
}

/// Builds the reference encryption of `pt` and the expected IV-out, using
/// the HSM's ECB as the block cipher (SP 800-38A section 6).
pub fn reference_encrypt(
    mode: RefMode,
    key: &HsmAesKey,
    iv: &[u8],
    pt: &[u8],
) -> (Vec<u8>, [u8; AES_BLOCK]) {
    let mut reg: [u8; AES_BLOCK] = iv.try_into().expect("IV length");
    let mut ct = Vec::with_capacity(pt.len());
    for block in pt.chunks(AES_BLOCK) {
        let ks = aes_block(key, &reg);
        let out: Vec<u8> = block.iter().zip(ks).map(|(p, k)| p ^ k).collect();
        match mode {
            RefMode::Cfb => {
                if out.len() == AES_BLOCK {
                    reg.copy_from_slice(&out);
                }
            }
            RefMode::Ofb => reg = ks,
            RefMode::Ctr => reg = u128::from_be_bytes(reg).wrapping_add(1).to_be_bytes(),
        }
        ct.extend_from_slice(&out);
    }
    (ct, reg)
}
