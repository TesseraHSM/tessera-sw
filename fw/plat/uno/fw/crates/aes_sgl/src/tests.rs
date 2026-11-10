// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host tests of the streamed GCM/XTS logic against a mock SGL stream.
//!
//! The block cipher is a toy keyed function: GCM only ever runs it
//! forwards, so chunking, counter, GHASH and checkpoint logic are checked
//! against an independent one-shot reference built on the same function.
//! Real AES is covered end to end by the TBOR tests.

use core::future::Future;
use core::pin::pin;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

use crate::gcm::gcm_decrypt_sgl;
use crate::gcm::gcm_encrypt_sgl;
use crate::gcm::GcmSglIo;
use crate::gcm::SglBuf;
use crate::gcm::GCM_TAG_LEN;
use crate::gcm::SGL_CHUNK;
use crate::ghash::Ghash;
use crate::xts::mul_alpha;
use crate::xts::xor_tweaks;
use crate::AES_BLOCK_SIZE;

type Block = [u8; AES_BLOCK_SIZE];

const KEY: Block = *b"0123456789abcdef";
const IV: [u8; 12] = *b"nonce-012345";

/// Run a future that never pends (the mock never does).
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    match pin!(fut).poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("mock future pended"),
    }
}

/// Toy keyed block function standing in for `E_K`.
fn toy_e(key: &Block, block: &Block) -> Block {
    let mut s = *block;
    for round in 0..4u8 {
        let mut n = [0u8; AES_BLOCK_SIZE];
        for i in 0..AES_BLOCK_SIZE {
            let a = s[i] ^ key[(i + usize::from(round)) % AES_BLOCK_SIZE];
            let b = s[(i + 1) % AES_BLOCK_SIZE].rotate_left(3);
            n[i] = a.wrapping_mul(0x1d).wrapping_add(b) ^ round.wrapping_mul(0x5b);
        }
        s = n;
    }
    s
}

fn inc32(cb: &Block, by: u32) -> Block {
    let mut c = *cb;
    let v = u32::from_be_bytes([c[12], c[13], c[14], c[15]]).wrapping_add(by);
    c[12..].copy_from_slice(&v.to_be_bytes());
    c
}

/// Bitwise GF(2¹²⁸) multiply (SP 800-38D Algorithm 1), independent of the
/// table-driven [`Ghash`].
fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let (mut z, mut v) = (0u128, y);
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

fn ref_ghash(h: &Block, aad: &[u8], ct: &[u8]) -> Block {
    let h = u128::from_be_bytes(*h);
    let mut y = 0u128;
    for data in [aad, ct] {
        for c in data.chunks(AES_BLOCK_SIZE) {
            let mut b = [0u8; AES_BLOCK_SIZE];
            b[..c.len()].copy_from_slice(c);
            y = gf_mul(y ^ u128::from_be_bytes(b), h);
        }
    }
    let lens = (((aad.len() as u128) * 8) << 64) | ((ct.len() as u128) * 8);
    gf_mul(y ^ lens, h).to_be_bytes()
}

/// One-shot GCM encrypt (96-bit IV) built on [`toy_e`].
fn ref_gcm_encrypt(aad: &[u8], pt: &[u8]) -> (Vec<u8>, Block) {
    let h = toy_e(&KEY, &[0; AES_BLOCK_SIZE]);
    let mut j0 = [0u8; AES_BLOCK_SIZE];
    j0[..12].copy_from_slice(&IV);
    j0[15] = 1;
    let mut ct = pt.to_vec();
    for (i, c) in ct.chunks_mut(AES_BLOCK_SIZE).enumerate() {
        let ks = toy_e(&KEY, &inc32(&j0, 1 + i as u32));
        c.iter_mut().zip(ks).for_each(|(b, k)| *b ^= k);
    }
    let mut tag = ref_ghash(&h, aad, &ct);
    tag.iter_mut()
        .zip(toy_e(&KEY, &j0))
        .for_each(|(t, e)| *t ^= e);
    (ct, tag)
}

/// Host `[padded AAD | text]` stream with the AAD at the SGL offset.
fn stream(aad: &[u8], text: &[u8]) -> Vec<u8> {
    let (padded, off) = if aad.is_empty() {
        (0, 0)
    } else {
        let p = aad.len().next_multiple_of(32);
        let r = aad.len() % 32;
        (p, if r != 0 && r <= 16 { 16 } else { 0 })
    };
    let mut s = vec![0xa5u8; padded];
    s[off..off + aad.len()].copy_from_slice(aad);
    s.extend_from_slice(text);
    s
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
        .collect()
}

/// A recorded `dst` write: which pass (1-based rewind count) and range.
#[derive(Debug)]
struct Write {
    pass: usize,
    at: usize,
    n: usize,
}

/// Mock host SGL stream and AES engine.
struct Mock {
    src: Vec<u8>,
    dst: Vec<u8>,
    rd: usize,
    wr: Option<usize>,
    buf: Vec<u8>,
    out: Vec<u8>,
    pass: usize,
    /// Flip `src[.1]` just before pass `.0` reads it.
    tamper: Option<(usize, usize)>,
    writes: Vec<Write>,
}

impl Mock {
    fn new(src: Vec<u8>) -> Self {
        let len = src.len();
        Self {
            src,
            dst: vec![0x77; len],
            rd: 0,
            wr: None,
            buf: vec![0; SGL_CHUNK],
            out: vec![0; SGL_CHUNK],
            pass: 0,
            tamper: None,
            writes: Vec::new(),
        }
    }
}

impl GcmSglIo for Mock {
    fn buf(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    fn out(&mut self) -> &mut [u8] {
        &mut self.out
    }

    fn rewind(&mut self, write: bool) -> HsmResult<()> {
        self.pass += 1;
        self.rd = 0;
        self.wr = write.then_some(0);
        Ok(())
    }

    async fn read(&mut self, n: usize) -> HsmResult<()> {
        let end = self.rd + n;
        if end > self.src.len() {
            return Err(HsmError::InvalidArg);
        }
        if let Some((pass, at)) = self.tamper {
            if pass == self.pass && (self.rd..end).contains(&at) {
                self.src[at] ^= 0x01;
                self.tamper = None;
            }
        }
        self.buf[..n].copy_from_slice(&self.src[self.rd..end]);
        self.rd = end;
        Ok(())
    }

    async fn write(&mut self, from: SglBuf, n: usize) -> HsmResult<()> {
        let at = self.wr.ok_or(HsmError::InvalidArg)?;
        if at + n > self.dst.len() {
            return Err(HsmError::InvalidArg);
        }
        let data = match from {
            SglBuf::In => &self.buf[..n],
            SglBuf::Out => &self.out[..n],
        };
        self.dst[at..at + n].copy_from_slice(data);
        self.wr = Some(at + n);
        self.writes.push(Write {
            pass: self.pass,
            at,
            n,
        });
        Ok(())
    }

    async fn ecb_encrypt(&mut self, block: &Block) -> HsmResult<Block> {
        Ok(toy_e(&KEY, block))
    }

    async fn ctr(&mut self, _encrypt: bool, counter: &Block, nb: usize) -> HsmResult<()> {
        assert_eq!(nb % AES_BLOCK_SIZE, 0);
        for (i, (o, b)) in self.out[..nb]
            .chunks_mut(AES_BLOCK_SIZE)
            .zip(self.buf[..nb].chunks(AES_BLOCK_SIZE))
            .enumerate()
        {
            let ks = toy_e(&KEY, &inc32(counter, i as u32));
            for j in 0..AES_BLOCK_SIZE {
                o[j] = b[j] ^ ks[j];
            }
        }
        Ok(())
    }
}

/// (AAD length, text length) cases: empty, sub-block, multi-chunk text
/// with partial final blocks, both AAD offsets, multi-chunk AAD, and the
/// 16 KiB TBOR maximum.
const CASES: &[(usize, usize)] = &[
    (0, 0),
    (0, 1),
    (13, 0),
    (16, 2049),
    (20, 4095),
    (48, 5000),
    (2050, 5000),
    (3000, 16384 - 3008),
    (0, 16384),
];

#[test]
fn encrypt_decrypt_match_one_shot_reference() {
    for &(aad_len, text_len) in CASES {
        let aad = pattern(aad_len, 1);
        let pt = pattern(text_len, 2);
        let (ref_ct, ref_tag) = ref_gcm_encrypt(&aad, &pt);
        let src = stream(&aad, &pt);
        let padded = src.len() - text_len;

        let mut enc = Mock::new(src.clone());
        let tag = block_on(gcm_encrypt_sgl(&mut enc, &IV, aad_len, src.len()))
            .unwrap_or_else(|e| panic!("encrypt {aad_len}/{text_len}: {e:?}"));
        assert_eq!(tag, ref_tag, "tag {aad_len}/{text_len}");
        assert_eq!(
            &enc.dst[..padded],
            &src[..padded],
            "aad {aad_len}/{text_len}"
        );
        assert_eq!(&enc.dst[padded..], &ref_ct[..], "ct {aad_len}/{text_len}");

        let mut dec = Mock::new(enc.dst.clone());
        block_on(gcm_decrypt_sgl(&mut dec, &IV, aad_len, src.len(), &tag))
            .unwrap_or_else(|e| panic!("decrypt {aad_len}/{text_len}: {e:?}"));
        assert_eq!(dec.dst, src, "round trip {aad_len}/{text_len}");
        assert!(dec.writes.iter().all(|w| w.pass == 2));
    }
}

/// Decrypt with `src[at]` flipped just before pass `pass` reads it.
/// Returns the mock and the stream start of the chunk holding `at`.
fn tampered_decrypt(aad_len: usize, text_len: usize, pass: usize, at: usize) -> (Mock, usize) {
    let aad = pattern(aad_len, 3);
    let pt = pattern(text_len, 4);
    let src = stream(&aad, &pt);
    let len = src.len();
    let mut enc = Mock::new(src);
    let tag = block_on(gcm_encrypt_sgl(&mut enc, &IV, aad_len, len)).expect("encrypt");

    let mut dec = Mock::new(enc.dst);
    dec.tamper = Some((pass, at));
    assert_eq!(
        block_on(gcm_decrypt_sgl(&mut dec, &IV, aad_len, len, &tag)),
        Err(HsmError::AesGcmDecryptTagDoesNotMatch)
    );
    assert!(dec.tamper.is_none(), "tamper point not reached");
    let padded = len - text_len;
    let chunk = if at < padded {
        at / SGL_CHUNK * SGL_CHUNK
    } else {
        padded + (at - padded) / SGL_CHUNK * SGL_CHUNK
    };
    (dec, chunk)
}

#[test]
fn decrypt_rejects_text_changed_between_passes() {
    // AAD padded to 64; text byte 5000 is in the third text chunk.
    let (dec, chunk) = tampered_decrypt(40, 9000, 2, 64 + 5000);
    let released: Vec<_> = dec.writes.iter().filter(|w| w.pass == 2).collect();
    assert!(!released.is_empty(), "verified chunks should be released");
    assert!(
        released.iter().all(|w| w.at + w.n <= chunk),
        "changed chunk released: {released:?}"
    );
    assert!(dec.writes.iter().any(|w| w.pass == 3), "no scrub");
    assert!(dec.dst.iter().all(|&b| b == 0), "output not scrubbed");
}

#[test]
fn decrypt_rejects_aad_changed_between_passes() {
    // 3000-byte AAD spans two chunks; byte 2100 is in the second.
    let (dec, chunk) = tampered_decrypt(3000, 5000, 2, 2100);
    assert!(dec
        .writes
        .iter()
        .filter(|w| w.pass == 2)
        .all(|w| w.at + w.n <= chunk));
    assert!(dec.dst.iter().all(|&b| b == 0), "output not scrubbed");
}

#[test]
fn decrypt_rejects_tampered_input_before_any_output() {
    // 20-byte AAD sits at offset 0 of its 32-byte pad; byte 10 is AAD,
    // 4103 is text in the third chunk.
    for at in [0, 10, 4096 + 7] {
        let (dec, _) = tampered_decrypt(20, 6000, 1, at);
        assert!(dec.writes.is_empty(), "wrote after failed verify: {at}");
        assert!(dec.dst.iter().all(|&b| b == 0x77));
    }
}

#[test]
fn decrypt_rejects_wrong_tag_and_too_many_chunks() {
    let src = stream(&[], &pattern(100, 5));
    let mut dec = Mock::new(src);
    assert_eq!(
        block_on(gcm_decrypt_sgl(&mut dec, &IV, 0, 100, &[0; GCM_TAG_LEN])),
        Err(HsmError::AesGcmDecryptTagDoesNotMatch)
    );
    assert_eq!(
        block_on(gcm_decrypt_sgl(&mut dec, &IV, 0, 100, &[0; 15])),
        Err(HsmError::InvalidArg)
    );
    assert!(dec.writes.is_empty());

    let len = 17 * SGL_CHUNK;
    let mut big = Mock::new(vec![0; len]);
    assert_eq!(
        block_on(gcm_decrypt_sgl(&mut big, &IV, 0, len, &[0; GCM_TAG_LEN])),
        Err(HsmError::AesGcmInvalidBufferSize)
    );
    assert!(big.writes.is_empty());
}

#[test]
fn chunk_buffers_are_zeroed_after_each_operation() {
    let src = stream(&pattern(20, 6), &pattern(3000, 7));
    let len = src.len();
    let mut m = Mock::new(src);
    block_on(gcm_encrypt_sgl(&mut m, &IV, 20, len)).expect("encrypt");
    assert!(m.buf.iter().chain(&m.out).all(|&b| b == 0));
}

#[test]
fn ghash_split_updates_match_reference() {
    let h = toy_e(&KEY, &[0; AES_BLOCK_SIZE]);
    let aad = pattern(48, 8);
    let ct = pattern(SGL_CHUNK * 2 + 5, 9);
    let mut g = Ghash::new(&h).expect("ghash");
    g.update(&aad);
    for c in ct.chunks(SGL_CHUNK) {
        g.update(c);
    }
    let mut lens = [0u8; AES_BLOCK_SIZE];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    g.update(&lens);
    assert_eq!(g.finish(), ref_ghash(&h, &aad, &ct));
}

#[test]
fn xts_mul_alpha_reduces_carry() {
    assert_eq!(mul_alpha(1 << 127), 0x87);
    assert_eq!(mul_alpha(1), 2);
    assert_eq!(mul_alpha((1 << 127) | 1), 0x85);
}

#[test]
fn xts_chunked_tweaks_match_one_shot() {
    let t0 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
    for dul in [4096usize, 3072, 2064] {
        let data = pattern(dul, 10);
        let mut whole = data.clone();
        let end = xor_tweaks(&mut whole, t0);

        let mut chunked = data.clone();
        let mut t = t0;
        for c in chunked.chunks_mut(2048) {
            t = xor_tweaks(c, t);
        }
        assert_eq!(chunked, whole, "dul {dul}");
        assert_eq!(t, end, "dul {dul}");

        let mut r = t0;
        for (i, blk) in data.chunks(AES_BLOCK_SIZE).enumerate() {
            let x: Vec<u8> = blk
                .iter()
                .zip(r.to_le_bytes())
                .map(|(a, b)| a ^ b)
                .collect();
            assert_eq!(&whole[i * AES_BLOCK_SIZE..][..AES_BLOCK_SIZE], &x[..]);
            // Reference α-multiply: little-endian shift with 0x87 feedback.
            let carry = r >> 127;
            r = (r << 1) ^ if carry == 1 { 0x87 } else { 0 };
        }
        assert_eq!(r, end);
    }
}
