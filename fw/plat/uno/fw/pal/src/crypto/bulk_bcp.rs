// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host bulk AES-GCM / AES-XTS IOs on the BCP (default build).
//!
//! The engine walks the host's SGLs itself over the function's host
//! interface, as the FP firmware had it do. A bulk IO never reaches the
//! per-IO allocator: its few AES blocks and the GCM tail live in the IO's
//! `BULK_SCRATCH` slot.
//!
//! ## GCM tag correction
//!
//! The host passes the AAD zero-padded to `pad` bytes (a multiple of 32,
//! per `tsra_fw_core_crypto_gcm_buf`) ahead of `n` bytes of whole-block
//! SGL text, and any final partial block (the tail) in a separate buffer.
//! The engine's tag `T'` covers the padded AAD and the SGL text with
//! length block `L' = [pad, n]`; GCM's covers the tail too, with
//! `L = [aad_len, n + tail]`. With `H = E_K(0)`, `C_t` the zero-padded
//! tail ciphertext and `E_K(J₀)`:
//!
//! * no tail: `T = T' ⊕ (L ⊕ L')·H`;
//! * tail: `T = (T' ⊕ E_K(J₀) ⊕ (L' ⊕ C_t)·H ⊕ L)·H ⊕ E_K(J₀)`, and the
//!   tail itself is CTR with counter block `n/16 + 2`.
//!
//! The engine reports the tag it computed even when a decrypt's check
//! fails, so every decrypt hands it a zero tag and the PAL checks `T`
//! itself, wiping the destination on a mismatch.
//!
//! An AAD-only GCM (`n = 0`) runs on the engine too, which copies the AAD
//! through and tags the padded AAD, and is corrected the same way (the FP
//! firmware and Manticore's `gcm_tag_correct_aad_only` do likewise). Only
//! a GCM with no SGL data at all has its tag computed in software, over
//! the tail alone.

use tsra_fw_hsm_bulk::BulkCqe;
use tsra_fw_hsm_bulk::BulkDir;
use tsra_fw_hsm_bulk::BulkParams;
use tsra_fw_hsm_bulk::BulkSqe;
use tsra_fw_hsm_bulk::GcmParams;
use tsra_fw_hsm_bulk::XtsDul;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_drivers_aes::AesMode;
use tsra_fw_uno_drivers_aes::AesOp;
use tsra_fw_uno_drivers_bcp::BcpError;
use tsra_fw_uno_drivers_bcp::BcpOp;
use tsra_fw_uno_drivers_bcp::HostCipher;
use tsra_fw_uno_drivers_bcp::HostRequest;

use super::aes::AES_BLOCK_SIZE;
use super::gcm_bcp::constant_time_eq;
use super::gcm_bcp::len_block;
use super::gcm_bcp::xor;
use super::ghash::Ghash;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::gdma::sgl_xfer_len;
use crate::vault::bulk_vault_key;

type Block = [u8; AES_BLOCK_SIZE];

/// SQE dword of the source SGL descriptor (byte 28).
const SRC_SGL_DW: usize = 7;

/// SQE dword of the destination SGL descriptor (byte 48).
const DST_SGL_DW: usize = 12;

/// `BULK_SCRATCH` layout, in blocks: `[0 | J₀ | ctr_tail]` in,
/// `[H | E(J₀) | E(ctr_tail)]` out, then the tail as read from the host and
/// as written back, each zero-padded to a block.
const ECB_IN: usize = 0;
const ECB_OUT: usize = 3;
const TAIL_IN: usize = 6;
const TAIL_OUT: usize = 7;
const SCRATCH_BLOCKS: usize = 8;

/// The IO's scratch, split into the views a bulk GCM uses.
///
/// GCM's secrets (`H`, `E_K(J₀)`, the tail) stay here rather than in the
/// IO's future, which keeps the future small and leaves their wipe to
/// `drop_io`.
struct Scratch<'a> {
    ecb_in: &'a mut HsmDmaBuf,
    ecb_out: &'a mut HsmDmaBuf,
    tail_in: &'a mut HsmDmaBuf,
    tail_out: &'a mut HsmDmaBuf,
}

impl Scratch<'_> {
    /// The views are not tied to `io`'s borrow, so the IO stays usable
    /// (for its CQE); they stay valid until `drop_io` frees the slot.
    fn new(io: &UnoHsmIo) -> HsmResult<Self> {
        let (ptr, len) = io.bulk_scratch();
        if len < SCRATCH_BLOCKS * AES_BLOCK_SIZE {
            return Err(HsmError::InternalError);
        }
        // SAFETY: the IO owns its `BULK_SCRATCH` slot (DMA-capable GSRAM,
        // `len` bytes) until `drop_io`, and the views are disjoint.
        let view = |block: usize, n: usize| unsafe {
            HsmDmaBuf::from_raw_mut(core::slice::from_raw_parts_mut(
                ptr.add(block * AES_BLOCK_SIZE),
                n * AES_BLOCK_SIZE,
            ))
        };
        Ok(Self {
            ecb_in: view(ECB_IN, 3),
            ecb_out: view(ECB_OUT, 3),
            tail_in: view(TAIL_IN, 1),
            tail_out: view(TAIL_OUT, 1),
        })
    }

    /// Block `i` of the ECB output.
    fn out(&self, i: usize) -> &Block {
        block(&self.ecb_out[i * AES_BLOCK_SIZE..])
    }

    /// The zero-padded tail ciphertext.
    fn ct_tail(&self, encrypt: bool) -> &Block {
        block(if encrypt { self.tail_out } else { self.tail_in })
    }

    /// Lay out the ECB input for `iv` and the tail's counter block.
    fn prepare(&mut self, iv: &[u8; 12], text: usize) {
        let ctr = u32::try_from(text / AES_BLOCK_SIZE + 2).unwrap_or(0);
        let blocks: &mut [u8] = self.ecb_in;
        blocks.fill(0);
        blocks[16..28].copy_from_slice(iv);
        blocks[31] = 1;
        blocks[32..44].copy_from_slice(iv);
        blocks[44..48].copy_from_slice(&ctr.to_be_bytes());
    }

    /// CTR over the `tail_len`-byte tail now in `tail_in`.
    fn crypt_tail(&mut self, tail_len: usize) {
        self.tail_in[tail_len..].fill(0);
        let ks = *self.out(2);
        for (i, b) in self.tail_out.iter_mut().enumerate() {
            *b = if i < tail_len {
                self.tail_in[i] ^ ks[i]
            } else {
                0
            };
        }
    }

    /// GCM's tag from the engine's `t_eng`.
    fn fix_tag(&self, t_eng: &Block, f: &Fix) -> HsmResult<Block> {
        let h = self.out(0);
        let l_eng = len_block(f.pad, f.text);
        if f.tail_len == 0 {
            return Ok(xor(t_eng, &mul_h(h, &xor(&f.l, &l_eng))?));
        }
        let ek_j0 = self.out(1);
        let p = mul_h(h, &xor(&l_eng, self.ct_tail(f.encrypt)))?;
        let x = xor(&xor(t_eng, ek_j0), &xor(&p, &f.l));
        Ok(xor(&mul_h(h, &x)?, ek_j0))
    }

    /// The tag of a GCM with no SGL data: GHASH over the tail and `L`.
    fn gmac(&self, f: &Fix) -> HsmResult<Block> {
        let mut g = Ghash::new(self.out(0)).ok_or(HsmError::InternalError)?;
        if f.tail_len != 0 {
            g.update(self.ct_tail(f.encrypt));
        }
        g.update(&f.l);
        Ok(xor(&g.finish(), self.out(1)))
    }
}

/// The lengths a GCM tag correction needs.
struct Fix {
    encrypt: bool,
    pad: usize,
    text: usize,
    tail_len: usize,
    /// GCM's length block, `[aad_len, text + tail]`.
    l: Block,
}

/// The block at the start of `b`, which holds at least one.
fn block(b: &[u8]) -> &Block {
    b.first_chunk().unwrap_or(&[0; AES_BLOCK_SIZE])
}

/// `x·H`.
#[inline(never)]
fn mul_h(h: &Block, x: &Block) -> HsmResult<Block> {
    let mut g = Ghash::new(h).ok_or(HsmError::InternalError)?;
    g.update(x);
    Ok(g.finish())
}

/// SGL data-block descriptor for the `len`-byte host tail buffer at `addr`.
///
/// The GDMA takes a host buffer's length from its descriptor, so the tail
/// needs one naming its length; type 0 (data block) is the zero top byte.
fn tail_desc(addr: u64, len: usize) -> [u8; 16] {
    let mut d = [0u8; 16];
    d[..8].copy_from_slice(&addr.to_le_bytes());
    d[8..12].copy_from_slice(&(len as u32).to_le_bytes());
    d
}

/// Raw SGL descriptor at SQE dword `dw`.
fn sgl_desc(sqe: &[u32], dw: usize) -> HsmResult<[u8; 16]> {
    let words = sqe.get(dw..dw + 4).ok_or(HsmError::UnsupportedCmd)?;
    let mut d = [0u8; 16];
    for (b, w) in d.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *b = w.to_le_bytes();
    }
    Ok(d)
}

/// Constant-time equality of two equal-length secrets.
fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The SQE fields every bulk path needs.
struct HostIo {
    op: BcpOp,
    session_id: u16,
    len: usize,
    src: [u8; 16],
    dst: [u8; 16],
    if_sel: u8,
}

impl HostIo {
    fn request<'a>(&'a self, cipher: HostCipher<'a>) -> HostRequest<'a> {
        HostRequest {
            op: self.op,
            cipher,
            len: self.len,
            src: &self.src,
            dst: &self.dst,
            if_sel: self.if_sel,
        }
    }
}

/// A GCM IO's state around its engine command.
struct GcmIo<'p> {
    gcm: &'p GcmParams,
    iv: [u8; 12],
    approved: bool,
    /// Whether the engine's tag needs correcting (see the module docs).
    fix: bool,
    f: Fix,
}

impl UnoHsmPal {
    /// Services a host bulk IO on the BCP and writes its CQE.
    pub(crate) async fn bulk_bcp_crypt(&self, io: &mut UnoHsmIo) -> HsmResult<()> {
        let sqe = BulkSqe::parse(io.sqe())?;
        let host = HostIo {
            op: match sqe.dir {
                BulkDir::Encrypt => BcpOp::Encrypt,
                BulkDir::Decrypt => BcpOp::Decrypt,
            },
            session_id: sqe.session_id,
            len: sqe.src_len as usize,
            src: sgl_desc(io.sqe(), SRC_SGL_DW)?,
            dst: sgl_desc(io.sqe(), DST_SGL_DW)?,
            if_sel: crate::pal::pfn_to_axi_id(u8::from(io.pid())).ok_or(HsmError::InvalidArg)?,
        };
        if host.len != 0 {
            sgl_xfer_len(&host.src, host.len)?;
            sgl_xfer_len(&host.dst, host.len)?;
        }
        // The PAL stamps the SQ id when it completes the IO.
        let mut cqe = BulkCqe::success(&sqe, 0);
        let encrypt = host.op == BcpOp::Encrypt;
        let mut s = Scratch::new(io)?;
        let iv;

        let (cipher, gcm) = match &sqe.params {
            BulkParams::Xts(xts) => {
                const XTS: &[HsmVaultKeyKind] = &[HsmVaultKeyKind::AesXtsBulk256];
                let (key1, _) = bulk_vault_key(io, xts.key_id1, host.session_id, XTS)?;
                let (key2, _) = bulk_vault_key(io, xts.key_id2, host.session_id, XTS)?;
                if constant_time_eq_slice(key1, key2) {
                    return Err(HsmError::KeyStructuralValidationFailed);
                }
                let dul = match xts.dul {
                    XtsDul::Full => 0,
                    XtsDul::B512 => 1,
                    XtsDul::B4096 => 2,
                    XtsDul::B8192 => 3,
                };
                let cipher = HostCipher::Xts {
                    key1,
                    key2,
                    tweak: &xts.tweak,
                    dul,
                };
                (cipher, None)
            }
            BulkParams::Gcm(gcm) => {
                const GCM: &[HsmVaultKeyKind] = &[
                    HsmVaultKeyKind::AesGcmBulk256,
                    HsmVaultKeyKind::AesGcmBulk256Unapproved,
                ];
                let (key, kind) = bulk_vault_key(io, gcm.key_id, host.session_id, GCM)?;
                let g = self
                    .bulk_gcm_prepare(io, &host, gcm, key, kind, &mut s)
                    .await?;
                if host.len == 0 {
                    let tag = s.gmac(&g.f)?;
                    return self
                        .bulk_finish(io, &host, Some(&g), tag, &s, &mut cqe)
                        .await;
                }
                iv = g.iv;
                let cipher = HostCipher::Gcm {
                    key,
                    iv: &iv,
                    aad_len: g.f.pad,
                    unpadded_aad_len: gcm.aad_len as usize,
                    // Every decrypt is checked here, not by the engine.
                    tag: &[0; AES_BLOCK_SIZE],
                };
                (cipher, Some(g))
            }
        };

        let done = self.bcp.host(host.request(cipher)).await?;
        let Some(g) = gcm else {
            if !done.ok() {
                return Err(BcpError::CMD_ERROR);
            }
            cqe.fips_approved = true;
            return self
                .bulk_finish(io, &host, None, [0; 16], &s, &mut cqe)
                .await;
        };
        if !(done.ok() || (!encrypt && done.tag_mismatch_only())) {
            return Err(BcpError::CMD_ERROR);
        }
        let tag = if g.fix {
            s.fix_tag(&done.tag, &g.f)?
        } else {
            done.tag
        };
        self.bulk_finish(io, &host, Some(&g), tag, &s, &mut cqe)
            .await
    }

    /// A GCM IO's work before its engine command: the IV, and when the
    /// tag needs correcting, `H`, `E_K(J₀)` and the tail.
    async fn bulk_gcm_prepare<'p>(
        &self,
        io: &UnoHsmIo,
        host: &HostIo,
        gcm: &'p GcmParams,
        key: &HsmDmaBuf,
        kind: HsmVaultKeyKind,
        s: &mut Scratch<'_>,
    ) -> HsmResult<GcmIo<'p>> {
        let approved = kind == HsmVaultKeyKind::AesGcmBulk256;
        let encrypt = host.op == BcpOp::Encrypt;
        let mut iv = gcm.iv;
        if encrypt && approved {
            self.rng_fill_bytes(io, &mut iv)?;
        }
        let aad_len = gcm.aad_len as usize;
        let pad = gcm.aligned_aad_len as usize;
        let text = host.len - pad;
        let tail_len = gcm.tail.map_or(0, |t| usize::from(t.len));
        let f = Fix {
            encrypt,
            pad,
            text,
            tail_len,
            l: len_block(aad_len, text + tail_len),
        };
        // With the AAD already block-aligned and no tail, the engine's tag
        // is GCM's; with no SGL data there is no engine tag.
        let fix = host.len == 0 || pad != aad_len || tail_len != 0;
        if fix {
            s.prepare(&iv, text);
            self.aes_run(AesMode::Ecb, AesOp::Encrypt, key, None, s.ecb_in, s.ecb_out)
                .await?;
        }
        if let Some(t) = &gcm.tail {
            let buf = &mut s.tail_in[..tail_len];
            self.copy_mem_from_host_raw(io, &tail_desc(t.src, tail_len), buf, false)
                .await?;
            s.crypt_tail(tail_len);
        }
        Ok(GcmIo {
            gcm,
            iv,
            approved,
            fix,
            f,
        })
    }

    /// A bulk IO's last step: for GCM (`g`) the decrypt check, the tail
    /// and the tag; then the CQE.
    async fn bulk_finish(
        &self,
        io: &mut UnoHsmIo,
        host: &HostIo,
        g: Option<&GcmIo<'_>>,
        tag: Block,
        s: &Scratch<'_>,
        cqe: &mut BulkCqe,
    ) -> HsmResult<()> {
        let Some(g) = g else {
            return cqe.write(io.cqe());
        };
        if !g.f.encrypt && !constant_time_eq(&tag, &g.gcm.tag) {
            if g.f.text != 0 {
                // Best effort: wipe the plaintext the engine wrote.
                let _ = self.zero_host_sgl(io, &host.dst, host.len).await;
            }
            return Err(HsmError::AesGcmDecryptTagDoesNotMatch);
        }
        if let Some(t) = &g.gcm.tail {
            let buf = &s.tail_out[..g.f.tail_len];
            self.copy_to_host_sgl(io, buf, &tail_desc(t.dst, g.f.tail_len))
                .await?;
        }
        if g.f.encrypt {
            cqe.tag = tag;
        }
        cqe.iv = g.iv;
        cqe.fips_approved = g.approved;
        cqe.write(io.cqe())
    }
}
