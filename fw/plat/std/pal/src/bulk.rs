// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmBulkCrypto`] implementation for the standard PAL.
//!
//! Bulk keys keep their AES-256 material in the partition vault, and the
//! host-visible bulk key id is the vault key id itself. Bulk IOs are
//! serviced in software: the SQE's single source / destination buffers
//! are copied in, run through the AES driver and copied back out.
//!
//! AES-GCM IV policy:
//!
//! | Kind | Encrypt IV | Decrypt IV | Service indicator |
//! |---|---|---|---|
//! | `AesGcmBulk256` | HSM-generated | host | approved |
//! | `AesGcmBulk256Unapproved` | host | host | not approved |

use tsra_fw_hsm_bulk::*;
use zeroize::Zeroizing;

use super::*;

/// AES-256 bulk key length in bytes.
const BULK_KEY_LEN: usize = 32;

/// True for the AES bulk (GCM / XTS) vault kinds.
pub(crate) fn is_bulk_kind(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256
            | HsmVaultKeyKind::AesGcmBulk256Unapproved
            | HsmVaultKeyKind::AesXtsBulk256
    )
}

impl HsmBulkCrypto for StdHsmPal {
    async fn bulk_key_create(
        &self,
        io: &StdHsmIo,
        key: &HsmDmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<(HsmKeyId, u16)> {
        if !is_bulk_kind(kind) {
            return Err(HsmError::InvalidKeyType);
        }
        if key.len() != BULK_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }
        let key_id = self.vault_store(io, key, kind, session_id, attrs)?;
        Ok((key_id, u16::from(key_id)))
    }

    fn bulk_key_id(&self, io: &StdHsmIo, key_id: HsmKeyId) -> HsmResult<u16> {
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return Err(HsmError::UnsupportedKeyType);
        }
        Ok(u16::from(key_id))
    }

    async fn bulk_crypt(&self, io: &mut StdHsmIo) -> HsmResult<()> {
        let sqe = BulkSqe::parse(io.sqe())?;
        let mut cqe = BulkCqe::success(&sqe, io.qid);
        match &sqe.params {
            BulkParams::Gcm(gcm) => self.bulk_gcm(io, &sqe, gcm, &mut cqe).await?,
            BulkParams::Xts(xts) => {
                self.bulk_xts(io, &sqe, xts).await?;
                cqe.fips_approved = true;
            }
        }
        cqe.write(io.cqe())
    }
}

impl StdHsmPal {
    /// Copies a bulk key's material out of the vault.
    ///
    /// Checks that `bulk_id` names a live key of an `accept`ed kind and,
    /// for a session-bound key, that `session_id` is the session it is
    /// bound to.
    ///
    /// # Errors
    /// - [`HsmError::KeyNotFound`] — no such key.
    /// - [`HsmError::InvalidKeyType`] — wrong kind.
    /// - [`HsmError::SessionNotFound`] — session mismatch.
    fn bulk_key(
        &self,
        io: &StdHsmIo,
        bulk_id: u32,
        session_id: u16,
        accept: impl Fn(HsmVaultKeyKind) -> bool,
    ) -> HsmResult<(Zeroizing<Vec<u8>>, HsmVaultKeyKind)> {
        let key_id = HsmKeyId::from(u16::try_from(bulk_id).map_err(|_| HsmError::KeyNotFound)?);
        let entry = self.active_part(io.pid())?;
        let kind = entry.vault.key_kind(key_id)?;
        if !accept(kind) {
            return Err(HsmError::InvalidKeyType);
        }
        if let Some(bound) = entry.vault.key_session_binding(key_id)? {
            let current = entry
                .session_table
                .physical_id(HsmSessId::from(session_id))
                .ok();
            if current != Some(bound) {
                return Err(HsmError::SessionNotFound);
            }
        }
        Ok((Zeroizing::new(entry.vault.key(key_id)?.to_vec()), kind))
    }

    /// Reads `len` bytes of host memory at `addr`.
    fn bulk_read(&self, addr: u64, len: usize) -> HsmResult<Zeroizing<Vec<u8>>> {
        let mut buf = Zeroizing::new(vec![0u8; len]);
        if len > 0 {
            // SAFETY: the std host passes in-process buffers of at least the
            // SQE's lengths; null addresses are rejected by `dma_addr`.
            unsafe { self.gdma.copy_mem_from_host(dma_addr(addr)?, &mut buf) };
        }
        Ok(buf)
    }

    /// Writes `data` to host memory at `addr`.
    fn bulk_write(&self, data: &[u8], addr: u64) -> HsmResult<()> {
        if !data.is_empty() {
            // SAFETY: as in `bulk_read`.
            unsafe { self.gdma.copy_mem_to_host(data, dma_addr(addr)?) };
        }
        Ok(())
    }

    /// Runs a bulk AES-GCM IO and fills the CQE's tag, IV and service
    /// indicator.
    async fn bulk_gcm(
        &self,
        io: &StdHsmIo,
        sqe: &BulkSqe,
        gcm: &GcmParams,
        cqe: &mut BulkCqe,
    ) -> HsmResult<()> {
        let (key, kind) = self.bulk_key(io, gcm.key_id, sqe.session_id, |k| {
            matches!(
                k,
                HsmVaultKeyKind::AesGcmBulk256 | HsmVaultKeyKind::AesGcmBulk256Unapproved
            )
        })?;
        let approved = kind == HsmVaultKeyKind::AesGcmBulk256;

        let aligned = gcm.aligned_aad_len as usize;
        let src = self.bulk_read(sqe.src_addr, sqe.src_len as usize)?;
        let mut input = Zeroizing::new(src[aligned..].to_vec());
        if let Some(tail) = &gcm.tail {
            input.extend_from_slice(&self.bulk_read(tail.src, usize::from(tail.len))?);
        }
        let aad = (gcm.aad_len > 0).then(|| &src[..gcm.aad_len as usize]);

        let mut output = Zeroizing::new(vec![0u8; input.len()]);
        let mut iv = gcm.iv;
        match sqe.dir {
            BulkDir::Encrypt => {
                if approved {
                    self.rng_fill_bytes(io, &mut iv)?;
                }
                self.aes
                    .gcm_encrypt(&key, &iv, aad, &input, &mut output, &mut cqe.tag)
                    .await?;
            }
            BulkDir::Decrypt => {
                self.aes
                    .gcm_decrypt(&key, &iv, aad, &gcm.tag, &input, &mut output)
                    .await?;
            }
        }

        let sgl_len = input.len() - gcm.tail.map_or(0, |t| usize::from(t.len));
        let mut dst = Zeroizing::new(Vec::with_capacity(sqe.dst_len as usize));
        dst.extend_from_slice(&src[..aligned]);
        dst.extend_from_slice(&output[..sgl_len]);
        self.bulk_write(&dst, sqe.dst_addr)?;
        if let Some(tail) = &gcm.tail {
            self.bulk_write(&output[sgl_len..], tail.dst)?;
        }

        cqe.iv = iv;
        cqe.fips_approved = approved;
        Ok(())
    }

    /// Runs a bulk AES-XTS IO.
    async fn bulk_xts(&self, io: &StdHsmIo, sqe: &BulkSqe, xts: &XtsParams) -> HsmResult<()> {
        let is_xts = |k| k == HsmVaultKeyKind::AesXtsBulk256;
        let (key1, _) = self.bulk_key(io, xts.key_id1, sqe.session_id, is_xts)?;
        let (key2, _) = self.bulk_key(io, xts.key_id2, sqe.session_id, is_xts)?;
        if ct_eq(&key1, &key2) {
            return Err(HsmError::KeyStructuralValidationFailed);
        }

        let mut data = self.bulk_read(sqe.src_addr, sqe.src_len as usize)?;
        let dul = xts.dul.len(sqe.src_len) as usize;
        self.aes
            .xts_crypt(
                &key1,
                &key2,
                sqe.dir == BulkDir::Encrypt,
                xts.tweak,
                dul,
                &mut data,
            )
            .await?;
        self.bulk_write(&data, sqe.dst_addr)
    }
}

/// Splits a host address, rejecting null.
fn dma_addr(addr: u64) -> HsmResult<HsmDmaAddr> {
    if addr == 0 {
        return Err(HsmError::IoChannelInvalidBufferDescriptor);
    }
    Ok(HsmDmaAddr {
        lo: addr as u32,
        hi: (addr >> 32) as u32,
    })
}

/// Constant-time equality of two equal-length secrets.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PID: u8 = 0;

    async fn setup() -> StdHsmPal {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        pal.part_alloc_internal(PID, 0b11).await.unwrap();
        pal
    }

    fn bulk_io(sqe: RawBulkSqe) -> StdHsmIo {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let req = HsmIoRequest {
            pid: HsmPartId::from(PID),
            qid: 0,
            qidx: 0,
            kind: HsmIoKind::Bulk,
            sqe,
            tx,
        };
        StdHsmIo::new(req, 0)
    }

    fn add_key(
        pal: &StdHsmPal,
        key: &[u8; 32],
        kind: HsmVaultKeyKind,
        session: Option<HsmKeyId>,
    ) -> u32 {
        let entry = pal.active_part_mut(HsmPartId::from(PID)).unwrap();
        let id = entry
            .vault
            .create(key, kind, session, HsmVaultKeyAttrs::new())
            .unwrap();
        u32::from(u16::from(id))
    }

    fn sqe(dir: BulkDir, src: &[u8], dst: &mut [u8], params: BulkParams) -> RawBulkSqe {
        BulkSqe {
            dir,
            cid: 7,
            session_id: 0,
            short_app_id: 0,
            src_len: src.len() as u32,
            src_addr: src.as_ptr() as u64,
            dst_len: dst.len() as u32,
            dst_addr: dst.as_mut_ptr() as u64,
            params,
        }
        .encode()
    }

    fn cqe(io: &mut StdHsmIo) -> BulkCqe {
        let raw: &RawBulkCqe = (&*io.cqe()).try_into().unwrap();
        BulkCqe::decode(raw)
    }

    struct GcmIo {
        src: Vec<u8>,
        dst: Vec<u8>,
        tail_src: [u8; 15],
        tail_dst: [u8; 15],
    }

    impl GcmIo {
        /// Lays out `aad` (padded to 32) and `text` as the host does,
        /// splitting a partial final block into the tail.
        fn new(aad: &[u8], text: &[u8]) -> Self {
            let sgl = text.len() / 16 * 16;
            let mut src = aad.to_vec();
            src.resize(aad.len().div_ceil(32) * 32, 0);
            src.extend_from_slice(&text[..sgl]);
            let mut tail_src = [0u8; 15];
            tail_src[..text.len() - sgl].copy_from_slice(&text[sgl..]);
            Self {
                dst: vec![0; src.len()],
                src,
                tail_src,
                tail_dst: [0; 15],
            }
        }

        fn entry(
            &mut self,
            dir: BulkDir,
            key_id: u32,
            aad_len: usize,
            text_len: usize,
            iv: [u8; 12],
            tag: [u8; 16],
        ) -> RawBulkSqe {
            let tail_len = (text_len % 16) as u8;
            let gcm = GcmParams {
                key_id,
                aad_len: aad_len as u32,
                aligned_aad_len: (aad_len.div_ceil(32) * 32) as u32,
                tag,
                iv,
                tail: (tail_len > 0).then_some(GcmTail {
                    len: tail_len,
                    src: self.tail_src.as_ptr() as u64,
                    dst: self.tail_dst.as_mut_ptr() as u64,
                }),
            };
            sqe(dir, &self.src, &mut self.dst, BulkParams::Gcm(gcm))
        }

        /// Output text: the SGL part after the AAD region, then the tail.
        fn output(&self, aad_len: usize, text_len: usize) -> Vec<u8> {
            let mut out = self.dst[aad_len.div_ceil(32) * 32..].to_vec();
            out.extend_from_slice(&self.tail_dst[..text_len % 16]);
            out
        }
    }

    #[tokio::test]
    async fn gcm_unapproved_round_trips_with_aad_and_tail() {
        let pal = setup().await;
        let key = [0x5au8; 32];
        let kid = add_key(&pal, &key, HsmVaultKeyKind::AesGcmBulk256Unapproved, None);
        let aad: Vec<u8> = (0..20u8).collect();
        let pt: Vec<u8> = (0..37u8).map(|b| b.wrapping_mul(3)).collect();
        let iv = [0x11u8; 12];

        let mut enc = GcmIo::new(&aad, &pt);
        let mut io = bulk_io(enc.entry(BulkDir::Encrypt, kid, aad.len(), pt.len(), iv, [0; 16]));
        pal.bulk_crypt(&mut io).await.unwrap();
        let c = cqe(&mut io);
        assert!(c.status.is_success());
        assert_eq!((c.cid, c.iv, c.fips_approved), (7, iv, false));
        assert_eq!((c.data_len, c.tail_len), (enc.src.len() as u32, 5));
        assert_eq!(enc.dst[..aad.len()], aad[..]);

        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; 16];
        pal.aes
            .gcm_encrypt(&key, &iv, Some(&aad), &pt, &mut ct, &mut tag)
            .await
            .unwrap();
        assert_eq!(enc.output(aad.len(), pt.len()), ct);
        assert_eq!(c.tag, tag);

        let mut dec = GcmIo::new(&aad, &ct);
        let mut io = bulk_io(dec.entry(BulkDir::Decrypt, kid, aad.len(), ct.len(), iv, tag));
        pal.bulk_crypt(&mut io).await.unwrap();
        assert!(cqe(&mut io).status.is_success());
        assert_eq!(dec.output(aad.len(), pt.len()), pt);

        tag[0] ^= 1;
        let mut io = bulk_io(dec.entry(BulkDir::Decrypt, kid, aad.len(), ct.len(), iv, tag));
        assert_eq!(
            pal.bulk_crypt(&mut io).await,
            Err(HsmError::AesGcmDecryptTagDoesNotMatch)
        );
    }

    #[tokio::test]
    async fn gcm_approved_uses_hsm_iv() {
        let pal = setup().await;
        let kid = add_key(&pal, &[0x6bu8; 32], HsmVaultKeyKind::AesGcmBulk256, None);
        let pt = [0x42u8; 32];

        let mut enc = GcmIo::new(&[], &pt);
        let mut io = bulk_io(enc.entry(BulkDir::Encrypt, kid, 0, pt.len(), [0; 12], [0; 16]));
        pal.bulk_crypt(&mut io).await.unwrap();
        let c = cqe(&mut io);
        assert!(c.fips_approved);
        assert_ne!(c.iv, [0; 12]);

        let ct = enc.output(0, pt.len());
        let mut dec = GcmIo::new(&[], &ct);
        let mut io = bulk_io(dec.entry(BulkDir::Decrypt, kid, 0, ct.len(), c.iv, c.tag));
        pal.bulk_crypt(&mut io).await.unwrap();
        assert!(cqe(&mut io).fips_approved);
        assert_eq!(dec.output(0, pt.len()), pt);
    }

    fn xts_entry(
        dir: BulkDir,
        src: &[u8],
        dst: &mut [u8],
        key_id1: u32,
        key_id2: u32,
        dul: XtsDul,
        tweak: u64,
    ) -> RawBulkSqe {
        let xts = XtsParams {
            dul,
            key_id1,
            key_id2,
            tweak: u128::from(tweak).to_le_bytes(),
        };
        sqe(dir, src, dst, BulkParams::Xts(xts))
    }

    #[tokio::test]
    async fn xts_round_trips_and_matches_driver() {
        let pal = setup().await;
        let (k1, k2) = ([0x01u8; 32], [0x02u8; 32]);
        let id1 = add_key(&pal, &k1, HsmVaultKeyKind::AesXtsBulk256, None);
        let id2 = add_key(&pal, &k2, HsmVaultKeyKind::AesXtsBulk256, None);
        let pt: Vec<u8> = (0..1024u32).map(|i| (i * 7) as u8).collect();

        let mut ct = vec![0u8; pt.len()];
        let mut io = bulk_io(xts_entry(
            BulkDir::Encrypt,
            &pt,
            &mut ct,
            id1,
            id2,
            XtsDul::B512,
            9,
        ));
        pal.bulk_crypt(&mut io).await.unwrap();
        let c = cqe(&mut io);
        assert!(c.status.is_success() && c.fips_approved);
        assert_eq!((c.tag, c.iv, c.data_len), ([0; 16], [0; 12], 1024));

        let mut expect = pt.clone();
        let tweak = u128::from(9u64).to_le_bytes();
        pal.aes
            .xts_crypt(&k1, &k2, true, tweak, 512, &mut expect)
            .await
            .unwrap();
        assert_eq!(ct, expect);

        let mut out = vec![0u8; pt.len()];
        let mut io = bulk_io(xts_entry(
            BulkDir::Decrypt,
            &ct,
            &mut out,
            id1,
            id2,
            XtsDul::B512,
            9,
        ));
        pal.bulk_crypt(&mut io).await.unwrap();
        assert_eq!(out, pt);
    }

    #[tokio::test]
    async fn rejects_bad_keys() {
        let pal = setup().await;
        let xts = add_key(&pal, &[1; 32], HsmVaultKeyKind::AesXtsBulk256, None);
        let xts_same = add_key(&pal, &[1; 32], HsmVaultKeyKind::AesXtsBulk256, None);
        let gcm = add_key(&pal, &[2; 32], HsmVaultKeyKind::AesGcmBulk256, None);
        let bound = add_key(
            &pal,
            &[3; 32],
            HsmVaultKeyKind::AesXtsBulk256,
            Some(HsmKeyId::from(0x7777u16)),
        );
        let src = [0u8; 32];
        let mut dst = [0u8; 32];

        for (k1, k2, err) in [
            (xts, xts_same, HsmError::KeyStructuralValidationFailed),
            (xts, xts, HsmError::KeyStructuralValidationFailed),
            (xts, gcm, HsmError::InvalidKeyType),
            (xts, 0x1_0000, HsmError::KeyNotFound),
            (xts, 0x0fff, HsmError::KeyNotFound),
            (bound, xts, HsmError::SessionNotFound),
        ] {
            let mut io = bulk_io(xts_entry(
                BulkDir::Encrypt,
                &src,
                &mut dst,
                k1,
                k2,
                XtsDul::Full,
                0,
            ));
            assert_eq!(pal.bulk_crypt(&mut io).await, Err(err), "{k1} {k2}");
        }

        let mut enc = GcmIo::new(&[], &src);
        let mut io = bulk_io(enc.entry(BulkDir::Encrypt, xts, 0, src.len(), [0; 12], [0; 16]));
        assert_eq!(pal.bulk_crypt(&mut io).await, Err(HsmError::InvalidKeyType));
    }

    #[tokio::test]
    async fn rejects_null_buffer() {
        let pal = setup().await;
        let id1 = add_key(&pal, &[1; 32], HsmVaultKeyKind::AesXtsBulk256, None);
        let id2 = add_key(&pal, &[2; 32], HsmVaultKeyKind::AesXtsBulk256, None);
        let sqe = BulkSqe {
            dir: BulkDir::Encrypt,
            cid: 1,
            session_id: 0,
            short_app_id: 0,
            src_len: 16,
            src_addr: 0,
            dst_len: 16,
            dst_addr: 0,
            params: BulkParams::Xts(XtsParams {
                dul: XtsDul::Full,
                key_id1: id1,
                key_id2: id2,
                tweak: [0; 16],
            }),
        }
        .encode();
        let mut io = bulk_io(sqe);
        assert_eq!(
            pal.bulk_crypt(&mut io).await,
            Err(HsmError::IoChannelInvalidBufferDescriptor)
        );
    }
}
