// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHash`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] enum
//! to [`tsra_crypto::HashAlgo`] and forwards one-shot hashing to the
//! [`StdHash`](crate::drivers::hash::StdHash) driver.
//!
//! Multi-step hashing consumes input before its storage is reused for output.

use tsra_crypto::HashAlgo;
use tsra_crypto::HashOpContext;
use tsra_crypto::HashStreamingOp;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmGdmaController;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use super::*;

const OOB_HASH_CHUNK_LEN: usize = 1024;
const OOB_SGL_DATA_BLOCK: u8 = 0;

fn validate_oob_hash_desc(desc: &[u8; 16], expected_len: usize) -> HsmResult<u64> {
    let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]) as usize;
    let addr = u64::from_le_bytes([
        desc[0], desc[1], desc[2], desc[3], desc[4], desc[5], desc[6], desc[7],
    ]);
    if len != expected_len
        || desc[12..15].iter().any(|&byte| byte != 0)
        || desc[15] != OOB_SGL_DATA_BLOCK
    {
        return Err(HsmError::InvalidArg);
    }
    if expected_len != 0 {
        if addr == 0 {
            return Err(HsmError::InvalidArg);
        }
        let host_addr = usize::try_from(addr).map_err(|_| HsmError::InvalidArg)?;
        host_addr
            .checked_add(expected_len)
            .ok_or(HsmError::InvalidArg)?;
    }
    Ok(addr)
}

fn oob_hash_chunk_desc(mut desc: [u8; 16], addr: u64, len: usize) -> HsmResult<[u8; 16]> {
    let len = u32::try_from(len).map_err(|_| HsmError::InvalidArg)?;
    desc[..8].copy_from_slice(&addr.to_le_bytes());
    desc[8..12].copy_from_slice(&len.to_le_bytes());
    Ok(desc)
}

/// The OpenSSL hash for `algo`; fixed-length algorithms only, so the HMAC,
/// KDF and RSA paths that share it reject SHAKE. SHA-3 is not supported yet.
pub(crate) fn to_hash_algo(algo: HsmHashAlgo) -> HsmResult<HashAlgo> {
    match algo {
        HsmHashAlgo::Sha1 => Ok(HashAlgo::sha1()),
        HsmHashAlgo::Sha256 => Ok(HashAlgo::sha256()),
        HsmHashAlgo::Sha384 => Ok(HashAlgo::sha384()),
        HsmHashAlgo::Sha512 => Ok(HashAlgo::sha512()),
        HsmHashAlgo::Sha3_256
        | HsmHashAlgo::Sha3_384
        | HsmHashAlgo::Sha3_512
        | HsmHashAlgo::Shake128(_)
        | HsmHashAlgo::Shake256(_) => Err(HsmError::UnsupportedDigestHashAlgorithm),
    }
}

/// The OpenSSL hash for [`HsmHash`]: [`to_hash_algo`] plus the SHAKE XOFs,
/// with their output length.
fn digest_algo(algo: HsmHashAlgo) -> HsmResult<HashAlgo> {
    match algo {
        HsmHashAlgo::Shake128(len) => Ok(HashAlgo::shake128(len.into())),
        HsmHashAlgo::Shake256(len) => Ok(HashAlgo::shake256(len.into())),
        _ => to_hash_algo(algo),
    }
}

pub struct StdHashCtx<'a> {
    algo: HsmHashAlgo,
    state: Option<<HashAlgo as HashStreamingOp>::Context>,
    _storage: &'a mut HsmDmaBuf,
}

impl HsmHash for StdHsmPal {
    type HashCtx<'a> = StdHashCtx<'a>;

    async fn hash(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        data: &HsmDmaBuf,
        form: HsmDigestForm,
        digest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let hash_algo = digest_algo(algo)?;
        let digest_len = algo.digest_len();
        let Some(digest) = digest else {
            return Ok(digest_len);
        };
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        self.hash
            .hash(hash_algo, data, &mut digest[..digest_len])
            .await?;
        if form.reversed(Self::BYTE_ORDER) {
            digest[..digest_len].reverse();
        }
        Ok(digest_len)
    }

    async fn hash_oob(
        &self,
        io: &StdHsmIo,
        algo: HsmHashAlgo,
        expected_len: usize,
        index: usize,
        form: HsmDigestForm,
        digest: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let state_len = self.hash_state_size(algo)?;
        let digest_len = algo.digest_len();
        if expected_len > 8192 || digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }

        let root_desc = if expected_len == 0 {
            None
        } else {
            let desc = self.oob_desc(io, index).await?;
            let addr = validate_oob_hash_desc(&desc, expected_len)?;
            Some((desc, addr))
        };

        self.alloc_scoped_async(io, async |scope| -> HsmResult<usize> {
            let state = scope.dma_alloc_zeroed(state_len)?;
            let staging = scope.dma_alloc_zeroed(OOB_HASH_CHUNK_LEN)?;
            let mut ctx = self.hash_begin(io, algo, state)?;
            let result = async {
                if let Some((root, base_addr)) = root_desc {
                    let mut offset = 0usize;
                    while offset < expected_len {
                        let chunk_len = (expected_len - offset).min(OOB_HASH_CHUNK_LEN);
                        let chunk_addr = base_addr
                            .checked_add(offset as u64)
                            .ok_or(HsmError::InvalidArg)?;
                        let chunk_desc = oob_hash_chunk_desc(root, chunk_addr, chunk_len)?;
                        self.copy_mem_from_host_raw(
                            io,
                            &chunk_desc,
                            &mut staging[..chunk_len],
                            false,
                        )
                        .await?;
                        self.hash_continue(io, &mut ctx, &staging[..chunk_len])
                            .await?;
                        offset += chunk_len;
                    }
                }
                self.hash_finish(io, &mut ctx, form, Some(digest)).await
            }
            .await;
            drop(ctx);
            result
        })
        .await
    }

    fn hash_state_size(&self, algo: HsmHashAlgo) -> HsmResult<usize> {
        digest_algo(algo)?;
        Ok(0)
    }

    fn hash_begin<'a>(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        storage: &'a mut HsmDmaBuf,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        let hash_algo = digest_algo(algo)?;
        let state = hash_algo.hash_init().map_err(|_| HsmError::ShaError)?;
        Ok(StdHashCtx {
            algo,
            state: Some(state),
            _storage: storage,
        })
    }

    async fn hash_continue(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HashCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()> {
        ctx.state
            .as_mut()
            .ok_or(HsmError::InvalidArg)?
            .update(data)
            .map_err(|_| HsmError::ShaError)
    }

    async fn hash_finish(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HashCtx<'_>,
        form: HsmDigestForm,
        digest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        if ctx.state.is_none() {
            return Err(HsmError::InvalidArg);
        }
        let digest_len = ctx.algo.digest_len();
        let Some(digest) = digest else {
            return Ok(digest_len);
        };
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        let mut state = ctx.state.take().ok_or(HsmError::InvalidArg)?;
        state
            .finish(Some(&mut digest[..digest_len]))
            .map_err(|_| HsmError::ShaError)?;
        if form.reversed(Self::BYTE_ORDER) {
            digest[..digest_len].reverse();
        }
        Ok(digest_len)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::num::NonZeroUsize;

    use tokio::runtime::Handle;

    use super::to_hash_algo;
    use super::*;
    use crate::drivers::hash::StdHash;
    use crate::worker::WorkerPool;
    use crate::HsmIoRequest;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    #[test]
    fn oob_hash_descriptor_checks_length_format_and_address_range() {
        let mut desc = [0u8; 16];
        desc[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        desc[8..12].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(validate_oob_hash_desc(&desc, 8), Ok(0x1000));

        assert_eq!(validate_oob_hash_desc(&desc, 7), Err(HsmError::InvalidArg));
        desc[12] = 1;
        assert_eq!(validate_oob_hash_desc(&desc, 8), Err(HsmError::InvalidArg));
        desc[12] = 0;
        desc[15] = 1;
        assert_eq!(validate_oob_hash_desc(&desc, 8), Err(HsmError::InvalidArg));
        desc[15] = 0;
        desc[..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(validate_oob_hash_desc(&desc, 8), Err(HsmError::InvalidArg));
        desc[..8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
        assert_eq!(validate_oob_hash_desc(&desc, 8), Err(HsmError::InvalidArg));
    }

    /// NIST FIPS 180-4 "abc" digests in big-endian (standard) byte order.
    const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    /// Hashes `msg` through the PAL with the requested digest form and returns
    /// the digest bytes.
    async fn pal_hash(algo: HsmHashAlgo, msg: &[u8], form: HsmDigestForm) -> Vec<u8> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        let digest_len = algo.digest_len();
        let data = pal.dma_alloc(&io, msg.len()).unwrap();
        data.copy_from_slice(msg);
        let digest = pal.dma_alloc(&io, digest_len).unwrap();

        pal.hash(&io, algo, data, form, Some(digest)).await.unwrap();
        digest[..digest_len].to_vec()
    }

    /// Reference big-endian digest computed by the OpenSSL-backed driver.
    async fn openssl_digest(algo: HsmHashAlgo, msg: &[u8]) -> Vec<u8> {
        let driver = StdHash::new(WorkerPool::new(Handle::current()));
        let mut digest = vec![0u8; algo.digest_len()];
        driver
            .hash(to_hash_algo(algo).unwrap(), msg, &mut digest)
            .await
            .unwrap();
        digest
    }

    /// Deterministic multi-block message used for reference-based checks.
    fn multiblock_msg() -> Vec<u8> {
        (0..200u32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3) as u8)
            .collect()
    }

    fn oob_io(desc: Option<&[u8; 16]>) -> StdHsmIo {
        let mut sqe: crate::cmd::RawSqe = [0; crate::cmd::SQE_DWORDS];
        if let Some(desc) = desc {
            let addr = desc.as_ptr() as usize as u64;
            let oob_addr_index = if crate::cmd::SQE_DWORDS == 16 { 13 } else { 2 };
            sqe[oob_addr_index] = addr as u32;
            sqe[oob_addr_index + 1] = (addr >> 32) as u32;
            sqe[oob_addr_index + 2] = 16;
        }
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let request = HsmIoRequest::cmd(HsmPartId::from(0u8), 0, 0, sqe, reply_tx);
        StdHsmIo::new(request, 0)
    }

    fn sgl_desc(message: &[u8], descriptor_len: usize) -> [u8; 16] {
        let mut desc = [0u8; 16];
        desc[..8].copy_from_slice(&(message.as_ptr() as usize as u64).to_le_bytes());
        desc[8..12].copy_from_slice(&(descriptor_len as u32).to_le_bytes());
        desc
    }

    async fn pal_hash_oob(
        algo: HsmHashAlgo,
        _message: &[u8],
        message_index: usize,
        message_len: usize,
        desc: Option<&[u8; 16]>,
        form: HsmDigestForm,
    ) -> HsmResult<Vec<u8>> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let io = oob_io(desc);
        let digest = pal.dma_alloc(&io, algo.digest_len())?;
        let len = pal
            .hash_oob(&io, algo, message_len, message_index, form, digest)
            .await?;
        Ok(digest[..len].to_vec())
    }

    /// Verifies the PAL hash of `msg` equals `expected_be` in standard form
    /// and the platform's operand form.
    async fn verify_endianness(algo: HsmHashAlgo, msg: &[u8], expected_be: &[u8]) {
        let standard = pal_hash(algo, msg, HsmDigestForm::Standard).await;
        assert_eq!(standard, expected_be);

        let mut expected_operand = expected_be.to_vec();
        if HsmDigestForm::Operand.reversed(StdHsmPal::BYTE_ORDER) {
            expected_operand.reverse();
        }
        let operand = pal_hash(algo, msg, HsmDigestForm::Operand).await;
        assert_eq!(operand, expected_operand);
    }

    #[tokio::test]
    async fn sha1_validate_nist() {
        verify_endianness(HsmHashAlgo::Sha1, b"abc", &hex::decode(SHA1_ABC).unwrap()).await;
    }

    #[tokio::test]
    async fn sha256_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha256,
            b"abc",
            &hex::decode(SHA256_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha384_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha384,
            b"abc",
            &hex::decode(SHA384_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha512_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha512,
            b"abc",
            &hex::decode(SHA512_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha1_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha1, &msg).await;
        verify_endianness(HsmHashAlgo::Sha1, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha256_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha256, &msg).await;
        verify_endianness(HsmHashAlgo::Sha256, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha384_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha384, &msg).await;
        verify_endianness(HsmHashAlgo::Sha384, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha512_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha512, &msg).await;
        verify_endianness(HsmHashAlgo::Sha512, &msg, &reference).await;
    }

    #[tokio::test]
    async fn oob_hash_streams_boundary_lengths_in_both_digest_forms() {
        for len in [0, 1023, 1024, 1025, 8192] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let desc = (!msg.is_empty()).then(|| sgl_desc(&msg, msg.len()));
            for algo in [
                HsmHashAlgo::Sha256,
                HsmHashAlgo::Sha384,
                HsmHashAlgo::Sha512,
            ] {
                let expected = openssl_digest(algo, &msg).await;
                for form in [HsmDigestForm::Standard, HsmDigestForm::Operand] {
                    let mut expected_form = expected.clone();
                    if form.reversed(StdHsmPal::BYTE_ORDER) {
                        expected_form.reverse();
                    }
                    assert_eq!(
                        pal_hash_oob(algo, &msg, 0, msg.len(), desc.as_ref(), form)
                            .await
                            .expect("OOB hash"),
                        expected_form,
                        "length {len}, algorithm {algo:?}, form {form:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn oob_hash_rejects_malformed_and_length_mismatched_descriptors() {
        let msg = b"descriptor validation";
        let valid_desc = sgl_desc(msg, msg.len());

        assert_eq!(
            pal_hash_oob(
                HsmHashAlgo::Sha256,
                msg,
                0,
                msg.len(),
                None,
                HsmDigestForm::Standard,
            )
            .await,
            Err(HsmError::InvalidArg)
        );

        let mut bad_reserved = valid_desc;
        bad_reserved[12] = 1;
        assert_eq!(
            pal_hash_oob(
                HsmHashAlgo::Sha256,
                msg,
                0,
                msg.len(),
                Some(&bad_reserved),
                HsmDigestForm::Standard,
            )
            .await,
            Err(HsmError::InvalidArg)
        );

        let short_desc = sgl_desc(msg, msg.len() - 1);
        assert_eq!(
            pal_hash_oob(
                HsmHashAlgo::Sha256,
                msg,
                0,
                msg.len(),
                Some(&short_desc),
                HsmDigestForm::Standard,
            )
            .await,
            Err(HsmError::InvalidArg)
        );

        assert_eq!(
            pal_hash_oob(
                HsmHashAlgo::Sha256,
                msg,
                1,
                msg.len(),
                Some(&valid_desc),
                HsmDigestForm::Standard,
            )
            .await,
            Err(HsmError::InvalidArg)
        );
    }

    #[tokio::test]
    async fn streaming_begin_queries_with_exhausted_dma_and_local_pools() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let dma = pal
            .dma_alloc(&io, crate::buf_pool::DMA_BUF_SIZE)
            .expect("DMA pool");
        let local = pal
            .alloc(&io, crate::buf_pool::NONDMA_BUF_SIZE)
            .expect("local pool");
        dma.fill(0xA5);
        local.fill(0x5A);

        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
            shake128(32),
            shake256(64),
        ] {
            let len = pal
                .hash_state_size(algo)
                .expect("hash query without allocation");
            assert_eq!(len, 0);
            assert_eq!(
                pal.hash(&io, algo, dma, HsmDigestForm::Standard, None)
                    .await
                    .expect("digest query without allocation"),
                algo.digest_len()
            );
            let (storage, data) = dma.split_at_mut(0);
            let mut ctx = pal.hash_begin(&io, algo, storage).expect("begin");
            pal.hash_continue(&io, &mut ctx, data)
                .await
                .expect("update");
            assert_eq!(
                pal.hash_finish(&io, &mut ctx, HsmDigestForm::Standard, None)
                    .await
                    .expect("finish query without allocation"),
                algo.digest_len()
            );
            let hmac = pal.hmac_state_size(algo);
            if algo.is_xof() {
                assert!(matches!(
                    hmac,
                    Err(HsmError::UnsupportedDigestHashAlgorithm)
                ));
            } else {
                let len = hmac.expect("HMAC query without allocation");
                assert_eq!(len, 0);
                assert_eq!(
                    pal.hmac_sign(&io, algo, dma, dma, None)
                        .await
                        .expect("tag query without allocation"),
                    algo.digest_len()
                );
                let (storage, data) = dma.split_at_mut(0);
                let mut ctx = pal
                    .hmac_begin(&io, algo, data, storage)
                    .await
                    .expect("begin");
                pal.hmac_continue(&io, &mut ctx, data)
                    .await
                    .expect("update");
                assert_eq!(
                    pal.hmac_finish(&io, &mut ctx, None).await.expect("query"),
                    algo.digest_len()
                );
                assert_eq!(
                    pal.hmac_finish_into(&io, &mut ctx, None)
                        .await
                        .expect("query"),
                    algo.digest_len()
                );
            }
        }
        for algo in [
            HsmHashAlgo::Sha3_256,
            HsmHashAlgo::Sha3_384,
            HsmHashAlgo::Sha3_512,
        ] {
            assert!(matches!(
                pal.hash_state_size(algo),
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            ));
            assert!(matches!(
                pal.hmac_state_size(algo),
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            ));
            assert!(matches!(
                pal.hash_begin(&io, algo, &mut dma[..16]),
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            ));
            let (key, state) = dma.split_at_mut(260);
            assert!(matches!(
                pal.hmac_begin(&io, algo, key, state).await,
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            ));
        }
        assert!(dma.iter().all(|&b| b == 0xA5));
        assert!(local.iter().all(|&b| b == 0x5A));
        assert!(matches!(
            pal.dma_alloc(&io, 4),
            Err(HsmError::NotEnoughSpace)
        ));
        assert!(matches!(pal.alloc(&io, 4), Err(HsmError::NotEnoughSpace)));
    }

    #[tokio::test]
    async fn hash_output_queries_preserve_streaming_state_and_output_tails() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let data = pal.dma_alloc(&io, 3).expect("message");
        data.copy_from_slice(b"abc");
        let state = pal.dma_alloc(&io, 16).expect("state");
        let output = pal.dma_alloc(&io, 68).expect("output");
        let expected = pal.dma_alloc(&io, 68).expect("reference");

        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
            shake128(32),
            shake256(64),
        ] {
            let len = algo.digest_len();
            for form in [HsmDigestForm::Standard, HsmDigestForm::Operand] {
                expected.fill(0xA5);
                output.fill(0x5A);
                assert_eq!(
                    pal.hash(&io, algo, data, form, Some(&mut output[..len - 1]))
                        .await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0x5A));
                assert_eq!(
                    pal.hash(&io, algo, data, form, Some(expected))
                        .await
                        .expect("one shot"),
                    len
                );
                assert!(expected[len..].iter().all(|&b| b == 0xA5));
                assert_eq!(
                    pal.hash(&io, algo, data, form, Some(&mut output[..len]))
                        .await
                        .expect("exact output"),
                    len
                );
                assert_eq!(&output[..len], &expected[..len]);
                output.fill(0x5A);

                let mut ctx = pal.hash_begin(&io, algo, state).expect("begin");
                for _ in 0..2 {
                    assert_eq!(
                        pal.hash_finish(&io, &mut ctx, form, None)
                            .await
                            .expect("empty query"),
                        len
                    );
                }
                pal.hash_continue(&io, &mut ctx, &data[..1])
                    .await
                    .expect("first update");
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, None)
                        .await
                        .expect("partial query"),
                    len
                );
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, Some(&mut output[..len - 1]))
                        .await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0x5A));
                pal.hash_continue(&io, &mut ctx, &data[1..])
                    .await
                    .expect("update after short output");
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, None)
                        .await
                        .expect("final query"),
                    len
                );
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, Some(output))
                        .await
                        .expect("finish"),
                    len
                );
                assert_eq!(&output[..len], &expected[..len]);
                assert!(output[len..].iter().all(|&b| b == 0x5A));

                output.fill(0xA5);
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, None).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hash_finish(&io, &mut ctx, form, Some(output)).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hash_continue(&io, &mut ctx, data).await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0xA5));
            }
        }
    }

    #[tokio::test]
    async fn hmac_output_queries_retry_and_truncating_finalizers() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&io, 20).expect("key");
        key.fill(0x0B);
        let data = pal.dma_alloc(&io, 8).expect("message");
        data.copy_from_slice(b"Hi There");
        let state = pal.dma_alloc(&io, 16).expect("state");
        let output = pal.dma_alloc(&io, 68).expect("output");
        let expected = pal.dma_alloc(&io, 68).expect("reference");

        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            let len = algo.digest_len();
            expected.fill(0xA5);
            output.fill(0x5A);
            assert_eq!(
                pal.hmac_sign(&io, algo, key, data, Some(&mut output[..len - 1]))
                    .await,
                Err(HsmError::InvalidArg)
            );
            assert!(output.iter().all(|&b| b == 0x5A));
            assert_eq!(
                pal.hmac_sign(&io, algo, key, data, Some(expected))
                    .await
                    .expect("one shot"),
                len
            );
            assert!(expected[len..].iter().all(|&b| b == 0xA5));
            assert_eq!(
                pal.hmac_sign(&io, algo, key, data, Some(&mut output[..len]))
                    .await
                    .expect("exact output"),
                len
            );
            assert_eq!(&output[..len], &expected[..len]);

            for finish in 0..5 {
                output.fill(0x5A);
                let mut ctx = pal.hmac_begin(&io, algo, key, state).await.expect("begin");
                assert_eq!(
                    pal.hmac_finish(&io, &mut ctx, None)
                        .await
                        .expect("empty query"),
                    len
                );
                assert_eq!(
                    pal.hmac_finish_into(&io, &mut ctx, None)
                        .await
                        .expect("empty query"),
                    len
                );
                pal.hmac_continue(&io, &mut ctx, &data[..1])
                    .await
                    .expect("first update");
                for _ in 0..2 {
                    assert_eq!(
                        pal.hmac_finish(&io, &mut ctx, None)
                            .await
                            .expect("partial query"),
                        len
                    );
                    assert_eq!(
                        pal.hmac_finish_into(&io, &mut ctx, None)
                            .await
                            .expect("partial query"),
                        len
                    );
                }
                assert_eq!(
                    pal.hmac_finish(&io, &mut ctx, Some(&mut output[..len - 1]))
                        .await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0x5A));
                pal.hmac_continue(&io, &mut ctx, &data[1..])
                    .await
                    .expect("update after short output");
                let written = match finish {
                    0 => pal
                        .hmac_finish(&io, &mut ctx, Some(output))
                        .await
                        .expect("finish"),
                    1 => pal
                        .hmac_finish_into(&io, &mut ctx, Some(output))
                        .await
                        .expect("finish into"),
                    2 => pal
                        .hmac_finish_into(&io, &mut ctx, Some(&mut output[..len - 1]))
                        .await
                        .expect("truncate"),
                    3 => pal
                        .hmac_finish_into(&io, &mut ctx, Some(&mut output[..0]))
                        .await
                        .expect("empty destination"),
                    _ => {
                        assert!(pal
                            .hmac_finish_verify(&io, ctx, &expected[..len])
                            .await
                            .expect("verify after queries"));
                        continue;
                    }
                };
                assert_eq!(
                    written,
                    match finish {
                        2 => len - 1,
                        3 => 0,
                        _ => len,
                    }
                );
                assert_eq!(&output[..written], &expected[..written]);
                assert!(output[written..].iter().all(|&b| b == 0x5A));
                output.fill(0xA5);
                assert_eq!(
                    pal.hmac_finish(&io, &mut ctx, None).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hmac_finish_into(&io, &mut ctx, None).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hmac_finish(&io, &mut ctx, Some(output)).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hmac_finish_into(&io, &mut ctx, Some(output)).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hmac_continue(&io, &mut ctx, data).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(
                    pal.hmac_finish_verify(&io, ctx, &expected[..len]).await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0xA5));
            }
        }
    }

    #[tokio::test]
    async fn streaming_hmac_uses_caller_storage_and_all_finalizers() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&io, 257).expect("key");
        let data = pal.dma_alloc(&io, 301).expect("message");
        let expected = pal.dma_alloc(&io, 64).expect("reference tag");
        let tag = pal.dma_alloc(&io, 68).expect("tag");
        let state = pal.dma_alloc(&io, 16).expect("state capacity");
        key.fill(0x0B);
        data.fill(0x37);
        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            let len = pal.hmac_state_size(algo).expect("query");
            assert!(state.len() >= len);
            for key_len in [20, 129, 257] {
                pal.hmac_sign(&io, algo, &key[..key_len], data, Some(expected))
                    .await
                    .expect("reference tag");
                for finish in 0..4 {
                    tag.fill(0xA5);
                    state.fill(0x5A);
                    let capacity = if finish % 2 == 0 { len } else { state.len() };
                    let mut ctx = pal
                        .hmac_begin(&io, algo, &key[..key_len], &mut state[..capacity])
                        .await
                        .expect("begin");
                    pal.hmac_continue(&io, &mut ctx, &data[..0])
                        .await
                        .expect("empty update");
                    for start in (0..data.len()).step_by(13) {
                        pal.hmac_continue(
                            &io,
                            &mut ctx,
                            &data[start..(start + 13).min(data.len())],
                        )
                        .await
                        .expect("update");
                    }
                    match finish {
                        0 => {
                            pal.hmac_finish(&io, &mut ctx, Some(tag))
                                .await
                                .expect("finish");
                        }
                        1 => pal
                            .hmac_finish_into(&io, &mut ctx, Some(tag))
                            .await
                            .map(|_| ())
                            .expect("finish into"),
                        _ => {
                            tag[..algo.digest_len()]
                                .copy_from_slice(&expected[..algo.digest_len()]);
                            if finish == 3 {
                                tag[0] ^= 1;
                            }
                            assert_eq!(
                                pal.hmac_finish_verify(&io, ctx, &tag[..algo.digest_len()])
                                    .await
                                    .expect("verify"),
                                finish == 2
                            );
                        }
                    }
                    if finish < 2 {
                        assert_eq!(&tag[..algo.digest_len()], &expected[..algo.digest_len()]);
                    }
                    assert!(tag[algo.digest_len()..].iter().all(|&b| b == 0xA5));
                    assert!(state.iter().all(|&b| b == 0x5A));
                }
            }
        }
    }

    #[tokio::test]
    async fn streaming_contexts_borrow_storage_independently_of_operation_ios() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let storage_io = StdHsmIo::admin(HsmPartId::from(0u8), 3, reply_tx);
        let hash_state = pal.dma_alloc(&storage_io, 16).expect("hash storage");
        let hmac_state = pal.dma_alloc(&storage_io, 16).expect("HMAC storage");
        hash_state.fill(0x5A);
        hmac_state.fill(0xA5);
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let begin_io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let key = pal.dma_alloc(&begin_io, 20).expect("key");
        key.fill(0x0B);
        let mut hash = pal
            .hash_begin(&begin_io, HsmHashAlgo::Sha256, &mut *hash_state)
            .expect("begin hash");
        let mut hmac = pal
            .hmac_begin(&begin_io, HsmHashAlgo::Sha256, key, &mut *hmac_state)
            .await
            .expect("begin HMAC");
        key.fill(0);
        drop(begin_io);

        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let update_io = StdHsmIo::admin(HsmPartId::from(0u8), 1, reply_tx);
        let data = pal.dma_alloc(&update_io, 8).expect("message");
        data.copy_from_slice(b"Hi There");
        pal.hash_continue(&update_io, &mut hash, data)
            .await
            .expect("hash update");
        pal.hmac_continue(&update_io, &mut hmac, data)
            .await
            .expect("HMAC update");
        data.fill(0);
        drop(update_io);

        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let finish_io = StdHsmIo::admin(HsmPartId::from(0u8), 2, reply_tx);
        let out = pal.dma_alloc(&finish_io, 36).expect("digest output");
        out.fill(0xA5);
        pal.hash_finish(&finish_io, &mut hash, HsmDigestForm::Standard, Some(out))
            .await
            .expect("hash finish");
        assert_eq!(
            &out[..32],
            openssl_digest(HsmHashAlgo::Sha256, b"Hi There")
                .await
                .as_slice()
        );
        pal.hmac_finish(&finish_io, &mut hmac, Some(out))
            .await
            .expect("HMAC finish");
        assert_eq!(
            &out[..32],
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .expect("RFC 4231 tag")
                .as_slice()
        );
        assert!(out[32..].iter().all(|&b| b == 0xA5));
        assert!(hash_state.iter().all(|&b| b == 0x5A));
        assert!(hmac_state.iter().all(|&b| b == 0xA5));

        let hash = pal
            .hash_begin(&finish_io, HsmHashAlgo::Sha256, &mut *hash_state)
            .expect("begin hash to abort");
        let hmac = pal
            .hmac_begin(
                &finish_io,
                HsmHashAlgo::Sha256,
                &out[..20],
                &mut *hmac_state,
            )
            .await
            .expect("begin HMAC to abort");
        drop((hash, hmac));

        let mut hash = pal
            .hash_begin(&finish_io, HsmHashAlgo::Sha256, &mut *hash_state)
            .expect("begin hash with short output");
        assert_eq!(
            pal.hash_finish(
                &finish_io,
                &mut hash,
                HsmDigestForm::Standard,
                Some(&mut out[..31])
            )
            .await,
            Err(HsmError::InvalidArg)
        );
        let mut hmac = pal
            .hmac_begin(
                &finish_io,
                HsmHashAlgo::Sha256,
                &out[..20],
                &mut *hmac_state,
            )
            .await
            .expect("begin HMAC with short output");
        assert_eq!(
            pal.hmac_finish(&finish_io, &mut hmac, Some(&mut out[..31]))
                .await,
            Err(HsmError::InvalidArg)
        );
        hash_state.fill(0);
        hmac_state.fill(0);
    }

    #[tokio::test]
    async fn streaming_hash_consumes_fragments_before_output_reuse() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let msg = multiblock_msg();
        let data = pal.dma_alloc(&io, msg.len()).unwrap();
        let digest = pal.dma_alloc(&io, 68).unwrap();
        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            for form in [HsmDigestForm::Standard, HsmDigestForm::Operand] {
                let mut expected = openssl_digest(algo, &msg).await;
                if form.reversed(StdHsmPal::BYTE_ORDER) {
                    expected.reverse();
                }
                data.copy_from_slice(&msg);
                digest.fill(0xA5);
                pal.alloc_scoped_async(&io, async |alloc| {
                    let state_len = pal.hash_state_size(algo)?;
                    let mut ctx = pal.hash_begin(&io, algo, alloc.dma_alloc(state_len)?)?;
                    pal.hash_continue(&io, &mut ctx, &data[..0]).await?;
                    for offset in (0..data.len()).step_by(13) {
                        pal.hash_continue(
                            &io,
                            &mut ctx,
                            &data[offset..(offset + 13).min(data.len())],
                        )
                        .await?;
                    }
                    data.fill(0xE7);
                    pal.hash_finish(&io, &mut ctx, form, Some(digest)).await
                })
                .await
                .unwrap();
                assert_eq!(&digest[..expected.len()], &expected[..]);
                assert!(digest[expected.len()..].iter().all(|&b| b == 0xA5));
            }
        }
        for algo in [HsmHashAlgo::Sha256, shake128(64)] {
            let result = pal
                .alloc_scoped_async(&io, async |alloc| {
                    let state_len = pal.hash_state_size(algo)?;
                    let mut ctx = pal.hash_begin(&io, algo, alloc.dma_alloc(state_len)?)?;
                    pal.hash_finish(
                        &io,
                        &mut ctx,
                        HsmDigestForm::Standard,
                        Some(&mut digest[..algo.digest_len() - 1]),
                    )
                    .await
                })
                .await;
            assert_eq!(result, Err(HsmError::InvalidArg), "{algo:?}");
        }
    }

    fn shake128(len: u16) -> HsmHashAlgo {
        HsmHashAlgo::Shake128(NonZeroU16::new(len).unwrap())
    }

    fn shake256(len: u16) -> HsmHashAlgo {
        HsmHashAlgo::Shake256(NonZeroU16::new(len).unwrap())
    }

    /// Reference SHAKE output computed directly with `tsra_crypto`.
    fn shake_reference(algo: HsmHashAlgo, msg: &[u8]) -> Vec<u8> {
        let len = NonZeroUsize::new(algo.digest_len()).unwrap();
        let mut hash = match algo {
            HsmHashAlgo::Shake128(_) => HashAlgo::shake128(len),
            HsmHashAlgo::Shake256(_) => HashAlgo::shake256(len),
            _ => unreachable!("not a SHAKE algorithm"),
        };
        let mut out = vec![0u8; len.get()];
        tsra_crypto::HashOp::hash(&mut hash, msg, Some(&mut out)).unwrap();
        out
    }

    /// Hashes `msg` through the multi-step API in 13-byte fragments into a
    /// buffer 4 bytes longer than the output, pre-filled with `0xA5`.
    async fn pal_streaming_hash(algo: HsmHashAlgo, msg: &[u8], form: HsmDigestForm) -> Vec<u8> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let data = pal.dma_alloc(&io, msg.len()).unwrap();
        data.copy_from_slice(msg);
        let digest = pal.dma_alloc(&io, algo.digest_len() + 4).unwrap();
        digest.fill(0xA5);
        pal.alloc_scoped_async(&io, async |alloc| {
            let state_len = pal.hash_state_size(algo)?;
            let mut ctx = pal.hash_begin(&io, algo, alloc.dma_alloc(state_len)?)?;
            for offset in (0..data.len()).step_by(13) {
                let end = (offset + 13).min(data.len());
                pal.hash_continue(&io, &mut ctx, &data[offset..end]).await?;
            }
            pal.hash_finish(&io, &mut ctx, form, Some(digest)).await
        })
        .await
        .unwrap();
        digest.to_vec()
    }

    /// Checks the multi-step PAL hash of `msg` against `expected_be`, in both
    /// byte orders, and that the bytes after the output are untouched.
    async fn verify_streaming(algo: HsmHashAlgo, msg: &[u8], expected_be: &[u8]) {
        for form in [HsmDigestForm::Standard, HsmDigestForm::Operand] {
            let mut expected = expected_be.to_vec();
            if form.reversed(StdHsmPal::BYTE_ORDER) {
                expected.reverse();
            }
            let out = pal_streaming_hash(algo, msg, form).await;
            let (head, tail) = out.split_at(expected.len());
            assert_eq!(head, &expected[..], "{algo:?} form={form:?}");
            assert!(tail.iter().all(|&b| b == 0xA5), "{algo:?} tail");
        }
    }

    /// FIPS 202 "abc" outputs: 32 bytes of SHAKE128, 64 bytes of SHAKE256.
    const SHAKE128_ABC: &str = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";
    const SHAKE256_ABC: &str = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";

    #[tokio::test]
    async fn shake_validate_nist() {
        for (algo, expected) in [(shake128(32), SHAKE128_ABC), (shake256(64), SHAKE256_ABC)] {
            let expected = hex::decode(expected).unwrap();
            verify_endianness(algo, b"abc", &expected).await;
            verify_streaming(algo, b"abc", &expected).await;
        }
    }

    /// One-shot and multi-step SHAKE output of the length the variant
    /// carries, including lengths beyond the 136/168-byte sponge rates,
    /// matches `tsra_crypto`.
    #[tokio::test]
    async fn shake_validate_openssl() {
        let msg = multiblock_msg();
        for len in [1, 32, 64, 169, 256] {
            for algo in [shake128(len), shake256(len)] {
                let expected = shake_reference(algo, &msg);
                verify_endianness(algo, &msg, &expected).await;
                verify_streaming(algo, &msg, &expected).await;
            }
        }
    }

    #[tokio::test]
    async fn sha3_is_unsupported() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let data = pal.dma_alloc(&io, 3).unwrap();
        data.copy_from_slice(b"abc");
        let digest = pal.dma_alloc(&io, 64).unwrap();
        for algo in [
            HsmHashAlgo::Sha3_256,
            HsmHashAlgo::Sha3_384,
            HsmHashAlgo::Sha3_512,
        ] {
            assert_eq!(
                pal.hash(&io, algo, data, HsmDigestForm::Standard, Some(digest))
                    .await,
                Err(HsmError::UnsupportedDigestHashAlgorithm),
                "{algo:?} one-shot"
            );
            let begin = pal.hash_begin(&io, algo, &mut digest[..0]).map(|_| ());
            assert_eq!(
                begin,
                Err(HsmError::UnsupportedDigestHashAlgorithm),
                "{algo:?} multi-step"
            );
        }
    }
}
