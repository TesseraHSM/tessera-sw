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

use super::*;

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

pub struct StdHashCtx {
    algo: HsmHashAlgo,
    state: <HashAlgo as HashStreamingOp>::Context,
}

impl HsmHash for StdHsmPal {
    type HashCtx<'a>
        = StdHashCtx
    where
        Self: 'a;

    async fn hash(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        data: &HsmDmaBuf,
        digest: &mut HsmDmaBuf,
        big_endian: bool,
    ) -> HsmResult<()> {
        let hash_algo = digest_algo(algo)?;
        let digest_len = algo.digest_len();
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        self.hash
            .hash(hash_algo, data, &mut digest[..digest_len])
            .await?;
        if !big_endian {
            // SHA primitive is BE-native; reverse to the wire-LE
            // layout used at the PAL boundary for hashes that feed
            // directly into PKA-style operations (e.g. `ecc_sign`).
            digest[..digest_len].reverse();
        }
        Ok(())
    }

    fn hash_begin<'a>(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        let state = digest_algo(algo)?
            .hash_init()
            .map_err(|_| HsmError::ShaError)?;
        Ok(StdHashCtx { algo, state })
    }

    async fn hash_continue(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HashCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()> {
        ctx.state.update(data).map_err(|_| HsmError::ShaError)
    }

    async fn hash_finish(
        &self,
        _io: &StdHsmIo,
        mut ctx: Self::HashCtx<'_>,
        digest: &mut HsmDmaBuf,
        big_endian: bool,
    ) -> HsmResult<()> {
        let digest_len = ctx.algo.digest_len();
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        ctx.state
            .finish(Some(&mut digest[..digest_len]))
            .map_err(|_| HsmError::ShaError)?;
        if !big_endian {
            digest[..digest_len].reverse();
        }
        Ok(())
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
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// NIST FIPS 180-4 "abc" digests in big-endian (standard) byte order.
    const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    /// Hashes `msg` through the PAL with the requested endianness and returns
    /// the digest bytes.
    async fn pal_hash(algo: HsmHashAlgo, msg: &[u8], big_endian: bool) -> Vec<u8> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        let digest_len = algo.digest_len();
        let data = pal.dma_alloc(&io, msg.len()).unwrap();
        data.copy_from_slice(msg);
        let digest = pal.dma_alloc(&io, digest_len).unwrap();

        pal.hash(&io, algo, data, digest, big_endian).await.unwrap();
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

    /// Verifies the PAL hash of `msg` equals `expected_be` in big-endian and
    /// its full byte reversal in little-endian.
    async fn verify_endianness(algo: HsmHashAlgo, msg: &[u8], expected_be: &[u8]) {
        // validate big-endian output
        let be = pal_hash(algo, msg, true).await;
        assert_eq!(be, expected_be);

        // validate little-endian output
        let mut expected_le = expected_be.to_vec();
        expected_le.reverse();
        let le = pal_hash(algo, msg, false).await;
        assert_eq!(le, expected_le);
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
            for big_endian in [true, false] {
                let mut expected = openssl_digest(algo, &msg).await;
                if !big_endian {
                    expected.reverse();
                }
                data.copy_from_slice(&msg);
                digest.fill(0xA5);
                pal.alloc_scoped_async(&io, async |alloc| {
                    let mut ctx = pal.hash_begin(&io, algo, alloc)?;
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
                    pal.hash_finish(&io, ctx, digest, big_endian).await
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
                    let ctx = pal.hash_begin(&io, algo, alloc)?;
                    pal.hash_finish(&io, ctx, &mut digest[..algo.digest_len() - 1], true)
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
    async fn pal_streaming_hash(algo: HsmHashAlgo, msg: &[u8], big_endian: bool) -> Vec<u8> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let data = pal.dma_alloc(&io, msg.len()).unwrap();
        data.copy_from_slice(msg);
        let digest = pal.dma_alloc(&io, algo.digest_len() + 4).unwrap();
        digest.fill(0xA5);
        pal.alloc_scoped_async(&io, async |alloc| {
            let mut ctx = pal.hash_begin(&io, algo, alloc)?;
            for offset in (0..data.len()).step_by(13) {
                let end = (offset + 13).min(data.len());
                pal.hash_continue(&io, &mut ctx, &data[offset..end]).await?;
            }
            pal.hash_finish(&io, ctx, digest, big_endian).await
        })
        .await
        .unwrap();
        digest.to_vec()
    }

    /// Checks the multi-step PAL hash of `msg` against `expected_be`, in both
    /// byte orders, and that the bytes after the output are untouched.
    async fn verify_streaming(algo: HsmHashAlgo, msg: &[u8], expected_be: &[u8]) {
        for big_endian in [true, false] {
            let mut expected = expected_be.to_vec();
            if !big_endian {
                expected.reverse();
            }
            let out = pal_streaming_hash(algo, msg, big_endian).await;
            let (head, tail) = out.split_at(expected.len());
            assert_eq!(head, &expected[..], "{algo:?} big_endian={big_endian}");
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
                pal.hash(&io, algo, data, digest, true).await,
                Err(HsmError::UnsupportedDigestHashAlgorithm),
                "{algo:?} one-shot"
            );
            let begin = pal
                .alloc_scoped_async(&io, async |alloc| {
                    pal.hash_begin(&io, algo, alloc).map(|_| ())
                })
                .await;
            assert_eq!(
                begin,
                Err(HsmError::UnsupportedDigestHashAlgorithm),
                "{algo:?} multi-step"
            );
        }
    }
}
