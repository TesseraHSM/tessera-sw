// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmKdf`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] enum to
//! [`tsra_crypto::HashAlgo`] and forwards the supported KDF operations to
//! the [`StdKdf`](crate::drivers::kdf::StdKdf) driver.
//!
//! HKDF extract/expand and SP 800-108 counter-mode KDF are backed by
//! OpenSSL. The X9.63 and SP 800-56A single-step concatenation KDFs are
//! backed by the platform-agnostic `tsra_crypto` implementation. MGF1
//! remains a `todo!()` stub.

use core::ops::Deref;

use super::*;
use crate::hash::to_hash_algo;
use crate::StdHsmPal;

impl HsmKdf for StdHsmPal {
    async fn hkdf_extract(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        salt: Option<&HsmDmaBuf>,
        ikm: &HsmDmaBuf,
        prk: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let hash_algo = to_hash_algo(algo)?;
        let len = algo.digest_len();
        let Some(prk) = prk else {
            return Ok(len);
        };
        if prk.len() < len {
            return Err(HsmError::InvalidArg);
        }

        self.kdf
            .hkdf(
                ikm,
                hash_algo,
                tsra_crypto::HkdfMode::Extract,
                salt.map(|s| s.deref()),
                None,
                &mut prk[..len],
            )
            .await?;
        Ok(len)
    }

    async fn hkdf_expand(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        prk: &HsmDmaBuf,
        info: Option<&HsmDmaBuf>,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .hkdf(
                prk,
                to_hash_algo(algo)?,
                tsra_crypto::HkdfMode::Expand,
                None,
                info.map(|s| s.deref()),
                output,
            )
            .await
    }

    async fn sp800_108_kdf(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        label: Option<&HsmDmaBuf>,
        context: Option<&HsmDmaBuf>,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .kbkdf(
                key,
                to_hash_algo(algo)?,
                label.map(|s| s.deref()),
                context.map(|s| s.deref()),
                output,
            )
            .await
    }

    async fn mgf1(
        &self,
        _io: &StdHsmIo,
        _algo: HsmHashAlgo,
        _seed: &HsmDmaBuf,
        _mask: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn mgf1_xor(
        &self,
        _io: &StdHsmIo,
        _algo: HsmHashAlgo,
        _seed: &HsmDmaBuf,
        _mask: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn x963_kdf(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        z: &HsmDmaBuf,
        shared_info: &HsmDmaBuf,
        key: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .concat_kdf(
                z,
                to_hash_algo(algo)?,
                tsra_crypto::ConcatKdfMode::X963,
                Some(shared_info.deref()),
                key,
            )
            .await
    }

    async fn sp800_56a_kdf(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        z: &HsmDmaBuf,
        other_info: &HsmDmaBuf,
        key: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .concat_kdf(
                z,
                to_hash_algo(algo)?,
                tsra_crypto::ConcatKdfMode::Sp800_56a,
                Some(other_info.deref()),
                key,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pal() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    #[tokio::test]
    async fn hkdf_extract_queries_and_short_outputs_without_scratch() {
        let (pal, io) = test_pal();
        let dma = pal
            .dma_alloc(&io, crate::buf_pool::DMA_BUF_SIZE)
            .expect("DMA pool");
        let local = pal
            .alloc(&io, crate::buf_pool::NONDMA_BUF_SIZE)
            .expect("local pool");
        dma.fill(0xA5);
        local.fill(0x5A);
        let (input, output) = dma.split_at_mut(256);
        let (ikm, salt) = input.split_at_mut(128);
        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            for salt in [None, Some(&salt[..0]), Some(&*salt)] {
                for _ in 0..2 {
                    assert_eq!(
                        pal.hkdf_extract(&io, algo, salt, ikm, None)
                            .await
                            .expect("query without scratch"),
                        algo.digest_len()
                    );
                }
                assert_eq!(
                    pal.hkdf_extract(
                        &io,
                        algo,
                        salt,
                        ikm,
                        Some(&mut output[..algo.digest_len() - 1])
                    )
                    .await,
                    Err(HsmError::InvalidArg)
                );
            }
        }
        let xof_len = core::num::NonZeroU16::new(32).expect("nonzero");
        for algo in [
            HsmHashAlgo::Sha3_256,
            HsmHashAlgo::Sha3_384,
            HsmHashAlgo::Sha3_512,
            HsmHashAlgo::Shake128(xof_len),
            HsmHashAlgo::Shake256(xof_len),
        ] {
            assert_eq!(
                pal.hkdf_extract(&io, algo, None, ikm, None).await,
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            );
            assert_eq!(
                pal.hkdf_extract(&io, algo, None, ikm, Some(output)).await,
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            );
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
    async fn hkdf_extract_default_salt_and_output_prefix() {
        let (pal, io) = test_pal();
        let ikm = pal.dma_alloc(&io, 22).expect("IKM");
        ikm.fill(0x0B);
        let salt = pal.dma_alloc(&io, 257).expect("salt");
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let zeros = pal.dma_alloc_zeroed(&io, 64).expect("default salt");
        let expected = pal.dma_alloc(&io, 64).expect("reference PRK");
        let output = pal.dma_alloc(&io, 68).expect("PRK capacity");
        for algo in [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            let len = algo.digest_len();
            for salt in [
                None,
                Some(&salt[..0]),
                Some(&zeros[..len]),
                Some(&salt[..13]),
                Some(&salt[..257]),
            ] {
                pal.hmac_sign(
                    &io,
                    algo,
                    salt.filter(|salt| !salt.is_empty())
                        .unwrap_or(&zeros[..len]),
                    ikm,
                    Some(expected),
                )
                .await
                .expect("reference PRK");
                if algo == HsmHashAlgo::Sha256 {
                    let rfc_prk = match salt.map(|salt| salt.len()) {
                        None | Some(0) => {
                            Some("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                        }
                        Some(13) => {
                            Some("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                        }
                        _ => None,
                    };
                    if let Some(rfc_prk) = rfc_prk {
                        assert_eq!(
                            &expected[..len],
                            hex::decode(rfc_prk).expect("RFC 5869 PRK").as_slice()
                        );
                    }
                }
                output.fill(0xA5);
                assert_eq!(
                    pal.hkdf_extract(&io, algo, salt, ikm, Some(&mut output[..len - 1]))
                        .await,
                    Err(HsmError::InvalidArg)
                );
                assert!(output.iter().all(|&b| b == 0xA5));
                for capacity in [len, output.len()] {
                    assert_eq!(
                        pal.hkdf_extract(&io, algo, salt, ikm, Some(&mut output[..capacity]))
                            .await
                            .expect("extract"),
                        len
                    );
                    assert_eq!(&output[..len], &expected[..len]);
                    assert!(output[len..].iter().all(|&b| b == 0xA5));
                    output.fill(0xA5);
                }
            }
        }
    }
}
