// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRsa`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (byte-slice keys —
//! recovered DER on import, the HSM byte layout for vault-stored private
//! keys, wire form for public keys) and the
//! [`StdRsa`](crate::drivers::rsa::StdRsa) driver (OpenSSL key handles).
//!
//! Raw key generation, modular exponentiation, PKCS#1 v1.5 and PSS
//! sign/verify, and PKCS#1 v1.5 and OAEP encrypt/decrypt are implemented
//! with tsra_crypto (OpenSSL). Signing and OAEP accept SHA-1/SHA-2 only.

use tsra_crypto::ExportableHsmKey;
use tsra_crypto::ExportableHsmRsaKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::Key;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaKeyOp;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use zeroize::Zeroizing;

use super::*;
use crate::StdHsmPal;

fn key_size_bits(key_size: HsmRsaKey) -> usize {
    key_size.modulus_len() * 8
}

/// Parse a vault (HSM byte format) private key and check its modulus
/// matches `key_size`.
fn vault_priv_key(key_size: HsmRsaKey, priv_key: &[u8]) -> HsmResult<RsaPrivateKey> {
    let pk = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
    if pk.n(None).map_err(|_| HsmError::InvalidArg)? != key_size.modulus_len() {
        return Err(HsmError::InvalidArg);
    }
    Ok(pk)
}

impl StdHsmPal {
    /// PKCS#1 v1.5 (`salt_len == None`) or PSS sign of a pre-computed
    /// digest; `out == None` queries the signature length.
    async fn rsa_sign(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &[u8],
        message_hash: &[u8],
        salt_len: Option<usize>,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let hash = crate::hash::to_hash_algo(algo)?;
        if message_hash.len() != algo.digest_len() {
            return Err(HsmError::InvalidArg);
        }
        let pk = vault_priv_key(key_size, priv_key)?;
        self.rsa
            .sign(
                key_size,
                hash,
                &pk,
                message_hash,
                salt_len,
                out.map(|buf| &mut **buf),
            )
            .await
    }

    pub(crate) async fn rsa_pair_pct(
        &self,
        private: &RsaPrivateKey,
        public: &RsaPublicKey,
        pct: HsmRsaPct,
    ) -> HsmResult<bool> {
        let sign = match pct {
            HsmRsaPct::None => return Ok(true),
            HsmRsaPct::SignVerify => true,
            HsmRsaPct::EncryptDecrypt => false,
        };
        let len = private.size();
        if !matches!(len, 256 | 384 | 512) || public.size() != len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        let mut input = Zeroizing::new(vec![0u8; len]);
        if sign {
            let (algo, hash_len) = match len {
                256 => (HashAlgo::sha256(), 32),
                384 => (HashAlgo::sha384(), 48),
                _ => (HashAlgo::sha512(), 64),
            };
            self.hash
                .hash(algo, &vec![100; len], &mut input[..hash_len])
                .await?;
        } else {
            input[..len - 1].fill(0x5a);
        }
        if Self::BYTE_ORDER.is_be() {
            input.reverse();
        }
        let mut middle = Zeroizing::new(vec![0u8; len]);
        let mut output = Zeroizing::new(vec![0xff; len]);
        if sign {
            self.rsa.mod_exp_priv(private, &input, &mut middle).await?;
            self.rsa.mod_exp_pub(public, &middle, &mut output).await?;
        } else {
            self.rsa.mod_exp_pub(public, &input, &mut middle).await?;
            self.rsa.mod_exp_priv(private, &middle, &mut output).await?;
        }
        let diff = input
            .iter()
            .zip(output.iter())
            .fold(0u8, |d, (a, b)| d | (a ^ b));
        let changed = input
            .iter()
            .zip(middle.iter())
            .fold(0u8, |d, (a, b)| d | (a ^ b));
        #[cfg(test)]
        if self.rsa_pct_fail.get() {
            return Ok(false);
        }
        Ok(core::hint::black_box(diff) == 0 && core::hint::black_box(changed) != 0)
    }
}

impl HsmRsa for StdHsmPal {
    async fn rsa_gen_keypair(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        pct: HsmRsaPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let k = key_size.modulus_len();
        // SPKI overhead for the supported RSA widths and exponent 65537.
        let capacities = (2 * k + 4, k + 38);
        let Some((priv_key, pub_key)) = out else {
            return Ok(capacities);
        };
        if priv_key.len() < capacities.0 || pub_key.len() < capacities.1 {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        let (pk, pubk) = self.rsa.gen_keypair(key_size_bits(key_size)).await?;

        // The vault stores the RSA private key in HSM byte format (raw
        // components), not DER; a generated key is stored non-CRT.
        let priv_len = pk.hsm_bytes_len();
        let pub_len = pubk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if priv_key.len() < priv_len || pub_key.len() < pub_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }

        let mut private = Zeroizing::new(vec![0u8; priv_len]);
        pk.to_hsm_bytes(&mut private)
            .map_err(|_| HsmError::RsaToDerError)?;

        let mut public = vec![0u8; pub_len];
        pubk.to_bytes(Some(&mut public))
            .map_err(|_| HsmError::RsaToDerError)?;

        if !matches!(pct, HsmRsaPct::None) {
            let tested_private =
                RsaPrivateKey::from_hsm_bytes(&private).map_err(|_| HsmError::RsaGenerateError)?;
            let tested_public =
                RsaPublicKey::from_bytes(&public).map_err(|_| HsmError::RsaGenerateError)?;
            if !self
                .rsa_pair_pct(&tested_private, &tested_public, pct)
                .await?
            {
                return Err(HsmError::RsaGenerateError);
            }
        }
        priv_key[..priv_len].copy_from_slice(&private);
        pub_key[..pub_len].copy_from_slice(&public);
        Ok((priv_len, pub_len))
    }

    async fn mod_exp_priv(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        y: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let k = key_size.modulus_len();
        let priv_key = RsaPrivateKey::from_hsm_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        if priv_key.hsm_bytes_len() != 2 * k + 4 || y.len() != k {
            return Err(HsmError::InvalidArg);
        }
        let Some(x) = out else {
            self.rsa.validate_mod_exp_priv_input(&priv_key, y)?;
            return Ok(k);
        };
        if x.len() < k {
            return Err(HsmError::InvalidArg);
        }
        self.rsa.mod_exp_priv(&priv_key, y, &mut x[..k]).await?;
        Ok(k)
    }

    async fn mod_exp_priv_in_place(
        &self,
        _io: &StdHsmIo,
        key_type: HsmRsaKey,
        key: &HsmDmaBuf,
        y_x: &mut HsmDmaBuf,
    ) -> Result<(), HsmError> {
        if y_x.len() != key_type.modulus_len() {
            return Err(HsmError::InvalidArg);
        }
        let private_key = RsaPrivateKey::from_hsm_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_priv_in_place(&private_key, y_x).await
    }

    async fn mod_exp_pub(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        x: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let k = key_size.modulus_len();
        let public_be = crate::drivers::rsa::pub_key_be(key, StdHsmPal::BYTE_ORDER, k)?;
        let pub_key = <RsaPublicKey as tsra_crypto::ImportableHsmKey>::from_hsm_bytes(&public_be)
            .map_err(|_| HsmError::InvalidArg)?;
        if pub_key.n(None).map_err(|_| HsmError::InvalidArg)? != k || x.len() != k {
            return Err(HsmError::InvalidArg);
        }
        let Some(y) = out else {
            return Ok(k);
        };
        if y.len() < k {
            return Err(HsmError::InvalidArg);
        }
        self.rsa.mod_exp_pub(&pub_key, x, &mut y[..k]).await?;
        Ok(k)
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &StdHsmIo,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The std PAL's vault representation is HSM byte format (raw
        // components): parse it, derive the public key, and emit raw
        // `n || e` in operand order.
        // In query mode (`pub_out == None`) only the wire length is returned.
        let pk = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let pubk = pk.public_key().map_err(|_| HsmError::RsaGenerateError)?;
        crate::drivers::rsa::rsa_pub_wire(&pubk, StdHsmPal::BYTE_ORDER, pub_out.map(|b| &mut **b))
    }

    async fn rsa_priv_der_to_vault<'a>(
        &'a self,
        io: &StdHsmIo,
        der: &'a mut HsmDmaBuf,
        crt: bool,
        pct: HsmRsaPct,
    ) -> HsmResult<(&'a HsmDmaBuf, usize)> {
        // Parse the recovered DER and re-serialize it in place into the vault
        // HSM byte format: the CRT layout (`n|e|d|p|q|dp|dq|qinv`) when `crt`,
        // else non-CRT (`n|e|p|q`). `der` doubles as the vault buffer unless
        // the layout is larger, e.g. a CRT key whose ignored `d` is short.
        // Like Uno, the components the layout uses must have supported sizes
        // and, unless `pct` is `None`, be consistent and pass the PCT; the
        // others are ignored. The key is rebuilt from `n`, `e`, `p` and `q`
        // (the backend derives `d`) plus, for CRT, the checked `dp`, `dq` and
        // `qInv`, and the PCT runs on the stored key.
        let parts = {
            let key =
                crate::key_assurance::parse_rsa_private_key(der).ok_or(HsmError::InvalidArg)?;
            crate::key_assurance::check_rsa_components(&key, crt, &pct)?;
            crate::key_assurance::rsa_stored_components(&key)
        };
        let modulus_len = (parts.len() - 4) * 2 / 7;
        let base_len = 2 * modulus_len + 4;
        let base =
            RsaPrivateKey::from_hsm_bytes(&parts[..base_len]).map_err(|_| HsmError::InvalidArg)?;
        let vault_len = if crt {
            base.hsm_crt_bytes_len()
        } else {
            base.hsm_bytes_len()
        };
        let vault = if der.len() >= vault_len {
            der
        } else {
            self.dma_alloc_zeroed(io, vault_len)?
        };
        let hsm_len = if crt {
            let len = base
                .to_hsm_crt_bytes(vault)
                .map_err(|_| HsmError::RsaToDerError)?;
            let crt_parts = &parts[base_len..];
            vault[len - crt_parts.len()..len].copy_from_slice(crt_parts);
            len
        } else {
            base.to_hsm_bytes(vault)
                .map_err(|_| HsmError::RsaToDerError)?
        };
        let pk = if crt {
            RsaPrivateKey::from_hsm_bytes(&vault[..hsm_len]).map_err(|_| HsmError::InvalidArg)?
        } else {
            base
        };
        self.check_rsa_pct(&pk, pct).await?;
        Ok((&vault[..hsm_len], modulus_len))
    }

    async fn rsa_pkcs1_encrypt(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        pub_key: &HsmDmaBuf,
        message: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let k = key_size.modulus_len();
        if message.len() > key_size.max_pkcs1_message() || pub_key.len() != k + 4 {
            return Err(HsmError::InvalidArg);
        }
        let Some(output) = out else {
            return Ok(k);
        };
        let output = output.get_mut(..k).ok_or(HsmError::InvalidArg)?;
        self.rsa
            .encrypt(key_size, pub_key, message, None, output)
            .await?;
        Ok(k)
    }

    async fn rsa_pkcs1_decrypt(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        priv_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        if ciphertext.len() != key_size.modulus_len() {
            return Err(HsmError::InvalidArg);
        }
        let pk = vault_priv_key(key_size, priv_key)?;
        let Some(output) = out else {
            return Ok(key_size.max_pkcs1_message());
        };
        self.rsa
            .pkcs1_decrypt(key_size, &pk, ciphertext, output)
            .await
    }

    async fn rsa_pkcs1_sign(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        self.rsa_sign(key_size, algo, priv_key, message_hash, None, out)
            .await
    }

    async fn rsa_pkcs1_verify(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        self.rsa
            .verify(
                key_size,
                crate::hash::to_hash_algo(algo)?,
                pub_key,
                message_hash,
                signature,
                None,
            )
            .await
    }

    async fn rsa_oaep_encrypt(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message: &HsmDmaBuf,
        label: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let hash = crate::hash::to_hash_algo(algo)?;
        let k = key_size.modulus_len();
        if message.len() > key_size.max_oaep_message(algo) || pub_key.len() != k + 4 {
            return Err(HsmError::InvalidArg);
        }
        let Some(output) = out else {
            return Ok(k);
        };
        let output = output.get_mut(..k).ok_or(HsmError::InvalidArg)?;
        let label = if label.is_empty() {
            None
        } else {
            Some(label.to_vec())
        };
        self.rsa
            .encrypt(key_size, pub_key, message, Some((hash, label)), output)
            .await?;
        Ok(k)
    }

    async fn rsa_oaep_decrypt(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        label: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The trait contract requires the ciphertext to be exactly one
        // modulus block; enforce it (OpenSSL would otherwise accept a
        // shorter block as a number with implicit leading zeros), matching
        // the hardware PAL.
        if ciphertext.len() != key_size.modulus_len() {
            return Err(HsmError::InvalidArg);
        }

        // Vault private key is HSM byte format in the std PAL; parse it,
        // then OAEP decrypt the wire-LE ciphertext (the driver flips
        // LE->BE).  An empty `label` maps to the default empty OAEP label.
        let pk = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        if pk.n(None).map_err(|_| HsmError::InvalidArg)? != key_size.modulus_len() {
            return Err(HsmError::InvalidArg);
        }
        let hash = crate::hash::to_hash_algo(algo)?;
        let Some(output) = out else {
            return Ok(key_size.max_oaep_message(algo));
        };
        let label = if label.is_empty() {
            None
        } else {
            Some(label.to_vec())
        };
        self.rsa
            .oaep_decrypt(&pk, hash, label, ciphertext, output)
            .await
    }

    async fn rsa_pss_sign(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        salt_len: usize,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let max_salt = key_size
            .modulus_len()
            .checked_sub(algo.digest_len() + 2)
            .ok_or(HsmError::InvalidArg)?;
        if salt_len > max_salt {
            return Err(HsmError::InvalidArg);
        }
        self.rsa_sign(key_size, algo, priv_key, message_hash, Some(salt_len), out)
            .await
    }

    async fn rsa_pss_verify(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        salt_len: usize,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        self.rsa
            .verify(
                key_size,
                crate::hash::to_hash_algo(algo)?,
                pub_key,
                message_hash,
                signature,
                Some(salt_len),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;
    use tsra_crypto::DecryptOp;
    use tsra_crypto::EncryptOp;
    use tsra_crypto::HashAlgo;
    use tsra_crypto::KeyGenerationOp;
    use tsra_crypto::RsaEncryptAlgo;
    use tsra_fw_hsm_pal_traits::HsmByteOrder;

    use super::*;

    fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    fn convert_to_or_from_device_order(bytes: &mut [u8]) {
        if StdHsmPal::BYTE_ORDER == HsmByteOrder::Le {
            bytes.reverse();
        }
    }

    #[tokio::test]
    async fn imported_rsa_pct_failure_covers_crt_and_non_crt() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        let pk = RsaPrivateKey::generate(256).expect("generate RSA key");
        let mut bytes = vec![0; pk.to_bytes(None).expect("DER size")];
        pk.to_bytes(Some(&mut bytes)).expect("export DER");
        for crt in [false, true] {
            for pct in [
                HsmRsaPct::SignVerify,
                HsmRsaPct::EncryptDecrypt,
                HsmRsaPct::None,
            ] {
                pal.alloc_scoped_async(&io, async |alloc| {
                    let der = alloc.dma_alloc(bytes.len()).expect("DER buffer");
                    der.copy_from_slice(&bytes);
                    pal.rsa_pct_fail.set(true);
                    let skip = matches!(&pct, HsmRsaPct::None);
                    let result = pal.rsa_priv_der_to_vault(&io, der, crt, pct).await;
                    if skip {
                        assert!(result.is_ok());
                    } else {
                        assert!(matches!(
                            result,
                            Err(HsmError::PctValidationRsaUnwrapRsaKeyFailed)
                        ));
                    }
                })
                .await;
            }
        }
    }

    #[tokio::test]
    async fn key_generation_and_mod_exp_use_queried_capacities() {
        for key_size in [
            HsmRsaKey::Rsa2048Priv,
            HsmRsaKey::Rsa3072Priv,
            HsmRsaKey::Rsa4096Priv,
        ] {
            let (pal, io) = pal_and_io();
            pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
                let capacities = pal
                    .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, None)
                    .await?;
                let private = alloc.dma_alloc(capacities.0 + 4)?;
                let public = alloc.dma_alloc(capacities.1 + 4)?;
                private.fill(0xCC);
                public.fill(0xCC);
                for short_private in [true, false] {
                    let private_len = capacities.0 - usize::from(short_private);
                    let public_len = capacities.1 - usize::from(!short_private);
                    assert_eq!(
                        pal.rsa_gen_keypair(
                            &io,
                            key_size,
                            HsmRsaPct::None,
                            Some((&mut private[..private_len], &mut public[..public_len]))
                        )
                        .await,
                        Err(HsmError::RsaInvalidKeyLength),
                    );
                    assert!(private.iter().all(|&b| b == 0xCC));
                    assert!(public.iter().all(|&b| b == 0xCC));
                }
                let written = pal
                    .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, Some((private, public)))
                    .await?;
                assert!(written.0 <= capacities.0 && written.1 <= capacities.1);
                assert!(private[written.0..].iter().all(|&b| b == 0xCC));
                assert!(public[written.1..].iter().all(|&b| b == 0xCC));
                let private = &private[..written.0];
                let _public_der = &public[..written.1];
                let k = key_size.modulus_len();
                let public_wire = alloc.dma_alloc(k + 4)?;
                assert_eq!(
                    pal.rsa_priv_pub_key(&io, private, Some(public_wire))?,
                    k + 4
                );
                let input = alloc.dma_alloc_zeroed(k)?;
                let low = if StdHsmPal::BYTE_ORDER == HsmByteOrder::Le {
                    0
                } else {
                    k - 1
                };
                input[low] = 2;
                let encrypted = alloc.dma_alloc(k + 4)?;
                let decrypted = alloc.dma_alloc(k + 4)?;
                encrypted.fill(0xCC);
                decrypted.fill(0xCC);
                let mark = pal.iic.pool().dma_mark(io.slot).get();
                pal.alloc_scoped_async(&io, async |reserve| -> HsmResult<()> {
                    let aligned_mark = mark.next_multiple_of(4);
                    let _remaining = reserve.dma_alloc(buf_pool::DMA_BUF_SIZE - aligned_mark)?;
                    let full_mark = pal.iic.pool().dma_mark(io.slot).get();
                    assert_eq!(
                        pal.rsa_gen_keypair(&io, key_size, HsmRsaPct::None, None)
                            .await?,
                        capacities
                    );
                    assert_eq!(
                        pal.mod_exp_priv(&io, key_size, private, input, None)
                            .await?,
                        k
                    );
                    assert_eq!(
                        pal.mod_exp_pub(&io, key_size.pub_variant(), public_wire, input, None)
                            .await?,
                        k
                    );
                    for outcome in [
                        pal.mod_exp_priv(
                            &io,
                            key_size,
                            private,
                            input,
                            Some(&mut decrypted[..k - 1]),
                        )
                        .await,
                        pal.mod_exp_pub(
                            &io,
                            key_size.pub_variant(),
                            public_wire,
                            input,
                            Some(&mut encrypted[..k - 1]),
                        )
                        .await,
                    ] {
                        assert_eq!(outcome, Err(HsmError::InvalidArg));
                    }
                    input[low] = 0;
                    assert_eq!(
                        pal.mod_exp_priv(&io, key_size, private, input, None).await,
                        Err(HsmError::InvalidArg)
                    );
                    assert_eq!(
                        pal.mod_exp_priv(&io, key_size, private, input, Some(decrypted))
                            .await,
                        Err(HsmError::InvalidArg)
                    );
                    input[low] = 2;
                    assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), full_mark);
                    Ok(())
                })
                .await?;
                assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), mark);
                assert!(encrypted.iter().all(|&b| b == 0xCC));
                assert!(decrypted.iter().all(|&b| b == 0xCC));
                assert_eq!(
                    pal.mod_exp_pub(
                        &io,
                        key_size.pub_variant(),
                        public_wire,
                        input,
                        Some(encrypted),
                    )
                    .await?,
                    k
                );
                assert_eq!(
                    pal.mod_exp_priv(&io, key_size, private, &encrypted[..k], Some(decrypted))
                        .await?,
                    k
                );
                assert_eq!(&decrypted[..k], &input[..]);
                assert_eq!(&encrypted[k..], &[0xCC; 4]);
                assert_eq!(&decrypted[k..], &[0xCC; 4]);
                assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), mark);
                Ok(())
            })
            .await
            .expect("query/size RSA outputs");
        }
    }

    #[tokio::test]
    async fn oaep_rejects_mismatched_private_key_width_in_query_and_execution() {
        let (pal, io) = pal_and_io();
        for key_len in [256, 384] {
            let key = RsaPrivateKey::generate(key_len).expect("RSA key");
            for crt in [false, true] {
                pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
                    let private = alloc.dma_alloc(if crt {
                        key.hsm_crt_bytes_len()
                    } else {
                        key.hsm_bytes_len()
                    })?;
                    if crt {
                        key.to_hsm_crt_bytes(private).expect("CRT vault key");
                    } else {
                        key.to_hsm_bytes(private).expect("vault key");
                    }
                    let ciphertext = alloc.dma_alloc_zeroed(512)?;
                    let label = alloc.dma_alloc(0)?;
                    let output = alloc.dma_alloc(512)?;
                    output.fill(0xCC);
                    for key_size in [
                        HsmRsaKey::Rsa2048Priv,
                        HsmRsaKey::Rsa3072Priv,
                        HsmRsaKey::Rsa4096Priv,
                    ] {
                        let ciphertext = &ciphertext[..key_size.modulus_len()];
                        let query = pal
                            .rsa_oaep_decrypt(
                                &io,
                                key_size,
                                HsmHashAlgo::Sha256,
                                private,
                                ciphertext,
                                label,
                                None,
                            )
                            .await;
                        if key_size.modulus_len() == key_len {
                            assert_eq!(query, Ok(key_size.max_oaep_message(HsmHashAlgo::Sha256)));
                        } else {
                            assert_eq!(query, Err(HsmError::InvalidArg));
                            assert_eq!(
                                pal.rsa_oaep_decrypt(
                                    &io,
                                    key_size,
                                    HsmHashAlgo::Sha256,
                                    private,
                                    ciphertext,
                                    label,
                                    Some(output),
                                )
                                .await,
                                Err(HsmError::InvalidArg)
                            );
                        }
                        assert!(output.iter().all(|&b| b == 0xCC));
                    }
                    Ok(())
                })
                .await
                .expect("OAEP private-key width validation");
            }
        }
    }

    #[tokio::test]
    async fn padded_encrypt_decrypt_interoperates_with_standard_rsa_encoding() {
        let (pal, io) = pal_and_io();
        let private = RsaPrivateKey::generate(256).expect("RSA key");
        let public = private.public_key().expect("public key");
        let message = [0x00, 0x31, 0x00, 0x82, 0xFE, 0x00];
        let label_bytes = b"raw-byte-label\0value";
        let mut public_wire = vec![0u8; 260];
        crate::drivers::rsa::rsa_pub_wire(&public, StdHsmPal::BYTE_ORDER, Some(&mut public_wire))
            .expect("public wire");

        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let private_wire = alloc.dma_alloc(private.hsm_bytes_len())?;
            private
                .to_hsm_bytes(private_wire)
                .map_err(|_| HsmError::RsaToDerError)?;
            let public_wire_buf = alloc.dma_alloc(public_wire.len())?;
            public_wire_buf.copy_from_slice(&public_wire);
            let message_buf = alloc.dma_alloc(message.len())?;
            message_buf.copy_from_slice(&message);
            let label = alloc.dma_alloc(label_bytes.len())?;
            label.copy_from_slice(label_bytes);
            let ciphertext = alloc.dma_alloc(256)?;
            let output = alloc.dma_alloc(512)?;

            assert_eq!(
                pal.rsa_pkcs1_encrypt(
                    &io,
                    HsmRsaKey::Rsa2048Pub,
                    public_wire_buf,
                    message_buf,
                    None
                )
                .await?,
                256
            );
            assert_eq!(
                pal.rsa_pkcs1_decrypt(&io, HsmRsaKey::Rsa2048Priv, private_wire, ciphertext, None,)
                    .await?,
                245
            );
            let (short_output, _) = output.split_at_mut(255);
            assert_eq!(
                pal.rsa_pkcs1_encrypt(
                    &io,
                    HsmRsaKey::Rsa2048Pub,
                    public_wire_buf,
                    message_buf,
                    Some(short_output),
                )
                .await,
                Err(HsmError::InvalidArg)
            );

            pal.rsa_pkcs1_encrypt(
                &io,
                HsmRsaKey::Rsa2048Pub,
                public_wire_buf,
                message_buf,
                Some(ciphertext),
            )
            .await?;
            let mut ciphertext_be = ciphertext.to_vec();
            convert_to_or_from_device_order(&mut ciphertext_be);
            let mut host_plaintext = vec![0u8; 256];
            let mut host_decrypt = RsaEncryptAlgo::with_pkcs1_padding();
            let written = host_decrypt
                .decrypt(&private, &ciphertext_be, Some(&mut host_plaintext))
                .map_err(|_| HsmError::RsaDecryptFailed)?;
            assert_eq!(&host_plaintext[..written], &message);

            let mut host_ciphertext = vec![0u8; 256];
            let mut host_encrypt = RsaEncryptAlgo::with_pkcs1_padding();
            host_encrypt
                .encrypt(&public, &message, Some(&mut host_ciphertext))
                .map_err(|_| HsmError::RsaEncryptFailed)?;
            convert_to_or_from_device_order(&mut host_ciphertext);
            ciphertext.copy_from_slice(&host_ciphertext);
            let written = pal
                .rsa_pkcs1_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    private_wire,
                    ciphertext,
                    Some(output),
                )
                .await?;
            assert_eq!(&output[..written], &message);

            let invalid_encoded = vec![0x41; 256];
            let mut invalid_ciphertext = vec![0u8; 256];
            let mut raw = RsaEncryptAlgo::with_no_padding();
            raw.encrypt(&public, &invalid_encoded, Some(&mut invalid_ciphertext))
                .map_err(|_| HsmError::RsaEncryptFailed)?;
            convert_to_or_from_device_order(&mut invalid_ciphertext);
            ciphertext.copy_from_slice(&invalid_ciphertext);
            output.fill(0xCC);
            assert_eq!(
                pal.rsa_pkcs1_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    private_wire,
                    ciphertext,
                    Some(output),
                )
                .await,
                Err(HsmError::RsaDecryptFailed)
            );
            assert!(output.iter().all(|byte| *byte == 0xCC));

            let oaep_ciphertext = alloc.dma_alloc(256)?;
            assert_eq!(
                pal.rsa_oaep_encrypt(
                    &io,
                    HsmRsaKey::Rsa2048Pub,
                    HsmHashAlgo::Sha256,
                    public_wire_buf,
                    message_buf,
                    label,
                    None,
                )
                .await?,
                256
            );
            pal.rsa_oaep_encrypt(
                &io,
                HsmRsaKey::Rsa2048Pub,
                HsmHashAlgo::Sha256,
                public_wire_buf,
                message_buf,
                label,
                Some(oaep_ciphertext),
            )
            .await?;
            let mut oaep_be = oaep_ciphertext.to_vec();
            convert_to_or_from_device_order(&mut oaep_be);
            let mut host_oaep_plaintext = vec![0u8; 256];
            let mut host_oaep_decrypt =
                RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), Some(label_bytes));
            let written = host_oaep_decrypt
                .decrypt(&private, &oaep_be, Some(&mut host_oaep_plaintext))
                .map_err(|_| HsmError::RsaDecryptFailed)?;
            assert_eq!(&host_oaep_plaintext[..written], &message);

            let mut host_oaep_ciphertext = vec![0u8; 256];
            let mut host_oaep_encrypt =
                RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), Some(label_bytes));
            host_oaep_encrypt
                .encrypt(&public, &message, Some(&mut host_oaep_ciphertext))
                .map_err(|_| HsmError::RsaEncryptFailed)?;
            convert_to_or_from_device_order(&mut host_oaep_ciphertext);
            oaep_ciphertext.copy_from_slice(&host_oaep_ciphertext);
            let written = pal
                .rsa_oaep_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    HsmHashAlgo::Sha256,
                    private_wire,
                    oaep_ciphertext,
                    label,
                    Some(output),
                )
                .await?;
            assert_eq!(&output[..written], &message);
            Ok(())
        })
        .await
        .expect("padded RSA interop");
    }

    #[tokio::test]
    async fn rsa_generation_runs_selected_pct_before_output() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        pal.alloc_scoped_async(&io, async |alloc| {
            let private = alloc.dma_alloc(516).unwrap();
            let public = alloc.dma_alloc(512).unwrap();
            for pct in [HsmRsaPct::SignVerify, HsmRsaPct::EncryptDecrypt] {
                pal.rsa_gen_keypair(&io, HsmRsaKey::Rsa2048Priv, pct, Some((private, public)))
                    .await
                    .unwrap();
            }
            private.fill(0xa5);
            public.fill(0xa5);
            pal.rsa_pct_fail.set(true);
            for pct in [HsmRsaPct::SignVerify, HsmRsaPct::EncryptDecrypt] {
                assert_eq!(
                    pal.rsa_gen_keypair(&io, HsmRsaKey::Rsa2048Priv, pct, Some((private, public)))
                        .await
                        .unwrap_err(),
                    HsmError::RsaGenerateError
                );
                assert!(private.iter().all(|&b| b == 0xa5));
                assert!(public.iter().all(|&b| b == 0xa5));
            }
            pal.rsa_gen_keypair(
                &io,
                HsmRsaKey::Rsa2048Priv,
                HsmRsaPct::None,
                Some((private, public)),
            )
            .await
            .unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn oaep_query_preserves_bounded_output_and_oversized_plaintext_errors() {
        let (pal, io) = pal_and_io();
        let key = RsaPrivateKey::generate(256).expect("RSA key");
        let public = key.public_key().expect("public key");
        let message = [0xA5; 32];
        let label_bytes = b"workspace";
        let mut cipher = vec![0; 256];
        let mut encryption =
            RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), Some(label_bytes));
        encryption
            .encrypt(&public, &message, Some(&mut cipher))
            .expect("OAEP ciphertext");
        if StdHsmPal::BYTE_ORDER == HsmByteOrder::Le {
            cipher.reverse();
        }

        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let private = alloc.dma_alloc(key.hsm_bytes_len())?;
            key.to_hsm_bytes(private).expect("vault key");
            let ciphertext = alloc.dma_alloc(cipher.len())?;
            ciphertext.copy_from_slice(&cipher);
            let label = alloc.dma_alloc(label_bytes.len())?;
            label.copy_from_slice(label_bytes);
            let output = alloc.dma_alloc(message.len())?;
            output.fill(0xCC);
            let mark = pal.iic.pool().dma_mark(io.slot).get().next_multiple_of(4);
            let _remaining = alloc.dma_alloc(buf_pool::DMA_BUF_SIZE - mark)?;
            let full_mark = pal.iic.pool().dma_mark(io.slot).get();
            let capacity = pal
                .rsa_oaep_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    HsmHashAlgo::Sha256,
                    private,
                    ciphertext,
                    label,
                    None,
                )
                .await?;
            assert!(capacity > message.len());
            assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), full_mark);
            let outcome = pal
                .rsa_oaep_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    HsmHashAlgo::Sha256,
                    private,
                    ciphertext,
                    label,
                    Some(&mut output[..message.len() - 1]),
                )
                .await;
            assert_eq!(outcome, Err(HsmError::RsaInvalidKeyLength));
            assert!(output.iter().all(|&b| b == 0xCC));
            assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), full_mark);

            let written = pal
                .rsa_oaep_decrypt(
                    &io,
                    HsmRsaKey::Rsa2048Priv,
                    HsmHashAlgo::Sha256,
                    private,
                    ciphertext,
                    label,
                    Some(&mut *output),
                )
                .await?;
            assert_eq!(written, message.len());
            assert_eq!(&output[..], &message);
            assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), full_mark);
            Ok(())
        })
        .await
        .expect("OAEP query and execution");
    }

    #[tokio::test]
    async fn invalid_rsa_inputs_are_rejected_without_writing_output() {
        let (pal, io) = pal_and_io();
        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let input = alloc.dma_alloc(0)?;
            let output = alloc.dma_alloc(256)?;
            output.fill(0xCC);
            let mark = pal.iic.pool().dma_mark(io.slot).get();
            for execute in [false, true] {
                let key = HsmRsaKey::Rsa2048Priv;
                let hash = HsmHashAlgo::Sha256;
                for outcome in [
                    pal.rsa_pkcs1_encrypt(&io, key, input, input, execute.then_some(&mut *output))
                        .await,
                    pal.rsa_pkcs1_decrypt(&io, key, input, input, execute.then_some(&mut *output))
                        .await,
                    pal.rsa_oaep_encrypt(
                        &io,
                        key,
                        hash,
                        input,
                        input,
                        input,
                        execute.then_some(&mut *output),
                    )
                    .await,
                    pal.rsa_pkcs1_sign(
                        &io,
                        key,
                        hash,
                        input,
                        input,
                        execute.then_some(&mut *output),
                    )
                    .await,
                    pal.rsa_pss_sign(
                        &io,
                        key,
                        hash,
                        input,
                        input,
                        32,
                        execute.then_some(&mut *output),
                    )
                    .await,
                ] {
                    assert_eq!(outcome, Err(HsmError::InvalidArg));
                }
                assert!(output.iter().all(|&b| b == 0xCC));
                assert_eq!(pal.iic.pool().dma_mark(io.slot).get(), mark);
            }
            Ok(())
        })
        .await
        .expect("invalid RSA inputs");
    }

    #[tokio::test]
    async fn sign_round_trips_through_verify() {
        let (pal, io) = pal_and_io();
        let key_size = HsmRsaKey::Rsa2048Priv;
        let k = key_size.modulus_len();
        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let (priv_len, pub_len) = pal
                .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, None)
                .await?;
            let private = alloc.dma_alloc(priv_len)?;
            let public = alloc.dma_alloc(pub_len)?;
            let (priv_len, _) = pal
                .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, Some((private, public)))
                .await?;
            let private = &private[..priv_len];
            let public = alloc.dma_alloc(pal.rsa_priv_pub_key(&io, private, None)?)?;
            pal.rsa_priv_pub_key(&io, private, Some(&mut *public))?;
            let public = &*public;
            let digest = alloc.dma_alloc(32)?;
            digest.fill(0x5A);
            let signature = alloc.dma_alloc(k + 4)?;
            for salt in [None, Some(0), Some(32), Some(k - 34)] {
                let sign = async |out: Option<&mut HsmDmaBuf>| match salt {
                    None => {
                        pal.rsa_pkcs1_sign(&io, key_size, HsmHashAlgo::Sha256, private, digest, out)
                            .await
                    }
                    Some(len) => {
                        pal.rsa_pss_sign(
                            &io,
                            key_size,
                            HsmHashAlgo::Sha256,
                            private,
                            digest,
                            len,
                            out,
                        )
                        .await
                    }
                };
                let verify = async |digest: &HsmDmaBuf, signature: &HsmDmaBuf| match salt {
                    None => {
                        pal.rsa_pkcs1_verify(
                            &io,
                            key_size.pub_variant(),
                            HsmHashAlgo::Sha256,
                            public,
                            digest,
                            signature,
                        )
                        .await
                    }
                    Some(len) => {
                        pal.rsa_pss_verify(
                            &io,
                            key_size.pub_variant(),
                            HsmHashAlgo::Sha256,
                            public,
                            digest,
                            len,
                            signature,
                        )
                        .await
                    }
                };
                signature.fill(0xCC);
                assert_eq!(sign(None).await, Ok(k));
                assert_eq!(
                    sign(Some(&mut signature[..k - 1])).await,
                    Err(HsmError::InvalidArg)
                );
                assert_eq!(sign(Some(&mut *signature)).await, Ok(k));
                assert_eq!(&signature[k..], &[0xCC; 4]);
                assert_eq!(verify(digest, &signature[..k]).await, Ok(true));
                digest[0] ^= 1;
                assert_ne!(verify(digest, &signature[..k]).await, Ok(true));
                digest[0] ^= 1;
            }
            assert_eq!(
                pal.rsa_pss_sign(
                    &io,
                    key_size,
                    HsmHashAlgo::Sha256,
                    private,
                    digest,
                    k - 33,
                    None
                )
                .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.rsa_pkcs1_sign(&io, key_size, HsmHashAlgo::Sha384, private, digest, None)
                    .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.rsa_pkcs1_sign(&io, key_size, HsmHashAlgo::Sha3_256, private, digest, None)
                    .await,
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            );
            Ok(())
        })
        .await
        .expect("RSA sign/verify");
    }

    #[tokio::test]
    async fn encrypt_round_trips_through_decrypt() {
        let (pal, io) = pal_and_io();
        let key_size = HsmRsaKey::Rsa2048Priv;
        let k = key_size.modulus_len();
        let hash = HsmHashAlgo::Sha256;
        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let (priv_len, pub_len) = pal
                .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, None)
                .await?;
            let private = alloc.dma_alloc(priv_len)?;
            let public = alloc.dma_alloc(pub_len)?;
            let (priv_len, _) = pal
                .rsa_gen_keypair(&io, key_size, HsmRsaPct::None, Some((private, public)))
                .await?;
            let private = &private[..priv_len];
            let public = alloc.dma_alloc(pal.rsa_priv_pub_key(&io, private, None)?)?;
            pal.rsa_priv_pub_key(&io, private, Some(&mut *public))?;
            let public = &*public;
            let pub_size = key_size.pub_variant();
            let message = alloc.dma_alloc(key_size.max_pkcs1_message() + 1)?;
            message.fill(0xA5);
            let label = alloc.dma_alloc(5)?;
            label.copy_from_slice(b"label");
            let ciphertext = alloc.dma_alloc(k)?;
            let plaintext = alloc.dma_alloc(k)?;

            // PKCS#1 v1.5
            let max = key_size.max_pkcs1_message();
            assert_eq!(
                pal.rsa_pkcs1_encrypt(&io, pub_size, public, message, None)
                    .await,
                Err(HsmError::InvalidArg)
            );
            let message = &message[..max];
            assert_eq!(
                pal.rsa_pkcs1_encrypt(&io, pub_size, public, message, None)
                    .await,
                Ok(k)
            );
            assert_eq!(
                pal.rsa_pkcs1_encrypt(&io, pub_size, public, message, Some(&mut *ciphertext))
                    .await,
                Ok(k)
            );
            assert_eq!(
                pal.rsa_pkcs1_decrypt(&io, key_size, private, ciphertext, None)
                    .await,
                Ok(max)
            );
            assert_eq!(
                pal.rsa_pkcs1_decrypt(
                    &io,
                    key_size,
                    private,
                    ciphertext,
                    Some(&mut plaintext[..max - 1])
                )
                .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.rsa_pkcs1_decrypt(&io, key_size, private, ciphertext, Some(&mut *plaintext))
                    .await,
                Ok(max)
            );
            assert_eq!(&plaintext[..max], message);

            // A block that is not EME-PKCS1-v1_5 encoded (EM = 2) fails the
            // padding check rather than yielding an implicit-rejection value.
            let block = alloc.dma_alloc_zeroed(k)?;
            let low = if StdHsmPal::BYTE_ORDER == HsmByteOrder::Le {
                0
            } else {
                k - 1
            };
            block[low] = 2;
            pal.mod_exp_pub(&io, pub_size, public, block, Some(&mut *ciphertext))
                .await?;
            assert_eq!(
                pal.rsa_pkcs1_decrypt(&io, key_size, private, ciphertext, Some(&mut *plaintext))
                    .await,
                Err(HsmError::RsaDecryptFailed)
            );

            // OAEP
            let max = key_size.max_oaep_message(hash);
            let message = &message[..max];
            assert_eq!(
                pal.rsa_oaep_encrypt(
                    &io,
                    pub_size,
                    hash,
                    public,
                    &plaintext[..max + 1],
                    label,
                    None
                )
                .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.rsa_oaep_encrypt(&io, pub_size, hash, public, message, label, None)
                    .await,
                Ok(k)
            );
            assert_eq!(
                pal.rsa_oaep_encrypt(
                    &io,
                    pub_size,
                    hash,
                    public,
                    message,
                    label,
                    Some(&mut *ciphertext)
                )
                .await,
                Ok(k)
            );
            assert_eq!(
                pal.rsa_oaep_decrypt(
                    &io,
                    key_size,
                    hash,
                    private,
                    ciphertext,
                    label,
                    Some(&mut *plaintext)
                )
                .await,
                Ok(max)
            );
            assert_eq!(&plaintext[..max], message);
            assert_eq!(
                pal.rsa_oaep_encrypt(
                    &io,
                    pub_size,
                    HsmHashAlgo::Sha3_256,
                    public,
                    message,
                    label,
                    None
                )
                .await,
                Err(HsmError::UnsupportedDigestHashAlgorithm)
            );
            Ok(())
        })
        .await
        .expect("RSA encrypt/decrypt");
    }

    #[tokio::test]
    async fn rsa_sign_queries_validate_hash_and_pss_salt() {
        let (pal, io) = pal_and_io();
        let key = RsaPrivateKey::generate(256).expect("RSA key");
        let mut key_bytes = vec![0; key.hsm_bytes_len()];
        key.to_hsm_bytes(&mut key_bytes).expect("serialize RSA key");

        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let private = alloc.dma_alloc(key_bytes.len())?;
            private.copy_from_slice(&key_bytes);
            let digest = alloc.dma_alloc_zeroed(64)?;
            let output = alloc.dma_alloc(256)?;

            for execute in [false, true] {
                assert_eq!(
                    pal.rsa_pkcs1_sign(
                        &io,
                        HsmRsaKey::Rsa2048Priv,
                        HsmHashAlgo::Sha3_256,
                        private,
                        &digest[..32],
                        execute.then_some(&mut *output),
                    )
                    .await,
                    Err(HsmError::UnsupportedDigestHashAlgorithm),
                );
                assert_eq!(
                    pal.rsa_pss_sign(
                        &io,
                        HsmRsaKey::Rsa2048Priv,
                        HsmHashAlgo::Sha256,
                        private,
                        &digest[..32],
                        223,
                        execute.then_some(&mut *output),
                    )
                    .await,
                    Err(HsmError::InvalidArg),
                );
            }
            Ok(())
        })
        .await
        .expect("RSA signing query validation");
    }
}
