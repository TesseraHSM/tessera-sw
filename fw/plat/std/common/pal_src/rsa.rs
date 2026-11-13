// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRsa`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (byte-slice keys —
//! recovered DER on import, the HSM byte layout for vault-stored private
//! keys, wire form for public keys) and the
//! [`StdRsa`](crate::drivers::rsa::StdRsa) driver (OpenSSL key handles).
//!
//! Raw key generation and modular exponentiation are implemented. The
//! newer padding-helper entry points are present in the trait but are not
//! currently used by the standard PAL, so they are left as `todo!()`.

use tsra_crypto::ExportableHsmKey;
use tsra_crypto::ExportableHsmRsaKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::Key;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use zeroize::Zeroizing;

use super::*;
use crate::StdHsmPal;

fn key_size_bits(key_size: HsmRsaKey) -> usize {
    key_size.modulus_len() * 8
}

impl StdHsmPal {
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
        priv_key: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        pct: HsmRsaPct,
    ) -> Result<(), HsmError> {
        let (pk, pubk) = self.rsa.gen_keypair(key_size_bits(key_size)).await?;

        // The vault stores the RSA private key in HSM byte format (raw
        // components), not DER; a generated key is stored non-CRT.
        let priv_len = pk.hsm_bytes_len();
        if priv_key.len() < priv_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }

        let mut private = Zeroizing::new(vec![0u8; priv_len]);
        pk.to_hsm_bytes(&mut private)
            .map_err(|_| HsmError::RsaToDerError)?;

        let pub_len = pubk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if pub_key.len() < pub_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
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
        Ok(())
    }

    async fn mod_exp_priv(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        y: &HsmDmaBuf,
        x: &mut HsmDmaBuf,
    ) -> Result<(), HsmError> {
        let priv_key = RsaPrivateKey::from_hsm_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_priv(&priv_key, y, x).await
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
        _key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        x: &HsmDmaBuf,
        y: &mut HsmDmaBuf,
    ) -> Result<(), HsmError> {
        let pub_key = RsaPublicKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_pub(&pub_key, x, y).await
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &StdHsmIo,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The std PAL's vault representation is HSM byte format (raw
        // components): parse it, derive the public key, and emit the raw
        // wire form `n_le || e_le`.  The BE->LE flip lives in the driver.
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

    async fn rsa_pkcs1_encrypt<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _pub_key: &HsmDmaBuf,
        _message: &HsmDmaBuf,
        _output: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_decrypt<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _priv_key: &HsmDmaBuf,
        _ciphertext: &HsmDmaBuf,
        _output: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_sign<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &HsmDmaBuf,
        _message_hash: &HsmDmaBuf,
        _signature: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_verify<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &HsmDmaBuf,
        _message_hash: &HsmDmaBuf,
        _signature: &HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_oaep_encrypt<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &HsmDmaBuf,
        _message: &HsmDmaBuf,
        _label: &HsmDmaBuf,
        _output: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_oaep_decrypt<'a>(
        &self,
        _io: &StdHsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        label: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
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
        let hash = crate::hash::to_hash_algo(algo)?;
        let label = if label.is_empty() {
            None
        } else {
            Some(label.to_vec())
        };
        self.rsa
            .oaep_decrypt(&pk, hash, label, ciphertext, output)
            .await
    }

    async fn rsa_pss_sign<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &HsmDmaBuf,
        _message_hash: &HsmDmaBuf,
        _salt_len: usize,
        _signature: &mut HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pss_verify<'a>(
        &self,
        _io: &StdHsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &HsmDmaBuf,
        _message_hash: &HsmDmaBuf,
        _salt_len: usize,
        _signature: &HsmDmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use tsra_crypto::KeyGenerationOp;

    use super::*;

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
    async fn rsa_generation_runs_selected_pct_before_output() {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (reply_tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        pal.alloc_scoped_async(&io, async |alloc| {
            let private = alloc.dma_alloc(516).unwrap();
            let public = alloc.dma_alloc(512).unwrap();
            for pct in [HsmRsaPct::SignVerify, HsmRsaPct::EncryptDecrypt] {
                pal.rsa_gen_keypair(&io, HsmRsaKey::Rsa2048Priv, private, public, pct)
                    .await
                    .unwrap();
            }
            private.fill(0xa5);
            public.fill(0xa5);
            pal.rsa_pct_fail.set(true);
            for pct in [HsmRsaPct::SignVerify, HsmRsaPct::EncryptDecrypt] {
                assert_eq!(
                    pal.rsa_gen_keypair(&io, HsmRsaKey::Rsa2048Priv, private, public, pct)
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
                private,
                public,
                HsmRsaPct::None,
            )
            .await
            .unwrap();
        })
        .await;
    }
}
