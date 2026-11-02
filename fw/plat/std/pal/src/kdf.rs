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

use tsra_crypto::HashAlgo;

use super::*;

fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
    match algo {
        HsmHashAlgo::Sha1 => HashAlgo::sha1(),
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
    }
}

impl HsmKdf for StdHsmPal {
    async fn hkdf_extract(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        salt: Option<&HsmDmaBuf>,
        ikm: &HsmDmaBuf,
        prk: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .hkdf(
                ikm,
                to_hash_algo(algo),
                tsra_crypto::HkdfMode::Extract,
                salt.map(|s| s.deref()),
                None,
                prk,
            )
            .await
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
                to_hash_algo(algo),
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
                to_hash_algo(algo),
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
                to_hash_algo(algo),
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
                to_hash_algo(algo),
                tsra_crypto::ConcatKdfMode::Sp800_56a,
                Some(other_info.deref()),
                key,
            )
            .await
    }
}
