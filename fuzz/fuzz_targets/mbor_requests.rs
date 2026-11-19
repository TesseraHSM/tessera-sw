// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MBOR request generation shared by host and in-process firmware fuzz targets.

#![allow(dead_code)]

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::arbitrary::Unstructured;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tsra_ddi::Ddi;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi::TsraDdi;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_types::*;

const REQUEST_BUFFER_SIZE: usize = 16 * 1024;

// Keep bounded generation local to fuzzing, including nested and optional arrays.
trait BoundedArbitrary: Sized {
    fn bounded_arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self>;
}

impl<const N: usize> BoundedArbitrary for MborByteArray<N> {
    fn bounded_arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let data = u.arbitrary()?;
        let len = u.int_in_range(0..=N)?;
        Self::new(data, len).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl<T: BoundedArbitrary> BoundedArbitrary for Option<T> {
    fn bounded_arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Some(T::bounded_arbitrary(u)?))
        } else {
            Ok(None)
        }
    }
}

macro_rules! bounded_structs {
    ($($ty:ident { $($field:ident $(=> $generator:ident)?),* $(,)? }),* $(,)?) => {
        $(impl BoundedArbitrary for $ty {
            fn bounded_arbitrary(_u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
                Ok(Self {
                    $($field: bounded_structs!(@field _u $(, $generator)?)),*
                })
            }
        })*
    };
    (@field $u:ident) => { $u.arbitrary()? };
    (@field $u:ident, bounded) => { BoundedArbitrary::bounded_arbitrary($u)? };
}

bounded_structs! {
    DdiDerPublicKey { der => bounded, key_kind },
    DdiTargetKeyProperties { key_metadata, key_label => bounded },
    DdiEncryptedEstablishCredential {
        encrypted_id => bounded, encrypted_pin => bounded, iv => bounded, nonce, tag,
    },
    DdiEncryptedSessionCredential {
        encrypted_id => bounded, encrypted_pin => bounded, encrypted_seed => bounded,
        iv => bounded, nonce, tag,
    },
}

pub struct RequestBuffers {
    input: [u8; REQUEST_BUFFER_SIZE],
    output: [u8; REQUEST_BUFFER_SIZE],
}

impl Default for RequestBuffers {
    fn default() -> Self {
        Self {
            input: [0; REQUEST_BUFFER_SIZE],
            output: [0; REQUEST_BUFFER_SIZE],
        }
    }
}

macro_rules! requests {
    ($($op:ident => ($request:ident, $command:ident)
        { $($field:ident $(=> $generator:ident)?),* $(,)? }),+ $(,)?) => {
        bounded_structs! {
            $($request { $($field $(=> $generator)?),* }),+
        }

        #[derive(Arbitrary, Debug, Clone, Copy)]
        pub enum TestDdiReqs {
            $($op),+
        }

        impl TestDdiReqs {
            pub fn header(
                self,
                session: Option<u16>,
                rev: Option<DdiApiRev>,
                seed: u64,
                valid_header: bool,
            ) -> arbitrary::Result<DdiReqHdr> {
                if !valid_header {
                    let mut bytes = [0; 32];
                    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
                    return DdiReqHdr::arbitrary(&mut Unstructured::new(&bytes));
                }

                let op = match self {
                    $(Self::$op => DdiOp::$op),+
                };
                Ok(DdiReqHdr {
                    op,
                    sess_id: match SessionControlKind::from(op) {
                        SessionControlKind::NoSession | SessionControlKind::Open => None,
                        SessionControlKind::Close | SessionControlKind::InSession => session,
                    },
                    rev: if op == DdiOp::GetApiRev { None } else { rev },
                })
            }

            pub fn encode(
                self,
                mut header: DdiReqHdr,
                seed: u64,
                valid_header: bool,
                buffers: &mut RequestBuffers,
            ) -> Result<&[u8], String>
            {
                StdRng::seed_from_u64(seed).fill_bytes(&mut buffers.input);
                let mut input = Unstructured::new(&buffers.input);
                match self {
                    $(Self::$op => {
                        let data = <$request>::bounded_arbitrary(&mut input)
                            .map_err(|err| err.to_string())?;
                        if valid_header {
                            header.op = DdiOp::$op;
                        }
                        let len = DdiEncoder::encode_parts(header, data, &mut buffers.output, true)
                            .map_err(|err| format!("{err:?}"))?;
                        Ok(&buffers.output[..len])
                    }),+
                }
            }

            pub fn execute(
                self,
                dev: &<TsraDdi as Ddi>::Dev,
                mut header: DdiReqHdr,
                seed: u64,
                valid_header: bool,
                buffers: &mut RequestBuffers,
            ) -> Result<(), DdiError> {
                StdRng::seed_from_u64(seed).fill_bytes(&mut buffers.input);
                let mut input = Unstructured::new(&buffers.input);
                match self {
                    $(Self::$op => {
                        let Ok(data) = <$request>::bounded_arbitrary(&mut input) else {
                            return Ok(());
                        };
                        if valid_header {
                            header.op = DdiOp::$op;
                        }

                        let mut resp = None;
                        dev.exec_op_mbor(
                            &$command { hdr: header, data, ext: None },
                            &mut resp,
                        ).map(|_| ())
                    }),+
                }
            }
        }

        #[cfg(test)]
        #[test]
        fn seeded_requests_generate_without_rejection() {
            let mut buffers = RequestBuffers::default();
            for seed in 0..64 {
                StdRng::seed_from_u64(seed).fill_bytes(&mut buffers.input);
                $(
                    let mut input = Unstructured::new(&buffers.input);
                    <$request>::bounded_arbitrary(&mut input)
                        .expect(concat!("Failed to generate ", stringify!($request)));
                )+
            }
        }
    };
}

requests! {
    GetApiRev => (DdiGetApiRevReq, DdiGetApiRevCmdReq) {},
    GetDeviceInfo => (DdiGetDeviceInfoReq, DdiGetDeviceInfoCmdReq) {},
    GetCertChainInfo => (DdiGetCertChainInfoReq, DdiGetCertChainInfoCmdReq) { slot_id },
    GetCertificate => (DdiGetCertificateReq, DdiGetCertificateCmdReq) { slot_id, cert_id },
    GetEstablishCredEncryptionKey => (DdiGetEstablishCredEncryptionKeyReq, DdiGetEstablishCredEncryptionKeyCmdReq) {},
    EstablishCredential => (DdiEstablishCredentialReq, DdiEstablishCredentialCmdReq) {
        encrypted_credential => bounded, pub_key => bounded, masked_bk3 => bounded,
        bmk => bounded, masked_unwrapping_key => bounded, pota_sig => bounded,
        pota_pub_key => bounded,
    },
    GetSessionEncryptionKey => (DdiGetSessionEncryptionKeyReq, DdiGetSessionEncryptionKeyCmdReq) {},
    OpenSession => (DdiOpenSessionReq, DdiOpenSessionCmdReq) {
        encrypted_credential => bounded, pub_key => bounded,
    },
    CloseSession => (DdiCloseSessionReq, DdiCloseSessionCmdReq) {},
    InitBk3 => (DdiInitBk3Req, DdiInitBk3CmdReq) { bk3 => bounded },
    GetUnwrappingKey => (DdiGetUnwrappingKeyReq, DdiGetUnwrappingKeyCmdReq) {},
    DeleteKey => (DdiDeleteKeyReq, DdiDeleteKeyCmdReq) { key_id },
    EccGenerateKeyPair => (DdiEccGenerateKeyPairReq, DdiEccGenerateKeyPairCmdReq) {
        curve, key_tag, key_properties => bounded,
    },
    EccSign => (DdiEccSignReq, DdiEccSignCmdReq) {
        key_id, digest => bounded, digest_algo,
    },
    EcdhKeyExchange => (DdiEcdhKeyExchangeReq, DdiEcdhKeyExchangeCmdReq) {
        priv_key_id, pub_key_der => bounded, key_type, key_tag, key_properties => bounded,
    },
    AesGenerateKey => (DdiAesGenerateKeyReq, DdiAesGenerateKeyCmdReq) {
        key_size, key_tag, key_properties => bounded,
    },
    AesEncryptDecrypt => (DdiAesEncryptDecryptReq, DdiAesEncryptDecryptCmdReq) {
        key_id, op, msg => bounded, iv => bounded,
    },
    Hmac => (DdiHmacReq, DdiHmacCmdReq) { key_id, msg => bounded },
    HkdfDerive => (DdiHkdfDeriveReq, DdiHkdfDeriveCmdReq) {
        key_id, hash_algorithm, salt => bounded, info => bounded, key_type, key_tag,
        key_properties => bounded, key_length,
    },
    KbkdfCounterHmacDerive => (DdiKbkdfCounterHmacDeriveReq, DdiKbkdfCounterHmacDeriveCmdReq) {
        key_id, hash_algorithm, label => bounded, context => bounded, key_type, key_tag,
        key_properties => bounded, key_length,
    },
    RsaUnwrap => (DdiRsaUnwrapReq, DdiRsaUnwrapCmdReq) {
        key_id, wrapped_blob => bounded, wrapped_blob_key_class, wrapped_blob_padding,
        wrapped_blob_hash_algorithm, key_tag, key_properties => bounded,
    },
    RsaModExp => (DdiRsaModExpReq, DdiRsaModExpCmdReq) { key_id, y => bounded, op_type },
    AttestKey => (DdiAttestKeyReq, DdiAttestKeyCmdReq) { key_id, report_data => bounded },
}

pub fn generate_random_testddireqs_list(count: usize, seed: u64) -> Vec<TestDdiReqs> {
    let mut bytes = vec![0; count * 4];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    let mut input = Unstructured::new(&bytes);
    (0..count)
        .filter_map(|_| TestDdiReqs::arbitrary(&mut input).ok())
        .collect()
}

pub fn get_rand_ddi_request(
    header: DdiReqHdr,
    seed: u64,
    buffers: &mut RequestBuffers,
) -> Result<&[u8], String> {
    let request = generate_random_testddireqs_list(1, seed)
        .into_iter()
        .next()
        .ok_or("Failed to select request")?;
    request.encode(header, seed, false, buffers)
}
