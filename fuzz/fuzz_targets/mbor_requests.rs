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
use tsra_ddi_mbor_types::*;

macro_rules! requests {
    ($($op:ident => ($request:ty, $command:ident)),+ $(,)?) => {
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

            pub fn encode(self, mut header: DdiReqHdr, seed: u64, valid_header: bool)
                -> Result<Vec<u8>, String>
            {
                let mut bytes = vec![0; 16384];
                StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
                let mut input = Unstructured::new(&bytes);
                match self {
                    $(Self::$op => {
                        let data = <$request>::arbitrary(&mut input)
                            .map_err(|err| err.to_string())?;
                        if valid_header {
                            header.op = DdiOp::$op;
                        }
                        let mut out = vec![0; 16384];
                        let len = DdiEncoder::encode_parts(header, data, &mut out, true)
                            .map_err(|err| format!("{err:?}"))?;
                        out.truncate(len);
                        Ok(out)
                    }),+
                }
            }

            pub fn execute(
                self,
                dev: &<TsraDdi as Ddi>::Dev,
                mut header: DdiReqHdr,
                seed: u64,
                valid_header: bool,
            ) -> Result<(), DdiError> {
                let mut bytes = vec![0; 16384];
                StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
                let mut input = Unstructured::new(&bytes);
                match self {
                    $(Self::$op => {
                        let Ok(data) = <$request>::arbitrary(&mut input) else {
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
    };
}

requests! {
    GetApiRev => (DdiGetApiRevReq, DdiGetApiRevCmdReq),
    GetDeviceInfo => (DdiGetDeviceInfoReq, DdiGetDeviceInfoCmdReq),
    GetCertChainInfo => (DdiGetCertChainInfoReq, DdiGetCertChainInfoCmdReq),
    GetCertificate => (DdiGetCertificateReq, DdiGetCertificateCmdReq),
    GetEstablishCredEncryptionKey => (DdiGetEstablishCredEncryptionKeyReq, DdiGetEstablishCredEncryptionKeyCmdReq),
    EstablishCredential => (DdiEstablishCredentialReq, DdiEstablishCredentialCmdReq),
    GetSessionEncryptionKey => (DdiGetSessionEncryptionKeyReq, DdiGetSessionEncryptionKeyCmdReq),
    OpenSession => (DdiOpenSessionReq, DdiOpenSessionCmdReq),
    CloseSession => (DdiCloseSessionReq, DdiCloseSessionCmdReq),
    InitBk3 => (DdiInitBk3Req, DdiInitBk3CmdReq),
    GetUnwrappingKey => (DdiGetUnwrappingKeyReq, DdiGetUnwrappingKeyCmdReq),
    DeleteKey => (DdiDeleteKeyReq, DdiDeleteKeyCmdReq),
    EccGenerateKeyPair => (DdiEccGenerateKeyPairReq, DdiEccGenerateKeyPairCmdReq),
    EccSign => (DdiEccSignReq, DdiEccSignCmdReq),
    EcdhKeyExchange => (DdiEcdhKeyExchangeReq, DdiEcdhKeyExchangeCmdReq),
    AesGenerateKey => (DdiAesGenerateKeyReq, DdiAesGenerateKeyCmdReq),
    AesEncryptDecrypt => (DdiAesEncryptDecryptReq, DdiAesEncryptDecryptCmdReq),
    Hmac => (DdiHmacReq, DdiHmacCmdReq),
    HkdfDerive => (DdiHkdfDeriveReq, DdiHkdfDeriveCmdReq),
    KbkdfCounterHmacDerive => (DdiKbkdfCounterHmacDeriveReq, DdiKbkdfCounterHmacDeriveCmdReq),
    RsaUnwrap => (DdiRsaUnwrapReq, DdiRsaUnwrapCmdReq),
    RsaModExp => (DdiRsaModExpReq, DdiRsaModExpCmdReq),
    AttestKey => (DdiAttestKeyReq, DdiAttestKeyCmdReq),
}

pub fn generate_random_testddireqs_list(count: usize, seed: u64) -> Vec<TestDdiReqs> {
    let mut bytes = vec![0; count * 4];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    let mut input = Unstructured::new(&bytes);
    (0..count)
        .filter_map(|_| TestDdiReqs::arbitrary(&mut input).ok())
        .collect()
}

pub fn get_rand_ddi_request(header: DdiReqHdr, seed: u64) -> Result<Vec<u8>, String> {
    let request = generate_random_testddireqs_list(1, seed)
        .into_iter()
        .next()
        .ok_or("Failed to select request")?;
    request.encode(header, seed, false)
}
