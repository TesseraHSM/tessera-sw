// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The measured operations: request construction with per-request input
//! rotation, and checks against host reference implementations.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use clap::ValueEnum;
use rand::RngExt;
use tsra_crypto::AesCbcAlgo;
use tsra_crypto::AesKey;
use tsra_crypto::EccAlgo;
use tsra_crypto::EccPublicKey;
use tsra_crypto::Encrypter;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::MlKemPublicKey;
use tsra_crypto::Rng;
use tsra_crypto::RsaSignAlgo;
use tsra_crypto::Verifier;
use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiDev;
use tsra_ddi_interface::DdiError;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_mbor_types::DdiGetApiRevCmdReq;
use tsra_ddi_mbor_types::DdiGetApiRevReq;
use tsra_ddi_mbor_types::DdiOp;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::MlKemParams;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_44;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_65;
use tsra_ddi_tbor_test_harness::pqc::ML_DSA_87;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_1024;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_512;
use tsra_ddi_tbor_test_harness::pqc::ML_KEM_768;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborMlDsaSignReq;
use tsra_ddi_tbor_types::TborMlDsaVerifyReq;
use tsra_ddi_tbor_types::TborMlKemDecapsulateReq;
use tsra_ddi_tbor_types::TborMlKemEncapsulateReq;
use tsra_ddi_tbor_types::TborRsaModExpReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::AES_MODE_CBC;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::MLDSA_HEDGE_PREFERRED;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;
use tsra_ddi_tbor_types::RSA_OP_SIGN;

use crate::pqc;
use crate::setup::harness_call;
use crate::setup::Env;
use crate::setup::SCOPE_LOCAL;
use crate::RunArgs;

/// A measured operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub(crate) enum OpKind {
    /// MBOR `GetApiRev`, no session.
    #[value(name = "mbor-get-api-rev")]
    MborGetApiRev,
    /// TBOR `ApiRev`, no session.
    #[value(name = "tbor-get-api-rev")]
    TborGetApiRev,
    /// TBOR `EccSign`, P-256, 32-byte digest.
    #[value(name = "tbor-ecc-sign-p256")]
    EccSignP256,
    /// TBOR `EccSign`, P-384, 48-byte digest.
    #[value(name = "tbor-ecc-sign-p384")]
    EccSignP384,
    /// TBOR `EccSign`, P-521, 64-byte digest.
    #[value(name = "tbor-ecc-sign-p521")]
    EccSignP521,
    /// TBOR `RsaModExp` sign, RSA-2048.
    #[value(name = "tbor-rsa-sign-2k")]
    RsaSign2k,
    /// TBOR `RsaModExp` sign, RSA-2048 CRT.
    #[value(name = "tbor-rsa-sign-2k-crt")]
    RsaSign2kCrt,
    /// TBOR `RsaModExp` sign, RSA-3072.
    #[value(name = "tbor-rsa-sign-3k")]
    RsaSign3k,
    /// TBOR `RsaModExp` sign, RSA-3072 CRT.
    #[value(name = "tbor-rsa-sign-3k-crt")]
    RsaSign3kCrt,
    /// TBOR `RsaModExp` sign, RSA-4096.
    #[value(name = "tbor-rsa-sign-4k")]
    RsaSign4k,
    /// TBOR `RsaModExp` sign, RSA-4096 CRT.
    #[value(name = "tbor-rsa-sign-4k-crt")]
    RsaSign4kCrt,
    /// TBOR `AesEncryptDecrypt` encrypt, AES-256-CBC.
    #[value(name = "tbor-aes-cbc-encrypt")]
    AesCbcEncrypt,
    /// TBOR `AesEncryptDecrypt` decrypt, AES-256-CBC.
    #[value(name = "tbor-aes-cbc-decrypt")]
    AesCbcDecrypt,
    /// TBOR `MlDsaGenerateKey`, ML-DSA-44.
    #[value(name = "tbor-mldsa-keygen-44")]
    MlDsaKeygen44,
    /// TBOR `MlDsaGenerateKey`, ML-DSA-65.
    #[value(name = "tbor-mldsa-keygen-65")]
    MlDsaKeygen65,
    /// TBOR `MlDsaGenerateKey`, ML-DSA-87.
    #[value(name = "tbor-mldsa-keygen-87")]
    MlDsaKeygen87,
    /// TBOR `MlDsaSign`, ML-DSA-44, 64-byte `μ`.
    #[value(name = "tbor-mldsa-sign-44")]
    MlDsaSign44,
    /// TBOR `MlDsaSign`, ML-DSA-65, 64-byte `μ`.
    #[value(name = "tbor-mldsa-sign-65")]
    MlDsaSign65,
    /// TBOR `MlDsaSign`, ML-DSA-87, 64-byte `μ`.
    #[value(name = "tbor-mldsa-sign-87")]
    MlDsaSign87,
    /// TBOR `MlDsaVerify`, ML-DSA-44, 64-byte `μ`.
    #[value(name = "tbor-mldsa-verify-44")]
    MlDsaVerify44,
    /// TBOR `MlDsaVerify`, ML-DSA-65, 64-byte `μ`.
    #[value(name = "tbor-mldsa-verify-65")]
    MlDsaVerify65,
    /// TBOR `MlDsaVerify`, ML-DSA-87, 64-byte `μ`.
    #[value(name = "tbor-mldsa-verify-87")]
    MlDsaVerify87,
    /// TBOR `MlKemGenerateKey`, ML-KEM-512.
    #[value(name = "tbor-mlkem-keygen-512")]
    MlKemKeygen512,
    /// TBOR `MlKemGenerateKey`, ML-KEM-768.
    #[value(name = "tbor-mlkem-keygen-768")]
    MlKemKeygen768,
    /// TBOR `MlKemGenerateKey`, ML-KEM-1024.
    #[value(name = "tbor-mlkem-keygen-1024")]
    MlKemKeygen1024,
    /// TBOR `MlKemEncapsulate`, ML-KEM-512.
    #[value(name = "tbor-mlkem-encap-512")]
    MlKemEncap512,
    /// TBOR `MlKemEncapsulate`, ML-KEM-768.
    #[value(name = "tbor-mlkem-encap-768")]
    MlKemEncap768,
    /// TBOR `MlKemEncapsulate`, ML-KEM-1024.
    #[value(name = "tbor-mlkem-encap-1024")]
    MlKemEncap1024,
    /// TBOR `MlKemDecapsulate`, ML-KEM-512.
    #[value(name = "tbor-mlkem-decap-512")]
    MlKemDecap512,
    /// TBOR `MlKemDecapsulate`, ML-KEM-768.
    #[value(name = "tbor-mlkem-decap-768")]
    MlKemDecap768,
    /// TBOR `MlKemDecapsulate`, ML-KEM-1024.
    #[value(name = "tbor-mlkem-decap-1024")]
    MlKemDecap1024,
}

/// An ML-DSA command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlDsaCmd {
    /// `MlDsaGenerateKey`.
    Keygen,
    /// `MlDsaSign`.
    Sign,
    /// `MlDsaVerify`.
    Verify,
}

/// An ML-KEM command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlKemCmd {
    /// `MlKemGenerateKey`.
    Keygen,
    /// `MlKemEncapsulate`.
    Encap,
    /// `MlKemDecapsulate`.
    Decap,
}

impl OpKind {
    /// The command-line name.
    pub(crate) fn name(self) -> String {
        self.to_possible_value()
            .map(|v| v.get_name().to_owned())
            .unwrap_or_default()
    }

    /// `(curve, digest length)` of an ECC sign operation.
    pub(crate) fn ecc(self) -> Option<(u8, usize)> {
        match self {
            Self::EccSignP256 => Some((ECC_CURVE_P256, 32)),
            Self::EccSignP384 => Some((ECC_CURVE_P384, 48)),
            Self::EccSignP521 => Some((ECC_CURVE_P521, 64)),
            _ => None,
        }
    }

    /// `(modulus bytes, CRT)` of an RSA sign operation.
    pub(crate) fn rsa(self) -> Option<(usize, bool)> {
        match self {
            Self::RsaSign2k => Some((256, false)),
            Self::RsaSign2kCrt => Some((256, true)),
            Self::RsaSign3k => Some((384, false)),
            Self::RsaSign3kCrt => Some((384, true)),
            Self::RsaSign4k => Some((512, false)),
            Self::RsaSign4kCrt => Some((512, true)),
            _ => None,
        }
    }

    /// `(command, parameter set)` of an ML-DSA operation.
    pub(crate) fn mldsa(self) -> Option<(MlDsaCmd, &'static MlDsaParams)> {
        match self {
            Self::MlDsaKeygen44 => Some((MlDsaCmd::Keygen, &ML_DSA_44)),
            Self::MlDsaKeygen65 => Some((MlDsaCmd::Keygen, &ML_DSA_65)),
            Self::MlDsaKeygen87 => Some((MlDsaCmd::Keygen, &ML_DSA_87)),
            Self::MlDsaSign44 => Some((MlDsaCmd::Sign, &ML_DSA_44)),
            Self::MlDsaSign65 => Some((MlDsaCmd::Sign, &ML_DSA_65)),
            Self::MlDsaSign87 => Some((MlDsaCmd::Sign, &ML_DSA_87)),
            Self::MlDsaVerify44 => Some((MlDsaCmd::Verify, &ML_DSA_44)),
            Self::MlDsaVerify65 => Some((MlDsaCmd::Verify, &ML_DSA_65)),
            Self::MlDsaVerify87 => Some((MlDsaCmd::Verify, &ML_DSA_87)),
            _ => None,
        }
    }

    /// `(command, parameter set)` of an ML-KEM operation.
    pub(crate) fn mlkem(self) -> Option<(MlKemCmd, &'static MlKemParams)> {
        match self {
            Self::MlKemKeygen512 => Some((MlKemCmd::Keygen, &ML_KEM_512)),
            Self::MlKemKeygen768 => Some((MlKemCmd::Keygen, &ML_KEM_768)),
            Self::MlKemKeygen1024 => Some((MlKemCmd::Keygen, &ML_KEM_1024)),
            Self::MlKemEncap512 => Some((MlKemCmd::Encap, &ML_KEM_512)),
            Self::MlKemEncap768 => Some((MlKemCmd::Encap, &ML_KEM_768)),
            Self::MlKemEncap1024 => Some((MlKemCmd::Encap, &ML_KEM_1024)),
            Self::MlKemDecap512 => Some((MlKemCmd::Decap, &ML_KEM_512)),
            Self::MlKemDecap768 => Some((MlKemCmd::Decap, &ML_KEM_768)),
            Self::MlKemDecap1024 => Some((MlKemCmd::Decap, &ML_KEM_1024)),
            _ => None,
        }
    }

    pub(crate) fn is_cbc(self) -> bool {
        matches!(self, Self::AesCbcEncrypt | Self::AesCbcDecrypt)
    }

    /// Whether the operation runs in the shared session, with keys from
    /// setup.
    pub(crate) fn needs_session(self) -> bool {
        self.ecc().is_some()
            || self.rsa().is_some()
            || self.is_cbc()
            || self.mldsa().is_some()
            || self.mlkem().is_some()
    }

    /// Input size, for reports.
    pub(crate) fn payload(self, args: &RunArgs) -> String {
        if let Some((_, len)) = self.ecc() {
            format!("{len}B digest")
        } else if let Some((bytes, _)) = self.rsa() {
            format!("{bytes}B")
        } else if self.is_cbc() {
            format!("{}B", args.cbc_len)
        } else if let Some((MlDsaCmd::Sign | MlDsaCmd::Verify, _)) = self.mldsa() {
            format!("{MLDSA_MU_LEN}B mu")
        } else if let Some((MlKemCmd::Encap | MlKemCmd::Decap, p)) = self.mlkem() {
            format!("{}B ct", p.ciphertext_len)
        } else {
            "-".into()
        }
    }
}

/// `NAME` or `NAME=WEIGHT`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpWeight {
    pub(crate) op: OpKind,
    pub(crate) weight: u32,
}

impl FromStr for OpWeight {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (name, weight) = match s.split_once('=') {
            Some((name, w)) => (
                name,
                w.parse::<u32>()
                    .map_err(|e| format!("bad weight in {s:?}: {e}"))?,
            ),
            None => (s, 1),
        };
        if weight == 0 {
            return Err(format!("weight must be at least 1 in {s:?}"));
        }
        let op = <OpKind as ValueEnum>::from_str(name, true)?;
        Ok(Self { op, weight })
    }
}

struct RsaMsg {
    /// Big-endian, for the host check.
    be: Vec<u8>,
    /// Little-endian, as the device takes it.
    le: Vec<u8>,
}

struct CbcEntry {
    key: usize,
    iv: [u8; 16],
    pt: Vec<u8>,
    ct: Vec<u8>,
}

/// Per-thread message pools.
#[derive(Default)]
struct Pools {
    digests: Vec<[u8; 64]>,
    /// Keyed by modulus bytes.
    rsa: BTreeMap<usize, Vec<RsaMsg>>,
    cbc: Vec<CbcEntry>,
    /// Messages for `MlDsaSign`.
    mldsa: Vec<Vec<u8>>,
}

impl Pools {
    fn new(env: &Env, args: &RunArgs, kinds: &[OpKind]) -> Result<Self, String> {
        let mut rng = rand::rng();
        let n = args.messages;
        let mut pools = Self::default();

        if kinds.iter().any(|k| k.ecc().is_some()) {
            pools.digests = (0..n)
                .map(|_| {
                    let mut d = [0u8; 64];
                    rng.fill(&mut d[..]);
                    d
                })
                .collect();
        }

        for (bytes, _) in kinds.iter().filter_map(|k| k.rsa()) {
            pools.rsa.entry(bytes).or_insert_with(|| {
                (0..n)
                    .map(|_| {
                        // Below every modulus of this size: moduli have the
                        // top bit set.
                        let mut be = vec![0u8; bytes];
                        rng.fill(&mut be[..]);
                        be[0] = 0x01;
                        let le = be.iter().rev().copied().collect();
                        RsaMsg { be, le }
                    })
                    .collect()
            });
        }

        if kinds.iter().any(|k| k.is_cbc()) {
            let keys = &env.keys.aes;
            pools.cbc = (0..n)
                .map(|j| {
                    let key = j % keys.len();
                    let iv = Rng::rand_vec(16)
                        .map_err(|e| format!("host CBC IV: {e:?}"))?
                        .try_into()
                        .map_err(|_| "unexpected CBC IV length")?;
                    let mut pt = vec![0u8; args.cbc_len];
                    rng.fill(&mut pt[..]);
                    let ct = host_cbc_encrypt(&keys[key].raw, &iv, &pt)?;
                    Ok(CbcEntry { key, iv, pt, ct })
                })
                .collect::<Result<_, String>>()?;
        }

        if kinds
            .iter()
            .any(|k| matches!(k.mldsa(), Some((MlDsaCmd::Sign, _))))
        {
            pools.mldsa = (0..n)
                .map(|_| Rng::rand_vec(MLDSA_MU_LEN))
                .collect::<Result<_, _>>()
                .map_err(|e| format!("host ML-DSA mu: {e:?}"))?;
        }
        Ok(pools)
    }
}

/// One thread's device handles and inputs.
pub(crate) struct Worker<'e> {
    env: &'e Env,
    /// This thread's own fd for out-of-session TBOR commands.
    own: Option<TestCtx>,
    /// This thread's own fd for MBOR commands.
    mbor: Option<<TsraDdi as Ddi>::Dev>,
    pools: Pools,
    tid: u16,
    /// Requests issued; drives input rotation.
    seq: u64,
    /// The indices [`Self::rotate_shared`] returned last, so a pre-flight
    /// follow-up can reuse that request's inputs.
    last_shared: (usize, usize),
    last_mldsa_keygen: Option<(Vec<u8>, MlDsaPublicKey)>,
    /// The ML-KEM key pair the last keygen response returned, once checked,
    /// for [`Self::prove_mlkem_keygen`] to decapsulate with.
    last_mlkem_keygen: Option<(Vec<u8>, MlKemPublicKey)>,
}

/// Time one device call.
fn timed<T>(call: impl FnOnce() -> DdiResult<T>) -> (Duration, Result<T, String>) {
    let start = Instant::now();
    let result = call();
    (start.elapsed(), result.map_err(|e| format!("{e:?}")))
}

fn ensure(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(what.into())
    }
}

/// Record `value` the first time; afterwards require the same value.
fn same_as_first(
    slot: &std::sync::OnceLock<String>,
    value: String,
    what: &str,
) -> Result<(), String> {
    let first = slot.get_or_init(|| value.clone());
    ensure(*first == value, what)
}

impl<'e> Worker<'e> {
    /// Open this thread's handles and build its inputs for `kinds`.
    pub(crate) fn new(
        env: &'e Env,
        args: &RunArgs,
        tid: usize,
        kinds: &[OpKind],
    ) -> Result<Self, String> {
        let own = if kinds.contains(&OpKind::TborGetApiRev) {
            Some(harness_call(&format!("open {}", env.path), || {
                TestCtx::new_with_path(&env.path)
            })?)
        } else {
            None
        };
        let mbor = if kinds.contains(&OpKind::MborGetApiRev) {
            Some(
                TsraDdi::default()
                    .open_dev(&env.path)
                    .map_err(|e| format!("open {}: {e:?}", env.path))?,
            )
        } else {
            None
        };
        Ok(Self {
            env,
            own,
            mbor,
            pools: Pools::new(env, args, kinds)?,
            tid: tid as u16,
            seq: 0,
            last_shared: (0, 0),
            last_mldsa_keygen: None,
            last_mlkem_keygen: None,
        })
    }

    /// Next `(key, message)` indices: every key meets every message.
    fn rotate(&mut self, keys: usize, msgs: usize) -> (usize, usize) {
        let n = self.seq as usize;
        self.seq += 1;
        (n % keys, (n / keys) % msgs)
    }

    /// [`Self::rotate`] over inputs all threads share: each thread starts at
    /// its own key and message, so concurrent requests differ.
    fn rotate_shared(&mut self, keys: usize, msgs: usize) -> (usize, usize) {
        let (k, m) = self.rotate(keys, msgs);
        let t = usize::from(self.tid);
        self.last_shared = ((k + t) % keys, (m + t) % msgs);
        self.last_shared
    }

    fn own(&self) -> &TestCtx {
        self.own
            .as_ref()
            .expect("opened for out-of-session TBOR operations")
    }

    /// Issue one `op` request. Returns the device call's duration and,
    /// with `verify`, the host check's verdict.
    pub(crate) fn exec(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        match op {
            OpKind::MborGetApiRev => self.mbor_api_rev(verify),
            OpKind::TborGetApiRev => self.tbor_api_rev(verify),
            OpKind::EccSignP256 | OpKind::EccSignP384 | OpKind::EccSignP521 => {
                self.ecc_sign(op, verify)
            }
            OpKind::RsaSign2k
            | OpKind::RsaSign2kCrt
            | OpKind::RsaSign3k
            | OpKind::RsaSign3kCrt
            | OpKind::RsaSign4k
            | OpKind::RsaSign4kCrt => self.rsa_sign(op, verify),
            OpKind::AesCbcEncrypt => self.cbc(true, verify),
            OpKind::AesCbcDecrypt => self.cbc(false, verify),
            OpKind::MlDsaKeygen44 | OpKind::MlDsaKeygen65 | OpKind::MlDsaKeygen87 => {
                self.mldsa_keygen(op, verify)
            }
            OpKind::MlDsaSign44 | OpKind::MlDsaSign65 | OpKind::MlDsaSign87 => {
                self.mldsa_sign(op, verify)
            }
            OpKind::MlDsaVerify44 | OpKind::MlDsaVerify65 | OpKind::MlDsaVerify87 => {
                self.mldsa_verify(op)
            }
            OpKind::MlKemKeygen512 | OpKind::MlKemKeygen768 | OpKind::MlKemKeygen1024 => {
                self.mlkem_keygen(op, verify)
            }
            OpKind::MlKemEncap512 | OpKind::MlKemEncap768 | OpKind::MlKemEncap1024 => {
                self.mlkem_encap(op, verify)
            }
            OpKind::MlKemDecap512 | OpKind::MlKemDecap768 | OpKind::MlKemDecap1024 => {
                self.mlkem_decap(op, verify)
            }
        }
    }

    /// Pre-flight follow-up to a checked `op` request, for operations whose
    /// response alone cannot show that the device did the work: a PQC
    /// keygen's checked response must be usable, and `MlDsaVerify` must
    /// reject a tampered signature. Other operations have none.
    pub(crate) fn prove(&mut self, op: OpKind) -> Result<(), String> {
        match op {
            OpKind::MlDsaKeygen44 | OpKind::MlDsaKeygen65 | OpKind::MlDsaKeygen87 => {
                self.prove_mldsa_keygen(op)
            }
            OpKind::MlDsaVerify44 | OpKind::MlDsaVerify65 | OpKind::MlDsaVerify87 => {
                self.prove_mldsa_verify(op)
            }
            OpKind::MlKemKeygen512 | OpKind::MlKemKeygen768 | OpKind::MlKemKeygen1024 => {
                self.prove_mlkem_keygen(op)
            }
            _ => Ok(()),
        }
    }

    /// Session-less and without an API revision, as the firmware requires
    /// of `GetApiRev`.
    fn mbor_api_rev(&mut self, verify: bool) -> (Duration, Result<(), String>) {
        let dev = self.mbor.as_ref().expect("opened for MBOR operations");
        let req = DdiGetApiRevCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetApiRev,
                sess_id: None,
                rev: None,
            },
            data: DdiGetApiRevReq {},
            ext: None,
        };
        let (dt, resp) = timed(|| dev.exec_op_mbor(&req, &mut None));
        let result = resp.and_then(|r| {
            if verify {
                same_as_first(
                    &self.env.mbor_rev,
                    format!("{:?}", r.data),
                    "MBOR API revision changed",
                )
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    fn tbor_api_rev(&mut self, verify: bool) -> (Duration, Result<(), String>) {
        let (dt, resp) = timed(|| self.own().api_rev());
        let result = resp.and_then(|r| {
            if verify {
                same_as_first(
                    &self.env.tbor_rev,
                    format!("{r:?}"),
                    "TBOR API revision changed",
                )
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    fn ecc_sign(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (curve, len) = op.ecc().expect("ECC sign operation");
        let env = self.env;
        let keys = &env.keys.ecc[&curve];
        let (k, m) = self.rotate(keys.len(), self.pools.digests.len());
        let key = &keys[k];
        let req = TborEccSignReq {
            session_id: env.session_id,
            masked_key: key.masked.clone(),
            digest: self.pools.digests[m][..len].to_vec(),
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                verify_wire_ecdsa(&key.pub_le, &r.signature, &req.digest)
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    fn rsa_sign(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (bytes, crt) = op.rsa().expect("RSA sign operation");
        let env = self.env;
        let keys = &env.keys.rsa[&(bytes, crt)];
        let msgs_len = self.pools.rsa[&bytes].len();
        let (k, m) = self.rotate(keys.len(), msgs_len);
        let key = &keys[k];
        let msg = &self.pools.rsa[&bytes][m];
        let req = TborRsaModExpReq {
            session_id: env.session_id,
            masked_key: key.masked.clone(),
            op_type: RSA_OP_SIGN,
            y: msg.le.clone(),
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if !verify {
                return Ok(());
            }
            ensure(r.x.len() == bytes, "RSA result has the wrong length")?;
            let sig_be: Vec<u8> = r.x.iter().rev().copied().collect();
            let ok = Verifier::verify(
                &mut RsaSignAlgo::with_no_padding(),
                &key.public,
                &msg.be,
                &sig_be,
            )
            .map_err(|e| format!("host RSA verify: {e:?}"))?;
            ensure(ok, "RSA signature does not verify")
        });
        (dt, result)
    }

    fn cbc(&mut self, encrypt: bool, verify: bool) -> (Duration, Result<(), String>) {
        let (_, m) = self.rotate(1, self.pools.cbc.len());
        let env = self.env;
        let e = &self.pools.cbc[m];
        let (input, expected) = if encrypt {
            (&e.pt, &e.ct)
        } else {
            (&e.ct, &e.pt)
        };
        let req = TborAesEncryptDecryptReq {
            session_id: env.session_id,
            masked_key: env.keys.aes[e.key].masked.clone(),
            op: if encrypt {
                AES_OP_ENCRYPT
            } else {
                AES_OP_DECRYPT
            },
            mode: AES_MODE_CBC,
            msg: input.clone(),
            iv: e.iv.to_vec(),
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                ensure(r.msg == *expected, "AES-CBC output differs from the host's")
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    fn mldsa_keygen(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (_, p) = op.mldsa().expect("ML-DSA operation");
        let env = self.env;
        let req = pqc::mldsa_keygen_req(env.session_id, p);
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let mut checked_key = None;
        let result = resp.and_then(|r| {
            if verify {
                let public = pqc::check_mldsa_key(p, &r.pub_key, &r.masked_key)?;
                checked_key = Some((r.masked_key, public));
                Ok(())
            } else {
                Ok(())
            }
        });
        self.last_mldsa_keygen = checked_key;
        (dt, result)
    }

    fn mldsa_sign(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (_, p) = op.mldsa().expect("ML-DSA operation");
        let env = self.env;
        let keys = &env.keys.mldsa[&p.key_kind];
        let (k, m) = self.rotate(keys.len(), self.pools.mldsa.len());
        let key = &keys[k];
        let req = TborMlDsaSignReq {
            session_id: env.session_id,
            masked_key: key.masked.clone(),
            mu: self.pools.mldsa[m].clone(),
            hedge: MLDSA_HEDGE_PREFERRED,
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                pqc::check_mldsa_sig(p, &key.public, &req.mu, &r.signature)
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    /// The device's verdict is the check: a signature it rejects fails the
    /// request, so every request is checked.
    fn mldsa_verify(&mut self, op: OpKind) -> (Duration, Result<(), String>) {
        let (_, p) = op.mldsa().expect("ML-DSA operation");
        let env = self.env;
        let signed = &env.keys.mldsa_signed[&p.key_kind];
        let (k, m) = self.rotate_shared(signed.keys.len(), signed.mus.len());
        let req = TborMlDsaVerifyReq {
            session_id: env.session_id,
            pub_key: signed.keys[k].pub_key.clone(),
            mu: signed.mus[m].clone(),
            signature: signed.keys[k].sigs[m].clone(),
        };
        // The device error is kept so that a rejection is reported by name.
        let (dt, resp) = timed(|| Ok(env.session_ctx().tbor(&req)));
        let result = resp.and_then(|r| match r {
            Ok(_) => Ok(()),
            Err(DdiError::TborStatus(TborStatus::MlDsaVerifyFailed)) => {
                Err("MlDsaVerify rejected a valid signature".into())
            }
            Err(e) => Err(format!("{e:?}")),
        });
        (dt, result)
    }

    fn mlkem_keygen(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (_, p) = op.mlkem().expect("ML-KEM operation");
        let env = self.env;
        let req = pqc::mlkem_keygen_req(env.session_id, p);
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let mut checked_key = None;
        let result = resp.and_then(|r| {
            if verify {
                let public = pqc::check_mlkem_key(p, &r.pub_key, &r.masked_key)?;
                checked_key = Some((r.masked_key, public));
                Ok(())
            } else {
                Ok(())
            }
        });
        self.last_mlkem_keygen = checked_key;
        (dt, result)
    }

    fn mlkem_encap(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (_, p) = op.mlkem().expect("ML-KEM operation");
        let env = self.env;
        let keys = &env.keys.mlkem_pub[&p.key_kind];
        let (k, _) = self.rotate_shared(keys.len(), 1);
        let req = TborMlKemEncapsulateReq {
            session_id: env.session_id,
            scope: SCOPE_LOCAL,
            pub_key: keys[k].clone(),
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                pqc::check_mlkem_ct(p, &r.ciphertext)?;
                pqc::check_masked_secret(&r.masked_shared_secret)
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    fn mlkem_decap(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (_, p) = op.mlkem().expect("ML-KEM operation");
        let env = self.env;
        let keys = &env.keys.mlkem[&p.key_kind];
        // Every key has `--messages` ciphertexts.
        let (k, m) = self.rotate_shared(keys.len(), keys[0].cts.len());
        let key = &keys[k];
        let req = TborMlKemDecapsulateReq {
            session_id: env.session_id,
            scope: SCOPE_LOCAL,
            masked_key: key.masked.clone(),
            ciphertext: key.cts[m].clone(),
        };
        let (dt, resp) = timed(|| env.session_ctx().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                pqc::check_masked_secret(&r.masked_shared_secret)
            } else {
                Ok(())
            }
        });
        (dt, result)
    }

    /// Generate an ML-DSA key, sign with it on the device, and verify the
    /// signature with its public key on the host.
    fn prove_mldsa_keygen(&mut self, op: OpKind) -> Result<(), String> {
        let (_, p) = op.mldsa().expect("ML-DSA operation");
        let env = self.env;
        let (masked_key, public) = self
            .last_mldsa_keygen
            .take()
            .ok_or("no checked ML-DSA keygen response to prove")?;
        let mu = Rng::rand_vec(MLDSA_MU_LEN).map_err(|e| format!("host ML-DSA mu: {e:?}"))?;
        let signed = env
            .session_ctx()
            .tbor(&TborMlDsaSignReq {
                session_id: env.session_id,
                masked_key,
                mu: mu.clone(),
                hedge: MLDSA_HEDGE_PREFERRED,
            })
            .map_err(|e| format!("MlDsaSign with a generated key: {e:?}"))?;
        pqc::check_mldsa_sig(p, &public, &mu, &signed.signature)
    }

    /// `MlDsaVerify` must reject a signature with a flipped bit. Tampers
    /// with the signature the preceding request had the device accept, so
    /// the pre-flight checks every key both ways.
    fn prove_mldsa_verify(&mut self, op: OpKind) -> Result<(), String> {
        let (_, p) = op.mldsa().expect("ML-DSA operation");
        let env = self.env;
        let signed = &env.keys.mldsa_signed[&p.key_kind];
        let (k, m) = self.last_shared;
        let mut signature = signed.keys[k].sigs[m].clone();
        // The signature starts with the challenge hash, which any change to
        // it breaks.
        signature[0] ^= 0x01;
        let resp = env.session_ctx().tbor(&TborMlDsaVerifyReq {
            session_id: env.session_id,
            pub_key: signed.keys[k].pub_key.clone(),
            mu: signed.mus[m].clone(),
            signature,
        });
        match resp {
            Err(DdiError::TborStatus(TborStatus::MlDsaVerifyFailed)) => Ok(()),
            Ok(_) => Err("MlDsaVerify accepted a tampered signature".into()),
            Err(e) => Err(format!("MlDsaVerify of a tampered signature: {e:?}")),
        }
    }

    /// Have the device decapsulate a host ciphertext with the key pair the
    /// checked keygen response returned. The device masks the shared secret,
    /// so this shows the key is usable, not that the two sides agree on the
    /// secret.
    fn prove_mlkem_keygen(&mut self, op: OpKind) -> Result<(), String> {
        let (_, p) = op.mlkem().expect("ML-KEM operation");
        let env = self.env;
        let (masked_key, public) = self
            .last_mlkem_keygen
            .take()
            .ok_or("no checked ML-KEM keygen response to prove")?;
        let decap = env
            .session_ctx()
            .tbor(&TborMlKemDecapsulateReq {
                session_id: env.session_id,
                scope: SCOPE_LOCAL,
                masked_key,
                ciphertext: pqc::host_encapsulate(p, &public)?,
            })
            .map_err(|e| format!("MlKemDecapsulate with a generated key: {e:?}"))?;
        pqc::check_masked_secret(&decap.masked_shared_secret)
    }
}

/// Verify a wire-format ECDSA signature (`r_le ‖ s_le`) over `digest`
/// against a wire-format public key (`x_le ‖ y_le`).
fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest: &[u8]) -> Result<(), String> {
    // Wire coordinates are zero-padded: P-521's 66 bytes travel as 68.
    let (wire, raw) = match pub_le.len() {
        64 => (32, 32),
        96 => (48, 48),
        136 => (68, 66),
        n => return Err(format!("unexpected ECC public key length {n}")),
    };
    ensure(
        sig_le.len() == 2 * wire,
        "ECDSA signature has the wrong length",
    )?;
    let rev = |b: &[u8]| b.iter().rev().copied().collect::<Vec<u8>>();

    let mut pub_be = rev(&pub_le[..wire]);
    pub_be.extend(rev(&pub_le[wire..]));
    let key = EccPublicKey::from_hsm_bytes(&pub_be).map_err(|e| format!("ECC key: {e:?}"))?;
    let mut sig_be = rev(&sig_le[..raw]);
    sig_be.extend(rev(&sig_le[wire..wire + raw]));

    // The device takes the digest little-endian.
    let ok = Verifier::verify(&mut EccAlgo::default(), &key, &rev(digest), &sig_be)
        .map_err(|e| format!("host ECDSA verify: {e:?}"))?;
    ensure(ok, "ECDSA signature does not verify")
}

fn host_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>, String> {
    let key = AesKey::from_bytes(key).map_err(|e| format!("host AES key: {e:?}"))?;
    Encrypter::encrypt_vec(&mut AesCbcAlgo::with_no_padding(iv), &key, pt)
        .map_err(|e| format!("host AES-CBC: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::OpKind;
    use super::OpWeight;

    #[test]
    fn op_weight_parses_name_and_optional_weight() {
        let w: OpWeight = "tbor-get-api-rev".parse().expect("bare name");
        assert_eq!((w.op, w.weight), (OpKind::TborGetApiRev, 1));
        let w: OpWeight = "mbor-get-api-rev=3".parse().expect("weighted");
        assert_eq!((w.op, w.weight), (OpKind::MborGetApiRev, 3));
        for bad in [
            "mbor-get-api-rev=0",
            "mbor-get-api-rev=x",
            "mbor-get-api-rev=-1",
            "mbor-get-api-rev=4294967296",
            "no-such-op",
        ] {
            assert!(bad.parse::<OpWeight>().is_err(), "{bad} was accepted");
        }
    }
}
