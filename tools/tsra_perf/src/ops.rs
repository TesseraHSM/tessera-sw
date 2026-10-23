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
use tsra_crypto::AesGcmAlgo;
use tsra_crypto::AesKey;
use tsra_crypto::EccAlgo;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EncryptOp;
use tsra_crypto::Encrypter;
use tsra_crypto::ImportableKey;
use tsra_crypto::RsaSignAlgo;
use tsra_crypto::Verifier;
use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiResult;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_ecc_sign;
use tsra_ddi_mbor_test_helpers::helper_get_api_rev;
use tsra_ddi_mbor_types::DdiHashAlgorithm;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesEncryptDecryptReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::TborRsaModExpReq;
use tsra_ddi_tbor_types::TborTestAesGcmReq;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::ECC_CURVE_P521;
use tsra_ddi_tbor_types::RSA_OP_SIGN;

use crate::mbor::REV;
use crate::setup::Env;
use crate::RunArgs;

/// A measured operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub(crate) enum OpKind {
    /// MBOR `GetApiRev`.
    #[value(name = "mbor-get-api-rev")]
    MborGetApiRev,
    /// MBOR `EccSign`, P-256, 32-byte digest (firmware with `mbor`).
    #[value(name = "mbor-ecc-sign-p256")]
    MborEccSignP256,
    /// MBOR `EccSign`, P-384, 48-byte digest (firmware with `mbor`).
    #[value(name = "mbor-ecc-sign-p384")]
    MborEccSignP384,
    /// TBOR `ApiRev`.
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
    /// TBOR `TestAesGcm` encrypt (test-only command, raw key).
    #[value(name = "tbor-aes-gcm-encrypt")]
    AesGcmEncrypt,
    /// TBOR `TestAesGcm` decrypt (test-only command, raw key).
    #[value(name = "tbor-aes-gcm-decrypt")]
    AesGcmDecrypt,
    /// TBOR `AesEncryptDecrypt` encrypt, AES-256-CBC.
    #[value(name = "tbor-aes-cbc-encrypt")]
    AesCbcEncrypt,
    /// TBOR `AesEncryptDecrypt` decrypt, AES-256-CBC.
    #[value(name = "tbor-aes-cbc-decrypt")]
    AesCbcDecrypt,
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

    /// `(curve, digest length, hash)` of an MBOR ECC sign operation.
    pub(crate) fn mbor_ecc(self) -> Option<(u8, usize, DdiHashAlgorithm)> {
        match self {
            Self::MborEccSignP256 => Some((ECC_CURVE_P256, 32, DdiHashAlgorithm::Sha256)),
            Self::MborEccSignP384 => Some((ECC_CURVE_P384, 48, DdiHashAlgorithm::Sha384)),
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

    fn is_gcm(self) -> bool {
        matches!(self, Self::AesGcmEncrypt | Self::AesGcmDecrypt)
    }

    fn is_cbc(self) -> bool {
        matches!(self, Self::AesCbcEncrypt | Self::AesCbcDecrypt)
    }

    /// Whether the operation runs in the shared session, with keys from
    /// setup.
    pub(crate) fn needs_session(self) -> bool {
        self.ecc().is_some() || self.rsa().is_some() || self.is_cbc()
    }

    /// Input size, for reports.
    pub(crate) fn payload(self, args: &RunArgs) -> String {
        if let Some((_, len)) = self.ecc() {
            format!("{len}B digest")
        } else if let Some((_, len, _)) = self.mbor_ecc() {
            format!("{len}B digest")
        } else if let Some((bytes, _)) = self.rsa() {
            format!("{bytes}B")
        } else if self.is_gcm() {
            format!("{}B+{}B AAD", args.gcm_len, args.gcm_aad_len)
        } else if self.is_cbc() {
            format!("{}B", args.cbc_len)
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

struct GcmEntry {
    key: usize,
    iv: [u8; 12],
    aad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: [u8; 16],
}

/// Per-thread message pools.
#[derive(Default)]
struct Pools {
    digests: Vec<[u8; 64]>,
    /// Keyed by modulus bytes.
    rsa: BTreeMap<usize, Vec<RsaMsg>>,
    cbc: Vec<CbcEntry>,
    gcm: Vec<GcmEntry>,
}

impl Pools {
    fn new(env: &Env, args: &RunArgs, kinds: &[OpKind]) -> Result<Self, String> {
        let mut rng = rand::rng();
        let n = args.messages;
        let mut pools = Self::default();

        if kinds
            .iter()
            .any(|k| k.ecc().is_some() || k.mbor_ecc().is_some())
        {
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
                    let mut iv = [0u8; 16];
                    rng.fill(&mut iv[..]);
                    let mut pt = vec![0u8; args.cbc_len];
                    rng.fill(&mut pt[..]);
                    let ct = host_cbc_encrypt(&keys[key].raw, &iv, &pt)?;
                    Ok(CbcEntry { key, iv, pt, ct })
                })
                .collect::<Result<_, String>>()?;
        }

        if kinds.iter().any(|k| k.is_gcm()) {
            let keys = &env.keys.gcm;
            pools.gcm = (0..n)
                .map(|j| {
                    let key = j % keys.len();
                    let mut iv = [0u8; 12];
                    rng.fill(&mut iv[..]);
                    let mut aad = vec![0u8; args.gcm_aad_len];
                    rng.fill(&mut aad[..]);
                    let mut pt = vec![0u8; args.gcm_len];
                    rng.fill(&mut pt[..]);
                    let (ct, tag) = host_gcm_seal(&keys[key], &iv, &aad, &pt)?;
                    Ok(GcmEntry {
                        key,
                        iv,
                        aad,
                        pt,
                        ct,
                        tag,
                    })
                })
                .collect::<Result<_, String>>()?;
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
    /// Requests issued; drives input rotation and GCM IVs.
    seq: u64,
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
        let own = kinds
            .iter()
            .any(|k| *k == OpKind::TborGetApiRev || k.is_gcm())
            .then(|| TestCtx::new_with_path(&env.path));
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
        })
    }

    /// Next `(key, message)` indices: every key meets every message.
    fn rotate(&mut self, keys: usize, msgs: usize) -> (usize, usize) {
        let n = self.seq as usize;
        self.seq += 1;
        (n % keys, (n / keys) % msgs)
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
            OpKind::MborEccSignP256 | OpKind::MborEccSignP384 => self.mbor_ecc_sign(op, verify),
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
            OpKind::AesGcmEncrypt => self.gcm_encrypt(verify),
            OpKind::AesGcmDecrypt => self.gcm_decrypt(verify),
            OpKind::AesCbcEncrypt => self.cbc(true, verify),
            OpKind::AesCbcDecrypt => self.cbc(false, verify),
        }
    }

    fn mbor_api_rev(&mut self, verify: bool) -> (Duration, Result<(), String>) {
        let dev = self.mbor.as_ref().expect("opened for MBOR operations");
        let (dt, resp) = timed(|| helper_get_api_rev(dev, None, None));
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

    fn mbor_ecc_sign(&mut self, op: OpKind, verify: bool) -> (Duration, Result<(), String>) {
        let (curve, len, hash) = op.mbor_ecc().expect("MBOR ECC sign operation");
        let mbor = self.env.mbor_session();
        let keys = &mbor.ecc[&curve];
        let (k, m) = self.rotate(keys.len(), self.pools.digests.len());
        let key = &keys[k];
        let digest = &self.pools.digests[m][..len];
        let arg = match MborByteArray::from_slice(digest) {
            Ok(a) => a,
            Err(e) => return (Duration::ZERO, Err(format!("digest: {e:?}"))),
        };
        let (dt, resp) = timed(|| {
            helper_ecc_sign(
                &mbor.dev,
                Some(mbor.session_id),
                Some(REV),
                key.id,
                arg,
                hash,
            )
        });
        let result = resp.and_then(|r| {
            if !verify {
                return Ok(());
            }
            // The host decode leaves the signature as big-endian `r ‖ s`.
            let ok = Verifier::verify(
                &mut EccAlgo::default(),
                &key.public,
                digest,
                r.data.signature.as_slice(),
            )
            .map_err(|e| format!("host ECDSA verify: {e:?}"))?;
            ensure(ok, "MBOR ECDSA signature does not verify")
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

    fn gcm_encrypt(&mut self, verify: bool) -> (Duration, Result<(), String>) {
        let (_, m) = self.rotate(1, self.pools.gcm.len());
        // A fresh IV per request: thread id and request number.
        let mut iv = [0u8; 12];
        iv[..2].copy_from_slice(&self.tid.to_be_bytes());
        iv[2..10].copy_from_slice(&self.seq.to_be_bytes());
        let e = &self.pools.gcm[m];
        let key = self.env.keys.gcm[e.key];
        let req = TborTestAesGcmReq {
            op: AES_OP_ENCRYPT,
            key,
            iv,
            aad: e.aad.clone(),
            data: e.pt.clone(),
            tag: [0; 16],
        };
        let (dt, resp) = timed(|| self.own().tbor(&req));
        let result = resp.and_then(|r| {
            if !verify {
                return Ok(());
            }
            let (ct, tag) = host_gcm_seal(&key, &iv, &e.aad, &e.pt)?;
            ensure(r.data == ct, "GCM ciphertext differs from the host's")?;
            ensure(r.tag == tag, "GCM tag differs from the host's")
        });
        (dt, result)
    }

    fn gcm_decrypt(&mut self, verify: bool) -> (Duration, Result<(), String>) {
        let (_, m) = self.rotate(1, self.pools.gcm.len());
        let e = &self.pools.gcm[m];
        let req = TborTestAesGcmReq {
            op: AES_OP_DECRYPT,
            key: self.env.keys.gcm[e.key],
            iv: e.iv,
            aad: e.aad.clone(),
            data: e.ct.clone(),
            tag: e.tag,
        };
        let (dt, resp) = timed(|| self.own().tbor(&req));
        let result = resp.and_then(|r| {
            if verify {
                ensure(r.data == e.pt, "GCM plaintext differs from the original")
            } else {
                Ok(())
            }
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
            msg: input.clone(),
            iv: e.iv,
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

fn host_gcm_seal(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    let key = AesKey::from_bytes(key).map_err(|e| format!("host AES key: {e:?}"))?;
    let aad = (!aad.is_empty()).then_some(aad);
    let mut algo = AesGcmAlgo::for_encrypt(iv, aad).map_err(|e| format!("host GCM: {e:?}"))?;
    let mut ct = vec![0u8; pt.len()];
    algo.encrypt(&key, pt, Some(&mut ct))
        .map_err(|e| format!("host GCM: {e:?}"))?;
    let tag = algo
        .tag()
        .try_into()
        .map_err(|_| "host GCM tag is not 16 bytes".to_owned())?;
    Ok((ct, tag))
}
