// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device, partition, session and key setup, and the pre-flight
//! correctness check.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

use rand::RngExt;
use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::Encrypter;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_mbor_test_helpers::helper_close_session;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::PolicyKeyKind;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborGetUnwrappingKeyReq;
use tsra_ddi_tbor_types::TborUnwrapKeyReq;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::KEY_CLASS_AES;
use tsra_ddi_tbor_types::KEY_CLASS_RSA;
use tsra_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use tsra_ddi_tbor_types::KEY_USAGE_DECRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;
use tsra_ddi_tbor_types::KEY_USAGE_VERIFY;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::PART_POLICY_LEN;
use tsra_ddi_tbor_types::POTA_THUMBPRINT_LEN;

use crate::mbor::MborSession;
use crate::mbor::REV;
use crate::ops::MlDsaCmd;
use crate::ops::MlKemCmd;
use crate::ops::OpKind;
use crate::ops::Worker;
use crate::pqc;
use crate::pqc::MlDsaKey;
use crate::pqc::MlDsaSigned;
use crate::pqc::MlKemKey;
use crate::RunArgs;

/// `KeyScope::Local`: keys masked under the partition-local masking key,
/// usable from any session of the partition.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// A device-generated ECC key.
pub(crate) struct EccKey {
    pub(crate) masked: Vec<u8>,
    /// Wire format `x_le ‖ y_le`.
    pub(crate) pub_le: Vec<u8>,
}

/// A host-generated RSA key imported with `UnwrapKey`.
pub(crate) struct RsaKey {
    pub(crate) masked: Vec<u8>,
    pub(crate) public: RsaPublicKey,
}

/// A host-generated AES-256 key imported with `UnwrapKey`, so the host can
/// check results.
pub(crate) struct AesKeyEntry {
    pub(crate) masked: Vec<u8>,
    pub(crate) raw: [u8; 32],
}

/// Key pools, shared read-only by all workers.
#[derive(Default)]
pub(crate) struct Keys {
    pub(crate) ecc: BTreeMap<u8, Vec<EccKey>>,
    /// Keyed by `(modulus bytes, CRT)`.
    pub(crate) rsa: BTreeMap<(usize, bool), Vec<RsaKey>>,
    pub(crate) aes: Vec<AesKeyEntry>,
    /// Raw keys for the out-of-session `TestAesGcm`.
    pub(crate) gcm: Vec<[u8; 32]>,
    /// Device-generated ML-DSA keys for `MlDsaSign`, keyed by `key_kind`.
    pub(crate) mldsa: BTreeMap<u8, Vec<MlDsaKey>>,
    /// Host-signed `MlDsaVerify` inputs, keyed by `key_kind`.
    pub(crate) mldsa_signed: BTreeMap<u8, MlDsaSigned>,
    /// Host-generated encapsulation keys for `MlKemEncapsulate`, keyed by
    /// `key_kind`.
    pub(crate) mlkem_pub: BTreeMap<u8, Vec<Vec<u8>>>,
    /// Device-generated ML-KEM keys with host ciphertexts for
    /// `MlKemDecapsulate`, keyed by `key_kind`.
    pub(crate) mlkem: BTreeMap<u8, Vec<MlKemKey>>,
}

/// The device under test and everything set up on it.
pub(crate) struct Env {
    pub(crate) path: String,
    /// Opened with a factory reset; holds the Crypto Officer session that
    /// keyed operations share. `None` when no selected operation needs a
    /// session.
    ctx: Option<TestCtx>,
    pub(crate) session_id: u16,
    pub(crate) keys: Keys,
    /// The MBOR session and keys of keyed MBOR operations.
    mbor: Option<MborSession>,
    /// API revisions seen in the pre-flight check, which later responses
    /// must repeat.
    pub(crate) mbor_rev: OnceLock<String>,
    pub(crate) tbor_rev: OnceLock<String>,
}

impl Env {
    /// Open the device, set up what `kinds` need, and run the pre-flight
    /// check.
    pub(crate) fn new(args: &RunArgs, kinds: &BTreeSet<OpKind>) -> Result<Self, String> {
        let infos = TsraDdi::default().dev_info_list();
        let path = infos
            .get(args.device)
            .ok_or_else(|| format!("no device {} ({} found)", args.device, infos.len()))?
            .path
            .clone();
        say(args, format!("device: {path}"));

        let mut env = Self {
            path,
            ctx: None,
            session_id: 0,
            keys: Keys::default(),
            mbor: None,
            mbor_rev: OnceLock::new(),
            tbor_rev: OnceLock::new(),
        };

        let mbor_curves: Vec<u8> = kinds
            .iter()
            .filter_map(|k| k.mbor_ecc().map(|m| m.0))
            .collect();
        if !mbor_curves.is_empty() {
            if kinds.iter().any(|k| k.needs_session()) {
                return Err("keyed MBOR and TBOR operations need separate runs (and a \
                            power cycle between them)"
                    .into());
            }
            say(args, "factory reset, MBOR credential and session".into());
            env.mbor = Some(MborSession::open(&env.path, &mbor_curves, args.keys)?);
        }

        if kinds.iter().any(|k| k.needs_session()) {
            say(
                args,
                "factory reset, partition init/final, CO session".into(),
            );
            let ctx = TestCtx::new_primary_with_path(&env.path);
            env.session_id = finalized_co_session(&ctx)?;
            env.ctx = Some(ctx);
            env.make_keys(args, kinds)?;
        }
        if kinds
            .iter()
            .any(|k| matches!(k, OpKind::AesGcmEncrypt | OpKind::AesGcmDecrypt))
        {
            let mut rng = rand::rng();
            env.keys.gcm = (0..args.keys)
                .map(|_| {
                    let mut k = [0u8; 32];
                    rng.fill(&mut k[..]);
                    k
                })
                .collect();
        }

        env.preflight(args, kinds)?;
        Ok(env)
    }

    /// The session context keyed operations run on.
    pub(crate) fn session_ctx(&self) -> &TestCtx {
        self.ctx
            .as_ref()
            .expect("keyed operations require the session set up by Env::new")
    }

    /// The MBOR session keyed MBOR operations run on.
    pub(crate) fn mbor_session(&self) -> &MborSession {
        self.mbor
            .as_ref()
            .expect("keyed MBOR operations require the session set up by Env::new")
    }

    /// Close the sessions.
    pub(crate) fn close(self) {
        if let Some(ctx) = &self.ctx {
            if let Err(e) = ctx.session_close(self.session_id) {
                eprintln!("warning: closing session {}: {e:?}", self.session_id);
            }
        }
        if let Some(m) = &self.mbor {
            if let Err(e) = helper_close_session(&m.dev, Some(m.session_id), Some(REV)) {
                eprintln!("warning: closing MBOR session {}: {e:?}", m.session_id);
            }
        }
    }

    fn make_keys(&mut self, args: &RunArgs, kinds: &BTreeSet<OpKind>) -> Result<(), String> {
        let ctx = self.session_ctx();
        let session_id = self.session_id;
        let mut keys = Keys::default();

        for (curve, _) in kinds.iter().filter_map(|k| k.ecc()) {
            say(
                args,
                format!("generating {} ECC keys (curve {curve})", args.keys),
            );
            let pool = (0..args.keys)
                .map(|_| {
                    let resp = ctx
                        .tbor(&TborEccGenerateKeyReq {
                            session_id,
                            scope: SCOPE_LOCAL,
                            curve,
                            key_usage: KEY_USAGE_SIGN,
                            key_label: Vec::new(),
                        })
                        .map_err(|e| format!("EccGenerateKey: {e:?}"))?;
                    Ok(EccKey {
                        masked: resp.masked_key,
                        pub_le: resp.pub_key,
                    })
                })
                .collect::<Result<_, String>>()?;
            keys.ecc.insert(curve, pool);
        }

        for (bytes, crt) in kinds.iter().filter_map(|k| k.rsa()) {
            say(
                args,
                format!(
                    "importing {} RSA-{} keys{}",
                    args.keys,
                    bytes * 8,
                    if crt { " (CRT)" } else { "" }
                ),
            );
            let class = if crt {
                KEY_CLASS_RSA_CRT
            } else {
                KEY_CLASS_RSA
            };
            let pool = (0..args.keys)
                .map(|_| {
                    let key = RsaPrivateKey::generate(bytes)
                        .map_err(|e| format!("host RSA keygen: {e:?}"))?;
                    let der = key.to_vec().map_err(|e| format!("RSA DER export: {e:?}"))?;
                    let masked = unwrap_key(
                        ctx,
                        session_id,
                        class,
                        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
                        &der,
                    )?;
                    let public = key
                        .public_key()
                        .map_err(|e| format!("RSA public key: {e:?}"))?;
                    Ok(RsaKey { masked, public })
                })
                .collect::<Result<_, String>>()?;
            keys.rsa.insert((bytes, crt), pool);
        }

        if kinds
            .iter()
            .any(|k| matches!(k, OpKind::AesCbcEncrypt | OpKind::AesCbcDecrypt))
        {
            say(args, format!("importing {} AES-256 keys", args.keys));
            let mut rng = rand::rng();
            keys.aes = (0..args.keys)
                .map(|_| {
                    let mut raw = [0u8; 32];
                    rng.fill(&mut raw[..]);
                    let masked = unwrap_key(
                        ctx,
                        session_id,
                        KEY_CLASS_AES,
                        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                        &raw,
                    )?;
                    Ok(AesKeyEntry { masked, raw })
                })
                .collect::<Result<_, String>>()?;
        }

        for &op in kinds {
            match op.mldsa() {
                Some((MlDsaCmd::Sign, p)) => {
                    say(args, format!("generating {} {} keys", args.keys, p.name));
                    let pool = pqc::device_mldsa_keys(ctx, session_id, p, args.keys)?;
                    keys.mldsa.insert(p.key_kind, pool);
                }
                Some((MlDsaCmd::Verify, p)) => {
                    say(
                        args,
                        format!(
                            "signing {} messages with each of {} host {} keys",
                            args.messages, args.keys, p.name
                        ),
                    );
                    let signed = pqc::host_mldsa_signed(p, args.keys, args.messages)?;
                    keys.mldsa_signed.insert(p.key_kind, signed);
                }
                _ => {}
            }
            match op.mlkem() {
                Some((MlKemCmd::Encap, p)) => {
                    say(
                        args,
                        format!("generating {} host {} keys", args.keys, p.name),
                    );
                    let pool = pqc::host_mlkem_pub_keys(p, args.keys)?;
                    keys.mlkem_pub.insert(p.key_kind, pool);
                }
                Some((MlKemCmd::Decap, p)) => {
                    say(
                        args,
                        format!(
                            "generating {} {} keys, {} host ciphertexts each",
                            args.keys, p.name, args.messages
                        ),
                    );
                    let pool =
                        pqc::device_mlkem_keys(ctx, session_id, p, args.keys, args.messages)?;
                    keys.mlkem.insert(p.key_kind, pool);
                }
                _ => {}
            }
        }

        self.keys = keys;
        Ok(())
    }

    /// Run every selected operation against each key, checking each
    /// response against the host reference (and following up where a
    /// response alone cannot show the device did the work; see
    /// [`Worker::prove`]).
    fn preflight(&self, args: &RunArgs, kinds: &BTreeSet<OpKind>) -> Result<(), String> {
        let list: Vec<OpKind> = kinds.iter().copied().collect();
        let mut worker = Worker::new(self, args, 0, &list)?;
        for &op in kinds {
            let rounds = 2 * args.keys;
            for i in 0..rounds {
                let (_, result) = worker.exec(op, true);
                result.and_then(|()| worker.prove(op)).map_err(|e| {
                    format!("pre-flight {} request {i}/{rounds} failed: {e}", op.name())
                })?;
            }
            say(
                args,
                format!("pre-flight ok: {} ({rounds} checked)", op.name()),
            );
        }
        Ok(())
    }
}

fn say(args: &RunArgs, msg: String) {
    if !args.quiet {
        println!("{msg}");
    }
}

/// Rotate the Crypto Officer PSK, then initialize and finalize the
/// partition, leaving an active CO session. Mirrors the TBOR tests'
/// `finalized_co_session`.
fn finalized_co_session(ctx: &TestCtx) -> Result<u16, String> {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .map_err(|e| format!("PartInit: {e:?}"))?;
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .map_err(|e| format!("PartFinal: {e:?}"))?;
    Ok(session.session_id)
}

/// A unified `PartPolicy` with the given POTA public key (raw P-384
/// `X ‖ Y`), placeholder SATA key, no SAPOTA or backing partition.
fn part_policy_with_pota(pota_raw: &[u8; 96]) -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    const OFF_SATA: usize = 102;
    const OFF_FLAGS: usize = 418;
    const OFF_INFO: usize = 419;

    fn write_pubkey(bytes: &mut [u8], off: usize, key: &[u8; 96]) {
        bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
        bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
        bytes[off + 4..off + 4 + 96].copy_from_slice(key);
    }

    let mut sata = [0u8; 96];
    for (i, b) in sata.iter_mut().enumerate() {
        *b = 0x20u8.wrapping_add(i as u8) | 0x80;
    }

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[0] = 1; // version major
    write_pubkey(&mut bytes, OFF_POTA, pota_raw);
    write_pubkey(&mut bytes, OFF_SATA, &sata);
    bytes[OFF_FLAGS] = 0;
    bytes[OFF_INFO..OFF_INFO + 64].fill(0xAB);
    bytes
}

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    core::array::from_fn(|i| 0x40 + i as u8)
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

/// Import `key` (DER for RSA, raw bytes for AES) with `UnwrapKey` under the
/// local scope; returns the masked key.
fn unwrap_key(
    ctx: &TestCtx,
    session_id: u16,
    class: u8,
    usage: u64,
    key: &[u8],
) -> Result<Vec<u8>, String> {
    let hsm_pub = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .map_err(|e| format!("GetUnwrappingKey: {e:?}"))?
        .pub_key;
    let wrapped = rsa_aes_wrap(&hsm_pub, key)?;
    let resp = ctx
        .tbor(&TborUnwrapKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            key_class: class,
            key_usage: usage,
            oaep_hash_algo: HASH_ALGO_SHA256,
            wrapped_blob: wrapped,
            key_label: b"tsra_perf".to_vec(),
        })
        .map_err(|e| format!("UnwrapKey: {e:?}"))?;
    Ok(resp.masked_key)
}

/// RSA-AES-wrap `data` for the device's unwrapping key (`n_le ‖ e_le`):
/// RSA-OAEP(SHA-256) a fresh 32-byte KEK, then AES-KWP the data under it.
fn rsa_aes_wrap(hsm_pub: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if hsm_pub.len() != 260 {
        return Err(format!(
            "unwrapping key is {} bytes, expected 260",
            hsm_pub.len()
        ));
    }
    // The device sends each component little-endian; `from_hsm_bytes`
    // parses them big-endian.
    let mut be = Vec::with_capacity(260);
    be.extend(hsm_pub[..256].iter().rev());
    be.extend(hsm_pub[256..].iter().rev());
    let pub_key =
        RsaPublicKey::from_hsm_bytes(&be).map_err(|e| format!("unwrapping key: {e:?}"))?;

    let mut kek_raw = [0u8; 32];
    rand::rng().fill(&mut kek_raw[..]);
    let mut enc_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &pub_key,
        &kek_raw,
    )
    .map_err(|e| format!("RSA-OAEP wrap: {e:?}"))?;
    // The device takes the OAEP ciphertext little-endian.
    enc_kek.reverse();

    let kek = AesKey::from_bytes(&kek_raw).map_err(|e| format!("KEK: {e:?}"))?;
    let enc_data = Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, data)
        .map_err(|e| format!("AES-KWP wrap: {e:?}"))?;

    enc_kek.extend(enc_data);
    Ok(enc_kek)
}
