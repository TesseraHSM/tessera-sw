// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC transfer envelopes on the std PAL, cross-checked against the
//! `hpke` crate for every recipient KEM (DHKEM(P-384), ML-KEM-1024 and
//! MLKEM1024-P384). The complete encrypted envelope is PID-signed;
//! the canonical header is HPKE `info` and AEAD AAD is empty.

#![allow(unsafe_code)]

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kdf::Kdf;
use hpke::kdf::KdfShake256;
use hpke::kem::DhP384HkdfSha384;
use hpke::kem::MlKem1024;
use hpke::kem::MlKem1024P384;
use hpke::Deserializable;
use hpke::Kem;
use hpke::OpModeR;
use hpke::OpModeS;
use hpke::Serializable;
use tokio::runtime::Handle;
use tsra_fw_core_crypto_key_report::report;
use tsra_fw_core_crypto_key_report::transfer::*;
use tsra_fw_core_crypto_key_report::ReportParams;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmIo;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::*;

const TMK: [u8; 32] = [0x5a; 32];
const KEMS: [TransferKem; 3] = [
    TransferKem::P384,
    TransferKem::MlKem1024,
    TransferKem::MlKem1024P384,
];

fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
    let (_tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, Handle::current());
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
    (pal, io)
}

fn dma(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

fn dma_mut(bytes: &mut [u8]) -> &mut HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw_mut(bytes) }
}

/// Convert a big-endian P-384 scalar to the PAL's opaque vault encoding.
fn scalar_to_pal(pal: &StdHsmPal, io: &StdHsmIo, be: &[u8]) -> Vec<u8> {
    let len = pal
        .ecc_priv_to_vault(io, HsmEccCurve::P384, dma(be), None)
        .expect("vault size");
    let mut out = vec![0u8; len];
    pal.ecc_priv_to_vault(io, HsmEccCurve::P384, dma(be), Some(dma_mut(&mut out)))
        .expect("vault scalar");
    out
}

/// Recipient key pair for `kem`.
struct Recipient {
    /// `hpke` crate private-key serialization.
    sk_ref: Vec<u8>,
    /// Firmware private key: PAL-order scalar or ML-KEM seed.
    sk_fw: Vec<u8>,
    /// Public key in its [`TransferKem`] encoding.
    pk: Vec<u8>,
}

fn derive<K: Kem>(ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = K::derive_keypair(ikm);
    (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
}

fn recipient(pal: &StdHsmPal, io: &StdHsmIo, kem: TransferKem) -> Recipient {
    let ikm = [0x42; 64];
    let (sk_ref, pk) = match kem {
        TransferKem::P384 => derive::<DhP384HkdfSha384>(&ikm),
        TransferKem::MlKem1024 => derive::<MlKem1024>(&ikm),
        TransferKem::MlKem1024P384 => derive::<MlKem1024P384>(&ikm),
    };
    let sk_fw = match kem {
        TransferKem::P384 => scalar_to_pal(pal, io, &sk_ref),
        _ => sk_ref.clone(),
    };
    Recipient { sk_ref, sk_fw, pk }
}

fn ref_seal_with<K: Kem, D: Kdf>(pk: &[u8], info: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = K::PublicKey::from_bytes(pk).expect("ref pk");
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, D, K>(&OpModeS::Base, &pk, info, &TMK, aad)
        .expect("ref seal");
    (enc.to_bytes().to_vec(), ct)
}

fn ref_open_with<K: Kem, D: Kdf>(sk: &[u8], enc: &[u8], ct: &[u8], header: &[u8]) -> Vec<u8> {
    let sk = K::PrivateKey::from_bytes(sk).expect("ref sk");
    let enc = K::EncappedKey::from_bytes(enc).expect("ref enc");
    hpke::single_shot_open::<AesGcm256, D, K>(&OpModeR::Base, &sk, &enc, header, ct, &[])
        .expect("ref open")
}

fn ref_seal(kem: TransferKem, pk: &[u8], info: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match kem {
        TransferKem::P384 => ref_seal_with::<DhP384HkdfSha384, HkdfSha384>(pk, info, aad),
        TransferKem::MlKem1024 => ref_seal_with::<MlKem1024, KdfShake256>(pk, info, aad),
        TransferKem::MlKem1024P384 => ref_seal_with::<MlKem1024P384, KdfShake256>(pk, info, aad),
    }
}

fn ref_open(kem: TransferKem, sk: &[u8], enc: &[u8], ct: &[u8], header: &[u8]) -> Vec<u8> {
    match kem {
        TransferKem::P384 => ref_open_with::<DhP384HkdfSha384, HkdfSha384>(sk, enc, ct, header),
        TransferKem::MlKem1024 => ref_open_with::<MlKem1024, KdfShake256>(sk, enc, ct, header),
        TransferKem::MlKem1024P384 => {
            ref_open_with::<MlKem1024P384, KdfShake256>(sk, enc, ct, header)
        }
    }
}

/// Report signer (P-384 PID): opaque vault private key and SEC1 public key.
fn signer(pal: &StdHsmPal, io: &StdHsmIo) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = derive::<DhP384HkdfSha384>(&[0x17; 48]);
    (scalar_to_pal(pal, io, &sk), pk)
}

async fn key_id(pal: &StdHsmPal, io: &StdHsmIo, pk: &[u8], signer: bool) -> [u8; 48] {
    let mut id = [0u8; 48];
    let out = dma_mut(&mut id);
    if signer {
        pal.alloc_scoped_async(io, async |alloc| {
            transfer_spki_thumbprint(pal, io, dma(pk), out, alloc).await
        })
        .await
    } else {
        transfer_key_id(pal, io, dma(pk), out).await
    }
    .expect("key id");
    id
}

/// Sign a `Darc` report over `envelope`.
async fn sign_report(pal: &StdHsmPal, io: &StdHsmIo, envelope: &[u8], signer_sk: &[u8]) -> Vec<u8> {
    let params = ReportParams::Transfer(dma(envelope));
    let len = report(pal, io, &params, dma(signer_sk), None)
        .await
        .expect("report size");
    let mut out = vec![0u8; len];
    report(pal, io, &params, dma(signer_sk), Some(dma_mut(&mut out)))
        .await
        .expect("sign report");
    out
}

/// Firmware verify + open of the complete signed encrypted artifact.
async fn fw_open(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    recipient: &Recipient,
    signer_pk: &[u8],
    signed_report: &[u8],
) -> HsmResult<Vec<u8>> {
    let cfg = TransferOpenConfig {
        verification: TransferVerifyConfig {
            expected_kind: tsra_fw_core_crypto_key_report::ReportKind::Darc,
            signer_public_key: dma(signer_pk),
            recipient_public_key: dma(&recipient.pk),
            expected_policy_hash: None,
        },
        recipient_private_key: dma(&recipient.sk_fw),
    };
    let mut out = vec![0u8; TMK.len()];
    let verified = pal
        .alloc_scoped_async(io, async |alloc| {
            verify_transfer(pal, io, &cfg.verification, dma(signed_report), alloc).await
        })
        .await
        .expect("complete DARC signature and canonical identities");
    let n = pal
        .alloc_scoped_async(io, async |alloc| {
            open_verified_transfer(
                pal,
                io,
                &verified,
                cfg.recipient_private_key,
                cfg.verification.recipient_public_key,
                dma_mut(&mut out),
                alloc,
            )
            .await
        })
        .await?;
    out.truncate(n);
    Ok(out)
}

/// The firmware seals and signs; the reference opens the signed payload.
#[tokio::test(flavor = "current_thread")]
async fn firmware_seal_opens_with_reference() {
    let (pal, io) = pal_and_io();
    let (signer_sk, signer_pk) = signer(&pal, &io);
    let source_id = key_id(&pal, &io, &signer_pk, true).await;
    for kem in KEMS {
        let recipient = recipient(&pal, &io, kem);
        let recipient_id = key_id(&pal, &io, &recipient.pk, false).await;
        let header = TransferHeader::Darc {
            source_pid_spki_thumbprint: &source_id,
            recipient_spki_thumbprint: &recipient_id,
            kem,
        };
        let mut envelope = vec![0u8; darc_envelope_len(kem)];
        let len = pal
            .alloc_scoped_async(&io, async |alloc| {
                seal_transfer(
                    &pal,
                    &io,
                    &header,
                    dma(&recipient.pk),
                    dma(&TMK),
                    dma_mut(&mut envelope),
                    alloc,
                )
                .await
            })
            .await
            .expect("firmware seal");
        assert_eq!(len, envelope.len(), "{kem:?}");

        let signed = sign_report(&pal, &io, &envelope, &signer_sk).await;
        let tsra_fw_core_crypto_key_report::ReportView::Transfer(view) =
            tsra_fw_core_crypto_key_report::parse_report(dma(&signed)).expect("signed artifact")
        else {
            panic!("expected transfer")
        };
        assert_eq!(&**view.envelope, envelope);
        assert_eq!(
            fw_open(&pal, &io, &recipient, &signer_pk, &signed)
                .await
                .unwrap_or_else(|e| panic!("{kem:?} verified artifact opening: {e:?}")),
            TMK
        );
        let (header_bytes, rest) = view.envelope.split_at(DARC_HEADER_LEN);
        let (enc, ct) = rest.split_at(kem.public_key_len());
        let pt = ref_open(kem, &recipient.sk_ref, enc, ct, header_bytes);
        assert_eq!(pt, TMK, "{kem:?}");
    }
}

/// Reference HPKE Base seal plus complete-envelope signing opens in firmware.
/// Duplicating the header as AAD fails despite a valid artifact signature.
#[tokio::test(flavor = "current_thread")]
async fn reference_seal_opens_in_firmware() {
    let (pal, io) = pal_and_io();
    let (signer_sk, signer_pk) = signer(&pal, &io);
    let source_id = key_id(&pal, &io, &signer_pk, true).await;
    for kem in KEMS {
        let recipient = recipient(&pal, &io, kem);
        let recipient_id = key_id(&pal, &io, &recipient.pk, false).await;
        let header = TransferHeader::Darc {
            source_pid_spki_thumbprint: &source_id,
            recipient_spki_thumbprint: &recipient_id,
            kem,
        };
        let mut header_bytes = vec![0u8; header.header_len()];
        header.encode(&mut header_bytes).expect("encode header");

        for (aad, ok) in [(&[][..], true), (&header_bytes[..], false)] {
            let (enc, ct) = ref_seal(kem, &recipient.pk, &header_bytes, aad);
            let envelope = [&header_bytes[..], &enc, &ct].concat();
            assert_eq!(envelope.len(), darc_envelope_len(kem), "{kem:?}");
            let signed_report = sign_report(&pal, &io, &envelope, &signer_sk).await;
            let opened = fw_open(&pal, &io, &recipient, &signer_pk, &signed_report).await;
            if ok {
                assert_eq!(
                    opened.unwrap_or_else(|e| panic!("{kem:?} firmware open: {e:?}")),
                    TMK,
                    "{kem:?}"
                );
            } else {
                assert!(opened.is_err(), "{kem:?}: AEAD AAD must be empty");
            }
        }
    }
}
