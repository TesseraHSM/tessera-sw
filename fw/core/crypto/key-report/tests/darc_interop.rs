// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DARC transfer envelopes on the std PAL, cross-checked against the
//! `hpke` crate for every recipient KEM (DHKEM(P-384), ML-KEM-1024 and
//! MLKEM1024-P384): the canonical header is both the HPKE `info` and AAD.

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
use tsra_fw_core_crypto_key_report::TransferReportParams;
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

/// Big-endian P-384 scalar in the PAL operand order.
fn scalar_to_pal(be: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; be.len()];
    tsra_fw_hsm_byte_order::int_copy_from_be(StdHsmPal::BYTE_ORDER, &mut out, be)
        .expect("scalar to PAL order");
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

fn recipient(kem: TransferKem) -> Recipient {
    let ikm = [0x42; 64];
    let (sk_ref, pk) = match kem {
        TransferKem::P384 => derive::<DhP384HkdfSha384>(&ikm),
        TransferKem::MlKem1024 => derive::<MlKem1024>(&ikm),
        TransferKem::MlKem1024P384 => derive::<MlKem1024P384>(&ikm),
    };
    let sk_fw = match kem {
        TransferKem::P384 => scalar_to_pal(&sk_ref),
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
    hpke::single_shot_open::<AesGcm256, D, K>(&OpModeR::Base, &sk, &enc, header, ct, header)
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

/// Report signer (P-384 PID): PAL-order scalar and SEC1 public key.
fn signer() -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = derive::<DhP384HkdfSha384>(&[0x17; 48]);
    (scalar_to_pal(&sk), pk)
}

async fn key_id(pal: &StdHsmPal, io: &StdHsmIo, pk: &[u8], signer: bool) -> [u8; 48] {
    let mut id = [0u8; 48];
    let out = dma_mut(&mut id);
    if signer {
        signer_key_id(pal, io, dma(pk), out).await
    } else {
        transfer_key_id(pal, io, dma(pk), out).await
    }
    .expect("key id");
    id
}

/// Sign a `Darc` report over `envelope`.
async fn sign_report(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    envelope: &[u8],
    source_id: &[u8; 48],
    recipient_id: &[u8; 48],
    signer_sk: &[u8],
) -> Vec<u8> {
    let mut hash = [0u8; 48];
    transfer_envelope_hash(pal, io, dma(envelope), dma_mut(&mut hash))
        .await
        .expect("envelope hash");
    let params = ReportParams::Darc(TransferReportParams {
        source_pid_key_id: dma(source_id),
        recipient_key_id: dma(recipient_id),
        envelope_hash: dma(&hash),
    });
    let len = report(pal, io, &params, dma(signer_sk), None)
        .await
        .expect("report size");
    let mut out = vec![0u8; len];
    report(pal, io, &params, dma(signer_sk), Some(dma_mut(&mut out)))
        .await
        .expect("sign report");
    out
}

/// Firmware verify + open of `envelope` authenticated by `signed_report`.
async fn fw_open(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    recipient: &Recipient,
    signer_pk: &[u8],
    envelope: &[u8],
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
    let n = pal
        .alloc_scoped_async(io, async |alloc| {
            open_transfer(
                pal,
                io,
                &cfg,
                dma(envelope),
                dma(signed_report),
                dma_mut(&mut out),
                alloc,
            )
            .await
        })
        .await?;
    out.truncate(n);
    Ok(out)
}

/// The firmware seals; the `hpke` crate opens with `info = aad = header`.
#[tokio::test(flavor = "current_thread")]
async fn firmware_seal_opens_with_reference() {
    let (pal, io) = pal_and_io();
    let (_, signer_pk) = signer();
    let source_id = key_id(&pal, &io, &signer_pk, true).await;
    for kem in KEMS {
        let recipient = recipient(kem);
        let recipient_id = key_id(&pal, &io, &recipient.pk, false).await;
        let header = TransferHeader::Darc {
            source_pid_key_id: &source_id,
            recipient_key_id: &recipient_id,
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

        let (header_bytes, rest) = envelope.split_at(DARC_HEADER_LEN);
        let (enc, ct) = rest.split_at(kem.public_key_len());
        let pt = ref_open(kem, &recipient.sk_ref, enc, ct, header_bytes);
        assert_eq!(pt, TMK, "{kem:?}");
    }
}

/// The `hpke` crate seals with `info = aad = header`; the firmware
/// verifies the PID report and opens. An envelope sealed with any other
/// AAD fails to open even though its report verifies.
#[tokio::test(flavor = "current_thread")]
async fn reference_seal_opens_in_firmware() {
    let (pal, io) = pal_and_io();
    let (signer_sk, signer_pk) = signer();
    let source_id = key_id(&pal, &io, &signer_pk, true).await;
    for kem in KEMS {
        let recipient = recipient(kem);
        let recipient_id = key_id(&pal, &io, &recipient.pk, false).await;
        let header = TransferHeader::Darc {
            source_pid_key_id: &source_id,
            recipient_key_id: &recipient_id,
            kem,
        };
        let mut header_bytes = vec![0u8; header.header_len()];
        header.encode(&mut header_bytes).expect("encode header");

        for (aad, ok) in [(&header_bytes[..], true), (&[][..], false)] {
            let (enc, ct) = ref_seal(kem, &recipient.pk, &header_bytes, aad);
            let envelope = [&header_bytes[..], &enc, &ct].concat();
            assert_eq!(envelope.len(), darc_envelope_len(kem), "{kem:?}");
            let signed_report =
                sign_report(&pal, &io, &envelope, &source_id, &recipient_id, &signer_sk).await;
            let opened =
                fw_open(&pal, &io, &recipient, &signer_pk, &envelope, &signed_report).await;
            if ok {
                assert_eq!(opened.expect("firmware open"), TMK, "{kem:?}");
            } else {
                assert!(opened.is_err(), "{kem:?}: AAD must be the header");
            }
        }
    }
}
