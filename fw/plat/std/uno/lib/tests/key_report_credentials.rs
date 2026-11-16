// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drives the Uno IO pipeline (`Hsm::handle_io`) with a real `StdHsmPal`.

use std::future::Future;
use std::task::Context;
use std::task::Waker;

use tsra_fw_ddi_tbor_types::TborKeyReportReq;
use tsra_fw_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::CQE_DWORDS;
use tsra_fw_hsm_io::OP_TBOR;
use tsra_fw_hsm_io::SQE_DWORDS;
use tsra_fw_hsm_pal_std_uno::HsmIoRequest;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartitionLock;

#[repr(align(4096))]
struct HostPage([u8; 4096]);

#[test]
fn key_report_waits_for_credential_transaction_before_default_psk_gate() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_credential_guard());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_credential_guard() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    hsm.pal()
        .part_alloc_internal(0, 1)
        .await
        .expect("partition");
    hsm.pal().part_enable_internal(0).await.expect("enable");
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .expect("control IO");
    let control_io = hsm.pal().poll_io().await.expect("poll control IO");
    let credential_guard = hsm
        .pal()
        .partition_lock(&control_io)
        .await
        .expect("credential transaction");

    let mut request = HostPage([0; 4096]);
    let mut response = HostPage([0xA5; 4096]);
    let request_len = TborKeyReportReq::encode(&mut request.0)
        .expect("encode")
        .session_id(0u16.into())
        .expect("session id")
        .masked_key(&[])
        .expect("masked key")
        .report_data(&[0; KEY_REPORT_DATA_LEN])
        .expect("report data")
        .auth_envelope(&[])
        .expect("auth envelope")
        .finish()
        .len();
    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_TBOR))
            .buf_lens(request_len as u32, 4096)
            .src_prp1(request.0.as_ptr() as u64)
            .dst_prp1(response.0.as_mut_ptr() as u64)
            .session_flags(SessionFlags::new().with_ctrl(3).with_id_valid(true))
            .build(),
        reply_tx,
    ))
    .await
    .expect("KeyReport IO");
    let io = hsm.pal().poll_io().await.expect("poll KeyReport");
    let mut handler = std::pin::pin!(hsm.handle_io(io));
    // The std PAL's inbound DMA is synchronous, so the first suspension
    // must be the credential guard, not an earlier DMA operation.
    assert!(handler
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(matches!(
        reply_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drop(credential_guard);
    handler.await;
    let mut completion = reply_rx.await.expect("KeyReport completion after unlock");
    let cqe = completion
        .first_chunk_mut::<CQE_DWORDS>()
        .expect("command CQE");
    assert_eq!(Cqe::from(cqe).status(), 0);
    hsm.pal()
        .drop_io(control_io)
        .await
        .expect("drop control IO");
}

#[test]
fn typed_reports_sign_verify_and_reject_wrong_kind_or_tampering() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_typed_reports());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_typed_reports() {
    use tsra_fw_core_crypto_key_report::parse_report;
    use tsra_fw_core_crypto_key_report::report;
    use tsra_fw_core_crypto_key_report::verify_report;
    use tsra_fw_core_crypto_key_report::AttestedPubKey;
    use tsra_fw_core_crypto_key_report::KeyReportParams;
    use tsra_fw_core_crypto_key_report::ReportKind;
    use tsra_fw_core_crypto_key_report::ReportParams;
    use tsra_fw_core_crypto_key_report::ReportView;
    use tsra_fw_core_crypto_key_report::TransferReportParams;
    use tsra_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;

    let (tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
    pal.part_alloc_internal(0, 1).await.expect("partition");
    pal.part_enable_internal(0).await.expect("enable");
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .expect("control IO");
    let io = pal.poll_io().await.expect("poll IO");
    let private = pal.dma_alloc_zeroed(&io, 48).expect("private key");
    private[0] = 1;
    let public = pal.dma_alloc(&io, 96).expect("public key");
    pal.ecc_pub_from_priv(&io, HsmEccCurve::P384, private, public)
        .await
        .expect("derive public key");
    let fields = pal.dma_alloc(&io, 48 * 4 + 16 + 128 + 16).expect("fields");
    fields.fill(0x55);
    let encoded = pal.dma_alloc(&io, KEY_REPORT_MAX_LEN).expect("report");

    for kind in [
        ReportKind::PublicKey,
        ReportKind::Darc,
        ReportKind::SdBackup,
    ] {
        pal.alloc_scoped_async(&io, async |alloc| {
            let transfer = TransferReportParams {
                source_pid_key_id: &fields[..48],
                recipient_key_id: &fields[48..96],
                envelope_hash: &fields[96..144],
            };
            let params = match kind {
                ReportKind::PublicKey => ReportParams::PublicKey(KeyReportParams {
                    key: AttestedPubKey::Ecc {
                        curve: HsmEccCurve::P384,
                        x: &public[..48],
                        y: &public[48..],
                    },
                    flags: u32::MAX,
                    app_uuid: &fields[192..208],
                    report_data: &fields[208..336],
                    vm_launch_id: &fields[336..352],
                    policy_hash: Some(&fields[144..192]),
                }),
                ReportKind::Darc => ReportParams::Darc(transfer),
                ReportKind::SdBackup => ReportParams::SdBackup {
                    transfer,
                    policy_hash: &fields[144..192],
                },
            };
            let size = report(&pal, &io, &params, private, None)
                .await
                .expect("query report size");
            let short =
                tsra_fw_hsm_pal_traits::HsmScopedAlloc::dma_alloc(alloc, 1).expect("short buffer");
            short[0] = 0xA5;
            assert!(report(&pal, &io, &params, private, Some(short))
                .await
                .is_err());
            assert_eq!(short[0], 0xA5);
            let written = report(&pal, &io, &params, private, Some(encoded))
                .await
                .expect("sign report");
            assert_eq!(written, size);
            assert_eq!(parse_report(&encoded[..size]).expect("parse").kind(), kind);
            assert!(
                verify_report(&pal, &io, alloc, &encoded[..size], public, kind)
                    .await
                    .expect("verify report")
            );
            let base = encoded.as_ptr() as usize;
            let offsets = match parse_report(&encoded[..size]).expect("parse signed fields") {
                ReportView::PublicKey(view) => vec![view.report_data.as_ptr() as usize - base],
                ReportView::Darc(view) => vec![
                    view.source_pid_key_id.as_ptr() as usize - base,
                    view.recipient_key_id.as_ptr() as usize - base,
                    view.envelope_hash.as_ptr() as usize - base,
                ],
                ReportView::SdBackup {
                    transfer,
                    policy_hash,
                } => vec![
                    transfer.envelope_hash.as_ptr() as usize - base,
                    policy_hash.as_ptr() as usize - base,
                ],
            };
            for offset in offsets {
                encoded[offset] ^= 1;
                assert!(!pal
                    .alloc_scoped_async(&io, async |scratch| {
                        verify_report(&pal, &io, scratch, &encoded[..size], public, kind).await
                    })
                    .await
                    .expect("verify changed payload"));
                encoded[offset] ^= 1;
            }
            let wrong_kind = if kind == ReportKind::Darc {
                ReportKind::SdBackup
            } else {
                ReportKind::Darc
            };
            assert!(
                verify_report(&pal, &io, alloc, &encoded[..size], public, wrong_kind)
                    .await
                    .is_err()
            );
            encoded[size - 1] ^= 1;
            assert!(
                !verify_report(&pal, &io, alloc, &encoded[..size], public, kind)
                    .await
                    .expect("verify changed signature")
            );
            Ok::<_, tsra_fw_hsm_pal_traits::HsmError>(())
        })
        .await
        .expect("report scope");
    }

    let params = ReportParams::SdBackup {
        transfer: TransferReportParams {
            source_pid_key_id: &fields[..48],
            recipient_key_id: &fields[48..96],
            envelope_hash: &fields[96..144],
        },
        policy_hash: &fields[144..191],
    };
    assert!(report(&pal, &io, &params, private, None).await.is_err());
    pal.drop_io(io).await.expect("drop IO");
}

#[test]
fn p384_transfer_reports_bind_encryption_identity_kind_and_policy() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_transfer_bindings());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_transfer_bindings() {
    use tsra_crypto::HashAlgo;
    use tsra_crypto::HashOpContext;
    use tsra_crypto::Hasher;
    use tsra_fw_core_crypto_key_report::report;
    use tsra_fw_core_crypto_key_report::transfer::open_transfer;
    use tsra_fw_core_crypto_key_report::transfer::p384_key_id;
    use tsra_fw_core_crypto_key_report::transfer::parse_transfer_envelope;
    use tsra_fw_core_crypto_key_report::transfer::seal_transfer;
    use tsra_fw_core_crypto_key_report::transfer::transfer_envelope_hash;
    use tsra_fw_core_crypto_key_report::transfer::transfer_report_params;
    use tsra_fw_core_crypto_key_report::transfer::verify_transfer;
    use tsra_fw_core_crypto_key_report::transfer::TransferHeader;
    use tsra_fw_core_crypto_key_report::transfer::TransferOpenConfig;
    use tsra_fw_core_crypto_key_report::transfer::TransferVerifyConfig;
    use tsra_fw_core_crypto_key_report::ReportKind;
    use tsra_fw_core_crypto_key_report::ReportParams;
    use tsra_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;
    use tsra_fw_hsm_byte_order::pair_to_be;
    use tsra_fw_hsm_pal_traits::HsmCryptoOrder;
    use tsra_fw_hsm_pal_traits::HsmDmaBuf;
    use tsra_fw_hsm_pal_traits::HsmEccPct;

    let (tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
    pal.part_alloc_internal(0, 1).await.expect("partition");
    pal.part_enable_internal(0).await.expect("enable");
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; SQE_DWORDS],
        reply_tx,
    ))
    .await
    .expect("control IO");
    let io = pal.poll_io().await.expect("poll IO");
    let keys = pal
        .dma_alloc_zeroed(&io, 3 * (48 + 97))
        .expect("key fixtures");
    for i in 0..3 {
        let key = &mut keys[i * 145..(i + 1) * 145];
        let (private, public) = key.split_at_mut(48);
        public[0] = 4;
        pal.alloc_scoped_async(&io, async |alloc| {
            pal.ecc_gen_keypair(
                &io,
                alloc,
                HsmEccCurve::P384,
                Some((private, &mut public[1..])),
                HsmEccPct::KeyAgreement,
            )
            .await
        })
        .await
        .expect("generate P384 key pair");
        pair_to_be(StdHsmPal::BYTE_ORDER, HsmEccCurve::P384, &mut public[1..])
            .expect("SEC1 coordinates");
    }
    let source_private = &keys[..48];
    let source_public = &keys[48..145];
    let recipient_private = &keys[145..193];
    let recipient_public = &keys[193..290];
    let wrong_public = &keys[338..435];
    let ids = pal.dma_alloc(&io, 96).expect("key identifiers");
    let (source_id_out, recipient_id_out) = ids.split_at_mut(48);
    for (public, id) in [
        (source_public, source_id_out),
        (recipient_public, recipient_id_out),
    ] {
        p384_key_id(&pal, &io, public, id)
            .await
            .expect("derive key identifier");
        let mut hash = Hasher::hash_init(HashAlgo::sha384()).expect("independent hash");
        hash.update(b"TSRA-P384-KEY-v1").expect("key domain");
        hash.update(public).expect("public key");
        let mut expected = [0; 48];
        hash.finish(Some(&mut expected)).expect("key ID hash");
        assert_eq!(&**id, expected);
    }
    let source_id: &[u8; 48] = ids[..48].as_ref().try_into().expect("source ID");
    let recipient_id: &[u8; 48] = ids[48..].as_ref().try_into().expect("recipient ID");
    let policy = [0x55; 48];
    let wrong_policy = [0x66; 48];
    let encoded_report = pal.dma_alloc(&io, KEY_REPORT_MAX_LEN).expect("report");

    let sign = async |envelope: &HsmDmaBuf, output: &mut HsmDmaBuf| {
        pal.alloc_scoped_async(&io, async |alloc| {
            use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
            let digest = alloc.dma_alloc(48)?;
            transfer_envelope_hash(&pal, &io, envelope, digest).await?;
            let mut hash = Hasher::hash_init(HashAlgo::sha384()).expect("independent hash");
            hash.update(b"TSRA-XFER-HASH-v1").expect("envelope domain");
            hash.update(envelope).expect("envelope bytes");
            let mut expected = [0; 48];
            hash.finish(Some(&mut expected)).expect("envelope hash");
            assert_eq!(&**digest, expected);
            let params = transfer_report_params(envelope, digest)?;
            report(&pal, &io, &params, source_private, Some(output)).await
        })
        .await
    };
    let verify =
        async |cfg: &TransferVerifyConfig<'_>, envelope: &HsmDmaBuf, report: &HsmDmaBuf| {
            pal.alloc_scoped_async(&io, async |alloc| {
                verify_transfer(&pal, &io, cfg, envelope, report, alloc)
                    .await
                    .map(|_| ())
            })
            .await
        };
    for header in [
        TransferHeader::Darc {
            source_pid_key_id: source_id,
            recipient_key_id: recipient_id,
            kem: tsra_fw_core_crypto_key_report::transfer::TransferKem::P384,
        },
        TransferHeader::SdBackup {
            source_pid_key_id: source_id,
            recipient_key_id: recipient_id,
            policy_hash: &policy,
            kem: tsra_fw_core_crypto_key_report::transfer::TransferKem::P384,
        },
    ] {
        let secret = pal.dma_alloc(&io, header.plaintext_len()).expect("secret");
        secret.fill(0xA5);
        let envelope = pal.dma_alloc(&io, header.envelope_len()).expect("envelope");
        pal.alloc_scoped_async(&io, async |alloc| {
            seal_transfer(
                &pal,
                &io,
                &header,
                recipient_public,
                secret,
                envelope,
                alloc,
            )
            .await
        })
        .await
        .expect("HPKE Base seal");
        let report_len = sign(envelope, encoded_report).await.expect("sign transfer");
        let mut cfg = TransferVerifyConfig {
            expected_kind: header.kind(),
            signer_public_key: source_public,
            recipient_public_key: recipient_public,
            expected_policy_hash: header.policy_hash(),
        };
        verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .expect("verify transfer");
        let plaintext = pal.dma_alloc(&io, secret.len()).expect("plaintext");
        plaintext.fill(0xCC);
        let open_cfg = TransferOpenConfig {
            verification: TransferVerifyConfig { ..cfg },
            recipient_private_key: recipient_private,
        };
        assert_eq!(
            pal.alloc_scoped_async(&io, async |alloc| {
                open_transfer(
                    &pal,
                    &io,
                    &open_cfg,
                    envelope,
                    &encoded_report[..report_len],
                    plaintext,
                    alloc,
                )
                .await
            })
            .await
            .expect("open verified transfer"),
            secret.len()
        );
        assert_eq!(&**plaintext, &**secret);

        let header_len = parse_transfer_envelope(envelope)
            .expect("view")
            .header_bytes
            .len();
        let mut offsets = vec![17, 65, header_len + 1, header_len + 97, envelope.len() - 1];
        if header.kind() == ReportKind::SdBackup {
            offsets.push(113);
        }
        for offset in offsets {
            envelope[offset] ^= 1;
            assert!(verify(&cfg, envelope, &encoded_report[..report_len])
                .await
                .is_err());
            plaintext.fill(0xCC);
            assert!(pal
                .alloc_scoped_async(&io, async |alloc| {
                    open_transfer(
                        &pal,
                        &io,
                        &open_cfg,
                        envelope,
                        &encoded_report[..report_len],
                        plaintext,
                        alloc,
                    )
                    .await
                })
                .await
                .is_err());
            assert!(plaintext.iter().all(|byte| *byte == 0xCC));
            envelope[offset] ^= 1;
        }
        encoded_report[report_len - 1] ^= 1;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        encoded_report[report_len - 1] ^= 1;
        cfg.recipient_public_key = wrong_public;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.recipient_public_key = recipient_public;
        cfg.signer_public_key = wrong_public;
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.signer_public_key = source_public;
        for wrong_kind in [
            ReportKind::PublicKey,
            if header.kind() == ReportKind::Darc {
                ReportKind::SdBackup
            } else {
                ReportKind::Darc
            },
        ] {
            cfg.expected_kind = wrong_kind;
            assert!(verify(&cfg, envelope, &encoded_report[..report_len])
                .await
                .is_err());
        }
        cfg.expected_kind = header.kind();
        cfg.expected_policy_hash = Some(&wrong_policy);
        assert!(verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .is_err());
        cfg.expected_policy_hash = None;
        verify(&cfg, envelope, &encoded_report[..report_len])
            .await
            .expect("no receiver-policy equality requirement");

        // Even correctly signed reports must agree with the envelope fields.
        for bad_claim in 0..if header.kind() == ReportKind::Darc {
            3
        } else {
            4
        } {
            let bad_len = pal
                .alloc_scoped_async(&io, async |alloc| {
                    use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
                    let digest = alloc.dma_alloc(48)?;
                    transfer_envelope_hash(&pal, &io, envelope, digest).await?;
                    let mut params = transfer_report_params(envelope, digest)?;
                    let transfer = match &mut params {
                        ReportParams::Darc(transfer) => transfer,
                        ReportParams::SdBackup {
                            transfer,
                            policy_hash,
                        } => {
                            if bad_claim == 3 {
                                *policy_hash = &ids[..48];
                            }
                            transfer
                        }
                        ReportParams::PublicKey(_) => unreachable!("operation envelope"),
                    };
                    match bad_claim {
                        0 => transfer.source_pid_key_id = &ids[48..],
                        1 => transfer.recipient_key_id = &ids[..48],
                        2 => transfer.envelope_hash = &ids[..48],
                        _ => {}
                    }
                    report(&pal, &io, &params, source_private, Some(encoded_report)).await
                })
                .await
                .expect("sign mismatched claim");
            assert!(verify(&cfg, envelope, &encoded_report[..bad_len])
                .await
                .is_err());
        }

        // A newly signed digest cannot rescue ciphertext sealed with an old
        // header: HPKE info/AAD must authenticate the header independently.
        if header.kind() == ReportKind::SdBackup {
            envelope[113] ^= 1;
            let resigned_len = sign(envelope, encoded_report)
                .await
                .expect("sign changed policy");
            verify(&cfg, envelope, &encoded_report[..resigned_len])
                .await
                .expect("valid new signature/bindings");
            let changed_cfg = TransferOpenConfig {
                verification: cfg,
                recipient_private_key: recipient_private,
            };
            plaintext.fill(0xCC);
            assert!(pal
                .alloc_scoped_async(&io, async |alloc| {
                    open_transfer(
                        &pal,
                        &io,
                        &changed_cfg,
                        envelope,
                        &encoded_report[..resigned_len],
                        plaintext,
                        alloc,
                    )
                    .await
                })
                .await
                .is_err());
            assert!(plaintext.iter().all(|byte| *byte == 0xCC));
        }

        envelope.fill(0xCC);
        assert!(pal
            .alloc_scoped_async(&io, async |alloc| {
                seal_transfer(&pal, &io, &header, wrong_public, secret, envelope, alloc).await
            })
            .await
            .is_err());
        assert!(envelope.iter().all(|byte| *byte == 0xCC));
        assert!(pal
            .alloc_scoped_async(&io, async |alloc| {
                seal_transfer(
                    &pal,
                    &io,
                    &header,
                    recipient_public,
                    &secret[..secret.len() - 1],
                    envelope,
                    alloc,
                )
                .await
            })
            .await
            .is_err());
        assert!(envelope.iter().all(|byte| *byte == 0xCC));
    }
    pal.drop_io(io).await.expect("drop IO");
}
