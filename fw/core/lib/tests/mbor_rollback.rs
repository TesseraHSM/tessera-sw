// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_fw_ddi_mbor::MborDecode;
use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_ddi_mbor_api::DdiDecoder;
use tsra_fw_ddi_mbor_api::DdiEncoder;
use tsra_fw_ddi_mbor_types::aes_generate_key::*;
use tsra_fw_ddi_mbor_types::derive_hkdf::*;
use tsra_fw_ddi_mbor_types::derive_kbkdf::*;
use tsra_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairCmdResp;
use tsra_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairReq;
use tsra_fw_ddi_mbor_types::ecdh_key_exchange::DdiEcdhKeyExchangeCmdResp;
use tsra_fw_ddi_mbor_types::ecdh_key_exchange::DdiEcdhKeyExchangeReq;
use tsra_fw_ddi_mbor_types::establish_credential::*;
use tsra_fw_ddi_mbor_types::get_establish_cred_encryption_key::*;
use tsra_fw_ddi_mbor_types::init_bk3::*;
use tsra_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use tsra_fw_ddi_mbor_types::open_session::*;
use tsra_fw_ddi_mbor_types::reopen_session::*;
use tsra_fw_ddi_mbor_types::rsa_unwrap::*;
use tsra_fw_ddi_mbor_types::unmask_key::*;
use tsra_fw_ddi_mbor_types::*;
use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::Cqe;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_io::CQE_DWORDS;
use tsra_fw_hsm_io::OP_MBOR;
use tsra_fw_hsm_io::SQE_DWORDS;
use tsra_fw_hsm_pal_std::HsmIoRequest;
use tsra_fw_hsm_pal_std::HsmPartId;
use tsra_fw_hsm_pal_std::StdHsmIo;
use tsra_fw_hsm_pal_std::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmAes;
use tsra_fw_hsm_pal_traits::HsmAesOp;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEccPct;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmHmac;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmKdf;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartitionManager;
use tsra_fw_hsm_pal_traits::HsmSeedStore;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionManager;
use tsra_fw_hsm_pal_traits::HsmSessionState;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

#[repr(align(4096))]
struct HostPage([u8; 4096]);

#[test]
fn mbor_ecc_generation_rolls_back_if_cqe_delivery_fails() {
    run_cqe_boundary(DdiOp::EccGenerateKeyPair, DdiKeyType::Ecc256Private);
}

#[test]
fn mbor_ecdh_exchange_rolls_back_if_cqe_delivery_fails() {
    run_cqe_boundary(DdiOp::EcdhKeyExchange, DdiKeyType::Secret256);
}

const AES_TARGETS: [DdiKeyType; 4] = [
    DdiKeyType::Aes256,
    DdiKeyType::AesGcmBulk256,
    DdiKeyType::AesGcmBulk256Unapproved,
    DdiKeyType::AesXtsBulk256,
];

#[test]
fn mbor_aes_generation_rolls_back_if_cqe_delivery_fails() {
    for kind in AES_TARGETS {
        run_cqe_boundary(DdiOp::AesGenerateKey, kind);
    }
}

#[test]
fn mbor_hkdf_rolls_back_if_cqe_delivery_fails() {
    for kind in AES_TARGETS.into_iter().chain([DdiKeyType::HmacSha256]) {
        run_cqe_boundary(DdiOp::HkdfDerive, kind);
    }
}

#[test]
fn mbor_kbkdf_rolls_back_if_cqe_delivery_fails() {
    for kind in AES_TARGETS.into_iter().chain([DdiKeyType::HmacSha256]) {
        run_cqe_boundary(DdiOp::KbkdfCounterHmacDerive, kind);
    }
}

#[test]
fn mbor_unmask_rolls_back_if_cqe_delivery_fails() {
    for kind in AES_TARGETS {
        run_cqe_boundary(DdiOp::UnmaskKey, kind);
    }
}

#[test]
fn mbor_rsa_unwrap_rolls_back_if_cqe_delivery_fails() {
    for kind in AES_TARGETS {
        run_cqe_boundary(DdiOp::RsaUnwrap, kind);
    }
}

fn run_cqe_boundary(op: DdiOp, kind: DdiKeyType) {
    run_test(move || check_cqe_boundary(op, kind));
}

fn run_test<F: std::future::Future<Output = ()>>(test: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(test());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_cqe_boundary(op: DdiOp, kind: DdiKeyType) {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    let pal = hsm.pal();
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
    let control_io = pal.poll_io().await.expect("poll control IO");
    let masking_key = pal.dma_alloc(&control_io, 80).expect("masking key");
    masking_key.fill(0x5a);
    let session_id = pal
        .session_create(&control_io, &[1, 0, 0, 0, 0, 0, 0, 0], masking_key, None)
        .await
        .expect("session");
    let label = pal.dma_alloc(&control_io, 1).expect("label");
    let mut metadata = [0; 16];
    let mut request = HostPage([0; 4096]);
    let hdr = DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op,
        sess_id: Some(session_id.into()),
    };
    let mut input_key = None;
    let request_len = match op {
        DdiOp::EccGenerateKeyPair => {
            // Session-scoped signing/verification key.
            metadata[0] = 0x31;
            DdiEncoder::encode_parts(
                hdr,
                DdiEccGenerateKeyPairReq {
                    curve: DdiEccCurve::P256,
                    key_tag: None,
                    key_properties: DdiTargetKeyProperties {
                        key_metadata: DdiTargetKeyMetadata { blob: metadata },
                        key_label: &mut label[..0],
                    },
                },
                &mut request.0,
            )
        }
        DdiOp::EcdhKeyExchange => {
            let curve = HsmEccCurve::P256;
            let private_key = pal
                .dma_alloc(&control_io, curve.wire_priv_key_len())
                .expect("private key");
            let public_key = pal
                .dma_alloc(&control_io, curve.wire_pub_key_len())
                .expect("public key");
            pal.alloc_scoped_async(&control_io, async |alloc| {
                pal.ecc_gen_keypair(
                    &control_io,
                    alloc,
                    curve,
                    Some((&mut *private_key, &mut *public_key)),
                    HsmEccPct::KeyAgreement,
                )
                .await
            })
            .await
            .expect("input ECC key pair");
            let key_id = pal
                .vault_key_create(
                    &control_io,
                    private_key,
                    HsmVaultKeyKind::Ecc256Private,
                    None,
                    HsmVaultKeyAttrs::new().with_derive(true),
                )
                .await
                .expect("store input ECC key");
            input_key = Some((key_id, &*private_key));
            // Session-scoped derived secret.
            metadata[0] = 0x41;
            DdiEncoder::encode_parts(
                hdr,
                DdiEcdhKeyExchangeReq {
                    priv_key_id: key_id.into(),
                    pub_key_der: public_key,
                    key_type: DdiKeyType::Secret256,
                    key_tag: None,
                    key_properties: DdiTargetKeyProperties {
                        key_metadata: DdiTargetKeyMetadata { blob: metadata },
                        key_label: &mut label[..0],
                    },
                },
                &mut request.0,
            )
        }
        DdiOp::AesGenerateKey => {
            metadata[0] = 0x0d;
            let key_size = match kind {
                DdiKeyType::Aes256 => DdiAesKeySize::Aes256,
                DdiKeyType::AesGcmBulk256 => DdiAesKeySize::AesGcmBulk256,
                DdiKeyType::AesGcmBulk256Unapproved => DdiAesKeySize::AesGcmBulk256Unapproved,
                DdiKeyType::AesXtsBulk256 => DdiAesKeySize::AesXtsBulk256,
                _ => panic!("unsupported AES target"),
            };
            DdiEncoder::encode_parts(
                hdr,
                DdiAesGenerateKeyReq {
                    key_size,
                    key_tag: None,
                    key_properties: DdiTargetKeyProperties {
                        key_metadata: DdiTargetKeyMetadata { blob: metadata },
                        key_label: &mut label[..0],
                    },
                },
                &mut request.0,
            )
        }
        DdiOp::HkdfDerive | DdiOp::KbkdfCounterHmacDerive => {
            let secret = pal.dma_alloc(&control_io, 32).expect("input secret");
            secret.fill(0x73);
            let key_id = pal
                .vault_key_create(
                    &control_io,
                    secret,
                    HsmVaultKeyKind::Secret256,
                    None,
                    HsmVaultKeyAttrs::new().with_derive(true),
                )
                .await
                .expect("store input secret");
            input_key = Some((key_id, &*secret));
            metadata[0] = if kind == DdiKeyType::HmacSha256 {
                0x31
            } else {
                0x0d
            };
            let properties = DdiTargetKeyProperties {
                key_metadata: DdiTargetKeyMetadata { blob: metadata },
                key_label: &mut label[..0],
            };
            if op == DdiOp::HkdfDerive {
                DdiEncoder::encode_parts(
                    hdr,
                    DdiHkdfDeriveReq {
                        key_id: key_id.into(),
                        hash_algorithm: DdiHashAlgorithm::Sha256,
                        salt: None,
                        info: None,
                        key_type: kind,
                        key_tag: None,
                        key_properties: properties,
                        key_length: None,
                    },
                    &mut request.0,
                )
            } else {
                let context = pal.dma_alloc(&control_io, 1).expect("KDF context");
                context[0] = 1;
                DdiEncoder::encode_parts(
                    hdr,
                    DdiKbkdfCounterHmacDeriveReq {
                        key_id: key_id.into(),
                        hash_algorithm: DdiHashAlgorithm::Sha256,
                        label: None,
                        context: Some(context),
                        key_type: kind,
                        key_tag: None,
                        key_properties: properties,
                        key_length: None,
                    },
                    &mut request.0,
                )
            }
        }
        DdiOp::UnmaskKey => {
            let material = pal.dma_alloc(&control_io, 32).expect("import material");
            material.fill(0x73);
            let attrs = HsmVaultKeyAttrs::new()
                .with_session(true)
                .with_encrypt(true)
                .with_decrypt(true);
            let metadata = DdiMaskedKeyMetadata {
                svn: pal.mfgr_svn(),
                key_type: kind,
                key_attributes: attrs.into(),
                bks2_index: Some(u16::try_from(pal.dev_owner_svn()).expect("owner SVN")),
                rsvd: None,
                key_label: &[],
                key_length: 32,
            };
            let masked = pal.dma_alloc(&control_io, 1024).expect("masked key");
            let len = tsra_fw_core_crypto_key_masking::cbc::mask(
                pal,
                &control_io,
                masking_key,
                material,
                &metadata,
                Some(masked),
            )
            .await
            .expect("mask input");
            DdiEncoder::encode_parts(
                hdr,
                DdiUnmaskKeyReq {
                    masked_key: &mut masked[..len],
                },
                &mut request.0,
            )
        }
        DdiOp::RsaUnwrap => {
            use tsra_crypto::*;

            let key_id = pal
                .part_prop_get_u16(&control_io, HsmPartPropId::RSA_UNWRAPPING_KEY_ID)
                .expect("unwrapping key");
            let material = pal
                .vault_key(&control_io, key_id.into())
                .expect("unwrap material");
            let expected = pal
                .dma_alloc(&control_io, material.len())
                .expect("input snapshot");
            expected.copy_from_slice(material);
            input_key = Some((key_id.into(), &*expected));
            let private = RsaPrivateKey::from_hsm_bytes(material).expect("unwrap private key");
            let public = private.public_key().expect("unwrap public key");
            let mut wrapper = RsaAesKeyWrap::new(HashAlgo::sha256(), 32);
            let mut wrapped =
                Encrypter::encrypt_vec(&mut wrapper, &public, &[0x73; 32]).expect("wrap AES key");
            wrapped[..private.size()].reverse();
            let blob = pal
                .dma_alloc(&control_io, wrapped.len())
                .expect("wrapped key");
            blob.copy_from_slice(&wrapped);
            metadata[0] = 0x0d;
            let key_class = match kind {
                DdiKeyType::Aes256 => DdiKeyClass::Aes,
                DdiKeyType::AesGcmBulk256 => DdiKeyClass::AesGcmBulk,
                DdiKeyType::AesGcmBulk256Unapproved => DdiKeyClass::AesGcmBulkUnapproved,
                DdiKeyType::AesXtsBulk256 => DdiKeyClass::AesXtsBulk,
                _ => panic!("unsupported unwrap target"),
            };
            DdiEncoder::encode_parts(
                hdr,
                DdiRsaUnwrapReq {
                    key_id,
                    wrapped_blob: blob,
                    wrapped_blob_key_class: key_class,
                    wrapped_blob_padding: DdiRsaCryptoPadding::Oaep,
                    wrapped_blob_hash_algorithm: DdiHashAlgorithm::Sha256,
                    key_tag: None,
                    key_properties: DdiTargetKeyProperties {
                        key_metadata: DdiTargetKeyMetadata { blob: metadata },
                        key_label: &mut label[..0],
                    },
                },
                &mut request.0,
            )
        }
        _ => panic!("unsupported rollback test operation"),
    }
    .expect("encode key creation");

    let mut retained_key = None;
    for deliver_cqe in [true, false] {
        let mut response = HostPage([0; 4096]);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let reply_rx = if deliver_cqe {
            Some(reply_rx)
        } else {
            // StdOic returns CompleteIoFailure when its receiver is gone.
            drop(reply_rx);
            None
        };
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_MBOR))
                .buf_lens(request_len as u32, 4096)
                .src_prp1(request.0.as_ptr() as u64)
                .dst_prp1(response.0.as_mut_ptr() as u64)
                .session_flags(SessionFlags::new().with_ctrl(3).with_id_valid(true))
                .session_id(session_id.into())
                .build(),
            reply_tx,
        ))
        .await
        .expect("key creation IO");
        let io = pal.poll_io().await.expect("poll key creation IO");
        hsm.handle_io(io).await;
        if let Some(reply_rx) = reply_rx {
            let mut completion = reply_rx.await.expect("key creation completion");
            let cqe = completion
                .first_chunk_mut::<CQE_DWORDS>()
                .expect("command CQE");
            assert_eq!(Cqe::from(cqe).status(), 0);
        }

        let decoded = pal.dma_alloc(&control_io, 4096).expect("response");
        decoded.copy_from_slice(&response.0);
        let mut decoder = MborDecoder::new(decoded);
        let (status, key_id) = match op {
            DdiOp::EccGenerateKeyPair => {
                let response = DdiEccGenerateKeyPairCmdResp::mbor_decode(&mut decoder)
                    .expect("ECC response DMA succeeded");
                (response.hdr.status, response.data.private_key_id)
            }
            DdiOp::EcdhKeyExchange => {
                let response = DdiEcdhKeyExchangeCmdResp::mbor_decode(&mut decoder)
                    .expect("ECDH response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            DdiOp::AesGenerateKey => {
                let response = DdiAesGenerateKeyCmdResp::mbor_decode(&mut decoder)
                    .expect("AES response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            DdiOp::HkdfDerive => {
                let response = DdiHkdfDeriveCmdResp::mbor_decode(&mut decoder)
                    .expect("HKDF response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            DdiOp::KbkdfCounterHmacDerive => {
                let response = DdiKbkdfCounterHmacDeriveCmdResp::mbor_decode(&mut decoder)
                    .expect("KBKDF response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            DdiOp::UnmaskKey => {
                let response = DdiUnmaskKeyCmdResp::mbor_decode(&mut decoder)
                    .expect("unmask response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            DdiOp::RsaUnwrap => {
                let response = DdiRsaUnwrapCmdResp::mbor_decode(&mut decoder)
                    .expect("RSA unwrap response DMA succeeded");
                (response.hdr.status, response.data.key_id)
            }
            _ => panic!("unsupported rollback test operation"),
        };
        assert_eq!(status, 0);
        let key_id = key_id.into();
        if deliver_cqe {
            retained_key = Some(key_id);
        } else {
            assert_eq!(
                pal.vault_key_delete(&control_io, key_id).await,
                Err(HsmError::KeyNotFound),
                "failed CQE delivery must roll back the created key"
            );
        }
    }
    pal.vault_key_delete(&control_io, retained_key.expect("successful output key"))
        .await
        .expect("successful CQE must retain the key across another IO's rollback");
    if let Some((key_id, expected)) = input_key {
        assert_eq!(
            pal.vault_key(&control_io, key_id).expect("input ECC key"),
            expected,
            "rollback must preserve the input key"
        );
    }
    assert_eq!(
        pal.session_masking_key(&control_io, session_id)
            .expect("session masking key"),
        &[0x5a; 80],
        "rollback must preserve the existing session"
    );
    if op == DdiOp::AesGenerateKey && kind == DdiKeyType::Aes256 {
        let material = pal.dma_alloc(&control_io, 32).expect("capacity probe");
        material.fill(0x73);
        let baseline = vault_capacity(pal, &control_io, material, HsmVaultKeyKind::Aes256).await;
        // App-scoped output creates a key, then fails masking because this
        // fixture deliberately has no partition masking key.
        metadata[0] = 0x0c;
        let len = DdiEncoder::encode_parts(
            DdiReqHdr {
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
                op,
                sess_id: Some(session_id.into()),
            },
            DdiAesGenerateKeyReq {
                key_size: DdiAesKeySize::Aes256,
                key_tag: None,
                key_properties: DdiTargetKeyProperties {
                    key_metadata: DdiTargetKeyMetadata { blob: metadata },
                    key_label: &mut label[..0],
                },
            },
            &mut request.0,
        )
        .expect("encode failing AES request");
        let mut response = HostPage([0; 4096]);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_MBOR))
                .buf_lens(len as u32, 4096)
                .src_prp1(request.0.as_ptr() as u64)
                .dst_prp1(response.0.as_mut_ptr() as u64)
                .session_flags(SessionFlags::new().with_ctrl(3).with_id_valid(true))
                .session_id(session_id.into())
                .build(),
            reply_tx,
        ))
        .await
        .expect("failing AES IO");
        hsm.handle_io(pal.poll_io().await.expect("poll failing AES"))
            .await;
        let mut completion = reply_rx.await.expect("DDI error completion");
        assert_eq!(
            Cqe::from(completion.first_chunk_mut::<CQE_DWORDS>().expect("CQE")).status(),
            0,
        );
        let decoded = pal
            .dma_alloc(&control_io, 4096)
            .expect("DDI error response");
        decoded.copy_from_slice(&response.0);
        let header: DdiRespHdr = DdiDecoder::new(decoded).decode_hdr().expect("error header");
        assert_eq!(header.status, HsmError::PartPropNotFound.0);
        assert_eq!(
            vault_capacity(pal, &control_io, material, HsmVaultKeyKind::Aes256).await,
            baseline,
            "a DDI failure must reclaim its key even when CQE delivery succeeds"
        );
    }
    pal.drop_io(control_io).await.expect("drop control IO");
}

#[test]
fn mbor_open_session_rolls_back_without_restoring_consumed_nonce() {
    run_test(check_open_session_boundary);
}

async fn check_open_session_boundary() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    let pal = hsm.pal();
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
    let control_io = pal.poll_io().await.expect("poll control IO");
    let mk = pal
        .dma_alloc(&control_io, 80)
        .expect("partition masking key");
    mk.fill(0x5a);
    let mk_id = pal
        .vault_key_create(
            &control_io,
            mk,
            HsmVaultKeyKind::MaskingKey,
            None,
            HsmVaultKeyAttrs::new().with_internal(true),
        )
        .await
        .expect("store masking key");
    pal.part_prop_set_u16(&control_io, HsmPartPropId::MK_KEY_ID, mk_id.into())
        .expect("provision partition");
    let credential = pal.dma_alloc(&control_io, 32).expect("credential");
    credential.fill(0x55);
    pal.part_prop_set_bytes(&control_io, HsmPartPropId::CREDENTIAL, credential)
        .expect("establish credential");
    let session_blob = pal.dma_alloc(&control_io, 88).expect("capacity probe");
    session_blob.fill(0);
    let baseline = vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await;
    let mut retained_session = None;

    for deliver_cqe in [true, false] {
        let mut request = HostPage([0; 4096]);
        let mut response = HostPage([0; 4096]);
        let (request_len, nonce) = encode_open_request(pal, &control_io, &mut request.0).await;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let reply_rx = if deliver_cqe {
            Some(reply_rx)
        } else {
            drop(reply_rx);
            None
        };
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            SqeBuilder::new()
                .cmd(CmdDword::new().with_op(OP_MBOR))
                .buf_lens(request_len as u32, 4096)
                .src_prp1(request.0.as_ptr() as u64)
                .dst_prp1(response.0.as_mut_ptr() as u64)
                .session_flags(SessionFlags::new().with_ctrl(1))
                .build(),
            reply_tx,
        ))
        .await
        .expect("open IO");
        hsm.handle_io(pal.poll_io().await.expect("poll open")).await;
        if let Some(reply_rx) = reply_rx {
            let mut completion = reply_rx.await.expect("completion");
            let cqe = Cqe::from(completion.first_chunk_mut::<CQE_DWORDS>().expect("CQE"));
            assert_eq!(cqe.status(), 0);
        }
        assert_ne!(
            pal.part_prop_get_bytes(&control_io, HsmPartPropId::NONCE)
                .expect("nonce"),
            &nonce[..],
            "rollback must not restore a consumed security nonce"
        );
        let decoded = pal.dma_alloc(&control_io, 4096).expect("open response");
        decoded.copy_from_slice(&response.0);
        let response = DdiOpenSessionCmdResp::mbor_decode(&mut MborDecoder::new(decoded))
            .expect("open response DMA succeeded");
        assert_eq!(response.hdr.status, 0);
        let id = response.data.sess_id.into();
        if deliver_cqe {
            retained_session = Some(id);
        } else {
            assert!(matches!(
                pal.session_state(&control_io, id),
                HsmSessionState::Invalid
            ));
        }
        assert_eq!(
            vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await,
            baseline - 1,
            "only the successful open may retain its backing vault allocation"
        );
    }
    pal.session_destroy(&control_io, retained_session.expect("successful open"))
        .await
        .expect("successful session survived rollback");
    assert_eq!(
        vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await,
        baseline,
    );
    assert_eq!(
        pal.vault_key(&control_io, mk_id)
            .expect("partition masking key"),
        mk
    );
    assert_eq!(
        pal.part_prop_get_bytes(&control_io, HsmPartPropId::CREDENTIAL)
            .expect("credential"),
        credential,
    );
    pal.drop_io(control_io).await.expect("drop control IO");
}

async fn encode_open_request(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    request: &mut [u8],
) -> (usize, Vec<u8>) {
    encode_session_request(pal, io, request, None).await
}

async fn encode_session_request(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    request: &mut [u8],
    reopen: Option<(HsmSessId, &mut tsra_fw_hsm_pal_traits::HsmDmaBuf)>,
) -> (usize, Vec<u8>) {
    pal.alloc_scoped_async(io, async |_scope| {
        let key_id = pal
            .part_prop_get_u16(io, HsmPartPropId::SESSION_ENC_KEY_ID)
            .expect("session encryption key");
        let key = pal
            .vault_key(io, key_id.into())
            .expect("session key material");
        let (public, private) = key.split_at(HsmEccCurve::P384.pub_key_len());
        let secret = pal.dma_alloc(io, 48).expect("ECDH secret");
        pal.ecdh_derive(io, HsmEccCurve::P384, private, public, secret)
            .await
            .expect("credential ECDH");
        secret.reverse();
        let nonce = pal.dma_alloc(io, 32).expect("request nonce");
        nonce.copy_from_slice(
            pal.part_prop_get_bytes(io, HsmPartPropId::NONCE)
                .expect("nonce"),
        );
        let old_nonce = nonce.to_vec();
        let prk = pal.dma_alloc(io, 48).expect("credential PRK");
        let okm = pal.dma_alloc(io, 80).expect("transport keys");
        pal.hkdf_extract(io, HsmHashAlgo::Sha384, None, secret, prk)
            .await
            .expect("extract");
        pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(nonce), okm)
            .await
            .expect("expand");
        let iv = pal.dma_alloc(io, 16).expect("IV");
        iv.fill(0x17);
        let encrypted = pal.dma_alloc(io, 80).expect("encrypted credential");
        encrypted[..32].fill(0x55);
        encrypted[32..].fill(0x73);
        pal.aes_cbc_enc_dec_in_place(io, HsmAesOp::Encrypt, &okm[..32], encrypted, iv, None)
            .await
            .expect("encrypt credential");
        let authenticated = pal.dma_alloc(io, 128).expect("authenticated credential");
        authenticated[..80].copy_from_slice(encrypted);
        authenticated[80..96].copy_from_slice(iv);
        authenticated[96..].copy_from_slice(nonce);
        let tag = pal.dma_alloc(io, 48).expect("credential tag");
        pal.hmac_sign(io, HsmHashAlgo::Sha384, &okm[32..], authenticated, tag)
            .await
            .expect("authenticate credential");
        let public_buf = pal.dma_alloc(io, public.len()).expect("host public key");
        public_buf.copy_from_slice(public);
        let (encrypted_id, rest) = encrypted.split_at_mut(16);
        let (encrypted_pin, encrypted_seed) = rest.split_at_mut(16);
        let encrypted_credential = DdiEncryptedSessionCredential {
            encrypted_id,
            encrypted_pin,
            encrypted_seed,
            iv,
            nonce,
            tag,
        };
        let pub_key = DdiPublicKey {
            raw: public_buf,
            key_kind: DdiKeyType::Ecc384Public,
        };
        let rev = Some(DdiApiRev { major: 1, minor: 0 });
        let len = if let Some((id, bmk_session)) = reopen {
            DdiEncoder::encode_parts(
                DdiReqHdr {
                    rev,
                    op: DdiOp::ReopenSession,
                    sess_id: Some(id.into()),
                },
                DdiReopenSessionReq {
                    encrypted_credential,
                    pub_key,
                    bmk_session,
                },
                request,
            )
        } else {
            DdiEncoder::encode_parts(
                DdiReqHdr {
                    rev,
                    op: DdiOp::OpenSession,
                    sess_id: None,
                },
                DdiOpenSessionReq {
                    encrypted_credential,
                    pub_key,
                },
                request,
            )
        }
        .expect("encode session request");
        (len, old_nonce)
    })
    .await
}

#[test]
fn mbor_reopen_session_cqe_failure_retains_id_and_allows_fresh_nonce_retry() {
    run_test(check_reopen_session_boundary);
}

async fn check_reopen_session_boundary() {
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    let pal = hsm.pal();
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
    let control_io = pal.poll_io().await.expect("poll control IO");
    let mk = pal
        .dma_alloc(&control_io, 80)
        .expect("partition masking key");
    mk.fill(0x5a);
    let credential = pal.dma_alloc(&control_io, 32).expect("credential");
    credential.fill(0x55);
    let mut request = HostPage([0; 4096]);
    let mut response = HostPage([0; 4096]);
    let mut session_id = None;
    let mut saved_bmk = Vec::new();
    let session_blob = pal.dma_alloc(&control_io, 88).expect("capacity probe");
    session_blob.fill(0);
    let mut baseline = 0;

    for stage in 0..3 {
        if stage < 2 {
            if stage == 1 {
                pal.part_disable_internal(0).expect("simulate migration");
                pal.part_enable_internal(0)
                    .await
                    .expect("enable after migration");
                assert!(matches!(
                    pal.session_state(&control_io, session_id.expect("saved ID")),
                    HsmSessionState::NeedsRenegotiation
                ));
            }
            let mk_id = pal
                .vault_key_create(
                    &control_io,
                    mk,
                    HsmVaultKeyKind::MaskingKey,
                    None,
                    HsmVaultKeyAttrs::new().with_internal(true),
                )
                .await
                .expect("restore partition masking key");
            pal.part_prop_set_u16(&control_io, HsmPartPropId::MK_KEY_ID, mk_id.into())
                .expect("provision partition");
            pal.part_prop_set_bytes(&control_io, HsmPartPropId::CREDENTIAL, credential)
                .expect("restore credential");
            baseline =
                vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await;
        }
        let (len, nonce) = if let Some(id) = session_id {
            let bmk = pal
                .dma_alloc(&control_io, saved_bmk.len())
                .expect("saved session BMK");
            bmk.copy_from_slice(&saved_bmk);
            encode_session_request(pal, &control_io, &mut request.0, Some((id, bmk))).await
        } else {
            encode_open_request(pal, &control_io, &mut request.0).await
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let reply_rx = if stage == 1 {
            drop(reply_rx);
            None
        } else {
            Some(reply_rx)
        };
        let mut sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_MBOR))
            .buf_lens(len as u32, 4096)
            .src_prp1(request.0.as_ptr() as u64)
            .dst_prp1(response.0.as_mut_ptr() as u64);
        sqe = if let Some(id) = session_id {
            sqe.session_flags(SessionFlags::new().with_ctrl(3).with_id_valid(true))
                .session_id(id.into())
        } else {
            sqe.session_flags(SessionFlags::new().with_ctrl(1))
        };
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            sqe.build(),
            reply_tx,
        ))
        .await
        .expect("session IO");
        hsm.handle_io(pal.poll_io().await.expect("poll session"))
            .await;
        if let Some(reply_rx) = reply_rx {
            let mut cqe = reply_rx.await.expect("completion");
            assert_eq!(
                Cqe::from(cqe.first_chunk_mut::<CQE_DWORDS>().expect("CQE")).status(),
                0
            );
        }
        let decoded = pal.dma_alloc(&control_io, 4096).expect("session response");
        decoded.copy_from_slice(&response.0);
        let mut decoder = MborDecoder::new(decoded);
        if stage == 0 {
            let opened = DdiOpenSessionCmdResp::mbor_decode(&mut decoder).expect("open response");
            assert_eq!(opened.hdr.status, 0);
            session_id = Some(opened.data.sess_id.into());
            saved_bmk = opened.data.bmk_session.to_vec();
        } else {
            let reopened =
                DdiReopenSessionCmdResp::mbor_decode(&mut decoder).expect("reopen response");
            assert_eq!(
                reopened.hdr.status, 0,
                "reopen must succeed before CQE delivery"
            );
            assert_eq!(reopened.hdr.sess_id, session_id.map(u16::from));
            assert!(!reopened.data.bmk_session.is_empty());
        }
        let id = session_id.expect("session ID");
        assert_ne!(
            pal.part_prop_get_bytes(&control_io, HsmPartPropId::NONCE)
                .expect("nonce"),
            &nonce[..],
            "completion rollback must not restore the authenticated nonce"
        );
        if stage == 1 {
            assert!(matches!(
                pal.session_state(&control_io, id),
                HsmSessionState::NeedsRenegotiation
            ));
            assert!(
                pal.session_masking_key(&control_io, id).is_err(),
                "physical mapping cleared"
            );
            assert_eq!(
                vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await,
                baseline,
                "failed completion must delete the recreated backing key"
            );
        } else {
            assert!(matches!(
                pal.session_state(&control_io, id),
                HsmSessionState::Active
            ));
            assert_eq!(
                vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await,
                baseline - 1,
                "successful completion must retain the backing key"
            );
        }
    }
    pal.session_destroy(&control_io, session_id.expect("reopened ID"))
        .await
        .expect("close reopened session");
    assert_eq!(
        vault_capacity(pal, &control_io, session_blob, HsmVaultKeyKind::Session).await,
        baseline
    );
    pal.drop_io(control_io).await.expect("drop control IO");
}

async fn vault_capacity(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    material: &tsra_fw_hsm_pal_traits::HsmDmaBuf,
    kind: HsmVaultKeyKind,
) -> usize {
    let mut keys = Vec::new();
    loop {
        match pal
            .vault_key_create(io, material, kind, None, HsmVaultKeyAttrs::new())
            .await
        {
            Ok(id) => keys.push(id),
            Err(HsmError::NotEnoughSpace) => break,
            Err(err) => panic!("capacity probe failed: {err:?}"),
        }
    }
    let capacity = keys.len();
    for key in keys {
        pal.vault_key_delete(io, key)
            .await
            .expect("remove capacity probe");
    }
    capacity
}

#[test]
fn mbor_establish_credential_fresh_cqe_failure_allows_new_transport_retry() {
    run_test(|| check_establish_boundary(EstablishFailure::FreshCompletion));
}

#[test]
fn mbor_establish_credential_recovery_cqe_failure_restores_prior_unwrapping_key() {
    run_test(|| check_establish_boundary(EstablishFailure::RecoveryCompletion));
}

#[test]
fn mbor_establish_credential_invalid_unwrapping_type_reclaims_new_masking_key() {
    run_test(|| check_establish_boundary(EstablishFailure::InvalidUnwrappingType));
}

#[test]
fn mbor_establish_credential_invalid_bk3_consumes_transport_before_provisioning() {
    run_test(|| check_establish_boundary(EstablishFailure::InvalidBk3));
}

enum EstablishFailure {
    FreshCompletion,
    RecoveryCompletion,
    InvalidUnwrappingType,
    InvalidBk3,
}

struct EstablishFixture {
    masked_bk3: Vec<u8>,
    bmk: Vec<u8>,
    masked_unwrapping_key: Vec<u8>,
    pota_private: Vec<u8>,
    pota_public: Vec<u8>,
}

async fn partition_mbor(
    hsm: &Hsm<StdHsmPal>,
    tx: &async_channel::Sender<HsmIoRequest>,
    request: &HostPage,
    len: usize,
    flags: SessionFlags,
    deliver_cqe: bool,
) -> HostPage {
    let mut response = HostPage([0; 4096]);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let reply_rx = if deliver_cqe {
        Some(reply_rx)
    } else {
        drop(reply_rx);
        None
    };
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_MBOR))
            .buf_lens(len as u32, 4096)
            .src_prp1(request.0.as_ptr() as u64)
            .dst_prp1(response.0.as_mut_ptr() as u64)
            .session_flags(flags)
            .build(),
        reply_tx,
    ))
    .await
    .expect("partition command IO");
    hsm.handle_io(hsm.pal().poll_io().await.expect("poll partition command"))
        .await;
    if let Some(reply_rx) = reply_rx {
        let mut completion = reply_rx.await.expect("partition completion");
        assert_eq!(
            Cqe::from(completion.first_chunk_mut::<CQE_DWORDS>().expect("CQE")).status(),
            0
        );
    }
    response
}

fn partition_header(op: DdiOp) -> DdiReqHdr {
    DdiReqHdr {
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
        op,
        sess_id: None,
    }
}

fn decode_partition_response<R>(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    response: &HostPage,
    decode: impl FnOnce(&mut tsra_fw_hsm_pal_traits::HsmDmaBuf) -> R,
) -> R {
    pal.alloc_scoped(io, |_scope| {
        let decoded = pal.dma_alloc(io, response.0.len()).expect("DDI response");
        decoded.copy_from_slice(&response.0);
        decode(decoded)
    })
}

async fn refresh_establish_key(
    hsm: &Hsm<StdHsmPal>,
    tx: &async_channel::Sender<HsmIoRequest>,
    io: &StdHsmIo,
    deliver_cqe: bool,
) -> (Vec<u8>, Vec<u8>) {
    let mut request = HostPage([0; 4096]);
    let len = DdiEncoder::encode_parts(
        partition_header(DdiOp::GetEstablishCredEncryptionKey),
        DdiGetEstablishCredEncryptionKeyReq {},
        &mut request.0,
    )
    .expect("encode encryption-key query");
    let response = partition_mbor(hsm, tx, &request, len, SessionFlags::new(), deliver_cqe).await;
    decode_partition_response(hsm.pal(), io, &response, |decoded| {
        let response =
            DdiGetEstablishCredEncryptionKeyCmdResp::mbor_decode(&mut MborDecoder::new(decoded))
                .expect("encryption-key query response");
        assert_eq!(response.hdr.status, 0);
        (
            response.data.pub_key.raw.to_vec(),
            response.data.nonce.to_vec(),
        )
    })
}

async fn encode_establish_request(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    fixture: &EstablishFixture,
    request: &mut HostPage,
) -> usize {
    pal.alloc_scoped_async(io, async |_scope| {
        let key_id = pal
            .part_prop_get_u16(io, HsmPartPropId::ESTABLISH_CRED_KEY_ID)
            .expect("establish transport key");
        let key = pal
            .vault_key(io, key_id.into())
            .expect("transport material");
        let (public, private) = key.split_at(HsmEccCurve::P384.pub_key_len());
        let secret = pal.dma_alloc(io, 48).expect("ECDH secret");
        pal.ecdh_derive(io, HsmEccCurve::P384, private, public, secret)
            .await
            .expect("establish ECDH");
        secret.reverse();
        let nonce = pal.dma_alloc(io, 32).expect("nonce");
        nonce.copy_from_slice(
            pal.part_prop_get_bytes(io, HsmPartPropId::NONCE)
                .expect("current nonce"),
        );
        let prk = pal.dma_alloc(io, 48).expect("PRK");
        let okm = pal.dma_alloc(io, 80).expect("transport keys");
        pal.hkdf_extract(io, HsmHashAlgo::Sha384, None, secret, prk)
            .await
            .expect("extract");
        pal.hkdf_expand(io, HsmHashAlgo::Sha384, prk, Some(nonce), okm)
            .await
            .expect("expand");
        let iv = pal.dma_alloc(io, 16).expect("IV");
        iv.fill(0x17);
        let encrypted = pal.dma_alloc(io, 32).expect("credential");
        encrypted.fill(0x55);
        pal.aes_cbc_enc_dec_in_place(io, HsmAesOp::Encrypt, &okm[..32], encrypted, iv, None)
            .await
            .expect("encrypt credential");
        let authenticated = pal.dma_alloc(io, 80).expect("authenticated credential");
        authenticated[..32].copy_from_slice(encrypted);
        authenticated[32..48].copy_from_slice(iv);
        authenticated[48..].copy_from_slice(nonce);
        let tag = pal.dma_alloc(io, 48).expect("credential HMAC");
        pal.hmac_sign(io, HsmHashAlgo::Sha384, &okm[32..], authenticated, tag)
            .await
            .expect("authenticate credential");

        let identity = pal
            .part_prop_get_bytes(io, HsmPartPropId::PART_ID_ECC_PUB_KEY)
            .expect("identity public key");
        let identity_sec1 = pal.dma_alloc(io, 97).expect("SEC1 identity");
        identity_sec1[0] = 4;
        identity_sec1[1..].copy_from_slice(identity);
        let digest = pal.dma_alloc(io, 48).expect("POTA digest");
        pal.hash(io, HsmHashAlgo::Sha384, identity_sec1, digest, false)
            .await
            .expect("hash identity");
        let pota_private = pal.dma_alloc(io, 48).expect("POTA private key");
        pota_private.copy_from_slice(&fixture.pota_private);
        let signature = pal.dma_alloc(io, 96).expect("POTA signature");
        pal.ecc_sign(io, HsmEccCurve::P384, pota_private, digest, signature)
            .await
            .expect("endorse identity");

        let public_buf = pal.dma_alloc(io, public.len()).expect("host public key");
        public_buf.copy_from_slice(public);
        let pota_public = pal.dma_alloc(io, 96).expect("POTA public key");
        pota_public.copy_from_slice(&fixture.pota_public);
        let masked_bk3 = pal.dma_alloc(io, fixture.masked_bk3.len()).expect("BK3");
        masked_bk3.copy_from_slice(&fixture.masked_bk3);
        let bmk = pal.dma_alloc(io, fixture.bmk.len()).expect("BMK");
        bmk.copy_from_slice(&fixture.bmk);
        let masked_unwrapping_key = pal
            .dma_alloc(io, fixture.masked_unwrapping_key.len())
            .expect("masked unwrapping key");
        masked_unwrapping_key.copy_from_slice(&fixture.masked_unwrapping_key);
        let (encrypted_id, encrypted_pin) = encrypted.split_at_mut(16);
        DdiEncoder::encode_parts(
            partition_header(DdiOp::EstablishCredential),
            DdiEstablishCredentialReq {
                encrypted_credential: DdiEncryptedEstablishCredential {
                    encrypted_id,
                    encrypted_pin,
                    iv,
                    nonce,
                    tag,
                },
                pub_key: DdiPublicKey {
                    raw: public_buf,
                    key_kind: DdiKeyType::Ecc384Public,
                },
                masked_bk3,
                bmk,
                masked_unwrapping_key,
                pota_sig: signature,
                pota_pub_key: DdiPublicKey {
                    raw: pota_public,
                    key_kind: DdiKeyType::Ecc384Public,
                },
            },
            &mut request.0,
        )
        .expect("encode establish credential")
    })
    .await
}

async fn check_establish_boundary(failure: EstablishFailure) {
    let recovery = matches!(failure, EstablishFailure::RecoveryCompletion);
    let (tx, rx) = async_channel::bounded(1);
    let hsm = Hsm::new(StdHsmPal::new(rx, tokio::runtime::Handle::current()));
    let pal = hsm.pal();
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
    let io = pal.poll_io().await.expect("poll control");
    let mut request = HostPage([0; 4096]);
    let bk3 = pal.dma_alloc(&io, 48).expect("BK3");
    bk3.fill(0x63);
    let len = DdiEncoder::encode_parts(
        partition_header(DdiOp::InitBk3),
        DdiInitBk3Req { bk3 },
        &mut request.0,
    )
    .expect("encode InitBk3");
    let response = partition_mbor(&hsm, &tx, &request, len, SessionFlags::new(), true).await;
    let masked_bk3 = decode_partition_response(pal, &io, &response, |decoded| {
        let initialized = DdiInitBk3CmdResp::mbor_decode(&mut MborDecoder::new(decoded))
            .expect("InitBk3 response");
        assert_eq!(initialized.hdr.status, 0);
        initialized.data.masked_bk3.to_vec()
    });
    let pota_private = pal.dma_alloc(&io, 48).expect("POTA private key");
    let pota_public = pal.dma_alloc(&io, 96).expect("POTA public key");
    pal.alloc_scoped_async(&io, async |scope| {
        pal.ecc_gen_keypair(
            &io,
            scope,
            HsmEccCurve::P384,
            Some((&mut *pota_private, &mut *pota_public)),
            HsmEccPct::SignVerify,
        )
        .await
    })
    .await
    .expect("POTA key pair");
    let mut fixture = EstablishFixture {
        masked_bk3,
        bmk: Vec::new(),
        masked_unwrapping_key: Vec::new(),
        pota_private: pota_private.to_vec(),
        pota_public: pota_public.to_vec(),
    };
    let material = pal.dma_alloc(&io, 32).expect("retained AES material");
    material.fill(0x39);
    let retained = pal
        .vault_key_create(
            &io,
            material,
            HsmVaultKeyKind::Aes256,
            None,
            HsmVaultKeyAttrs::new(),
        )
        .await
        .expect("pre-existing key");
    let mut original_mk = Vec::new();
    let mut prior_unwrapping = None;
    if recovery {
        let len = encode_establish_request(pal, &io, &fixture, &mut request).await;
        let response = partition_mbor(&hsm, &tx, &request, len, SessionFlags::new(), true).await;
        fixture.bmk = decode_partition_response(pal, &io, &response, |decoded| {
            let established =
                DdiEstablishCredentialCmdResp::mbor_decode(&mut MborDecoder::new(decoded))
                    .expect("initial provisioning response");
            assert_eq!(established.hdr.status, 0);
            established.data.bmk.to_vec()
        });
        let mk_id = pal
            .part_prop_get_u16(&io, HsmPartPropId::MK_KEY_ID)
            .expect("MK");
        let mk = pal.vault_key(&io, mk_id.into()).expect("MK material");
        original_mk = mk.to_vec();
        let uk_id = pal
            .part_prop_get_u16(&io, HsmPartPropId::RSA_UNWRAPPING_KEY_ID)
            .expect("pre-existing unwrapping key");
        let uk = pal.vault_key(&io, uk_id.into()).expect("RSA material");
        prior_unwrapping = Some((uk_id, uk.to_vec()));
        let metadata = DdiMaskedKeyMetadata {
            svn: pal.mfgr_svn(),
            key_type: DdiKeyType::RsaUnwrap,
            key_attributes: pal
                .vault_key_attrs(&io, uk_id.into())
                .expect("RSA attrs")
                .into(),
            bks2_index: Some(u16::try_from(pal.dev_owner_svn()).expect("owner SVN")),
            rsvd: None,
            key_label: &[],
            key_length: uk.len() as u16,
        };
        let masked = pal.dma_alloc(&io, 1024).expect("masked RSA key");
        let len =
            tsra_fw_core_crypto_key_masking::cbc::mask(pal, &io, mk, uk, &metadata, Some(masked))
                .await
                .expect("mask RSA key for recovery");
        fixture.masked_unwrapping_key = masked[..len].to_vec();
        // Model re-provisioning while retaining a previously published UK.
        // Do not reset the PAL or delete unrelated vault entries.
        pal.part_prop_clear(&io, HsmPartPropId::CREDENTIAL)
            .expect("clear credential");
        pal.part_prop_clear(&io, HsmPartPropId::MK_KEY_ID)
            .expect("clear MK publication");
        pal.vault_key_delete(&io, mk_id.into())
            .await
            .expect("remove prior MK");
    }
    let (old_public, old_nonce) = refresh_establish_key(&hsm, &tx, &io, true).await;
    let old_transport = pal
        .part_prop_get_u16(&io, HsmPartPropId::ESTABLISH_CRED_KEY_ID)
        .expect("transport key ID");
    let masked_boot_key = pal
        .part_prop_get_bytes(&io, HsmPartPropId::MASKED_BK_BOOT)
        .expect("boot-key backup")
        .to_vec();
    let baseline = vault_capacity(pal, &io, material, HsmVaultKeyKind::Aes256).await;
    let transport_cost = vault_allocation_cost(
        pal,
        &io,
        material,
        pal.vault_key(&io, old_transport.into())
            .expect("old transport material"),
        HsmVaultKeyKind::EstablishCred,
    )
    .await;
    let mk_probe = pal.dma_alloc(&io, 80).expect("MK capacity probe");
    mk_probe.fill(0x5a);
    let mk_cost =
        vault_allocation_cost(pal, &io, material, mk_probe, HsmVaultKeyKind::MaskingKey).await;
    let uk_cost = if let Some((id, _)) = &prior_unwrapping {
        vault_allocation_cost(
            pal,
            &io,
            material,
            pal.vault_key(&io, (*id).into()).expect("UK capacity probe"),
            HsmVaultKeyKind::Rsa2kPrivate,
        )
        .await
    } else {
        0
    };
    let valid_bk3 = fixture.masked_bk3.clone();
    let expected_status = match failure {
        EstablishFailure::FreshCompletion | EstablishFailure::RecoveryCompletion => 0,
        EstablishFailure::InvalidUnwrappingType => {
            // A valid envelope with a non-RSA role fails after the new MK exists.
            fixture.masked_unwrapping_key = fixture.masked_bk3.clone();
            HsmError::InvalidKeyType.0
        }
        EstablishFailure::InvalidBk3 => {
            fixture.masked_bk3 = vec![0];
            HsmError::MaskedKeyDecodeFailed.0
        }
    };
    let len = encode_establish_request(pal, &io, &fixture, &mut request).await;
    let response = partition_mbor(
        &hsm,
        &tx,
        &request,
        len,
        SessionFlags::new(),
        expected_status != 0,
    )
    .await;
    let header: DdiRespHdr = decode_partition_response(pal, &io, &response, |decoded| {
        DdiDecoder::new(decoded)
            .decode_hdr()
            .expect("failed command response header")
    });
    assert_eq!(header.status, expected_status);
    for property in [
        HsmPartPropId::CREDENTIAL,
        HsmPartPropId::MK_KEY_ID,
        HsmPartPropId::ESTABLISH_CRED_KEY_ID,
    ] {
        if property == HsmPartPropId::CREDENTIAL {
            assert_eq!(
                pal.part_prop_get_bytes(&io, property),
                Err(HsmError::PartPropNotFound)
            );
        } else {
            assert_eq!(
                pal.part_prop_get_u16(&io, property),
                Err(HsmError::PartPropNotFound)
            );
        }
    }
    assert_eq!(
        pal.vault_key(&io, old_transport.into()),
        Err(HsmError::KeyNotFound)
    );
    assert_ne!(
        pal.part_prop_get_bytes(&io, HsmPartPropId::NONCE)
            .expect("consumed nonce"),
        old_nonce.as_slice()
    );
    assert_eq!(
        pal.part_prop_get_bytes(&io, HsmPartPropId::MASKED_BK_BOOT)
            .expect("preserved boot-key backup"),
        masked_boot_key.as_slice()
    );
    assert!(
        pal.part_prop_get_bool(&io, HsmPartPropId::BK3_INITIALIZED)
            .expect("BK3 initialization state"),
        "failed establishment must not require InitBk3 again"
    );
    assert_eq!(
        vault_capacity(pal, &io, material, HsmVaultKeyKind::Aes256).await,
        baseline + transport_cost,
        "only the consumed transport key may change vault capacity"
    );
    assert_eq!(
        pal.vault_key(&io, retained).expect("retained AES key"),
        material
    );
    assert_eq!(
        pal.part_existing_unwrapping_key_id(&io)
            .expect("published UK"),
        prior_unwrapping.as_ref().map(|(id, _)| (*id).into()),
    );
    if let Some((id, expected)) = &prior_unwrapping {
        assert_eq!(
            pal.vault_key(&io, (*id).into()).expect("original UK"),
            expected.as_slice()
        );
    }
    let replay = partition_mbor(&hsm, &tx, &request, len, SessionFlags::new(), true).await;
    let replay: DdiRespHdr = decode_partition_response(pal, &io, &replay, |decoded| {
        DdiDecoder::new(decoded)
            .decode_hdr()
            .expect("replay header")
    });
    assert_eq!(replay.status, HsmError::NonceMismatch.0);
    let mut provisioning_probe = HostPage([0; 4096]);
    let bmk_session = pal.dma_alloc(&io, 0).expect("empty probe BMK");
    let (probe_len, _) = encode_session_request(
        pal,
        &io,
        &mut provisioning_probe.0,
        Some((HsmSessId::from(0u16), bmk_session)),
    )
    .await;
    let response = partition_mbor(
        &hsm,
        &tx,
        &provisioning_probe,
        probe_len,
        SessionFlags::new().with_ctrl(3).with_id_valid(true),
        true,
    )
    .await;
    let probe: DdiRespHdr = decode_partition_response(pal, &io, &response, |decoded| {
        DdiDecoder::new(decoded)
            .decode_hdr()
            .expect("provisioning probe header")
    });
    assert_eq!(probe.status, HsmError::PartitionNotProvisioned.0);
    let (undelivered_public, undelivered_nonce) =
        refresh_establish_key(&hsm, &tx, &io, false).await;
    assert_ne!(undelivered_public, old_public);
    assert_ne!(undelivered_nonce, old_nonce);
    assert_eq!(
        pal.part_prop_get_u16(&io, HsmPartPropId::ESTABLISH_CRED_KEY_ID),
        Err(HsmError::PartPropNotFound),
        "a regenerated transport key must not survive failed query completion"
    );
    assert_eq!(
        vault_capacity(pal, &io, material, HsmVaultKeyKind::Aes256).await,
        baseline + transport_cost,
        "failed key-query completion must reclaim its generated transport key"
    );
    let (new_public, new_nonce) = refresh_establish_key(&hsm, &tx, &io, true).await;
    assert_ne!(
        new_public, old_public,
        "Get must regenerate the consumed key"
    );
    assert_ne!(new_nonce, old_nonce, "Get must expose the fresh nonce");
    assert_ne!(new_public, undelivered_public);
    assert_eq!(
        new_nonce, undelivered_nonce,
        "key queries do not consume nonces"
    );
    fixture.masked_bk3 = valid_bk3;
    if matches!(failure, EstablishFailure::InvalidUnwrappingType) {
        fixture.masked_unwrapping_key.clear();
    }
    let len = encode_establish_request(pal, &io, &fixture, &mut request).await;
    let response = partition_mbor(&hsm, &tx, &request, len, SessionFlags::new(), true).await;
    decode_partition_response(pal, &io, &response, |decoded| {
        let established =
            DdiEstablishCredentialCmdResp::mbor_decode(&mut MborDecoder::new(decoded))
                .expect("fresh-nonce retry response");
        assert_eq!(established.hdr.status, 0);
        assert!(!established.data.bmk.is_empty());
    });
    assert_eq!(
        pal.part_prop_get_bytes(&io, HsmPartPropId::CREDENTIAL)
            .expect("credential"),
        &[0x55; 32]
    );
    let mk_id = pal
        .part_prop_get_u16(&io, HsmPartPropId::MK_KEY_ID)
        .expect("retry MK");
    let mk = pal.vault_key(&io, mk_id.into()).expect("retry MK material");
    assert_eq!(mk.len(), 80);
    if recovery {
        assert_eq!(
            mk,
            original_mk.as_slice(),
            "BMK retry must restore the same MK"
        );
        let (id, expected) = prior_unwrapping.as_ref().expect("prior UK");
        let imported = pal
            .part_existing_unwrapping_key_id(&io)
            .expect("imported UK")
            .expect("published import");
        assert_ne!(u16::from(imported), *id);
        assert_eq!(
            pal.vault_key(&io, imported).expect("imported material"),
            expected.as_slice()
        );
        assert_eq!(
            pal.vault_key(&io, (*id).into())
                .expect("preserved prior UK"),
            expected.as_slice()
        );
    }
    assert_eq!(
        vault_capacity(pal, &io, material, HsmVaultKeyKind::Aes256).await,
        baseline + transport_cost - mk_cost - uk_cost,
        "retry retains exactly its MK and optional imported UK"
    );
    assert_eq!(
        pal.vault_key(&io, retained)
            .expect("retained AES after retry"),
        material
    );
    let (len, _) = encode_open_request(pal, &io, &mut request.0).await;
    let response = partition_mbor(
        &hsm,
        &tx,
        &request,
        len,
        SessionFlags::new().with_ctrl(1),
        true,
    )
    .await;
    let session_id = decode_partition_response(pal, &io, &response, |decoded| {
        let opened = DdiOpenSessionCmdResp::mbor_decode(&mut MborDecoder::new(decoded))
            .expect("open after retry");
        assert_eq!(opened.hdr.status, 0);
        opened.data.sess_id
    });
    pal.session_destroy(&io, session_id.into())
        .await
        .expect("close retried session");
    pal.drop_io(io).await.expect("drop control IO");
}

async fn vault_allocation_cost(
    pal: &StdHsmPal,
    io: &StdHsmIo,
    probe: &tsra_fw_hsm_pal_traits::HsmDmaBuf,
    material: &tsra_fw_hsm_pal_traits::HsmDmaBuf,
    kind: HsmVaultKeyKind,
) -> usize {
    let before = vault_capacity(pal, io, probe, HsmVaultKeyKind::Aes256).await;
    let key = pal
        .vault_key_create(io, material, kind, None, HsmVaultKeyAttrs::new())
        .await
        .expect("allocation-size probe");
    let after = vault_capacity(pal, io, probe, HsmVaultKeyKind::Aes256).await;
    pal.vault_key_delete(io, key)
        .await
        .expect("remove allocation-size probe");
    before - after
}
