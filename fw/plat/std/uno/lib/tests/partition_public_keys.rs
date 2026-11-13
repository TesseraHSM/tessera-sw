// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableHsmKey;
use tsra_crypto::PrivateKey;
use tsra_fw_hsm_core::part_state;
use tsra_fw_hsm_pal_std_uno::HsmIoRequest;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartitionManager;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

#[test]
fn public_keys_follow_vault_references_and_preserve_big_endian_encoding() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(check_public_keys());
        })
        .expect("test thread")
        .join()
        .expect("test result");
}

async fn check_public_keys() {
    let (tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
    pal.part_alloc_internal(0, 1).await.expect("partition");
    pal.part_enable_internal(0).await.expect("enable");
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    tx.send(HsmIoRequest::cmd(
        HsmPartId::from(0u8),
        0,
        0,
        [0; 16],
        reply_tx,
    ))
    .await
    .expect("IO request");
    let io = pal.poll_io().await.expect("poll IO");

    let identity_id = part_state::part_id_key_id(&pal, &io).expect("identity key ID");
    let identity = EccPrivateKey::from_hsm_bytes(pal.vault_key(&io, identity_id).expect("key"))
        .expect("identity private key");
    let identity_public = identity.public_key().expect("identity public key");
    let mut expected = [0u8; 96];
    identity_public
        .to_hsm_bytes(&mut expected)
        .expect("export identity public key");
    let public = pal.dma_alloc(&io, 96).expect("public key buffer");
    part_state::part_id_pub_key(&pal, &io, public)
        .await
        .expect("derive identity public key");
    assert_eq!(&**public, expected.as_slice());

    assert_eq!(
        part_state::part_pta_pub_key(&pal, &io, public).await,
        Err(HsmError::PartPropNotFound)
    );
    let short = pal.dma_alloc(&io, 95).expect("short public key buffer");
    assert_eq!(
        part_state::part_id_pub_key(&pal, &io, short).await,
        Err(HsmError::EccInvalidKeyLength)
    );
    assert_eq!(
        pal.ecc_vault_pub_key(&io, identity_id, short).await,
        Err(HsmError::InvalidArg)
    );
    let misaligned = pal.dma_alloc(&io, 97).expect("misaligned output backing");
    misaligned.fill(0xA5);
    assert_eq!(
        pal.ecc_vault_pub_key(&io, identity_id, misaligned.split_at_mut(1).1)
            .await,
        Err(HsmError::InvalidArg)
    );
    assert!(misaligned.iter().all(|&b| b == 0xA5));

    let scalar = pal.dma_alloc(&io, 48).expect("private scalar");
    scalar.fill(0);
    scalar[47] = 1;
    let first = pal
        .vault_key_create(
            &io,
            scalar,
            HsmVaultKeyKind::PartitionTrustAnchor,
            None,
            HsmVaultKeyAttrs::new().with_internal(true),
        )
        .await
        .expect("PTA key");
    part_state::part_set_pta_key_id(&pal, &io, first).expect("bind PTA key");
    part_state::part_pta_pub_key(&pal, &io, public)
        .await
        .expect("derive PTA public key");
    let generator = hex::decode(concat!(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
    ))
    .expect("P-384 generator");
    assert_eq!(&**public, generator.as_slice());

    pal.part_prop_clear(&io, HsmPartPropId::PTA_KEY_ID)
        .expect("clear PTA reference");
    assert_eq!(
        part_state::part_pta_pub_key(&pal, &io, public).await,
        Err(HsmError::PartPropNotFound)
    );
    scalar[47] = 2;
    let second = pal
        .vault_key_create(
            &io,
            scalar,
            HsmVaultKeyKind::PartitionTrustAnchor,
            None,
            HsmVaultKeyAttrs::new().with_internal(true),
        )
        .await
        .expect("replacement PTA key");
    part_state::part_set_pta_key_id(&pal, &io, second).expect("bind replacement");
    part_state::part_pta_pub_key(&pal, &io, public)
        .await
        .expect("derive replacement public key");
    assert_ne!(&**public, generator.as_slice());
    pal.vault_key_delete(&io, second)
        .await
        .expect("delete referenced key");
    assert_eq!(
        part_state::part_pta_pub_key(&pal, &io, public).await,
        Err(HsmError::KeyNotFound)
    );
}
