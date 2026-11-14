// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::Signer;
use tsra_ddi::*;
use tsra_ddi_mbor::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_establish_credential;
use tsra_ddi_mbor_types::*;
use common::*;
use libfuzzer_sys::fuzz_target;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Fuzz input for Establish Credential DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid pub key
    pub use_valid_pub_key: bool,
    /// If 'true', the fuzz test will generate a valid value for the masked_bk3 field
    pub use_valid_masked_bk3: bool,
    /// If 'true', the fuzz test will generate a valid value for pota_pub_key field
    pub use_valid_pota_pub_key: bool,
    /// If 'true', the fuzz test will generate a valid value for encrypted_credential field
    pub use_valid_encrypted_credential: bool,
    /// If 'true', the fuzz test will generate a valid value for pota_sig field
    pub use_valid_pota_sig: bool,
    /// A fuzzed `DdiEstablishCredentialReq` structure that provides the base for request parameters for the Establish Credential operation
    pub cmdreq_data: DdiEstablishCredentialReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_establish_credential(input);
});

pub fn fuzz_ddi_establish_credential(input: FuzzInput) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let mut dev = ddi
        .open_dev(&dev_infos[0].path)
        .expect("Failed to open device");

    cleanup(&ddi, &dev_infos[0].path, None);

    // Note: This test case to fuzz "EstablishCredential" does not need prior credential

    let mut cmdreq_data = input.cmdreq_data;
    let rev = Some(DdiApiRev { major: 1, minor: 0 });

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_establish_cred(&dev, TEST_CRED_ID, TEST_CRED_PIN);

    if input.use_valid_pub_key {
        cmdreq_data.pub_key = pub_key;
    }

    if input.use_valid_encrypted_credential {
        cmdreq_data.encrypted_credential = encrypted_credential;
    }

    if input.use_valid_masked_bk3 {
        cmdreq_data.masked_bk3 = helper_get_or_init_bk3(&mut dev);
    }

    if input.use_valid_pota_pub_key {
        // Set POTA public key from test constants
        cmdreq_data.pota_pub_key = DdiDerPublicKey {
            der: MborByteArray::from_slice(&TEST_POTA_ECC_PUB_KEY)
                .expect("Failed to create MborByteArray from POTA ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        };
    }

    if input.use_valid_pota_sig {
        let get_cert_chain_info =
            tsra_ddi_mbor_test_helpers::helper_get_cert_chain_info(&dev).unwrap();
        // Get last cert
        let cert_resp = tsra_ddi_mbor_test_helpers::helper_get_certificate(
            &dev,
            get_cert_chain_info.data.num_certs - 1,
        )
        .unwrap();

        let cert = cert_resp.data.certificate.as_slice();
        let cert = X509Certificate::from_der(cert).unwrap();
        let cert_pub_key_der = cert.get_public_key_der().unwrap();
        let cert_pub_key_obj = tsra_crypto::DerEccPublicKey::from_der(&cert_pub_key_der).unwrap();
        let mut cert_pub_uncomp = vec![0x04u8];
        cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.x());
        cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.y());
        let hash_algo = HashAlgo::sha384();
        let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);

        let pota_priv_key =
            tsra_crypto::EccPrivateKey::from_bytes(&TEST_POTA_ECC_PRIVATE_KEY).unwrap();

        let sig_len =
            Signer::sign(&mut ecdsa_algo, &pota_priv_key, &cert_pub_uncomp, None).unwrap();
        let mut signature = vec![0u8; sig_len];

        let _ = Signer::sign(
            &mut ecdsa_algo,
            &pota_priv_key,
            &cert_pub_uncomp,
            Some(&mut signature),
        )
        .unwrap();

        cmdreq_data.pota_sig = MborByteArray::from_slice(&signature)
            .expect("Failed to create MborByteArray from POTA signature");
    }

    debug_print_control_flags(&format!(
        "Input use_valid_pub_key: {}, use_valid_masked_bk3: {}, use_valid_pota_pub_key: {}, use_valid_encrypted_credential: {}, use_valid_pota_sig: {}",
        input.use_valid_pub_key,
        input.use_valid_masked_bk3,
        input.use_valid_pota_pub_key,
        input.use_valid_encrypted_credential,
        input.use_valid_pota_sig
    ));

    static FUZZ_DDI_ESTABLISH_CRED_INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = FUZZ_DDI_ESTABLISH_CRED_INVOCATION.fetch_add(1, Ordering::SeqCst) + 1;
    debug_print_request(
        "fuzz_ddi_establish_credential",
        invocation,
        invocation,
        &cmdreq_data,
    );

    let resp = helper_establish_credential(
        &dev,
        None,
        rev,
        cmdreq_data.encrypted_credential,
        cmdreq_data.pub_key,
        cmdreq_data.masked_bk3,
        cmdreq_data.bmk,
        cmdreq_data.masked_unwrapping_key,
        cmdreq_data.pota_sig,
        cmdreq_data.pota_pub_key,
    );

    if let Err(err) = &resp {
        if matches!(err, DdiError::DriverError(_)) {
            panic!("Crash Detected: {}", err);
        } else {
            debug_print_control_flags(&format!("Other error detected: {}", err));
        }
    }
}
