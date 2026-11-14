// Copyright (C) Microsoft Corporation. All rights reserved.

#![no_main]

#[path = "../../common.rs"]
mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_ddi::*;
use tsra_ddi_mbor::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_ecdh_key_exchange;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;
use common::*;
use libfuzzer_sys::fuzz_target;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;

/// Fuzz input for ECDH Key Exchange DDI op.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    // If `true`, the fuzz test will generate a valid ECC private key
    pub use_valid_key_id: bool,
    // If `true`, the fuzz test will generate a valid peer ECC key pair
    pub use_valid_pub_key_der: bool,
    // Seed used to deterministically generate a 192-byte DER buffer when use_valid_pub_key_der` is false
    pub seed: u64,
    // Specifies the availability property of keys created during the test
    pub key_availability: DdiKeyAvailability,
    //Selects the elliptic curve to be used for ECC key generation
    pub curve: DdiEccCurve,
    // A fuzzed `DdiEcdhKeyExchangeReq` structure that provides the base for request parameters for the ECDH operation
    pub cmdreq_data: DdiEcdhKeyExchangeReq,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_ddi_ecdh_key_exchange(input);
});

pub fn fuzz_ddi_ecdh_key_exchange(input: FuzzInput) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let mut dev = ddi
        .open_dev(&dev_infos[0].path)
        .expect("Failed to open device");

    cleanup(&ddi, &dev_infos[0].path, None);
    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

    let sess_id = match helper_common_open_session(&mut dev) {
        Ok(id) => id,
        Err(err) => {
            panic!("Could not open session: {}", err);
        }
    };

    let mut cmdreq_data = input.cmdreq_data;
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut priv_key_id = cmdreq_data.priv_key_id;

    let key_props = helper_key_properties(DdiKeyUsage::Derive, input.key_availability);

    debug_print_control_flags(&format!(
        "Input use_valid_key_id: {}, use_valid_pub_key_der: {}",
        input.use_valid_key_id, input.use_valid_pub_key_der
    ));

    if input.use_valid_key_id {
        let key_resp =
            helper_ecc_generate_key_pair(&dev, Some(sess_id), rev, input.curve, None, key_props);

        priv_key_id = match key_resp {
            Ok(resp) => resp.data.private_key_id,
            Err(err) => {
                panic!("Could not generate ECC key pair: {}", err);
            }
        };

        if input.use_valid_pub_key_der {
            let pub_key_resp = helper_ecc_generate_key_pair(
                &dev,
                Some(sess_id),
                rev,
                input.curve,
                None,
                key_props,
            );

            // Extract both pub_key_der and the peer private key id from the same match,
            let (pub_key_der, peer_priv_id) = match pub_key_resp {
                Ok(resp) => {
                    let der = MborByteArray::from_slice(resp.data.pub_key.der.as_slice())
                        .expect("Could not convert generated ECC public key DER to request buffer");
                    (der, resp.data.private_key_id)
                }
                Err(err) => {
                    panic!(
                        "Could not generate ECC key pair for peer public key: {}",
                        err
                    );
                }
            };

            cmdreq_data.pub_key_der = pub_key_der;

            // Delete the peer key pair's private key now; we only need the DER public key.
            helper_delete_key(&dev, Some(sess_id), rev, peer_priv_id)
                .expect("Could not delete peer public key's private key");
        } else {
            // Deterministically generate buffer for `pub_key_der` using the provided seed.
            let mut rng = StdRng::seed_from_u64(input.seed);
            let mut buf = [0u8; 192];
            rng.fill_bytes(&mut buf);

            cmdreq_data.pub_key_der = MborByteArray::from_slice(&buf)
                .expect("Could not convert seeded DER buffer to request buffer");
        }
    }

    static FUZZ_DDI_ECDH_INVOCATION: AtomicUsize = AtomicUsize::new(0);
    let invocation = FUZZ_DDI_ECDH_INVOCATION.fetch_add(1, Ordering::SeqCst) + 1;
    let effective_priv_key_id = format!("Effective priv_key_id: {:?}", priv_key_id);
    debug_print_request_with_meta(
        "fuzz_ddi_ecdh_key_exchange",
        invocation,
        invocation,
        &cmdreq_data,
        Some(&effective_priv_key_id),
    );

    let resp = helper_ecdh_key_exchange(
        &dev,
        Some(sess_id),
        rev,
        priv_key_id,
        cmdreq_data.pub_key_der,
        cmdreq_data.key_tag,
        cmdreq_data.key_type,
        key_props,
    );

    if let Err(err) = &resp {
        if matches!(err, DdiError::DriverError(_)) {
            panic!("Crash Detected: {}", err);
        } else {
            debug_print_control_flags(&format!("Other error detected: {}", err));
        }
    }

    if input.use_valid_key_id {
        helper_delete_key(&dev, Some(sess_id), rev, priv_key_id).expect("Could not delete key");
    }

    cleanup_with_session(&dev, Some(sess_id));
}
