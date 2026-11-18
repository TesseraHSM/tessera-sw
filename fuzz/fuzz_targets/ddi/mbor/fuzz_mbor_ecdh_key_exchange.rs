// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../mbor_common.rs"]
mod common;

use common::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_delete_key;
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_ecdh_key_exchange;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_types::*;

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

    if input.use_valid_key_id {
        let curve = match input.curve {
            DdiEccCurve::P256 | DdiEccCurve::P384 | DdiEccCurve::P521 => input.curve,
            _ => DdiEccCurve::P256,
        };
        let key_resp = helper_ecc_generate_key_pair(&dev, Some(sess_id), rev, curve, key_props);

        priv_key_id = match key_resp {
            Ok(resp) => resp.data.private_key_id,
            Err(err) => {
                panic!("Could not generate ECC key pair: {}", err);
            }
        };

        if input.use_valid_pub_key_der {
            let pub_key_resp =
                helper_ecc_generate_key_pair(&dev, Some(sess_id), rev, curve, key_props);

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

    let resp = helper_ecdh_key_exchange(
        &dev,
        Some(sess_id),
        rev,
        priv_key_id,
        cmdreq_data.pub_key_der,
        cmdreq_data.key_type,
        key_props,
    );

    if let Err(err @ DdiError::DriverError(_)) = &resp {
        panic!("Crash Detected: {err}");
    }

    if input.use_valid_key_id {
        helper_delete_key(&dev, Some(sess_id), rev, priv_key_id).expect("Could not delete key");
    }

    cleanup_with_session(&dev, Some(sess_id));
}
