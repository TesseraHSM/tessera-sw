// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]

// mod cbc_tests;
mod cbc_tests_helper;
mod cbc_tests_nist_gf_sbox;
mod cbc_tests_nist_mct;
mod cbc_tests_nist_mmt;
mod cbc_tests_nist_sbox;
mod cbc_tests_nist_varkey;
mod cbc_tests_nist_vartxt;
mod cfb_tests;
mod cfb_tests_helper;
mod cfb_tests_nist_gf_sbox;
mod cfb_tests_nist_mct;
mod cfb_tests_nist_mmt;
mod cfb_tests_nist_sbox;
mod cfb_tests_nist_varkey;
mod cfb_tests_nist_vartxt;
mod ctr_tests;
mod ecb_tests;
mod gcm_tests;
mod kw_tests;
mod kwp_tests;
mod ofb_tests;
mod ofb_tests_helper;
mod ofb_tests_nist_gf_sbox;
mod ofb_tests_nist_mct;
mod ofb_tests_nist_mmt;
mod ofb_tests_nist_sbox;
mod ofb_tests_nist_varkey;
mod ofb_tests_nist_vartxt;
mod xts_tests;

use super::*;
