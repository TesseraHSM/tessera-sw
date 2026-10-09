// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level tests for the DARC key-transfer command family
//! (`DarcKexKeyGen`, `DarcTmkGen`, `DarcTmkExport`, `DarcTmkImport`,
//! `DarcKeyWrap`, `DarcKeyUnwrap`) driven through the public
//! [`tsra_api::HsmSession`] surface against a real (emu/hardware)
//! backend.

mod transfer_tests;
