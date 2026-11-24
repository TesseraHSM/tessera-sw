// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build-orchestration crate for the TSRA PKCS#11 module.
//!
//! This crate intentionally contains no Rust logic. The PKCS#11 module itself
//! is implemented in C under `src/*.c` and built by `build.rs` via CMake (see
//! `CMakeLists.txt`), exactly like `plugins/ossl_prov`. The C code binds to the
//! TSRA native C API (`tsra.h`, generated from `api/native` by cbindgen).
//!
//! See `README.md` for the layering and the mapping to the TSRA SDK.
