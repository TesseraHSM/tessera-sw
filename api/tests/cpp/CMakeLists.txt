# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.14)

if(CMAKE_GENERATOR STREQUAL "Visual Studio 18 2026")
    # VS2026 generator requires 4.2
    cmake_minimum_required(VERSION 4.2)
endif()

project(tsra_api_cpp_tests VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()



include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
    ScopeGuard
    GIT_REPOSITORY https://github.com/Neargye/scope_guard.git
    GIT_TAG v0.9.1
)
FetchContent_MakeAvailable(ScopeGuard)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6 # Optionally specify a commit hash, version tag or branch here
)
FetchContent_MakeAvailable(Corrosion)

enable_testing()

corrosion_import_crate(
    MANIFEST_PATH ../../native/Cargo.toml
    CRATE_TYPES cdylib
    CRATES tsra_api_native
    )

corrosion_experimental_cbindgen(
    TARGET tsra_api_native
    HEADER_NAME "tsra_api.h"
    )

set(SOURCE 
    handle/part_list_handle.cpp
    utils/aes_keygen.cpp
    utils/kdf_derive.cpp
    utils/key_import.cpp
    utils/rsa_keygen.cpp
    utils/shared_secret.cpp
    utils/part_init_config.cpp
    utils/resiliency_config.cpp
    algo/aes/cbc_enc_dec_tests.cpp
    algo/aes/cfb_enc_dec_tests.cpp
    algo/aes/ctr_enc_dec_tests.cpp
    algo/aes/ecb_enc_dec_tests.cpp
    algo/aes/helpers.cpp
    algo/aes/keygen_tests.cpp
    algo/aes/ofb_enc_dec_tests.cpp
    algo/ecc/ecc_static_der.cpp
    algo/ecc/keygen_tests.cpp
    algo/ecc/unwrap_tests.cpp
    algo/ecc/unwrap_property_tests.cpp
    algo/ecc/unwrap_semantic_tests.cpp
    algo/ecc/helpers.cpp
    algo/ecc/sign_verify_tests.cpp
    algo/ecc/keyreport_tests.cpp
    algo/hmac/sign_verify_tests.cpp
    algo/hmac/keygen_tests.cpp
    algo/kdf/hkdf_tests.cpp
    algo/aes/gcm_enc_dec_tests.cpp
    algo/aes/xts_enc_dec_tests.cpp
    algo/rsa/keygen_tests.cpp
    algo/rsa/keyreport_tests.cpp
    algo/rsa/enc_dec_tests.cpp
    algo/rsa/rsa_static_der.cpp
    algo/rsa/sign_verify_tests.cpp
    algo/rsa/unwrap_tests.cpp
    algo/sha/digest_tests.cpp
    algo/secret/unmask_tests.cpp
    # `open_session_ex` tests (run with api_rev=1_1 in TSRA_TEST_ARGS)
    utils/sd_provision.cpp
    session_ex_tests.cpp
    algo/sealing/keygen_tests.cpp
    sd/create_backup_tests.cpp
    sd/create_peer_tests.cpp
    sd/reseal_tests.cpp
    sd/restore_local_tests.cpp
    sd/restore_peer_tests.cpp
    sd/restore_tests.cpp
    darc/transfer_tests.cpp
    # `open_session` tests (run with session unset or `1_0` in TSRA_TEST_ARGS)
    partition_tests.cpp
    session_tests.cpp
    handle_mgmt_tests.cpp
    multi_process_tests.cpp
    algo/kdf/kbkdf_tests.cpp
    resiliency/init_stress_tests.cpp
    resiliency/aes_stress_tests.cpp
    resiliency/ecc_stress_tests.cpp
    resiliency/mixed_stress_tests.cpp
)

add_executable(tsra_api_cpp_tests ${SOURCE})
target_include_directories(tsra_api_cpp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    # `StdHsm::build()` constructs the `Hsm`/`StdHsmPal` core synchronously
    # on the calling thread (only the Embassy executor itself runs on a
    # dedicated 8 MiB thread, see `EMBASSY_STACK_SIZE` in
    # `fw/plat/std/lib/src/lib.rs`). Those debug-build task frames are large
    # enough to overflow the default 1 MiB MSVC main-thread stack, crashing
    # this binary with STATUS_STACK_OVERFLOW (0xc00000fd) before any gtest
    # output is printed. Match the main thread's reserved stack to the
    # Embassy thread's so both can build `StdHsm` without overflowing.
    target_link_options(tsra_api_cpp_tests PRIVATE /STACK:8388608)
endif()

if(UNIX)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(
        tsra_api_cpp_tests
        PUBLIC
            tsra_api_native
            GTest::gtest_main
            scope_guard::scope_guard
            OpenSSL::Crypto
    )
else()
    target_link_libraries(
        tsra_api_cpp_tests
        PUBLIC
            tsra_api_native
            GTest::gtest_main
            scope_guard::scope_guard
            bcrypt
            ncrypt
    )
endif()

include(GoogleTest)
gtest_discover_tests(tsra_api_cpp_tests DISCOVERY_TIMEOUT 30)
