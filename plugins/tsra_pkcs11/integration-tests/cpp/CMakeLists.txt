# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Functional tests for the TSRA PKCS#11 module, driven through the real
# Cryptoki ABI: the test binary dlopens the built module (path from the
# TSRA_PKCS11_MODULE environment variable, defaulting to the cargo build
# output) and talks to the device behind it, so it needs the simulator or
# hardware-backed build. The same build reaches a running ddi_sock_server
# named by TSRA_DDI_ARGS; cases that need an unprovisioned device start their
# own from server_bin= in TSRA_TEST_ARGS (and skip without it). The module
# also needs a partition ID and an owner backup key file to provision the
# device, as plugins/tsra_pkcs11/tests/start_sock_server.sh sets up in CI:
#
#   cargo build -p tsra_pkcs11
#   cargo build -p ddi_sock_server
#   target/debug/ddi_sock_server tcp://127.0.0.1:23456 &
#   export TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:23456"
#   export TSRA_TEST_ARGS="$TSRA_DDI_ARGS;server_bin=$PWD/target/debug/ddi_sock_server"
#   export TSRA_PKCS11_ID=01010101010101010101010101010101
#   (umask 077; head -c 48 /dev/urandom > target/owner-backup-key.bin)
#   export TSRA_PKCS11_OBK_PATH="$PWD/target/owner-backup-key.bin"
#   cmake -S plugins/tsra_pkcs11/integration-tests/cpp -B target/pkcs11-cpp-tests
#   cmake --build target/pkcs11-cpp-tests
#   ctest --test-dir target/pkcs11-cpp-tests --output-on-failure --no-tests=error
#
# Same shape as plugins/ossl_prov/integration-tests/openssl-capi/cpp.

cmake_minimum_required(VERSION 3.14)
project(tsra_pkcs11_cpp_tests VERSION 0.1.0 LANGUAGES CXX)

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

# Project Wycheproof (Apache-2.0) supplies negative known-answer vectors. It is
# third-party data, so it is fetched at a pinned commit, never committed, and
# converted in the build directory. FETCHCONTENT_SOURCE_DIR_WYCHEPROOF may name
# a local copy of the commit, or of its testvectors_v1 directory alone.
FetchContent_Declare(
    wycheproof
    URL https://github.com/C2SP/wycheproof/archive/7a325932231bd7a724c791c8b0d65ea4d6d2f435.tar.gz
    URL_HASH SHA256=a96fc6b82db54a32d87c95b88421868a84e254255f247cc5af3b8935dca818d2
)
FetchContent_MakeAvailable(wycheproof)
set(WYCHEPROOF_VECTORS "${wycheproof_SOURCE_DIR}/testvectors_v1")
if(NOT EXISTS "${WYCHEPROOF_VECTORS}")
    set(WYCHEPROOF_VECTORS "${wycheproof_SOURCE_DIR}")
endif()

enable_testing()

# The module's own tree (vendored PKCS#11 headers + the platform-macro header
# that fixes the Cryptoki ABI, and the template header for its constants).
get_filename_component(TSRA_PKCS11_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(TSRA_REPO_ROOT "${TSRA_PKCS11_ROOT}/../.." ABSOLUTE)

set(SOURCE
    main.cpp
    smoke_tests.cpp
    config_tests.cpp
    interface_tests.cpp
    host_crypto_tests.cpp
    aes/keygen_tests.cpp
    aes/cbc_tests.cpp
    aes/gcm_tests.cpp
    aes/xts_tests.cpp
    aes/multipart_tests.cpp
    aes/relation_tests.cpp
    aes/survival_tests.cpp
    ec/keygen_tests.cpp
    ec/sign_tests.cpp
    session/login_tests.cpp
    session/op_lifecycle_tests.cpp
    session/logout_tests.cpp
    object/attr_tests.cpp
    object/persist_tests.cpp
    object/policy_tests.cpp
    unwrap/pair_tests.cpp
    unwrap/unwrap_tests.cpp
    unwrap/kat_tests.cpp
)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(WYCHEPROOF_OUT "${CMAKE_CURRENT_BINARY_DIR}/wycheproof")
set(WYCHEPROOF_INC
    ${WYCHEPROOF_OUT}/aes_kwp.inc
    ${WYCHEPROOF_OUT}/aes_cbc_pkcs5.inc
    ${WYCHEPROOF_OUT}/aes_gcm.inc
)
add_custom_command(
    OUTPUT ${WYCHEPROOF_INC}
    COMMAND Python3::Interpreter -I ${TSRA_PKCS11_ROOT}/tools/gen_wycheproof.py
        ${WYCHEPROOF_VECTORS} ${WYCHEPROOF_OUT}
    DEPENDS ${TSRA_PKCS11_ROOT}/tools/gen_wycheproof.py
    COMMENT "Converting the Wycheproof vectors"
    VERBATIM
)

add_executable(tsra_pkcs11_cpp_tests ${SOURCE} ${WYCHEPROOF_INC})
target_include_directories(
    tsra_pkcs11_cpp_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${TSRA_PKCS11_ROOT}/include/pkcs11-v3.1
        ${TSRA_PKCS11_ROOT}/src
)
target_compile_options(tsra_pkcs11_cpp_tests PRIVATE -Wall -Wextra -Werror)
# Where the cargo build puts the module; TSRA_PKCS11_MODULE overrides at run time.
target_compile_definitions(
    tsra_pkcs11_cpp_tests
    PRIVATE TSRA_PKCS11_DEFAULT_MODULE="${TSRA_REPO_ROOT}/target/debug/tsra_pkcs11.so"
)

# The host oracle (utils/host_crypto.hpp) links the system libcrypto.
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
target_link_libraries(
    tsra_pkcs11_cpp_tests
    PRIVATE
        GTest::gtest
        OpenSSL::Crypto
        Threads::Threads
        ${CMAKE_DL_LIBS}
)

include(GoogleTest)
gtest_discover_tests(tsra_pkcs11_cpp_tests)
