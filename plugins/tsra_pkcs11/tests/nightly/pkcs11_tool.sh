#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# OpenSC pkcs11-tool smokes for the nightly workflow, judged by the tool's
# output (grep), never by its exit status.
#
#   pkcs11_tool.sh threads <module.so>   three threads initialise the library
#                                        and read the token concurrently
#   pkcs11_tool.sh import <module.so>    a plaintext AES key written with
#                                        --write-object must be refused
#
# TSRA_PKCS11_TEST_PIN overrides the simulator PIN 1234.
set -euo pipefail

CHECK="${1:?usage: $0 threads|import <module.so>}"
MOD="${2:?usage: $0 threads|import <module.so>}"
PIN="${TSRA_PKCS11_TEST_PIN:-1234}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "$CHECK" in
    threads)
        # IL: C_Initialize with CKF_OS_LOCKING_OK, IN: without; GI, SL, T0:
        # C_GetInfo, C_GetSlotList, C_GetTokenInfo on slot index 0.
        pkcs11-tool --module "$MOD" --test-threads ILGISLT0 --test-threads ILGISLT0 \
            --test-threads INGISLT0 --show-info > "$WORK/out" 2>&1 || true
        cat "$WORK/out"
        ok="$(grep -c '^Test thread [0-9]* returning rv:CKR_OK$' "$WORK/out" || true)"
        [ "$ok" -eq 3 ] || {
            echo "pkcs11_tool threads: $ok of 3 threads returned CKR_OK" >&2
            exit 1
        }
        ;;
    import)
        head -c 32 /dev/urandom > "$WORK/aes.key"
        pkcs11-tool --module "$MOD" --login --pin "$PIN" --write-object "$WORK/aes.key" \
            --type secrkey --key-type AES:32 --label import-refusal > "$WORK/out" 2>&1 || true
        cat "$WORK/out"
        if grep -q 'Created secret key' "$WORK/out" || ! grep -q CKR_TEMPLATE_INCONSISTENT "$WORK/out"; then
            echo "pkcs11_tool import: a plaintext key import was not refused" >&2
            exit 1
        fi
        ;;
    *)
        echo "usage: $0 threads|import <module.so>" >&2
        exit 2
        ;;
esac
echo "pkcs11_tool $CHECK: OK"
