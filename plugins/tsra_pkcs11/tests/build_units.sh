#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Builds and runs the device-free unit harnesses. Each one links only the
# module sources it tests (no device, no libcrypto), so a compiler is all it
# needs. run_validation.sh and the pkcs11 workflow both run the harnesses
# through this script.
#
#   build_units.sh [out-dir]
#
# out-dir (default: a temporary directory, removed afterwards) receives the
# binaries and one log per harness. SANITIZE=ubsan (default) or asan picks the
# sanitizer every harness is built with; any finding fails the harness. Each
# harness ends its output with its check count, which is printed as its
# summary line; a failing harness prints its whole log.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$(cd "$HERE/.." && pwd)"

case "${SANITIZE:-ubsan}" in
    ubsan) SAN=(-fsanitize=undefined -fno-sanitize-recover=all) ;;
    asan) SAN=(-fsanitize=address -fno-omit-frame-pointer) ;;
    *)
        echo "build_units: SANITIZE must be ubsan or asan" >&2
        exit 2
        ;;
esac

if [ $# -gt 0 ]; then
    OUT="$1"
    mkdir -p "$OUT"
else
    OUT="$(mktemp -d)"
    trap 'rm -rf "$OUT"' EXIT
fi

STORE="tsra_pkcs11_objstore_file.c tsra_pkcs11_objstore_mem.c tsra_pkcs11_store_io.c \
tsra_pkcs11_store_record.c tsra_pkcs11_attr_types.c"

# One harness per line: tests/<name>.c, then the src/ files it links.
HARNESS=(
    "digest_kat_test tsra_pkcs11_digest.c"
    "store_io_test tsra_pkcs11_store_io.c"
    "record_test tsra_pkcs11_store_record.c"
    "objstore_file_test $STORE"
    "objstore_stress_test $STORE"
    "aes_template_test tsra_pkcs11_template.c tsra_pkcs11_attr_types.c tsra_pkcs11_status.c"
    "attr_types_test tsra_pkcs11_attr_types.c"
    "attr_policy_test tsra_pkcs11_attr_policy.c tsra_pkcs11_attr_types.c tsra_pkcs11_template.c \
tsra_pkcs11_ec_template.c"
    "mech_table_test tsra_pkcs11_mech.c tsra_pkcs11_template.c tsra_pkcs11_attr_types.c \
tsra_pkcs11_digest.c tsra_pkcs11_ec_template.c tsra_pkcs11_unwrap_params.c"
    "ec_template_test tsra_pkcs11_ec_template.c tsra_pkcs11_template.c tsra_pkcs11_attr_types.c"
    "config_test tsra_pkcs11_config.c tsra_pkcs11_store_io.c"
    "config_file_test tsra_pkcs11_config.c tsra_pkcs11_store_io.c"
    "unwrap_params_test tsra_pkcs11_unwrap_params.c tsra_pkcs11_template.c \
tsra_pkcs11_attr_types.c tsra_pkcs11_digest.c"
)

echo "unit harnesses (${SANITIZE:-ubsan}):"
for entry in "${HARNESS[@]}"; do
    read -r -a words <<< "$entry"
    name="${words[0]}"
    srcs=("${words[@]:1}")
    # TSRA_WITH_HSM: the hardware build's configuration rules. No harness links
    # the device code.
    gcc -Wall -Wextra -Werror "${SAN[@]}" -DTSRA_WITH_HSM \
        -I"$PLUGIN/include/pkcs11-v3.1" -I"$PLUGIN/src" \
        "$HERE/$name.c" "${srcs[@]/#/$PLUGIN/src/}" \
        -o "$OUT/$name" -lpthread
    if ! "$OUT/$name" > "$OUT/$name.log" 2>&1; then
        cat "$OUT/$name.log"
        echo "build_units: $name failed" >&2
        exit 1
    fi
    printf '  %-22s %s\n' "$name" "$(tail -n 1 "$OUT/$name.log")"
done
