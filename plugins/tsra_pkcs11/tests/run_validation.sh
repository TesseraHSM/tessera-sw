#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Runs the checks of the CI workflow's build-and-drive and unit-tests jobs in
# one go. Builds the standalone no-device module and drives it with OpenSC
# pkcs11-tool, and runs the device-free unit harnesses under UBSan and ASan
# (build_units.sh); if the mock-backed module has been built (cargo build -p
# tsra_pkcs11 --features mock; TSRA_PKCS11_MODULE overrides its path), it also
# runs the C_Login provisioning ceremony, a pkcs11-tool AES keygen, EC key
# pair generation and a refused pkcs11-tool key import, the gtest functional suite
# (integration-tests/cpp) on the memory and the file object store, the
# pkcs11test conformance gate (tests/pkcs11test) and the per-PR part of the
# pkcs11-check gate (tests/pkcs11-check) against the simulator. The
# workflow's ASan module build (functional-asan) and its libFuzzer run
# (template-fuzz, which needs clang) are not repeated here.
#
# pkcs11-tool is expected locally (extracted from a distro package, no system
# install). Point PKCS11_TESTING at that directory; it defaults to the
# repo-sibling layout with an env.sh that puts the tools on PATH. pkcs11test
# is cloned and built by the gate script itself.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$PLUGIN/../.." && pwd)"
PKCS11_TESTING="${PKCS11_TESTING:-$(cd "$REPO/.." && pwd)/pkcs11-testing}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building standalone module (no device) =="
gcc -shared -fPIC -Wall -Wextra -Wno-unknown-pragmas \
    -I"$PLUGIN/include/pkcs11-v3.1" \
    "$PLUGIN"/src/*.c \
    -o "$WORK/tsra_pkcs11.so" -lpthread
MOD="$WORK/tsra_pkcs11.so"
echo "  built $MOD ; exported C_ symbols: $(nm -D "$MOD" | grep -c ' T C_')"

echo; echo "== unit harnesses (no device): UBSan, then ASan =="
"$HERE/build_units.sh" "$WORK/units-ubsan"
SANITIZE=asan "$HERE/build_units.sh" "$WORK/units-asan"

if [ -f "$PKCS11_TESTING/env.sh" ]; then
    # shellcheck disable=SC1091
    source "$PKCS11_TESTING/env.sh"
fi
# The memory store, unless a step asks for the file store: an environment
# value wins over a persist = 1 in a TSRA_PKCS11_CONF file.
export TSRA_PKCS11_PERSIST=0

echo; echo "== pkcs11-tool: show-info / slots / mechanisms =="
pkcs11-tool --module "$MOD" --show-info
pkcs11-tool --module "$MOD" --list-slots
pkcs11-tool --module "$MOD" --list-mechanisms | head -n 20

echo; echo "== pkcs11-tool: digests of 'abc' must equal coreutils =="
printf abc > "$WORK/msg"
for pair in SHA-1:sha1sum SHA256:sha256sum SHA384:sha384sum SHA512:sha512sum; do
    mech="${pair%%:*}"; sum="${pair##*:}"
    pkcs11-tool --module "$MOD" --hash --mechanism "$mech" \
        --input-file "$WORK/msg" --output-file "$WORK/dig" 2>/dev/null
    got="$(xxd -p -c130 "$WORK/dig")"
    exp="$("$sum" < "$WORK/msg" | cut -d' ' -f1)"
    echo "  $mech module   : $got"; echo "  $mech coreutils: $exp"
    [ "$got" = "$exp" ] && echo "  *** $mech OK ***" || { echo "  MISMATCH"; exit 1; }
done

# --- mock-backed C_Login ceremony (needs the integrated build + mock DDI) ----
HSMMOD="${TSRA_PKCS11_MODULE:-$REPO/target/debug/tsra_pkcs11.so}"
if [ -f "$HSMMOD" ]; then
    echo; echo "== mock-backed: C_Login provisioning ceremony =="
    echo "   (build it with: cargo build -p tsra_pkcs11 --features mock)"
    TSRA_PKCS11_DEBUG=1 pkcs11-tool --module "$HSMMOD" --login --pin 1234 \
        --list-objects 2>&1 | sed 's/^/   /' || echo "   (login harness failed)"

    # The AES checks below are hard gates (real functionality, not the login
    # ceremony's best-effort diagnostic above), so announce a failure before the
    # pipefail/errexit abort rather than aborting the script silently.
    echo; echo "== mock-backed: AES keygen via pkcs11-tool =="
    # --sensitive is required: this token refuses non-sensitive HSM keys.
    if ! pkcs11-tool --module "$HSMMOD" --login --pin 1234 --keygen \
        --key-type aes:32 --label validation --sensitive 2>&1 | sed 's/^/   /'; then
        echo "   (AES keygen failed)"; exit 1
    fi

    echo; echo "== mock-backed: EC key pair via pkcs11-tool =="
    # A private EC key signs or derives, never both: a named usage works, the
    # tool's default (both) is refused.
    if ! pkcs11-tool --module "$HSMMOD" --login --pin 1234 --keypairgen \
        --key-type EC:prime256v1 --usage-sign --label validation-ec 2>&1 | sed 's/^/   /'; then
        echo "   (EC key pair generation failed)"; exit 1
    fi
    pkcs11-tool --module "$HSMMOD" --login --pin 1234 --keypairgen \
        --key-type EC:prime256v1 --label validation-ec-both > "$WORK/ec-both.log" 2>&1 || true
    sed 's/^/   /' "$WORK/ec-both.log"
    grep -q CKR_TEMPLATE_INCONSISTENT "$WORK/ec-both.log" \
        || { echo "   (an EC key that signs and derives was not refused)"; exit 1; }

    echo; echo "== mock-backed: plaintext key import via pkcs11-tool is refused =="
    printf '0123456789abcdef' > "$WORK/import.key"
    pkcs11-tool --module "$HSMMOD" --login --pin 1234 --write-object "$WORK/import.key" \
        --type secrkey --key-type AES:16 --label import > "$WORK/import.log" 2>&1 || true
    sed 's/^/   /' "$WORK/import.log"
    grep -q CKR_TEMPLATE_INCONSISTENT "$WORK/import.log" \
        || { echo "   (plaintext key import was not refused)"; exit 1; }

    echo; echo "== mock-backed: gtest functional suite (integration-tests/cpp) =="
    # googletest and Wycheproof are fetched by CMake. Cache only their SOURCE
    # between runs and let every build tree compile privately: a shared build
    # directory breaks as soon as one of the trees using it goes away.
    deps="${XDG_CACHE_HOME:-$HOME/.cache}/tsra-pkcs11-cpp-deps"
    src_arg=()
    for dep in googletest wycheproof; do
        if [ -d "$deps/$dep-src" ]; then
            src_arg+=(-DFETCHCONTENT_SOURCE_DIR_"${dep^^}"="$deps/$dep-src")
        fi
    done
    cmake -S "$PLUGIN/integration-tests/cpp" -B "$WORK/cpp-tests" \
        -DCMAKE_BUILD_TYPE=Release "${src_arg[@]}" > "$WORK/cmake.log" 2>&1 \
        || { tail -n 20 "$WORK/cmake.log"; echo "   (cmake configure failed)"; exit 1; }
    # Seed the cache from the first run's downloads.
    for dep in googletest wycheproof; do
        if [ ! -d "$deps/$dep-src" ] && [ -d "$WORK/cpp-tests/_deps/$dep-src" ]; then
            mkdir -p "$deps"
            cp -r "$WORK/cpp-tests/_deps/$dep-src" "$deps/$dep-src" || true
        fi
    done
    cmake --build "$WORK/cpp-tests" --parallel > "$WORK/cmake-build.log" 2>&1 \
        || { tail -n 30 "$WORK/cmake-build.log"; echo "   (cmake build failed)"; exit 1; }
    TSRA_PKCS11_MODULE="$HSMMOD" ctest --test-dir "$WORK/cpp-tests" --output-on-failure \
        --no-tests=error || { echo "   (functional suite failed)"; exit 1; }

    echo; echo "== mock-backed: gtest functional suite on the file store (PERSIST=1) =="
    # Not pre-created: the module must create the store directory owner-only.
    store="$WORK/pkcs11-store"
    TSRA_PKCS11_PERSIST=1 TSRA_PKCS11_STORE_DIR="$store" TSRA_PKCS11_MODULE="$HSMMOD" \
        ctest --test-dir "$WORK/cpp-tests" --output-on-failure --no-tests=error \
        || { echo "   (functional suite on the file store failed)"; exit 1; }
    mode="$(stat -c %a "$store")"
    [ "$mode" = 700 ] || { echo "   (store directory mode is $mode, not 700)"; exit 1; }
    echo "   store directory created with mode $mode"

    echo; echo "== mock-backed: pkcs11test conformance gate =="
    # Clones and builds the tool on first use; the work directory is reused. It
    # lives in this checkout's target/ so two worktrees never share a clone.
    "$HERE/pkcs11test/run.sh" "$HSMMOD" "$REPO/target/pkcs11test" \
        || { echo "   (conformance gate failed)"; exit 1; }

    echo; echo "== mock-backed: pkcs11-check conformance gate (PR subset) =="
    # Installs the pinned tool into target/ on first use (needs python3 3.12
    # and PyPI), like the workflow's per-PR step.
    "$HERE/pkcs11-check/run.sh" --pr "$HSMMOD" "$REPO/target/pkcs11-check" \
        || { echo "   (pkcs11-check gate failed)"; exit 1; }
else
    echo; echo "== mock-backed checks skipped (no $HSMMOD) =="
fi

echo; echo "All validation steps completed."
