#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Second conformance gate: pkcs11-check, pinned with every dependency by hash
# (requirements.txt), installed into a virtual environment, patched
# (*.patch here) and run against the given module. See README.md alongside.
#
#   run.sh [--pr|--full] <module.so> [work-dir]
#
# Without an option it runs the files of the tests in include-list.txt; every
# listed test must pass and nothing may crash beyond the known crashes in
# baseline.txt. --pr does the same for the listed tests in the files PR_FILES
# matches, the subset that fits the pull-request budget of three minutes.
# --full runs the whole fast profile and also fails on a passing test that is
# neither listed nor in baseline.txt (the nightly run).
#
# work-dir (default: $RUNNER_TEMP or $TMPDIR or /tmp, plus tsra-pkcs11-check)
# keeps the environment between runs; it is rebuilt when requirements.txt, a
# patch or the pip pin changes. Needs python3 3.12 or later and network
# access to PyPI (PIP_INDEX_URL or PIP_FIND_LINKS with PIP_NO_INDEX=1 point
# pip at a mirror). TSRA_PKCS11_TEST_PIN overrides the simulator PIN 1234.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=gate
case "${1:-}" in
    --pr) MODE=pr ;;
    --full) MODE=full ;;
esac
[ "$MODE" = gate ] || shift
MOD="${1:?usage: $0 [--pr|--full] <module.so> [work-dir]}"
WORK="${2:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tsra-pkcs11-check}"
PIN="${TSRA_PKCS11_TEST_PIN:-1234}"
INCLUDE="$HERE/include-list.txt"
BASELINE="$HERE/baseline.txt"
# The include-list only grows: fewer names than this fails the gate. Raise the
# floor when names are added; lowering it is a deliberate edit with a reason.
FLOOR=885
# The --pr subset: return-value rules, the security probes and attributes.
PR_FILES='^testcases/(ckr/|security/|test_attribute_|test_set_?attr)'
# pip itself is not in requirements.txt: it runs from its wheel.
PIP_WHEEL=pip-26.2-py3-none-any.whl
PIP_URL=https://files.pythonhosted.org/packages/62/36/a3aed958d60531cb442b7ab4596cda7b3621cfb916f8ae1d6769795c7dc1/$PIP_WHEEL
PIP_SHA256=931c303696af6fa3417112103b1cad26890e5a07eccb5b99783700e33f2b8aad

fail()
{
    echo "pkcs11-check gate: $*" >&2
    exit 1
}

[ -f "$MOD" ] || fail "module not found: $MOD"
MOD="$(cd "$(dirname "$MOD")" && pwd)/$(basename "$MOD")"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' ||
    fail "pkcs11-check needs python3 3.12 or later ($(python3 --version 2>&1))"

mapfile -t NAMES < <(
    sed -e 's/\r$//' -e 's/[[:space:]]*$//' "$INCLUDE" | grep -v -E '^[[:space:]]*(#|$)' | sort -u
)
[ "${#NAMES[@]}" -ge "$FLOOR" ] ||
    fail "include-list names ${#NAMES[@]} tests, fewer than its floor of $FLOOR: $INCLUDE"

# --- 1. The pinned tool, patched --------------------------------------------
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
VENV="$WORK/venv"
STAMP="$(cat "$HERE/requirements.txt" "$HERE"/*.patch | sha256sum | cut -d' ' -f1)-$PIP_SHA256"
if [ "$(cat "$VENV/.stamp" 2>/dev/null)" != "$STAMP" ]; then
    rm -rf "$VENV"
    if ! echo "$PIP_SHA256  $WORK/$PIP_WHEEL" | sha256sum -c --status 2>/dev/null; then
        curl -fsSL --retry 3 -o "$WORK/$PIP_WHEEL" "$PIP_URL" || fail "cannot download $PIP_URL"
        echo "$PIP_SHA256  $WORK/$PIP_WHEEL" | sha256sum -c --status ||
            fail "$PIP_WHEEL does not match its pinned SHA-256"
    fi
    # --without-pip: no ensurepip needed, pip runs from its pinned wheel.
    python3 -m venv --without-pip "$VENV" || fail "cannot create $VENV"
    "$VENV/bin/python" "$WORK/$PIP_WHEEL/pip" install --quiet --disable-pip-version-check \
        --no-deps --require-hashes --only-binary :all: -r "$HERE/requirements.txt" ||
        fail "cannot install requirements.txt"
    SITE="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
    for p in "$HERE"/*.patch; do
        patch -p1 --quiet -d "$SITE" < "$p" || fail "$(basename "$p") does not apply"
    done
    echo "$STAMP" > "$VENV/.stamp"
fi
SITE="$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

# --- 2. Run -----------------------------------------------------------------
# A fresh run directory: the tool reads pkcs11_check.toml from the working
# directory and leaves its state files there. The empty data directory keeps
# the downloadable vector suites skipped, so a local fetch-data cannot change
# what the gate runs.
RUN="$WORK/run"
rm -rf "$RUN"
mkdir -p "$RUN/data" "$RUN/out"
if [ "$MODE" = pr ]; then
    printf '%s\n' "${NAMES[@]}" | grep -E "$PR_FILES" > "$RUN/listed.txt"
else
    printf '%s\n' "${NAMES[@]}" > "$RUN/listed.txt"
fi
# Whole files: a node id as a target costs a process per test.
TARGETS=()
if [ "$MODE" != full ]; then
    mapfile -t FILES < <(sed 's/::.*//' "$RUN/listed.txt" | sort -u)
    for f in "${FILES[@]}"; do
        TARGETS+=("$SITE/pkcs11_check/$f")
    done
fi
echo "pkcs11-check $MODE: $("$VENV/bin/pkcs11-check" version) against $MOD"
start=$SECONDS
set +e
# Set, not unset: a persist = 1 in TSRA_PKCS11_CONF would otherwise apply.
(
    cd "$RUN" &&
        env TSRA_PKCS11_PERSIST=0 P11TEST_PIN="$PIN" PKCS11_CHECK_DATA_DIR="$RUN/data" \
            XDG_CACHE_HOME="$WORK/cache" \
            "$VENV/bin/pkcs11-check" test --module "$MOD" --slot 0 --skip-slow \
            --output json --output-file "$RUN/out/results.json" "${TARGETS[@]}"
) > "$RUN/console.log" 2>&1
set -e
echo "pkcs11-check $MODE: ran in $((SECONDS - start)) s (log: $RUN/console.log)"
[ -f "$RUN/out/results.json" ] || {
    tail -n 30 "$RUN/console.log"
    fail "no results.json: the run did not complete"
}

# --- 3. Judge ---------------------------------------------------------------
JUDGE=gate
[ "$MODE" = full ] && JUDGE=full
"$VENV/bin/python" -I "$HERE/report.py" "$JUDGE" "$RUN/out" "$RUN/listed.txt" "$BASELINE"
