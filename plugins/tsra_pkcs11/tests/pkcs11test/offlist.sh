#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Off-list report: runs pkcs11test without a filter and sorts every test that
# is not on include-list.txt into a bucket, the reason it is off the list.
# Rewrites offlist.md next to this script. Fails when a name falls into no
# bucket, or when an off-list test passes and asserts something: that test
# belongs on the include-list.
#
#   offlist.sh <module.so> [work-dir]
#
# Runs the gate (run.sh, same arguments and environment) first, which also
# builds the tool in the work directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD="${1:?usage: $0 <module.so> [work-dir]}"
WORK="${2:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tsra-pkcs11test}"
PIN="${TSRA_PKCS11_TEST_PIN:-1234}"
OUT="$HERE/offlist.md"

# Bucket rules, "<bucket> <extended regex over the full test name>"; the first
# match wins.
RULES=(
    'aes-ecb ^Ciphers/SecretKeyTest\..*/4$'
    'des ^(Ciphers/SecretKeyTest|Duals/DualSecretKeyTest)\..*/[0-3]$'
    'des ^ReadWriteSessionTest\.FindObjectSubset$'
    'sensitive ^RWUserSessionTest\.TookanAttackA(4|5b)$'
    'md5 ^Digests/DigestTest\..*/0$'
    'hmac ^(HMACs/HmacTest\.|ReadOnlySessionTest\.HmacTestVectors$)'
    'rsa-keygen ^(Signatures/SignTest\.|KeyPairTest\.)'
    'rsa-keygen ^ReadOnlySessionTest\.SignVerifyRecover$'
    'rsa-keygen ^ReadWriteSessionTest\.(ExtractKeys|AsymmetricTokenKeyPair|PublicExponent4Bytes)$'
    'later ^ReadOnlySessionTest\.GenerateKeyPairInvalid$'
    'so ^(RWSOSessionTest\.|RWUserSessionTest\.SOLoginFail$)'
    'so ^(ReadOnlySessionTest\.SOLoginFail|ReadWriteSessionTest\.(ReadOnlySessionSOLoginFail|SOLogin))$'
    'so ^(PKCS11Test\.TokenInit|ReadOnlySessionTest\.TokenInitWithSession$)'
    'rng ^(PKCS11Test|ReadOnlySessionTest)\.(Generate|Seed)Random'
    'import ^ReadOnlySessionTest\.(CreateSecretKeyAttributes|CreateKeyPairObjects|SecretKeyTestVectors)$'
    'unsupported ^(Duals/DualSecretKeyTest\.|Digests/DigestTest\.DigestKey)'
    'unsupported ^(DataObjectTest\.CopyDestroyObjectInvalid|ReadWriteSessionTest\.CreateCopyDestroyObject)$'
    'unsupported ^ReadWriteSessionTest\.(GetSetOperationState(Invalid)?|TookanAttackA1)$'
    'unsupported ^(ROUserSessionTest\.(WrapUnwrap|WrapInvalid|UnwrapInvalid)|RWEitherSessionTest\.TookanAttackA2)$'
    'sdk-lag ^(Ciphers/SecretKeyTest\.EncryptDecryptParts/5|ReadOnlySessionTest\.UserLoginWrongPIN)$'
    'spec-gap ^Ciphers/SecretKeyTest\.EncryptDecryptInitInvalid/5$'
)

# What keeps each bucket off the list, in table order.
BUCKETS=(des aes-ecb rsa-keygen hmac md5 so rng import sensitive unsupported later sdk-lag spec-gap)
declare -A WHY=(
    [des]="DES or 3DES, which the SDK does not have: the cipher and dual-function fixtures' DES cases, and FindObjectSubset, which generates DES keys and RSA key pairs."
    [aes-ecb]="AES-ECB, out of scope for the module. The two IV cases pass without asserting anything: ECB takes no IV."
    [rsa-keygen]="The fixture generates an RSA key pair. The module does not generate RSA keys: they arrive by unwrap, and the signature cases need an unwrap fixture."
    [hmac]="HMAC keys from CKM_GENERIC_SECRET_KEY_GEN, which the SDK cannot generate. The module's HMAC keys come from ECDH plus HKDF, so these fixtures cannot pass."
    [md5]="MD5, which the module does not offer. pkcs11test skips these cases."
    [so]="The Security Officer. The device session has one user credential, so CKU_SO is refused and the token is presented initialised. pkcs11test skips the SO logins under -X and token initialisation without -I."
    [rng]="Random numbers. The module has no generator."
    [import]="Plaintext key material through C_CreateObject, which is not a way to make keys on this token."
    [sensitive]="The fixture asks C_GenerateKey for a key with CKA_SENSITIVE=FALSE. Device keys exist only masked, so the token refuses it (CKR_TEMPLATE_INCONSISTENT)."
    [unsupported]="Entry points the module does not offer: C_CopyObject, C_DigestKey, C_GetOperationState, the dual-function calls and key wrapping."
    [later]="C_GenerateKeyPair, not implemented yet (it comes with EC key generation)."
    [sdk-lag]="SDK behaviour the module cannot change: the CBC stream holds back the last full block until the final call (SDK issue #51), and a wrong PIN is the generic -8 (SDK issue #53), so C_Login cannot answer CKR_PIN_INCORRECT."
    [spec-gap]="Expectations this token does not share: CKR_KEY_TYPE_INCONSISTENT for a mechanism it does not offer, and an error for a NULL mechanism, which PKCS#11 3.0 defines as ending the active operation."
)

# Pass without asserting anything, yet absent from pkcs11test's skip report.
VACUOUS=(
    Ciphers/SecretKeyTest.EncryptInvalidIV/4
    Ciphers/SecretKeyTest.DecryptInvalidIV/4
    ReadOnlySessionTest.GenerateRandomNone
)

fail()
{
    echo "pkcs11test off-list: $*" >&2
    exit 1
}

"$HERE/run.sh" "$MOD" "$WORK"
MOD="$(cd "$(dirname "$MOD")" && pwd)/$(basename "$MOD")"
SRC="$WORK/src"

# The full run fails by design; its log is the input.
(
    cd "$SRC" &&
        ./pkcs11test -m "$(basename "$MOD")" -l "$(dirname "$MOD")" -s 0 -u "$PIN" -X
) > "$WORK/full.log" 2>&1 || true

declare -A LISTED=() PASSED=() SKIPPED=() QUIET=()
while read -r name; do LISTED[$name]=1; done < <(
    sed -e 's/\r$//' -e 's/[[:space:]]*$//' "$HERE/include-list.txt" |
        grep -v -E '^[[:space:]]*(#|$)'
)
while read -r name; do PASSED[$name]=1; done < <(
    sed -n -E 's/^\[       OK \] ([^ ]+).*/\1/p' "$WORK/full.log"
)
while read -r name; do SKIPPED[$name]=1; done < <(
    awk '/^Following tests were skipped/ { f = 1; next }
         /^\[/ { f = 0 }
         f && NF { sub(/^ +/, ""); print }' "$WORK/full.log"
)
for name in "${VACUOUS[@]}"; do QUIET[$name]=1; done
mapfile -t RAN < <(sed -n -E 's/^\[ RUN      \] //p' "$WORK/full.log" | LC_ALL=C sort -u)
[ "${#RAN[@]}" -gt 0 ] || fail "the unfiltered run ran nothing (see $WORK/full.log)"

declare -A COUNT=() LINES=()
unbucketed=()
green=()
off=0
failing=0
for name in "${RAN[@]}"; do
    [ -z "${LISTED[$name]:-}" ] || continue
    off=$((off + 1))
    if [ -z "${PASSED[$name]:-}" ]; then
        outcome="fails"
        failing=$((failing + 1))
    elif [ -n "${SKIPPED[$name]:-}" ]; then
        outcome="skipped by pkcs11test"
    elif [ -n "${QUIET[$name]:-}" ]; then
        outcome="passes, asserts nothing"
    else
        green+=("$name")
        continue
    fi
    bucket=""
    for rule in "${RULES[@]}"; do
        if [[ "$name" =~ ${rule#* } ]]; then
            bucket="${rule%% *}"
            break
        fi
    done
    if [ -z "$bucket" ]; then
        unbucketed+=("$name ($outcome)")
        continue
    fi
    [ -n "${WHY[$bucket]:-}" ] || fail "bucket $bucket has no description in $0"
    COUNT[$bucket]=$((${COUNT[$bucket]:-0} + 1))
    LINES[$bucket]+="- \`$name\`: $outcome"$'\n'
done

if [ "${#green[@]}" -gt 0 ]; then
    printf '  %s\n' "${green[@]}" >&2
    fail "${#green[@]} off-list test(s) pass and assert something: add them to include-list.txt"
fi
if [ "${#unbucketed[@]}" -gt 0 ]; then
    printf '  %s\n' "${unbucketed[@]}" >&2
    fail "${#unbucketed[@]} off-list test(s) match no bucket rule in $0"
fi

{
    echo "# pkcs11test names off the include-list"
    echo
    echo "Written by \`offlist.sh\` from an unfiltered pkcs11test run"
    echo "($(git -C "$SRC" rev-parse --short=12 HEAD), with the fixture patches) against the"
    echo "emulator module. Do not edit it by hand: change the bucket rules in"
    echo "\`offlist.sh\` and run it again."
    echo
    echo "${#RAN[@]} tests: $((${#RAN[@]} - off)) on the include-list, $off off it ($failing fail,"
    echo "$((off - failing)) pass without asserting anything)."
    echo
    echo "| Bucket | Names | Why they are off the list |"
    echo "|---|---|---|"
    for bucket in "${BUCKETS[@]}"; do
        [ -n "${COUNT[$bucket]:-}" ] || continue
        echo "| $bucket | ${COUNT[$bucket]} | ${WHY[$bucket]} |"
    done
    for bucket in "${BUCKETS[@]}"; do
        [ -n "${COUNT[$bucket]:-}" ] || continue
        echo
        echo "## $bucket"
        echo
        printf '%s' "${LINES[$bucket]}"
    done
} > "$OUT"
echo "pkcs11test off-list: $off names in ${#COUNT[@]} buckets, written to $OUT"
