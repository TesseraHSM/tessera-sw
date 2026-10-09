# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

parent_folder="$(dirname "$0")"
curve=P-$1
dgst=$2
cleanup=$3
testdata="$parent_folder"/testdata/testdata_"$curve"_"$dgst".bin
maskedkeyfile="$parent_folder"/testdata/masked_"$curve".bin
signature_filename=testdata.sig."$dgst"_"$curve"
signature="$parent_folder"/testdata/"$signature_filename"

mkdir -p "$parent_folder"/testdata

"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt tsra.session:false \
    -outform DER \
    -pkeyopt "tsra.masked_key:$maskedkeyfile" \
    -pkeyopt tsra.key_usage:digitalSignature

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -sign "tsra://$maskedkeyfile;type=ec" \
    -out "$signature" \
    "$testdata"

#CHECK: Verified OK
"$OPENSSL_BIN" dgst -"$dgst" \
    -propquery "$PROPQUERY" \
    -verify "tsra://$maskedkeyfile;type=ec" \
    -signature "$signature" \
    "$testdata"

if [[ "$cleanup" == "true" ]]; then
    rm -f "$testdata" "$maskedkeyfile" "$signature"
    rmdir "$parent_folder"/testdata 2>/dev/null || true
fi
