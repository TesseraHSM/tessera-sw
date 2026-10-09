# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @dgst @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

curve=P-$1
dgst=$2
cleanup=$3
testdata=testdata_verify.bin
maskedkeyfile=./masked_verify_"$curve"_"$dgst".bin
signature=testdata_verify.sig."$dgst"_"$curve"

# Generate a fresh key
"$OPENSSL_BIN" genpkey \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt tsra.session:false \
    -outform DER \
    -pkeyopt "tsra.masked_key:$maskedkeyfile" \
    -pkeyopt tsra.key_usage:digitalSignature

# Create and sign test data
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
  rm -f "$testdata" "$signature" "$maskedkeyfile"
fi
