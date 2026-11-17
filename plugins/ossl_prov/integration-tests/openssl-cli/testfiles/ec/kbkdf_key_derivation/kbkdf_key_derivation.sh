# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @ikm @dgst @withcontext @cleanup

source "$(dirname "${BASH_SOURCE[0]}")/../../env.sh"

generic_secret=$1
dgst_bits=$2
dgst="sha"$dgst_bits""
withcontext=$3
cleanup=$4
kbkdf_output=kbkdf_aes_"$dgst".bin

# The tsra provider maps the standard OSSL_KDF_PARAM_SALT/INFO parameters to the
# SP 800-108 Label/Context inputs. At least one of Label/Context must be present, so a
# Label (hexsalt) is always supplied; the Context (hexinfo) is optional.
if [[ "$withcontext" == "true" ]]; then
    kdfopts="-kdfopt hexsalt:000102030405060708090a0b0c -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9"
else
    kdfopts="-kdfopt hexsalt:000102030405060708090a0b0c"
fi

"$OPENSSL_BIN" kdf \
    -propquery "$PROPQUERY" \
    -keylen 4096 \
    -kdfopt "digest:$dgst" \
    -kdfopt mode:counter \
    -kdfopt "tsra.ikm_file:$generic_secret" \
    -kdfopt "output_file:$kbkdf_output" \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    $kdfopts \
    -binary -out /dev/null \
    KBKDF

#CHECK: file created
if [[ -f "$kbkdf_output" && -s "$kbkdf_output" ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm -f "$kbkdf_output"
fi
