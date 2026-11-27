#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Convert the Project Wycheproof vectors the functional tests use into C++
arrays. The functional test build fetches Wycheproof at a pinned commit
(integration-tests/cpp/CMakeLists.txt) and runs this at build time; the
output lives in the build directory only and is never committed:

    gen_wycheproof.py <wycheproof testvectors_v1 dir> <out dir>

Writes aes_kwp.inc, aes_cbc_pkcs5.inc, aes_gcm.inc and ecdh_ecpoint.inc, each
one array of a struct from integration-tests/cpp/vectors/wycheproof.hpp.
AES-GCM keeps only what the device takes: a 256-bit key, a 96-bit IV and a
128-bit tag. ECDH keeps the peer points the token must refuse and each
curve's normal case as their control: the other valid vectors need their
private key on the token.
"""
import json
import os
import sys


def cases(src, name, keep=lambda group: True):
    """(group, test) for every test of the file, with its verdict checked:
    these sets have no "acceptable" cases, and a new one must not slip by."""
    data = json.load(open(os.path.join(src, name)))
    for group in data["testGroups"]:
        if not keep(group):
            continue
        for test in group["tests"]:
            if test["result"] not in ("valid", "invalid"):
                sys.exit(f"{name} tcId {test['tcId']}: result {test['result']}")
            yield group, test


def emit(out, fname, source, ctype, array, rows):
    with open(os.path.join(out, fname), "w") as f:
        f.write("// GENERATED at build time by tools/gen_wycheproof.py from Project\n")
        f.write(f"// Wycheproof (Apache-2.0) {source}. Not part of the repository.\n\n")
        f.write("// clang-format off\n#pragma once\n\n#include \"vectors/wycheproof.hpp\"\n\n")
        f.write(f"namespace vectors\n{{\n\ninline constexpr {ctype} {array}[] = {{\n")
        for r in rows:
            f.write("    { " + ", ".join(r) + " },\n")
        f.write("};\n\n} // namespace vectors\n")


def q(s):
    return f'"{s}"'


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)

    rows = [[str(t["tcId"]), q(t["key"]), q(t["msg"]), q(t["ct"]), str(t["result"] == "valid").lower()]
            for _, t in cases(src, "aes_kwp_test.json")]
    emit(out, "aes_kwp.inc", "aes_kwp_test.json", "WycheproofKwp", "kWycheproofAesKwp", rows)

    rows = [[str(t["tcId"]), q(t["key"]), q(t["iv"]), q(t["msg"]), q(t["ct"]),
             str(t["result"] == "valid").lower()]
            for _, t in cases(src, "aes_cbc_pkcs5_test.json")]
    emit(out, "aes_cbc_pkcs5.inc", "aes_cbc_pkcs5_test.json", "WycheproofCbc",
         "kWycheproofAesCbcPkcs5", rows)

    device = lambda g: (g["keySize"], g["ivSize"], g["tagSize"]) == (256, 96, 128)
    rows = [[str(t["tcId"]), q(t["key"]), q(t["iv"]), q(t["aad"]), q(t["msg"]), q(t["ct"]),
             q(t["tag"]), str(t["result"] == "valid").lower()]
            for _, t in cases(src, "aes_gcm_test.json", device)]
    emit(out, "aes_gcm.inc", "aes_gcm_test.json, 256-bit keys, 96-bit IVs, 128-bit tags",
         "WycheproofGcm", "kWycheproofAesGcm", rows)

    # The "acceptable" ECDH vectors are compressed points, which this module
    # refuses like the invalid ones; any other acceptable vector must not slip by.
    rows = []
    for curve, name in (("P-256", "secp256r1"), ("P-384", "secp384r1"), ("P-521", "secp521r1")):
        fname = f"ecdh_{name}_ecpoint_test.json"
        for group in json.load(open(os.path.join(src, fname)))["testGroups"]:
            for t in group["tests"]:
                result = t["result"]
                if (result == "acceptable") and ("CompressedPoint" not in t["flags"]):
                    sys.exit(f"{fname} tcId {t['tcId']}: acceptable but not compressed")
                if result not in ("valid", "invalid", "acceptable"):
                    sys.exit(f"{fname} tcId {t['tcId']}: result {result}")
                if (result != "valid") or ("Normal" in t["flags"]):
                    rows.append([str(t["tcId"]), q(curve), q(t["public"]),
                                 str(result == "valid").lower()])
    emit(out, "ecdh_ecpoint.inc",
         "ecdh_secp256r1/384r1/521r1_ecpoint_test.json, refused points and the normal cases",
         "WycheproofEcPoint", "kWycheproofEcdhPoints", rows)


if __name__ == "__main__":
    main()
