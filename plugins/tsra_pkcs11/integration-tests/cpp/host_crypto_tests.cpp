// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file host_crypto_tests.cpp
///
/// The host oracle (utils/host_crypto.hpp) against published vectors, so a
/// module test that relies on it relies on OpenSSL and the vectors, not on new
/// code: RFC 4231 (HMAC), RFC 5869 (HKDF), NIST CAVP (AES-CBC, ECDH, RSA
/// PKCS#1 v1.5 and PSS signatures), RFC 5649 (AES key wrap with padding), RFC
/// 6979 (ECDSA) and BoringSSL (RSA-OAEP). Hand-built cases check that bad
/// padding, a bad key wrap, a point off the curve and a tampered OAEP
/// ciphertext are refused. Each case runs in a process that has the module
/// loaded; the coexistence case also uses a token key between host operations,
/// after the login has started the SDK's own libcrypto use.

#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/module.hpp"
#include "vectors/aes_cbc_nist.inc"
#include "vectors/ecdh_nist.inc"
#include "vectors/rsa_oaep.inc"
#include "vectors/rsa_pkcs1_nist.inc"
#include "vectors/rsa_pss_nist.inc"

using host::Bytes;
using vectors::hex;

namespace
{

Bytes text(const char *s)
{
    return Bytes(s, s + std::strlen(s));
}

/// RFC 6979 A.2.5 and A.2.6: the key pair and the signature over "sample".
struct EcdsaRfc6979
{
    const char *curve;
    const char *md;
    const char *x;  /* private scalar */
    const char *ux; /* public point */
    const char *uy;
    const char *r;
    const char *s;
    const char *digest; /* md("sample"), for the prehashed form */
};

const EcdsaRfc6979 kRfc6979[] = {
    {
        "P-256",
        "SHA256",
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
    },
    {
        "P-384",
        "SHA384",
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
        "96d5724e4c70a825f872c9ea60d2edf5",
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64"
        "def8f0ea9055866064a254515480bc13",
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1"
        "288b231c3ae0d4fe7344fd2533264720",
        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c"
        "81a648152e44acf96e36dd1e80fabe46",
        "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f"
        "a329c145786e679e7b82c71a38628ac8",
        "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312"
        "313bca4a9b5b890efee42c77b1ee25fe",
    },
};

Bytes rfc6979_point(const EcdsaRfc6979 &v)
{
    return hex(std::string("04") + v.ux + v.uy);
}

} // namespace

TEST(host_crypto, hmac_matches_rfc4231)
{
    struct
    {
        Bytes key;
        Bytes data;
        const char *sha256;
        const char *sha384;
        const char *sha512;
    } cases[] = {
        {
            Bytes(20, 0x0b),
            text("Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
            "faea9ea9076ede7f4af152e8b2fa9cb6",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        },
        {
            text("Jefe"),
            text("what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
            "8e2240ca5e69e2c78b3239ecfab21649",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        },
        {
            Bytes(131, 0xaa),
            text("Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
            "0c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        },
    };
    for (const auto &c : cases)
    {
        EXPECT_EQ(hex(c.sha256), host::hmac("SHA256", c.key, c.data));
        EXPECT_EQ(hex(c.sha384), host::hmac("SHA384", c.key, c.data));
        EXPECT_EQ(hex(c.sha512), host::hmac("SHA512", c.key, c.data));
    }
}

TEST(host_crypto, hkdf_matches_rfc5869)
{
    struct
    {
        const char *ikm;
        const char *salt;
        const char *info;
        const char *okm;
    } cases[] = {
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    };
    for (const auto &c : cases)
    {
        Bytes okm = hex(c.okm);
        EXPECT_EQ(okm, host::hkdf("SHA256", hex(c.ikm), hex(c.salt), hex(c.info), okm.size()));
    }
}

TEST(host_crypto, aes_cbc_matches_nist)
{
    for (const auto &v : vectors::kAesCbcNist)
    {
        Bytes key = hex(v.key);
        Bytes iv = hex(v.iv);
        EXPECT_EQ(hex(v.ct), host::aes_cbc_encrypt(key, iv, hex(v.pt), false)) << v.ct;
        EXPECT_EQ(hex(v.pt), host::aes_cbc_decrypt(key, iv, hex(v.ct), false)) << v.ct;
    }
}

TEST(host_crypto, aes_cbc_pad_refuses_bad_padding)
{
    const auto &nist = vectors::kAesCbcNist[0];
    Bytes key = hex(nist.key);
    Bytes iv = hex(nist.iv);
    auto raw = [&key, &iv](const Bytes &in) { return host::aes_cbc_encrypt(key, iv, in, false); };

    // PKCS#7 padding by hand, for a part block, a whole block and no data.
    for (size_t len : { 11, 16, 0 })
    {
        Bytes msg(len, 'a');
        size_t pad = kAesBlock - (len % kAesBlock);
        Bytes padded = msg;
        padded.insert(padded.end(), pad, static_cast<unsigned char>(pad));
        EXPECT_EQ(raw(padded), host::aes_cbc_encrypt(key, iv, msg, true)) << len;
        EXPECT_EQ(msg, host::aes_cbc_decrypt(key, iv, raw(padded), true)) << len;
    }

    // A last block that ends in bad padding, encrypted without padding.
    const struct
    {
        const char *what;
        Bytes tail;
    } bad[] = {
        { "pad byte 0", { 0x00 } },
        { "pad byte 17", { 0x11 } },
        { "unequal pad bytes", { 0x03, 0x04, 0x04, 0x04 } },
    };
    for (const auto &b : bad)
    {
        Bytes block(kAesBlock - b.tail.size(), 'a');
        block.insert(block.end(), b.tail.begin(), b.tail.end());
        EXPECT_FALSE(host::aes_cbc_decrypt(key, iv, raw(block), true).has_value()) << b.what;
    }
    Bytes ct = host::aes_cbc_encrypt(key, iv, text("abc"), true);
    ct.pop_back();
    EXPECT_FALSE(host::aes_cbc_decrypt(key, iv, ct, true).has_value()) << "not a whole block";
}

TEST(host_crypto, aes_kwp_matches_rfc5649)
{
    Bytes kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    EXPECT_EQ(
        hex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"),
        host::aes_kwp_wrap(kek, hex("c37b7e6492584340bed12207808941155068f738"))
    );
    EXPECT_EQ(
        hex("afbeb0f07dfbf5419200f2ccb50bb24f"),
        host::aes_kwp_wrap(kek, hex("466f7250617369"))
    );
}

TEST(host_crypto, aes_kwp_unwrap_refuses_bad_input)
{
    // The RFC 5649 examples again. Up to 8 bytes wrap as one AES block: the
    // ICV A65959A6, the 32-bit length and the key padded with zeros.
    const size_t semiblock = 8;
    Bytes kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    auto unwrap = [&kek](const Bytes &in) {
        return host::cipher("AES-192-WRAP-PAD", false, kek, Bytes(), in, false);
    };
    auto block = [&kek](const char *in) {
        return *host::cipher("AES-192-ECB", true, kek, Bytes(), hex(in), false);
    };
    Bytes ct = hex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
    EXPECT_EQ(hex("c37b7e6492584340bed12207808941155068f738"), unwrap(ct));
    EXPECT_EQ(hex("afbeb0f07dfbf5419200f2ccb50bb24f"), block("a65959a600000007466f725061736900"));
    EXPECT_EQ(hex("466f7250617369"), unwrap(block("a65959a600000007466f725061736900")));

    Bytes tampered = ct;
    tampered.back() ^= 0x01;
    EXPECT_FALSE(unwrap(tampered).has_value()) << "tampered";
    EXPECT_FALSE(unwrap(Bytes(ct.begin(), ct.end() - 1)).has_value()) << "not whole semiblocks";
    EXPECT_FALSE(unwrap(Bytes(ct.begin(), ct.begin() + semiblock)).has_value()) << "one semiblock";
    EXPECT_FALSE(unwrap(block("a65959a600000009466f725061736900")).has_value())
        << "a length of 9 in one block";
    EXPECT_FALSE(unwrap(block("a65959a600000007466f725061736901")).has_value())
        << "a nonzero pad byte";
}

TEST(host_crypto, ecdsa_verify_matches_rfc6979)
{
    for (const auto &v : kRfc6979)
    {
        host::Pkey pub = host::ec_public(v.curve, rfc6979_point(v));
        Bytes sig = hex(std::string(v.r) + v.s);
        EXPECT_TRUE(host::ecdsa_verify(pub.get(), v.md, text("sample"), sig)) << v.curve;
        EXPECT_TRUE(host::ecdsa_verify(pub.get(), nullptr, hex(v.digest), sig)) << v.curve;
        EXPECT_FALSE(host::ecdsa_verify(pub.get(), v.md, text("sample!"), sig)) << v.curve;
        Bytes bad = sig;
        bad.back() ^= 0x01;
        EXPECT_FALSE(host::ecdsa_verify(pub.get(), v.md, text("sample"), bad)) << v.curve;
        Bytes trailing = sig;
        trailing.push_back(0x00);
        EXPECT_FALSE(host::ecdsa_verify(pub.get(), v.md, text("sample"), trailing))
            << v.curve << ": r || s must be exactly twice the order length";
    }
}

TEST(host_crypto, ec_private_derives_the_rfc6979_public_point)
{
    for (const auto &v : kRfc6979)
    {
        host::Pkey key = host::ec_private(v.curve, hex(v.x));
        EXPECT_EQ(rfc6979_point(v), host::ec_point(key.get())) << v.curve;
        host::Pkey again = host::private_key(host::pkcs8(key.get()));
        EXPECT_EQ(rfc6979_point(v), host::ec_point(again.get()))
            << v.curve << ": PKCS#8 round trip";
    }
}

TEST(host_crypto, ecdh_matches_nist)
{
    for (const auto &v : vectors::kEcdhNist)
    {
        host::Pkey key = host::ec_private(v.curve, hex(v.priv));
        EXPECT_EQ(hex(v.shared), host::ecdh(key.get(), hex(v.pub))) << v.curve << " " << v.pub;
    }

    // Two generated keys agree from both sides.
    host::Pkey a = host::ec_generate("P-384");
    host::Pkey b = host::ec_generate("P-384");
    EXPECT_EQ(
        host::ecdh(a.get(), host::ec_point(b.get())),
        host::ecdh(b.get(), host::ec_point(a.get()))
    );
}

TEST(host_crypto, ecdh_refuses_a_point_off_the_curve)
{
    for (const auto &v : vectors::kEcdhNist)
    {
        host::Pkey key = host::ec_private(v.curve, hex(v.priv));
        Bytes point = hex(v.pub);
        EXPECT_NO_THROW(host::ecdh(key.get(), point)) << v.curve << " " << v.pub;
        point.back() ^= 0x01; /* y off by one */
        EXPECT_ANY_THROW(host::ecdh(key.get(), point)) << v.curve << " " << v.pub;
    }
}

TEST(host_crypto, rsa_pkcs1_signatures_match_nist)
{
    for (const auto &v : vectors::kRsaPkcs1Nist)
    {
        host::Pkey key = host::private_key(hex(v.key->pkcs8));
        host::Pkey pub = host::rsa_public(hex(v.key->n), hex(v.key->e));
        EXPECT_EQ(hex(v.sig), host::rsa_sign(key.get(), v.md, RSA_PKCS1_PADDING, hex(v.msg)))
            << v.sig;
        EXPECT_TRUE(host::rsa_verify(pub.get(), v.md, RSA_PKCS1_PADDING, hex(v.msg), hex(v.sig)))
            << v.sig;
    }
}

TEST(host_crypto, rsa_pss_matches_nist)
{
    for (const auto &v : vectors::kRsaPssNist)
    {
        host::Pkey pub = host::rsa_public(hex(v.key->n), hex(v.key->e));
        Bytes msg = hex(v.msg);
        Bytes sig = hex(v.sig);
        EXPECT_TRUE(host::rsa_verify(pub.get(), v.md, RSA_PKCS1_PSS_PADDING, msg, sig)) << v.sig;
        msg.back() ^= 0x01;
        EXPECT_FALSE(host::rsa_verify(pub.get(), v.md, RSA_PKCS1_PSS_PADDING, msg, sig)) << v.sig;
    }

    // Our own signatures verify, and the PSS salt makes two of them differ.
    host::Pkey key = host::private_key(hex(vectors::kRsaPssKey0.pkcs8));
    Bytes s1 = host::rsa_sign(key.get(), "SHA384", RSA_PKCS1_PSS_PADDING, text("message"));
    Bytes s2 = host::rsa_sign(key.get(), "SHA384", RSA_PKCS1_PSS_PADDING, text("message"));
    EXPECT_NE(s1, s2);
    EXPECT_TRUE(host::rsa_verify(key.get(), "SHA384", RSA_PKCS1_PSS_PADDING, text("message"), s1));
    EXPECT_FALSE(host::rsa_verify(key.get(), "SHA384", RSA_PKCS1_PADDING, text("message"), s1));
}

TEST(host_crypto, rsa_oaep_matches_boringssl)
{
    for (const auto &v : vectors::kRsaOaep)
    {
        host::Pkey key = host::private_key(hex(v.key->pkcs8));
        host::Pkey pub = host::rsa_public(hex(v.key->n), hex(v.key->e));
        EXPECT_EQ(hex(v.msg), host::rsa_oaep_decrypt(key.get(), v.md, hex(v.ct), Bytes())) << v.ct;
        Bytes ct = host::rsa_oaep_encrypt(pub.get(), v.md, hex(v.msg), Bytes());
        EXPECT_EQ(hex(v.msg), host::rsa_oaep_decrypt(key.get(), v.md, ct, Bytes())) << v.ct;
    }
}

TEST(host_crypto, rsa_oaep_refuses_a_tampered_ciphertext)
{
    for (const auto &v : vectors::kRsaOaep)
    {
        host::Pkey key = host::private_key(hex(v.key->pkcs8));
        Bytes ct = hex(v.ct);
        EXPECT_TRUE(host::rsa_oaep_decrypt(key.get(), v.md, ct, Bytes()).has_value()) << v.ct;
        ct[ct.size() / 2] ^= 0x01;
        EXPECT_FALSE(host::rsa_oaep_decrypt(key.get(), v.md, ct, Bytes()).has_value()) << v.ct;
    }
}

TEST(host_crypto, pkcs8_reencodes_vector_keys_unchanged)
{
    for (const vectors::RsaKey *k : { &vectors::kRsaPkcs1Key0,
                                      &vectors::kRsaPkcs1Key1,
                                      &vectors::kRsaPssKey0,
                                      &vectors::kRsaOaepKey0 })
    {
        host::Pkey key = host::private_key(hex(k->pkcs8));
        EXPECT_EQ(hex(k->pkcs8), host::pkcs8(key.get()));
    }
}

TEST(host_crypto, rsa_aes_key_wrap_is_oaep_kek_then_kwp)
{
    host::Pkey key = host::private_key(hex(vectors::kRsaOaepKey0.pkcs8));
    const size_t modulus = 256; /* the vector key is RSA-2048 */
    for (const Bytes &target : { Bytes(32, 0x5a), hex(vectors::kRsaPkcs1Key0.pkcs8) })
    {
        Bytes blob = host::rsa_aes_key_wrap(key.get(), "SHA256", target);
        ASSERT_GT(blob.size(), modulus);
        std::optional<Bytes> kek = host::rsa_oaep_decrypt(
            key.get(),
            "SHA256",
            Bytes(blob.begin(), blob.begin() + modulus),
            Bytes()
        );
        ASSERT_TRUE(kek.has_value());
        EXPECT_EQ(32u, kek->size()) << "an AES-256 KEK";
        EXPECT_EQ(Bytes(blob.begin() + modulus, blob.end()), host::aes_kwp_wrap(*kek, target));
    }
}

/// The coexistence check: the module and the SDK behind it use libcrypto in
/// this process, and the oracle must keep working around token operations.
class host_crypto_coexistence : public UserSession
{
};

TEST_F(host_crypto_coexistence, token_and_host_operations_interleave)
{
    const auto &nist = vectors::kAesCbcNist[0];
    auto host_cbc_ok = [&nist]() {
        return host::aes_cbc_encrypt(hex(nist.key), hex(nist.iv), hex(nist.pt), false) ==
               hex(nist.ct);
    };
    const EcdsaRfc6979 &ec = kRfc6979[0];
    host::Pkey ec_pub = host::ec_public(ec.curve, rfc6979_point(ec));
    Bytes ec_sig = hex(std::string(ec.r) + ec.s);

    EXPECT_TRUE(host_cbc_ok()) << "host AES before the first token operation";

    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "coexistence", &key));
    CK_BYTE iv[kAesBlock];
    std::memset(iv, 0x3c, sizeof(iv));
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    std::vector<CK_BYTE> plain = pattern(64);
    std::vector<CK_BYTE> ct1;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &cbc, key, plain, ct1));

    EXPECT_TRUE(host_cbc_ok()) << "host AES after a token encryption";
    EXPECT_TRUE(host::ecdsa_verify(ec_pub.get(), ec.md, text("sample"), ec_sig));

    std::vector<CK_BYTE> ct2;
    std::vector<CK_BYTE> back;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &cbc, key, plain, ct2));
    EXPECT_EQ(ct1, ct2) << "the token key behaves the same after host operations";
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &cbc, key, ct1, back));
    EXPECT_EQ(plain, back);

    EXPECT_EQ(
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        host::hmac("SHA256", Bytes(20, 0x0b), text("Hi There"))
    ) << "host HMAC after the token decryption";
}
