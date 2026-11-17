// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file policy_tests.cpp
///
/// The object policy through the module ABI: C_CreateObject needs a class and
/// creates no secret or private key, every template entry point holds a value
/// to its type's width without reading past it, the count and byte ceilings,
/// attribute arrays, attributes only the token sets, keys private by default,
/// the read-only-session gates of C_CreateObject and C_DestroyObject,
/// C_DestroyObject's CKA_DESTROYABLE gate, the file store's record limit, and
/// the file store never sees refused key material. The verdict matrix is
/// unit-tested in tests/attr_types_test.c and tests/attr_policy_test.c; here
/// each case proves the wiring of one entry point. The guard-page cases put a
/// value at the very end of a readable page, so a read past it faults.

#include <cstring>
#include <gtest/gtest.h>
#include <iterator>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "tsra_pkcs11_attr_types.h"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"

namespace
{

CK_BBOOL g_true = CK_TRUE;
CK_BBOOL g_false = CK_FALSE;
CK_OBJECT_CLASS g_data = CKO_DATA;
CK_OBJECT_CLASS g_secret = CKO_SECRET_KEY;
CK_OBJECT_CLASS g_private = CKO_PRIVATE_KEY;
CK_OBJECT_CLASS g_public = CKO_PUBLIC_KEY;
CK_KEY_TYPE g_aes = CKK_AES;
/// A CK_BBOOL or CK_KEY_TYPE value sent eight bytes wide.
CK_BYTE g_v8[8] = { 0 };
/// FIPS-197's AES-128 example key: what an import attempt hands the token.
CK_BYTE g_aes_key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
CK_MECHANISM g_keygen = { CKM_AES_KEY_GEN, nullptr, 0 };
CK_ULONG g_len32 = 32;

CK_RV create(CK_SESSION_HANDLE s, std::vector<CK_ATTRIBUTE> tmpl, CK_OBJECT_HANDLE *out)
{
    *out = CK_INVALID_HANDLE;
    return p11()->C_CreateObject(s, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()), out);
}

CK_ATTRIBUTE label_attr(const char *label)
{
    return { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) };
}

/// The handles of the objects `s` finds by `label`, drained in pages of `page`.
std::vector<CK_OBJECT_HANDLE> find_by_label(CK_SESSION_HANDLE s, const char *label, CK_ULONG page)
{
    std::vector<CK_OBJECT_HANDLE> found;
    CK_ATTRIBUTE by_label = label_attr(label);
    CK_RV rv = p11()->C_FindObjectsInit(s, &by_label, 1);
    EXPECT_CKR_OK(rv) << "a failed search finds nothing for the wrong reason";
    if (rv != CKR_OK)
    {
        return found;
    }
    std::vector<CK_OBJECT_HANDLE> batch(page);
    CK_ULONG n = 0;
    while ((p11()->C_FindObjects(s, batch.data(), page, &n) == CKR_OK) && (n > 0))
    {
        found.insert(found.end(), batch.begin(), batch.begin() + n);
    }
    (void)p11()->C_FindObjectsFinal(s);
    return found;
}

/// `n` bytes at the end of a readable page that an unreadable page follows.
class GuardedBytes
{
  public:
    explicit GuardedBytes(size_t n) : page_(static_cast<size_t>(sysconf(_SC_PAGESIZE))), n_(n)
    {
        void *m =
            mmap(nullptr, 2 * page_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((m != MAP_FAILED) &&
            (mprotect(static_cast<CK_BYTE *>(m) + page_, page_, PROT_NONE) == 0))
        {
            base_ = static_cast<CK_BYTE *>(m);
        }
        else if (m != MAP_FAILED)
        {
            munmap(m, 2 * page_);
        }
    }
    ~GuardedBytes()
    {
        if (base_ != nullptr)
        {
            munmap(base_, 2 * page_);
        }
    }
    GuardedBytes(const GuardedBytes &) = delete;
    GuardedBytes &operator=(const GuardedBytes &) = delete;

    CK_BYTE *data() const
    {
        return (base_ != nullptr) ? (base_ + page_ - n_) : nullptr;
    }

  private:
    size_t page_;
    size_t n_;
    CK_BYTE *base_ = nullptr;
};

} // namespace

// ---------------------------------------------------------------------------
// C_CreateObject, logged out
// ---------------------------------------------------------------------------

class object_policy : public PublicSession
{
};

TEST_F(object_policy, empty_template_is_incomplete)
{
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    EXPECT_CKR(CKR_TEMPLATE_INCOMPLETE, p11()->C_CreateObject(s_, nullptr, 0, &h));
    EXPECT_EQ(CK_INVALID_HANDLE, h);
}

TEST_F(object_policy, value_only_template_is_incomplete)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_TEMPLATE_INCOMPLETE,
        create(s_, { { CKA_VALUE, const_cast<char *>("abc"), 3 } }, &h)
    );
}

TEST_F(object_policy, unsupported_class_is_value_invalid)
{
    for (CK_OBJECT_CLASS cls : { 0xDEADBEEFUL, CKO_VENDOR_DEFINED })
    {
        SCOPED_TRACE(::testing::Message() << "class 0x" << std::hex << cls);
        CK_OBJECT_HANDLE h = 0;
        EXPECT_CKR(
            CKR_ATTRIBUTE_VALUE_INVALID,
            create(s_, { { CKA_CLASS, &cls, sizeof(cls) }, label_attr("bogus") }, &h)
        );
        EXPECT_EQ(CK_INVALID_HANDLE, h);
    }
}

TEST_F(object_policy, secret_key_with_value_is_inconsistent)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) },
              { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
              { CKA_TOKEN, &g_false, sizeof(g_false) },
              { CKA_VALUE, g_aes_key, sizeof(g_aes_key) },
              label_attr("policy-import") },
            &h
        )
    );
    EXPECT_EQ(CK_INVALID_HANDLE, h);
    EXPECT_TRUE(find_by_label(s_, "policy-import", 4).empty()) << "nothing to read back";

    // Without the material PKCS#11 calls the template incomplete; either way
    // no secret or private key is created here.
    EXPECT_CKR(
        CKR_TEMPLATE_INCOMPLETE,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) }, { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) } },
            &h
        )
    );
    CK_BYTE d[4] = { 1, 2, 3, 4 };
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        create(
            s_,
            { { CKA_CLASS, &g_private, sizeof(g_private) },
              { CKA_PRIVATE_EXPONENT, d, sizeof(d) } },
            &h
        )
    );
}

TEST_F(object_policy, bool_of_eight_bytes_is_invalid)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, { CKA_PRIVATE, g_v8, 8 } }, &h)
    );
}

TEST_F(object_policy, bool_of_two_bytes_is_not_read)
{
    GuardedBytes val(1);
    ASSERT_NE(nullptr, val.data());
    *val.data() = CK_FALSE;
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, { CKA_PRIVATE, val.data(), 2 } }, &h)
    );
}

TEST_F(object_policy, label_longer_than_the_ceiling_is_not_read)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_data, sizeof(g_data) },
              { CKA_LABEL, const_cast<char *>("abc"), 0xFFFFFFFFUL } },
            &h
        )
    );
}

TEST_F(object_policy, huge_ulcount_is_arguments_bad_without_allocation)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, label_attr("x") }, &h));
    CK_BYTE buf[4];
    CK_ATTRIBUTE one = { CKA_LABEL, buf, sizeof(buf) };
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GetAttributeValue(s_, h, &one, 0xFFFFFFFFUL));
    EXPECT_EQ(sizeof(buf), one.ulValueLen) << "the template was not touched";

    std::vector<CK_ATTRIBUTE> many(TEMPLATE_MAX_ATTRS + 1, { CKA_LABEL, nullptr, 0 });
    EXPECT_CKR_OK(p11()->C_GetAttributeValue(s_, h, many.data(), TEMPLATE_MAX_ATTRS));
    EXPECT_EQ(1u, many[TEMPLATE_MAX_ATTRS - 1].ulValueLen);
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GetAttributeValue(s_, h, many.data(), TEMPLATE_MAX_ATTRS + 1)
    );
}

TEST_F(object_policy, wrap_template_attribute_is_rejected)
{
    // Its entries point into the caller's memory; storing them flat would keep
    // the caller's pointers.
    CK_ATTRIBUTE inner[] = { { CKA_ENCRYPT, &g_true, sizeof(g_true) } };
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_TYPE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) },
              { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
              { CKA_TOKEN, &g_false, sizeof(g_false) },
              { CKA_WRAP_TEMPLATE, inner, sizeof(inner) } },
            &h
        )
    );
    EXPECT_CKR(
        CKR_ATTRIBUTE_TYPE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_data, sizeof(g_data) },
              { CKA_UNWRAP_TEMPLATE, inner, sizeof(inner) } },
            &h
        )
    );
    CK_ATTRIBUTE find = { CKA_DERIVE_TEMPLATE, inner, sizeof(inner) };
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, p11()->C_FindObjectsInit(s_, &find, 1));
}

TEST_F(object_policy, modifiable_of_eight_bytes_is_invalid)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, { CKA_MODIFIABLE, g_v8, 8 } }, &h)
    );
}

TEST_F(object_policy, key_encrypt_flag_of_eight_bytes_is_invalid)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) },
              { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
              { CKA_TOKEN, &g_false, sizeof(g_false) },
              { CKA_ENCRYPT, g_v8, 8 } },
            &h
        )
    );
}

TEST_F(object_policy, modifiable_of_two_bytes_is_not_read)
{
    GuardedBytes val(1);
    ASSERT_NE(nullptr, val.data());
    *val.data() = CK_TRUE;
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_data, sizeof(g_data) }, { CKA_MODIFIABLE, val.data(), 2 } },
            &h
        )
    );
}

TEST_F(object_policy, key_type_of_two_bytes_is_invalid)
{
    CK_BYTE v2[2] = { 0x1f, 0 };
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) },
              { CKA_KEY_TYPE, v2, sizeof(v2) },
              { CKA_TOKEN, &g_false, sizeof(g_false) } },
            &h
        )
    );
}

TEST_F(object_policy, find_bool_of_eight_bytes_is_invalid)
{
    CK_ATTRIBUTE t = { CKA_MODIFIABLE, g_v8, 8 };
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_FindObjectsInit(s_, &t, 1));
    CK_OBJECT_HANDLE found[1];
    CK_ULONG n = 0;
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_FindObjects(s_, found, 1, &n))
        << "a refused search starts nothing";
}

TEST_F(object_policy, token_set_attributes_are_read_only)
{
    for (CK_ATTRIBUTE_TYPE t :
         { CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_TRUSTED, CKA_UNIQUE_ID })
    {
        SCOPED_TRACE(t);
        CK_OBJECT_HANDLE h = 0;
        EXPECT_CKR(
            CKR_ATTRIBUTE_READ_ONLY,
            create(
                s_,
                { { CKA_CLASS, &g_public, sizeof(g_public) }, { t, &g_true, sizeof(g_true) } },
                &h
            )
        );
    }
}

TEST_F(object_policy, trusted_false_is_accepted)
{
    // Only TRUE is the Security Officer's; FALSE is the default.
    CK_OBJECT_CLASS cert = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE x509 = CKC_X_509;
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &cert, sizeof(cert) },
          { CKA_CERTIFICATE_TYPE, &x509, sizeof(x509) },
          { CKA_TRUSTED, &g_false, sizeof(g_false) } },
        &h
    ));
    CK_BBOOL trusted = CK_TRUE;
    CK_ATTRIBUTE a = { CKA_TRUSTED, &trusted, sizeof(trusted) };
    EXPECT_CKR_OK(p11()->C_GetAttributeValue(s_, h, &a, 1));
    EXPECT_EQ(CK_FALSE, trusted);
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));
}

TEST_F(object_policy, dates_are_checked_at_create)
{
    CK_DATE good = { { '2', '0', '2', '6' }, { '1', '1' }, { '0', '4' } };
    CK_DATE bad = { { '2', '0', '2', '6' }, { '1', '3' }, { '0', '4' } };
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        create(
            s_,
            { { CKA_CLASS, &g_public, sizeof(g_public) }, { CKA_END_DATE, &bad, sizeof(bad) } },
            &h
        )
    );
    EXPECT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_public, sizeof(g_public) }, { CKA_END_DATE, &good, sizeof(good) } },
        &h
    ));
}

TEST_F(object_policy, set_attribute_refuses_arrays_and_huge_values)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, label_attr("before") }, &h));
    CK_ATTRIBUTE inner[] = { { CKA_ENCRYPT, &g_true, sizeof(g_true) } };
    CK_ATTRIBUTE wrap = { CKA_WRAP_TEMPLATE, inner, sizeof(inner) };
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, p11()->C_SetAttributeValue(s_, h, &wrap, 1));
    CK_ATTRIBUTE huge = { CKA_LABEL, const_cast<char *>("after"), 0xFFFFFFFFUL };
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_SetAttributeValue(s_, h, &huge, 1));
    EXPECT_EQ(1u, find_by_label(s_, "before", 4).size());
}

TEST_F(object_policy, destroy_token_object_needs_read_write_session)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) },
          { CKA_TOKEN, &g_true, sizeof(g_true) },
          label_attr("destroy-from-ro") },
        &h
    ));
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    EXPECT_CKR(CKR_SESSION_READ_ONLY, p11()->C_DestroyObject(ro, h));
    EXPECT_EQ(1u, find_by_label(s_, "destroy-from-ro", 4).size()) << "the object stays";

    // A session object may be destroyed from a read-only session.
    CK_OBJECT_HANDLE sess = 0;
    ASSERT_CKR_OK(create(ro, { { CKA_CLASS, &g_data, sizeof(g_data) } }, &sess));
    EXPECT_CKR_OK(p11()->C_DestroyObject(ro, sess));

    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));
}

TEST_F(object_policy, create_in_read_only_session_names_the_session_first)
{
    // A token key from a read-only session: the session is the answer, not
    // the key this token would refuse anyway.
    const std::vector<CK_ATTRIBUTE> tmpl = { { CKA_CLASS, &g_secret, sizeof(g_secret) },
                                             { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
                                             { CKA_TOKEN, &g_true, sizeof(g_true) },
                                             { CKA_VALUE, g_aes_key, sizeof(g_aes_key) } };
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(CKR_SESSION_READ_ONLY, create(ro, tmpl, &h));
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, create(s_, tmpl, &h));
    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(object_policy, undestroyable_object_is_prohibited)
{
    // A session object, so the close of the session still reaps it.
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) },
          { CKA_DESTROYABLE, &g_false, sizeof(g_false) },
          label_attr("undestroyable") },
        &h
    ));
    EXPECT_CKR(CKR_ACTION_PROHIBITED, p11()->C_DestroyObject(s_, h));
    EXPECT_EQ(1u, find_by_label(s_, "undestroyable", 4).size()) << "the object stays";
}

TEST_F(object_policy, find_objects_page_boundary)
{
    constexpr CK_ULONG kN = 3;
    for (CK_ULONG i = 0; i < kN; i++)
    {
        CK_OBJECT_HANDLE h = 0;
        ASSERT_CKR_OK(create(s_, { { CKA_CLASS, &g_data, sizeof(g_data) }, label_attr("page") }, &h)
        );
    }
    CK_ATTRIBUTE by_label = label_attr("page");
    for (CK_ULONG page : { kN, kN + 1 })
    {
        SCOPED_TRACE(page);
        ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &by_label, 1));
        std::vector<CK_OBJECT_HANDLE> out(page);
        CK_ULONG n = 0;
        EXPECT_CKR_OK(p11()->C_FindObjects(s_, out.data(), page, &n));
        EXPECT_EQ(kN, n);
        EXPECT_CKR_OK(p11()->C_FindObjects(s_, out.data(), page, &n));
        EXPECT_EQ(0u, n) << "the search is drained";
        EXPECT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    }
}

// ---------------------------------------------------------------------------
// Keys, logged in
// ---------------------------------------------------------------------------

class object_policy_key : public UserSession
{
};

TEST_F(object_policy_key, private_object_hidden_when_logged_out)
{
    // A key is private unless the template says otherwise. A token key keeps
    // the case independent of what a logout does to session objects.
    const char kLabel[] = "policy-private-default";
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) },
                            { CKA_TOKEN, &g_true, sizeof(g_true) },
                            label_attr(kLabel) };
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(p11()->C_GenerateKey(s_, &g_keygen, tmpl, std::size(tmpl), &key));
    CK_BBOOL priv = CK_FALSE;
    CK_ATTRIBUTE a = { CKA_PRIVATE, &priv, sizeof(priv) };
    EXPECT_CKR_OK(p11()->C_GetAttributeValue(s_, key, &a, 1));
    EXPECT_EQ(CK_TRUE, priv);

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, p11()->C_GetAttributeValue(s_, key, &a, 1));
    EXPECT_TRUE(find_by_label(s_, kLabel, 4).empty());

    ASSERT_CKR_OK(login_user(s_));
    EXPECT_EQ(1u, find_by_label(s_, kLabel, 4).size());
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, key));
}

TEST_F(object_policy_key, generate_key_uses_the_same_table)
{
    CK_ATTRIBUTE inner[] = { { CKA_ENCRYPT, &g_true, sizeof(g_true) } };
    const std::vector<std::pair<CK_ATTRIBUTE, CK_RV>> rows = {
        { { CKA_TRUSTED, &g_true, sizeof(g_true) }, CKR_ATTRIBUTE_READ_ONLY },
        { { CKA_UNIQUE_ID, const_cast<char *>("id"), 2 }, CKR_ATTRIBUTE_READ_ONLY },
        { { CKA_WRAP_TEMPLATE, inner, sizeof(inner) }, CKR_ATTRIBUTE_TYPE_INVALID },
        { { CKA_PRIVATE, g_v8, 8 }, CKR_ATTRIBUTE_VALUE_INVALID },
        { { CKA_PRIME_1, g_aes_key, sizeof(g_aes_key) }, CKR_TEMPLATE_INCONSISTENT },
    };
    for (const auto &[extra, want] : rows)
    {
        SCOPED_TRACE(extra.type);
        CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) }, extra };
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        EXPECT_CKR(want, p11()->C_GenerateKey(s_, &g_keygen, tmpl, std::size(tmpl), &key));
        EXPECT_EQ(CK_INVALID_HANDLE, key);
    }

    CK_ATTRIBUTE untrusted[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) },
                                 { CKA_TRUSTED, &g_false, sizeof(g_false) } };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(p11()->C_GenerateKey(s_, &g_keygen, untrusted, std::size(untrusted), &key))
        << "CKA_TRUSTED=FALSE is the default, not the Security Officer's";
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, key));
}

// ---------------------------------------------------------------------------
// The file store (TSRA_PKCS11_PERSIST=1)
// ---------------------------------------------------------------------------

class object_policy_store : public StoreDirFixture
{
};

TEST_F(object_policy_store, refused_key_material_never_reaches_the_store)
{
    CK_OBJECT_HANDLE h = 0;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        create(
            s_,
            { { CKA_CLASS, &g_secret, sizeof(g_secret) },
              { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
              { CKA_TOKEN, &g_true, sizeof(g_true) },
              { CKA_PRIVATE, &g_false, sizeof(g_false) },
              { CKA_VALUE, g_aes_key, sizeof(g_aes_key) } },
            &h
        )
    );
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        create(
            s_,
            { { CKA_CLASS, &g_private, sizeof(g_private) },
              { CKA_TOKEN, &g_true, sizeof(g_true) },
              { CKA_PRIVATE, &g_false, sizeof(g_false) },
              { CKA_PRIME_1, g_aes_key, sizeof(g_aes_key) } },
            &h
        )
    );
    // The positive control: a public token object's value is in the store.
    CK_BYTE marker[] = { 0x5a, 0xa5, 0x5a, 0xa5, 0x0f, 0xf0, 0x0f, 0xf0 };
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) },
          { CKA_TOKEN, &g_true, sizeof(g_true) },
          { CKA_VALUE, marker, sizeof(marker) } },
        &h
    ));
    EXPECT_TRUE(store_contains(std::vector<CK_BYTE>(marker, marker + sizeof(marker))));
    EXPECT_FALSE(store_contains(std::vector<CK_BYTE>(g_aes_key, g_aes_key + sizeof(g_aes_key))));
    EXPECT_FALSE(store_contains({ 0x2b, 0x7e, 0x15, 0x16 })) << "not even the key's first word";
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));
}

TEST_F(object_policy_store, undestroyable_token_object_stays)
{
    // TearDown removes the store, and the object with it.
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) },
          { CKA_TOKEN, &g_true, sizeof(g_true) },
          { CKA_DESTROYABLE, &g_false, sizeof(g_false) },
          label_attr("undestroyable-token") },
        &h
    ));
    EXPECT_CKR(CKR_ACTION_PROHIBITED, p11()->C_DestroyObject(s_, h));
    EXPECT_EQ(1u, find_by_label(s_, "undestroyable-token", 4).size()) << "the object stays";
}

TEST_F(object_policy_store, record_over_the_file_limit_is_device_memory)
{
    // Within the 1 MiB template ceiling, over the file store's 256 KiB record.
    std::vector<CK_BYTE> big(300 * 1024, 0x5a);
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_DEVICE_MEMORY,
        create(
            s_,
            { { CKA_CLASS, &g_data, sizeof(g_data) },
              { CKA_TOKEN, &g_true, sizeof(g_true) },
              { CKA_VALUE, big.data(), static_cast<CK_ULONG>(big.size()) } },
            &h
        )
    );
    EXPECT_EQ(CK_INVALID_HANDLE, h);

    // A session object lives in the memory store, which has no such limit.
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) },
          { CKA_VALUE, big.data(), static_cast<CK_ULONG>(big.size()) } },
        &h
    ));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));

    // Growing a stored token object past the limit is refused the same way.
    ASSERT_CKR_OK(create(
        s_,
        { { CKA_CLASS, &g_data, sizeof(g_data) }, { CKA_TOKEN, &g_true, sizeof(g_true) } },
        &h
    ));
    CK_ATTRIBUTE label = { CKA_LABEL, big.data(), static_cast<CK_ULONG>(big.size()) };
    EXPECT_CKR(CKR_DEVICE_MEMORY, p11()->C_SetAttributeValue(s_, h, &label, 1));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));
}
