// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file persist_tests.cpp
///
/// The file object store (TSRA_PKCS11_PERSIST=1): a token object one process
/// creates is there for the next process that loads the module on the same
/// store, and a private token object is sealed on disk, readable again after
/// a logout or a re-initialization, and refused once tampered with.

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/sock_server.hpp"
#include "utils/store_dir.hpp"
#include "utils/subprocess.hpp"

namespace
{

const char kLabel[] = "persist-across-processes";
const std::string kPayload = "token object payload";
const char kPrivateLabel[] = "persist-private-label";
const std::string kPrivateValue = "persist private value";

/// Create a token data object with `label` and `value`.
CK_RV create_data(
    CK_SESSION_HANDLE s,
    CK_BBOOL priv,
    const char *label,
    const std::string &value,
    CK_OBJECT_HANDLE *out
)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &priv, sizeof(priv) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
        { CKA_VALUE, const_cast<char *>(value.data()), static_cast<CK_ULONG>(value.size()) },
    };
    return p11()->C_CreateObject(s, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/// The objects `s` finds by `label`.
std::vector<CK_OBJECT_HANDLE> find_label(CK_SESSION_HANDLE s, const char *label)
{
    std::vector<CK_OBJECT_HANDLE> out;
    CK_ATTRIBUTE by_label = { CKA_LABEL,
                              const_cast<char *>(label),
                              static_cast<CK_ULONG>(std::strlen(label)) };
    if (p11()->C_FindObjectsInit(s, &by_label, 1) != CKR_OK)
    {
        return out;
    }
    CK_OBJECT_HANDLE found[8];
    CK_ULONG n = 0;
    if (p11()->C_FindObjects(s, found, 8, &n) == CKR_OK)
    {
        out.assign(found, found + n);
    }
    (void)p11()->C_FindObjectsFinal(s);
    return out;
}

/// CKA_VALUE of `obj` as a string; empty when it cannot be read.
std::string read_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE obj)
{
    std::string value(256, '\0');
    CK_ATTRIBUTE a = { CKA_VALUE, value.data(), static_cast<CK_ULONG>(value.size()) };
    if (p11()->C_GetAttributeValue(s, obj, &a, 1) != CKR_OK)
    {
        return std::string();
    }
    value.resize(a.ulValueLen);
    return value;
}

std::vector<CK_BYTE> bytes(const std::string &s)
{
    return std::vector<CK_BYTE>(s.begin(), s.end());
}

/// Open a session in place of the one C_Finalize closed; `login` logs it in.
void reopen(CK_SESSION_HANDLE *s, bool login)
{
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, s)
    );
    if (login)
    {
        ASSERT_CKR_OK(login_user(*s));
    }
}

} // namespace

class persist : public StoreDirFixture
{
};

class persist_child : public PublicSession
{
};

class persist_private_child : public UserSession
{
};

TEST_F(persist, a_second_process_sees_the_token_object)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    std::vector<CK_BYTE> value(kPayload.begin(), kPayload.end());
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, const_cast<char *>(kLabel), sizeof(kLabel) - 1 },
        { CKA_VALUE, value.data(), static_cast<CK_ULONG>(value.size()) },
    };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(p11()->C_CreateObject(s_, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), &obj));
    EXPECT_TRUE(store_contains(value)) << "a public value is stored as it is";

    SubprocessModule::Result child =
        SubprocessModule::run("persist_child.reads_the_token_object", store_env());
    ASSERT_EQ(0, child.exit_code);
    EXPECT_EQ("1", child.values["found"]);
    EXPECT_EQ(kPayload, child.values["value"]);
}

TEST_F(persist_child, reads_the_token_object)
{
    SUBPROCESS_ONLY();
    CK_ATTRIBUTE by_label = { CKA_LABEL, const_cast<char *>(kLabel), sizeof(kLabel) - 1 };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &by_label, 1));
    CK_OBJECT_HANDLE found[2] = {};
    CK_ULONG n = 0;
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, found, 2, &n));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    SubprocessModule::report("found", std::to_string(n));
    ASSERT_EQ(1u, n);

    std::string value(kPayload.size() + 16, '\0');
    CK_ATTRIBUTE read = { CKA_VALUE, value.data(), static_cast<CK_ULONG>(value.size()) };
    ASSERT_CKR_OK(p11()->C_GetAttributeValue(s_, found[0], &read, 1));
    value.resize(read.ulValueLen);
    SubprocessModule::report("value", value);
}

TEST_F(persist, private_label_and_value_are_not_stored_in_clear)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, kPrivateValue, &obj));
    const char key_label[] = "persist-private-key-label";
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_family_key(s_, CKM_AES_CBC, CK_TRUE, CK_TRUE, key_label, &key));
    EXPECT_EQ(kPrivateValue, read_value(s_, obj));

    EXPECT_FALSE(store_contains(bytes(kPrivateLabel))) << "the private label is sealed";
    EXPECT_FALSE(store_contains(bytes(kPrivateValue))) << "the private value is sealed";
    EXPECT_FALSE(store_contains(bytes(key_label))) << "the private key's label is sealed";
}

TEST_F(persist, private_object_reads_back_after_logout_and_reinitialize)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, kPrivateValue, &obj));

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_TRUE(find_label(s_, kPrivateLabel).empty()) << "a private object is hidden logged out";
    ASSERT_CKR_OK(login_user(s_));
    std::vector<CK_OBJECT_HANDLE> found = find_label(s_, kPrivateLabel);
    ASSERT_EQ(1u, found.size());
    EXPECT_EQ(kPrivateValue, read_value(s_, found[0])) << "after C_Logout and C_Login";

    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    s_ = 0;
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_NO_FATAL_FAILURE(reopen(&s_, true));
    found = find_label(s_, kPrivateLabel);
    ASSERT_EQ(1u, found.size());
    EXPECT_EQ(kPrivateValue, read_value(s_, found[0])) << "after C_Finalize and C_Initialize";
}

TEST_F(persist, public_object_reads_without_login)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_FALSE, kLabel, kPayload, &obj));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_EQ(kPayload, read_value(s_, obj)) << "logged out";

    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    s_ = 0;
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_NO_FATAL_FAILURE(reopen(&s_, false));
    std::vector<CK_OBJECT_HANDLE> found = find_label(s_, kLabel);
    ASSERT_EQ(1u, found.size());
    EXPECT_EQ(kPayload, read_value(s_, found[0])) << "after C_Initialize, never logged in";
}

TEST_F(persist, tampered_private_record_is_refused)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, kPrivateValue, &obj));
    std::filesystem::path record;
    for (const auto &f : std::filesystem::directory_iterator(dir_ + "/slot-0"))
    {
        if (f.path().extension() == ".object")
        {
            ASSERT_TRUE(record.empty()) << "the store holds one object";
            record = f.path();
        }
    }
    ASSERT_FALSE(record.empty());
    std::vector<char> data;
    {
        std::ifstream in(record, std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    ASSERT_FALSE(data.empty());
    auto write_record = [&record](const std::vector<char> &d) {
        std::ofstream out(record, std::ios::binary | std::ios::trunc);
        out.write(d.data(), static_cast<std::streamsize>(d.size()));
    };

    std::vector<char> tampered = data;
    tampered.back() ^= 0x01; /* the last byte of the GCM tag */
    write_record(tampered);
    CK_BYTE buf[64];
    CK_ATTRIBUTE label = { CKA_LABEL, buf, sizeof(buf) };
    EXPECT_CKR(CKR_FUNCTION_FAILED, p11()->C_GetAttributeValue(s_, obj, &label, 1));
    CK_RV find_rv = p11()->C_FindObjectsInit(s_, nullptr, 0);
    if (find_rv == CKR_OK)
    {
        (void)p11()->C_FindObjectsFinal(s_);
    }
    EXPECT_CKR(CKR_FUNCTION_FAILED, find_rv) << "a search fails rather than leave it out";

    write_record(data);
    EXPECT_EQ(kPrivateValue, read_value(s_, obj)) << "the untouched record reads again";
}

TEST_F(persist, a_second_process_reads_the_private_object)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, kPrivateValue, &obj));

    SubprocessModule::Result child =
        SubprocessModule::run("persist_private_child.reads_the_private_object", store_env());
    ASSERT_EQ(0, child.exit_code);
    EXPECT_EQ("1", child.values["ran"]);
    EXPECT_EQ(kPrivateValue, child.values["value"]) << "the same device unmasks the record key";
}

TEST_F(persist_private_child, reads_the_private_object)
{
    SUBPROCESS_ONLY();
    std::vector<CK_OBJECT_HANDLE> found = find_label(s_, kPrivateLabel);
    ASSERT_EQ(1u, found.size());
    SubprocessModule::report("value", read_value(s_, found[0]));
}

TEST_F(persist, a_freshly_provisioned_device_reads_only_its_own_private_objects)
{
    EMU_ONLY("needs a second simulator, provisioned afresh with another masking key");
    if (PrivateSimulator::server_bin().empty())
    {
        GTEST_SKIP() << "needs a fresh simulator: set server_bin in TSRA_TEST_ARGS";
    }
    PrivateSimulator sim;
    ASSERT_TRUE(sim.ok()) << "could not start " << PrivateSimulator::server_bin();
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, kPrivateValue, &obj));

    std::vector<std::string> env = store_env();
    for (const std::string &e : sim.env())
    {
        env.push_back(e);
    }
    SubprocessModule::Result child =
        SubprocessModule::run("persist_private_child.creates_a_private_object_of_its_own", env);
    ASSERT_EQ(0, child.exit_code);
    EXPECT_EQ("1", child.values["ran"]);
    EXPECT_EQ("0", child.values["seen"]) << "the parent's record key does not unmask there";
    EXPECT_EQ(kPayload, child.values["value"]) << "the child seals with keys of its own";

    EXPECT_EQ(kPrivateValue, read_value(s_, obj)) << "the parent's record keeps its key";
    EXPECT_TRUE(find_label(s_, kLabel).empty()) << "the child's object is sealed for the child";
    CK_OBJECT_HANDLE again = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kLabel, kPayload, &again));
    EXPECT_EQ(kPayload, read_value(s_, again));
}

TEST_F(persist_private_child, creates_a_private_object_of_its_own)
{
    SUBPROCESS_ONLY();
    SubprocessModule::report("seen", std::to_string(find_label(s_, kPrivateLabel).size()));
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kLabel, kPayload, &obj));
    SubprocessModule::report("value", read_value(s_, obj));
}
