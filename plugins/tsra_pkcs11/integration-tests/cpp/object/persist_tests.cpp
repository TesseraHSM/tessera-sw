// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file persist_tests.cpp
///
/// The file object store (TSRA_PKCS11_PERSIST=1) across processes: a token
/// object one process creates is there for the next process that loads the
/// module on the same store.

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/subprocess.hpp"

namespace
{

const char kLabel[] = "persist-across-processes";
const std::string kPayload = "token object payload";

} // namespace

class persist : public StoreDirFixture
{
};

class persist_child : public PublicSession
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
