// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file interface_tests.cpp
///
/// The interfaces the module offers: "PKCS 11" 3.1, 3.0 and 2.40,
/// in that order, 3.1 the default; lookups by version and flags; two-call
/// sizing of the list; C_GetFunctionList handing out the 2.40 table; and
/// C_LoginUser, which is C_Login with the username ignored.

#include <cstddef>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/module.hpp"

namespace
{

/// The version every function list starts with.
CK_VERSION version_of(const CK_INTERFACE &iface)
{
    return *static_cast<const CK_VERSION *>(iface.pFunctionList);
}

/// C_GetInterface("PKCS 11", major.minor), or nullptr if the lookup fails.
CK_INTERFACE_PTR lookup(CK_BYTE major, CK_BYTE minor, CK_FLAGS flags = 0)
{
    CK_VERSION v = { major, minor };
    CK_INTERFACE_PTR iface = nullptr;
    CK_RV rv = p11_3()->C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &iface, flags);
    return (rv == CKR_OK) ? iface : nullptr;
}

} // namespace

class interfaces : public ::testing::Test
{
};

class interfaces_login : public PublicSession
{
};

TEST_F(interfaces, list_is_3_1_then_3_0_then_2_40)
{
    CK_ULONG n = 0;
    ASSERT_CKR_OK(p11_3()->C_GetInterfaceList(nullptr, &n));
    ASSERT_EQ(3u, n);

    std::vector<CK_INTERFACE> list(n);
    ASSERT_CKR_OK(p11_3()->C_GetInterfaceList(list.data(), &n));
    ASSERT_EQ(3u, n);
    const CK_VERSION want[] = { { 3, 1 }, { 3, 0 }, { 2, 40 } };
    for (CK_ULONG i = 0; i < n; i++)
    {
        SCOPED_TRACE(::testing::Message() << "entry " << i);
        EXPECT_STREQ("PKCS 11", reinterpret_cast<const char *>(list[i].pInterfaceName));
        EXPECT_EQ(want[i].major, version_of(list[i]).major);
        EXPECT_EQ(want[i].minor, version_of(list[i]).minor);
        EXPECT_EQ(0u, list[i].flags) << "no CKF_INTERFACE_FORK_SAFE until fork is handled";
    }
}

TEST_F(interfaces, list_sizing_follows_the_two_call_rule)
{
    std::vector<CK_INTERFACE> list(2);
    CK_ULONG n = 2;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11_3()->C_GetInterfaceList(list.data(), &n));
    EXPECT_EQ(3u, n);
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11_3()->C_GetInterfaceList(list.data(), nullptr));
}

TEST_F(interfaces, default_is_3_1)
{
    CK_INTERFACE_PTR iface = nullptr;
    ASSERT_CKR_OK(p11_3()->C_GetInterface(nullptr, nullptr, &iface, 0));
    ASSERT_NE(nullptr, iface);
    EXPECT_EQ(3, version_of(*iface).major);
    EXPECT_EQ(1, version_of(*iface).minor);
    EXPECT_EQ(lookup(3, 1), iface);
}

TEST_F(interfaces, lookup_by_version)
{
    CK_INTERFACE_PTR v31 = lookup(3, 1);
    CK_INTERFACE_PTR v30 = lookup(3, 0);
    CK_INTERFACE_PTR v240 = lookup(2, 40);
    ASSERT_NE(nullptr, v31);
    ASSERT_NE(nullptr, v30);
    ASSERT_NE(nullptr, v240);
    EXPECT_EQ(0, version_of(*v30).minor);
    EXPECT_EQ(40, version_of(*v240).minor);

    // 3.0 and 3.1 are the same v3 entry points under two versions.
    auto *f31 = static_cast<CK_FUNCTION_LIST_3_0_PTR>(v31->pFunctionList);
    auto *f30 = static_cast<CK_FUNCTION_LIST_3_0_PTR>(v30->pFunctionList);
    EXPECT_NE(f31, f30);
    EXPECT_EQ(
        0,
        std::memcmp(
            &f31->C_Initialize,
            &f30->C_Initialize,
            sizeof(*f31) - offsetof(CK_FUNCTION_LIST_3_0, C_Initialize)
        )
    );
    EXPECT_NE(nullptr, f30->C_LoginUser);

    // The 2.40 interface is the table C_GetFunctionList hands out.
    CK_FUNCTION_LIST_PTR legacy = nullptr;
    ASSERT_CKR_OK(p11()->C_GetFunctionList(&legacy));
    EXPECT_EQ(static_cast<void *>(legacy), v240->pFunctionList);
    EXPECT_EQ(2, legacy->version.major);
    EXPECT_EQ(40, legacy->version.minor);
}

TEST_F(interfaces, lookups_that_match_nothing_are_refused)
{
    CK_INTERFACE_PTR iface = nullptr;
    EXPECT_EQ(nullptr, lookup(2, 11));
    EXPECT_EQ(nullptr, lookup(3, 2));
    EXPECT_EQ(nullptr, lookup(3, 1, CKF_INTERFACE_FORK_SAFE)) << "no interface is fork safe yet";
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11_3()->C_GetInterface((CK_UTF8CHAR_PTR) "Vendor", nullptr, &iface, 0)
    );
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11_3()->C_GetInterface(nullptr, nullptr, nullptr, 0));
}

TEST_F(interfaces_login, login_user_forwards_to_login)
{
    std::string pin = Pkcs11Module::pin();
    CK_UTF8CHAR name[] = "anybody";
    ASSERT_CKR_OK(p11_3()->C_LoginUser(
        s_,
        CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data()),
        static_cast<CK_ULONG>(pin.size()),
        name,
        sizeof(name) - 1
    )) << "the username selects nothing";
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(s_, &info));
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_USER_FUNCTIONS), info.state);
    EXPECT_CKR(
        CKR_USER_ALREADY_LOGGED_IN,
        p11_3()->C_LoginUser(
            s_,
            CKU_USER,
            reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data()),
            static_cast<CK_ULONG>(pin.size()),
            nullptr,
            0
        )
    );
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(
        CKR_USER_TYPE_INVALID,
        p11_3()->C_LoginUser(
            s_,
            CKU_SO,
            reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data()),
            static_cast<CK_ULONG>(pin.size()),
            name,
            sizeof(name) - 1
        )
    );
}
