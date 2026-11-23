// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file persist_tests.cpp
///
/// The file object store (TSRA_PKCS11_PERSIST=1): a token object one process
/// creates is there for the next process that loads the module on the same
/// store, and a private token object is sealed on disk, readable again after
/// a logout or a re-initialization, and refused once tampered with. A sealed
/// record's own key, written into a clear record, encrypts nothing.

#include <climits>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_store_record.h"
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
/// Private values just under and over what one device AES-GCM call seals
/// (16 KiB with the record header).
constexpr size_t kPrivateValueThatFits = 15 * 1024;
constexpr size_t kPrivateValueTooLarge = 17 * 1024;

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

/// The record layout of tsra_pkcs11_store_record.c: magic, u16 version, u16
/// flags, u32 attribute count, u32 body length, u32 total length; a sealed
/// record then holds u32 key length and its key's masked blob.
const CK_BYTE kRecordMagic[] = { 'P', '1', '1', 'O' };
constexpr size_t kRecordHeaderLen =
    sizeof(kRecordMagic) + (2 * sizeof(uint16_t)) + (3 * sizeof(uint32_t));
constexpr size_t kRecordKeyAt = kRecordHeaderLen + sizeof(uint32_t);

/// Append `v` to `out` little-endian in `n` bytes, as the record codec does.
void put_le(std::vector<CK_BYTE> &out, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        out.push_back(static_cast<CK_BYTE>(v >> (i * CHAR_BIT)));
    }
}

/// The `n` bytes of `in` at `at` as a little-endian value, as put_le writes it.
uint64_t get_le(const std::vector<CK_BYTE> &in, size_t at, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
    {
        v |= static_cast<uint64_t>(in[at + i]) << (i * CHAR_BIT);
    }
    return v;
}

/// The bytes of a fixed-size attribute value, as the module stores them.
template <typename T> std::vector<CK_BYTE> raw(const T &v)
{
    const CK_BYTE *p = reinterpret_cast<const CK_BYTE *>(&v);
    return std::vector<CK_BYTE>(p, p + sizeof(T));
}

/// A clear (unsealed) record holding `attrs` and the masked blob `body`.
std::vector<CK_BYTE> clear_record(
    const std::vector<std::pair<CK_ATTRIBUTE_TYPE, std::vector<CK_BYTE>>> &attrs,
    const std::vector<CK_BYTE> &body
)
{
    std::vector<CK_BYTE> payload;
    for (const auto &[type, value] : attrs)
    {
        put_le(payload, type, sizeof(uint32_t));
        put_le(payload, value.size(), sizeof(uint32_t));
        payload.insert(payload.end(), value.begin(), value.end());
    }
    payload.insert(payload.end(), body.begin(), body.end());
    std::vector<CK_BYTE> rec(std::begin(kRecordMagic), std::end(kRecordMagic));
    put_le(rec, P11_RECORD_VERSION, sizeof(uint16_t));
    put_le(rec, 0, sizeof(uint16_t)); // flags: not sealed
    put_le(rec, attrs.size(), sizeof(uint32_t));
    put_le(rec, body.size(), sizeof(uint32_t));
    put_le(rec, kRecordHeaderLen + payload.size(), sizeof(uint32_t));
    rec.insert(rec.end(), payload.begin(), payload.end());
    return rec;
}

void write_file(const std::filesystem::path &path, const std::vector<CK_BYTE> &data)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(
        reinterpret_cast<const char *>(data.data()),
        static_cast<std::streamsize>(data.size())
    );
}

/// The path and bytes of the one record in slot 0 of the store at `dir`;
/// fails the test unless there is exactly one and it is not empty.
void only_record(const std::string &dir, std::filesystem::path *path, std::vector<CK_BYTE> *data)
{
    path->clear();
    for (const auto &f : std::filesystem::directory_iterator(dir + "/slot-0"))
    {
        if (f.path().extension() == ".object")
        {
            ASSERT_TRUE(path->empty()) << "the store holds one object";
            *path = f.path();
        }
    }
    ASSERT_FALSE(path->empty());
    std::ifstream in(*path, std::ios::binary);
    data->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    ASSERT_FALSE(data->empty());
}

/// A record file whose object number is above every object a test creates.
const char kForgedRecordFile[] = "900.object";

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
    std::vector<CK_BYTE> data;
    ASSERT_NO_FATAL_FAILURE(only_record(dir_, &record, &data));

    std::vector<CK_BYTE> tampered = data;
    tampered.back() ^= 0x01; /* the last byte of the GCM tag */
    write_file(record, tampered);
    CK_BYTE buf[64];
    CK_ATTRIBUTE label = { CKA_LABEL, buf, sizeof(buf) };
    EXPECT_CKR(CKR_FUNCTION_FAILED, p11()->C_GetAttributeValue(s_, obj, &label, 1));
    CK_RV find_rv = p11()->C_FindObjectsInit(s_, nullptr, 0);
    if (find_rv == CKR_OK)
    {
        (void)p11()->C_FindObjectsFinal(s_);
    }
    EXPECT_CKR(CKR_FUNCTION_FAILED, find_rv) << "a search fails rather than leave it out";

    write_file(record, data);
    EXPECT_EQ(kPrivateValue, read_value(s_, obj)) << "the untouched record reads again";
}

TEST_F(persist, a_record_key_in_a_clear_record_encrypts_nothing)
{
    // A sealed record keeps its device GCM key's masked blob in the clear
    // header. As the body of a clear record claiming an AES-GCM key, it would
    // seal and open records under a caller-chosen IV and AAD.
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_family_key(s_, CKM_AES_GCM, CK_TRUE, CK_TRUE, "sealed-gcm-key", &key));
    CK_BYTE iv[AES_GCM_IV_LEN] = { 0 };
    CK_GCM_PARAMS params{};
    params.pIv = iv;
    params.ulIvLen = sizeof(iv);
    params.ulIvBits = sizeof(iv) * CHAR_BIT;
    params.ulTagBits = AES_GCM_TAG_LEN * CHAR_BIT;
    CK_MECHANISM gcm = { CKM_AES_GCM, &params, sizeof(params) };
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &gcm, key)) << "the generated key encrypts";
    abandon_operations(s_);

    std::filesystem::path sealed;
    std::vector<CK_BYTE> data;
    ASSERT_NO_FATAL_FAILURE(only_record(dir_, &sealed, &data));
    ASSERT_GT(data.size(), kRecordKeyAt);
    const size_t key_len = get_le(data, kRecordHeaderLen, sizeof(uint32_t));
    ASSERT_GT(key_len, 0u);
    ASSERT_GE(data.size(), kRecordKeyAt + key_len);
    std::vector<CK_BYTE> record_key(
        data.begin() + kRecordKeyAt,
        data.begin() + static_cast<std::ptrdiff_t>(kRecordKeyAt + key_len)
    );

    const std::string label = "lent-record-key";
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_KEY_TYPE aes = CKK_AES;
    CK_MECHANISM_TYPE gcm_only = CKM_AES_GCM;
    // Each record says CKA_PRIVATE FALSE outright; one row leaves it out.
    auto forge = [&](CK_OBJECT_CLASS cls, CK_ATTRIBUTE_TYPE omit) {
        std::vector<std::pair<CK_ATTRIBUTE_TYPE, std::vector<CK_BYTE>>> attrs = {
            { CKA_CLASS, raw(cls) },     { CKA_TOKEN, raw(yes) },
            { CKA_KEY_TYPE, raw(aes) },  { CKA_ALLOWED_MECHANISMS, raw(gcm_only) },
            { CKA_ENCRYPT, raw(yes) },   { CKA_DECRYPT, raw(yes) },
            { CKA_LABEL, bytes(label) }, { CKA_PRIVATE, raw(no) },
        };
        std::erase_if(attrs, [omit](const auto &a) { return a.first == omit; });
        return clear_record(attrs, record_key);
    };
    struct Row
    {
        CK_OBJECT_CLASS cls;
        CK_ATTRIBUTE_TYPE omit; // CKA_VENDOR_DEFINED: none of the above
        CK_RV want;
        const char *rule;
    };
    const Row rows[] = {
        { CKO_DATA, CKA_VENDOR_DEFINED, CKR_KEY_FUNCTION_NOT_PERMITTED, "only a secret key" },
        { CKO_PUBLIC_KEY, CKA_VENDOR_DEFINED, CKR_KEY_FUNCTION_NOT_PERMITTED, "only a secret key" },
        { CKO_DATA, CKA_PRIVATE, CKR_KEY_FUNCTION_NOT_PERMITTED, "no CKA_PRIVATE changes nothing" },
        { CKO_DATA, CKA_CLASS, CKR_KEY_FUNCTION_NOT_PERMITTED, "no class is no secret key" },
        { CKO_DATA, CKA_KEY_TYPE, CKR_KEY_TYPE_INCONSISTENT, "no key type is no AES key" },
    };
    std::filesystem::path forged = sealed.parent_path() / kForgedRecordFile;
    CK_OBJECT_HANDLE lent = CK_INVALID_HANDLE;
    for (const Row &row : rows)
    {
        SCOPED_TRACE(row.rule);
        write_file(forged, forge(row.cls, row.omit));
        std::vector<CK_OBJECT_HANDLE> found = find_label(s_, label.c_str());
        ASSERT_EQ(1u, found.size()) << "a clear record of this class is a valid object";
        lent = found[0];
        EXPECT_CKR(row.want, p11()->C_EncryptInit(s_, &gcm, lent)) << row.rule << " encrypts";
        EXPECT_CKR(row.want, p11()->C_DecryptInit(s_, &gcm, lent)) << row.rule << " decrypts";
        abandon_operations(s_);
    }
    // The same record as a secret key: the store never writes a clear one. With
    // CKA_PRIVATE FALSE it is what an earlier build wrote for a public token key.
    for (CK_ATTRIBUTE_TYPE omit : { CKA_VENDOR_DEFINED, CKA_PRIVATE })
    {
        write_file(forged, forge(CKO_SECRET_KEY, omit));
        EXPECT_CKR(CKR_FUNCTION_FAILED, p11()->C_EncryptInit(s_, &gcm, lent))
            << "a clear secret key is refused like a tampered record, CKA_PRIVATE "
            << (omit == CKA_PRIVATE ? "left out" : "FALSE");
        abandon_operations(s_);
    }
    std::filesystem::remove(forged);
}

TEST_F(persist, a_private_record_is_sealed_up_to_the_device_limit)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_DEVICE_MEMORY,
        create_data(s_, CK_TRUE, kPrivateLabel, std::string(kPrivateValueTooLarge, 'p'), &obj)
    );
    EXPECT_EQ(CK_INVALID_HANDLE, obj);

    const std::string big(kPrivateValueThatFits, 'p');
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, kPrivateLabel, big, &obj));
    std::string back(big.size(), '\0');
    CK_ATTRIBUTE value = { CKA_VALUE, back.data(), static_cast<CK_ULONG>(back.size()) };
    ASSERT_CKR_OK(p11()->C_GetAttributeValue(s_, obj, &value, 1));
    EXPECT_EQ(big.size(), value.ulValueLen);
    EXPECT_TRUE(big == back) << "the value reads back unchanged";
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
