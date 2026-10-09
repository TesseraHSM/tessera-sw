// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <tsra_api.h>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/utils.hpp"

class tsra_sess : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(tsra_sess, open_and_close)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);

        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_NE(sess_handle, 0);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(tsra_sess_close(sess_handle), TSRA_STATUS_SUCCESS);
        });
    });
}

TEST_F(tsra_sess, open_null_sess_handle)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        auto err = tsra_sess_open(partition.get(), &creds, nullptr, nullptr);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(tsra_sess, open_null_creds)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_handle sess_handle = 0;

        auto err = tsra_sess_open(partition.get(), nullptr, nullptr, &sess_handle);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(tsra_sess, open_invalid_partition_handle)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle bad_handle = 0xDEADBEEF;

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;

        auto err = tsra_sess_open(bad_handle, &creds, nullptr, &sess_handle);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

TEST_F(tsra_sess, close_invalid_handle)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle bad_handle = 0xBADCAFE;
        auto err = tsra_sess_close(bad_handle);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

TEST_F(tsra_sess, close_double_close)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;

        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);

        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        // First close should succeed
        err = tsra_sess_close(sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        // Second close should fail
        err = tsra_sess_close(sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

TEST_F(tsra_sess, open_close_multiple)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        // Open and close sessions sequentially
        for (int i = 0; i < 5; ++i)
        {
            tsra_handle sess_handle = 0;
            auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);

            ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
            ASSERT_NE(sess_handle, 0);

            err = tsra_sess_close(sess_handle);
            ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        }
    });
}

TEST_F(tsra_sess, open_with_wrong_handle_type)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto list_handle_wrapper = PartitionListHandle();
        tsra_handle list_handle = list_handle_wrapper.get();

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(list_handle, &creds, nullptr, &sess_handle);

        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}

TEST_F(tsra_sess, open_with_corrupt_creds)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{}; // All zeros - invalid credentials

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);

        ASSERT_NE(err, TSRA_STATUS_SUCCESS);
    });
}

TEST_F(tsra_sess, get_prop_api_rev)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(tsra_sess_close(sess_handle), TSRA_STATUS_SUCCESS);
        });

        tsra_api_rev retrieved_api_rev = { 0, 0 };
        tsra_session_prop prop = { TSRA_SESSION_PROP_ID_API_REV,
                                   &retrieved_api_rev,
                                   sizeof(retrieved_api_rev) };

        err = tsra_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);
        ASSERT_EQ(prop.len, sizeof(tsra_api_rev));
        ASSERT_EQ(retrieved_api_rev.major, 1);
        ASSERT_EQ(retrieved_api_rev.minor, 0);
    });
}

TEST_F(tsra_sess, get_prop_api_rev_buffer_too_small)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(tsra_sess_close(sess_handle), TSRA_STATUS_SUCCESS);
        });

        // Provide buffer that's too small
        tsra_api_rev retrieved_api_rev = { 0, 0 };
        tsra_session_prop prop = { TSRA_SESSION_PROP_ID_API_REV,
                                   &retrieved_api_rev,
                                   1 }; // Only 1 byte instead of sizeof

        err = tsra_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, TSRA_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(prop.len, sizeof(tsra_api_rev)); // Should return required size
    });
}

TEST_F(tsra_sess, get_prop_null_prop_ptr)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(tsra_sess_close(sess_handle), TSRA_STATUS_SUCCESS);
        });

        err = tsra_session_get_prop(sess_handle, nullptr);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(tsra_sess, get_prop_invalid_handle)
{
    tsra_handle bad_handle = 0xDEADBEEF;
    tsra_api_rev api_rev = { 0, 0 };
    tsra_session_prop prop = { TSRA_SESSION_PROP_ID_API_REV, &api_rev, sizeof(api_rev) };

    auto err = tsra_session_get_prop(bad_handle, &prop);
    ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
}

TEST_F(tsra_sess, get_prop_unsupported_property)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        tsra_handle sess_handle = 0;
        auto err = tsra_sess_open(partition.get(), &creds, nullptr, &sess_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(tsra_sess_close(sess_handle), TSRA_STATUS_SUCCESS);
        });

        // Test an unsupported property
        tsra_session_prop prop = { static_cast<tsra_session_prop_id>(-1), nullptr, 0 };

        err = tsra_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, TSRA_STATUS_UNSUPPORTED_PROPERTY);
    });
}

TEST_F(tsra_sess, get_prop_wrong_handle_type)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);

        tsra_api_rev api_rev = { 0, 0 };
        tsra_session_prop prop = { TSRA_SESSION_PROP_ID_API_REV, &api_rev, sizeof(api_rev) };

        // Try to use partition handle instead of session handle
        auto err = tsra_session_get_prop(partition.get(), &prop);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_HANDLE);
    });
}