// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tsra_api.h>

// Generic RAII wrapper for managing an existing HSM context handle
// with automatic cleanup.
struct auto_ctx
{
    tsra_handle handle = 0;

    auto_ctx() = default;

    // Prevent copying
    auto_ctx(const auto_ctx &) = delete;
    auto_ctx &operator=(const auto_ctx &) = delete;

    // Allow moving
    auto_ctx(auto_ctx &&other) noexcept : handle(other.handle)
    {
        other.handle = 0;
    }

    auto_ctx &operator=(auto_ctx &&other) noexcept
    {
        if (this != &other)
        {
            if (handle != 0)
            {
                tsra_free_ctx_handle(handle);
            }
            handle = other.handle;
            other.handle = 0;
        }
        return *this;
    }

    ~auto_ctx()
    {
        if (handle != 0)
        {
            tsra_free_ctx_handle(handle);
        }
    }

    tsra_handle get() const
    {
        return handle;
    }

    tsra_handle *get_ptr()
    {
        return &handle;
    }

    // Allow implicit conversion to tsra_handle for convenience
    operator tsra_handle() const
    {
        return handle;
    }

    tsra_handle release()
    {
        tsra_handle temp = handle;
        handle = 0;
        return temp;
    }
};