// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <windows.h>

#include <bcrypt.h>
#include <tsra_api.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
constexpr const char *default_endpoint = "tcp://127.0.0.1:1234";

void check_status(tsra_status status, const char *operation)
{
    if (status != TSRA_STATUS_SUCCESS)
    {
        throw std::runtime_error(
            std::string(operation) + " failed with status " + std::to_string(status)
        );
    }
}

template <tsra_status (*Close)(tsra_handle)> class ApiHandle
{
  public:
    ApiHandle() = default;
    ApiHandle(const ApiHandle &) = delete;
    ApiHandle &operator=(const ApiHandle &) = delete;
    ApiHandle(ApiHandle &&other) noexcept : handle_(std::exchange(other.handle_, 0))
    {
    }

    ~ApiHandle()
    {
        if (handle_ != 0)
        {
            Close(handle_);
        }
    }

    tsra_handle get() const noexcept
    {
        return handle_;
    }
    tsra_handle *out() noexcept
    {
        return &handle_;
    }

  private:
    tsra_handle handle_ = 0;
};

using PartitionList = ApiHandle<tsra_part_free_list>;
using Partition = ApiHandle<tsra_part_close>;
using Session = ApiHandle<tsra_sess_close>;
using Key = ApiHandle<tsra_key_delete>;

struct Options
{
    std::string endpoint = default_endpoint;
    size_t count = 1;
};

Options parse_args(int argc, char **argv)
{
    if (argc > 3)
    {
        throw std::runtime_error("expected [ENDPOINT] [COUNT]");
    }
    Options options;
    if (argc > 1)
    {
        options.endpoint = argv[1];
    }
    if (options.endpoint.rfind("tcp://", 0) != 0 || options.endpoint.size() == 6)
    {
        throw std::runtime_error("endpoint must have the form tcp://HOST:PORT");
    }
    if (argc > 2)
    {
        const std::string count = argv[2];
        const auto result =
            std::from_chars(count.data(), count.data() + count.size(), options.count);
        if (result.ec != std::errc{} || result.ptr != count.data() + count.size() ||
            options.count == 0)
        {
            throw std::runtime_error("iteration count must be a positive integer");
        }
    }
    return options;
}

std::wstring to_utf16(const std::string &text)
{
    if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
    {
        throw std::runtime_error("endpoint is too long");
    }
    const int length = static_cast<int>(text.size());
    const int required =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
    if (required == 0)
    {
        throw std::runtime_error("endpoint is not valid UTF-8");
    }
    std::wstring result(static_cast<size_t>(required), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            length,
            result.data(),
            required
        ) != required)
    {
        throw std::runtime_error("failed to convert endpoint to UTF-16");
    }
    return result;
}

Partition open_partition(const std::string &endpoint)
{
    const auto expected_path = to_utf16(endpoint);
    if (!SetEnvironmentVariableW(L"TSRA_DDI_SOCK", expected_path.c_str()))
    {
        throw std::runtime_error("failed to configure the socket endpoint");
    }

    PartitionList partitions;
    check_status(tsra_part_get_list(partitions.out()), "partition discovery");
    uint32_t count = 0;
    check_status(tsra_part_get_count(partitions.get(), &count), "partition count");
    for (uint32_t index = 0; index < count; ++index)
    {
        tsra_part_info info{};
        const auto status = tsra_part_get_info(partitions.get(), index, &info);
        if (status != TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            check_status(status, "partition path size");
        }
        if (info.path.len == 0)
        {
            throw std::runtime_error("partition discovery returned an empty path");
        }
        std::vector<tsra_char> path(info.path.len);
        info.path.str = path.data();
        check_status(tsra_part_get_info(partitions.get(), index, &info), "partition information");
        if (info.path.len == 0 || info.path.len > path.size())
        {
            throw std::runtime_error("partition discovery returned an invalid path length");
        }
        path.resize(info.path.len);
        if (path.back() != 0 ||
            !std::equal(path.begin(), path.end() - 1, expected_path.begin(), expected_path.end()))
        {
            continue;
        }
        Partition partition;
        check_status(
            tsra_part_open(&info.path, partition.out(), info.api_rev_max),
            "partition open"
        );
        return partition;
    }
    throw std::runtime_error(
        "TCP partition not found; build the native SDK with --features tsra_api/sock"
    );
}

Session open_session(tsra_handle partition)
{
    std::array<uint8_t, TSRA_PSK_LEN> test_psk{};
    test_psk.fill(0xA5);
    tsra_buffer psk_buffer{ test_psk.data(), static_cast<uint32_t>(test_psk.size()) };
    tsra_session_psk credential{};
    credential.psk_id = 0;

    Session session;
    const auto default_status = tsra_sess_ex_open(
        partition,
        &credential,
        TSRA_SESSION_EX_TYPE_AUTHENTICATED,
        session.out()
    );
    if (default_status == TSRA_STATUS_SUCCESS)
    {
        check_status(tsra_sess_ex_psk_change(session.get(), &psk_buffer), "test CO PSK rotation");
    }
    else
    {
        credential.psk = &psk_buffer;
        const auto rotated_status = tsra_sess_ex_open(
            partition,
            &credential,
            TSRA_SESSION_EX_TYPE_AUTHENTICATED,
            session.out()
        );
        if (rotated_status != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "session open failed with default PSK status " + std::to_string(default_status) +
                " and test PSK status " + std::to_string(rotated_status)
            );
        }
    }
    return session;
}

void generate_key_pair(tsra_handle session, Key &private_key, Key &public_key)
{
    uint32_t private_class = TSRA_KEY_CLASS_PRIVATE;
    uint32_t public_class = TSRA_KEY_CLASS_PUBLIC;
    uint32_t kind = TSRA_KEY_KIND_ECC;
    uint32_t curve = TSRA_ECC_CURVE_P384;
    uint8_t enabled = 1;
    std::array<tsra_key_prop, 5> private_properties{ {
        { TSRA_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
        { TSRA_KEY_PROP_ID_KIND, &kind, sizeof(kind) },
        { TSRA_KEY_PROP_ID_EC_CURVE, &curve, sizeof(curve) },
        { TSRA_KEY_PROP_ID_SESSION, &enabled, sizeof(enabled) },
        { TSRA_KEY_PROP_ID_SIGN, &enabled, sizeof(enabled) },
    } };
    std::array<tsra_key_prop, 5> public_properties{ {
        { TSRA_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
        { TSRA_KEY_PROP_ID_KIND, &kind, sizeof(kind) },
        { TSRA_KEY_PROP_ID_EC_CURVE, &curve, sizeof(curve) },
        { TSRA_KEY_PROP_ID_SESSION, &enabled, sizeof(enabled) },
        { TSRA_KEY_PROP_ID_VERIFY, &enabled, sizeof(enabled) },
    } };
    tsra_key_prop_list private_list{ private_properties.data(),
                                     static_cast<uint32_t>(private_properties.size()) };
    tsra_key_prop_list public_list{ public_properties.data(),
                                    static_cast<uint32_t>(public_properties.size()) };
    tsra_algo algorithm{};
    algorithm.id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN;
    check_status(
        tsra_key_gen_pair(
            session,
            &algorithm,
            &private_list,
            &public_list,
            private_key.out(),
            public_key.out()
        ),
        "P-384 key generation"
    );
}

std::array<uint8_t, 48> sha384(const std::string &message)
{
    if (message.size() > (std::numeric_limits<ULONG>::max)())
    {
        throw std::runtime_error("message is too large for SHA-384");
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA384_ALGORITHM, nullptr, 0) != 0)
    {
        throw std::runtime_error("failed to open the Windows SHA-384 provider");
    }
    std::array<uint8_t, 48> digest{};
    const auto status = BCryptHash(
        algorithm,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(const_cast<char *>(message.data())),
        static_cast<ULONG>(message.size()),
        digest.data(),
        static_cast<ULONG>(digest.size())
    );
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status != 0)
    {
        throw std::runtime_error("Windows SHA-384 hashing failed");
    }
    return digest;
}

std::string signature_prefix(const std::vector<uint8_t> &signature)
{
    if (signature.size() < 32)
    {
        throw std::runtime_error("P-384 signature is too short");
    }
    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (size_t index = 0; index < 32; ++index)
    {
        encoded << std::setw(2) << static_cast<unsigned int>(signature[index]);
    }
    return encoded.str();
}

void run(const Options &options)
{
    auto partition = open_partition(options.endpoint);
    auto session = open_session(partition.get());
    for (size_t index = 0; index < options.count; ++index)
    {
        Key private_key;
        Key public_key;
        generate_key_pair(session.get(), private_key, public_key);
        auto digest = sha384("TSRA TCP ECC P-384 loop iteration " + std::to_string(index + 1));
        tsra_buffer data{ digest.data(), static_cast<uint32_t>(digest.size()) };
        tsra_algo algorithm{};
        algorithm.id = TSRA_ALGO_ID_ECDSA;
        tsra_buffer output{};
        const auto status = tsra_crypt_sign(&algorithm, private_key.get(), &data, &output);
        if (status != TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            check_status(status, "signature size");
        }
        if (output.len == 0)
        {
            throw std::runtime_error("signature size is zero");
        }
        std::vector<uint8_t> signature(output.len);
        output.ptr = signature.data();
        check_status(tsra_crypt_sign(&algorithm, private_key.get(), &data, &output), "ECDSA sign");
        if (output.len > signature.size())
        {
            throw std::runtime_error("invalid signature length");
        }
        signature.resize(output.len);
        check_status(
            tsra_crypt_verify(&algorithm, public_key.get(), &data, &output),
            "ECDSA verify"
        );
        std::cout << "ECC P-384 " << index + 1 << "/" << options.count
                  << " succeeded: generated key, signed SHA-384 digest, verified signature="
                  << signature_prefix(signature) << '\n';
    }
    std::cout << "Completed " << options.count << " iteration(s) over " << options.endpoint << '\n';
}
} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string(argv[1]) == "--help")
    {
        std::cout << "Usage: tsra_api_sock_ecc384_loop_cpp [ENDPOINT] [COUNT]\n"
                  << "Defaults: tcp://127.0.0.1:1234 and one iteration\n"
                  << "Use only a disposable test partition; this rotates the CO PSK.\n";
        return EXIT_SUCCESS;
    }
    try
    {
        run(parse_args(argc, argv));
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}