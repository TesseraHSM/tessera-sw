# C++ P-384 Loop over TCP on Windows

This is the native Windows C++ counterpart of the
[Rust TCP ECC example](../api_sock_ecc384_loop/README.md). It uses only the public
C API declared in the SDK's `tsra_api.h` for TSRA operations. No internal DDI
headers, direct socket calls, or test helper libraries are used.

Windows CNG supplies local SHA-384 hashing through `bcrypt.lib`, following the
repository's Windows C++ test conventions. The example does not need a separate
OpenSSL C++ dependency. The native SDK retains its normal build dependencies.

## Platform Support

This C++ implementation is currently **Windows-only**. In addition to CNG hashing,
it uses Windows environment APIs and UTF-16 partition paths. The shared TCP
transport works on Windows and Linux, but that does not make these Windows API
calls portable.

For Linux, use the [Rust TCP ECC example](../api_sock_ecc384_loop/README.md).
Porting this C++ example would require platform-specific hashing, environment
configuration, and path handling; changing the endpoint alone is not sufficient.

## Safety

Use only a disposable test partition. Like the Rust example, this program
rotates the default Crypto Officer (CO) PSK to `0xA5` repeated for
`TSRA_PSK_LEN` bytes, a publicly known test value. Later runs reconnect using
that value. Do not use a production partition or one containing valuable data.

All server connections share partition state. Keep the unauthenticated,
unencrypted test server bound to loopback and coordinate other clients.
Only public signature bytes are printed; keys and PSKs are never logged.

## Build

Use an **x64 Native Tools Command Prompt** or **Developer PowerShell for Visual
Studio**, with the MSVC C++ compiler and Windows SDK installed. Run all commands
from the repository root. No Linux, WSL, or VSOCK driver is required.

Restore the repository's development tools and build the native SDK with the
socket backend:

```powershell
cargo xtask precheck --setup
cargo build -p tsra_api_native --features tsra_api/sock
```

Compile the standalone C++17 example:

```powershell
cl /nologo /std:c++17 /EHsc /W4 /WX /DNOMINMAX /DWIN32_LEAN_AND_MEAN /Iapi/native/include examples/sock/api_sock_ecc384_loop_cpp/main.cpp /Fotarget/debug/tsra_api_sock_ecc384_loop_cpp.obj /Fetarget/debug/tsra_api_sock_ecc384_loop_cpp.exe /link /LIBPATH:target/debug tsra_api_native.dll.lib bcrypt.lib
```

The executable is placed beside `tsra_api_native.dll` so Windows can load the
SDK without changing `PATH`. Use the x64 compiler to match the native SDK build.
Rebuild the DLL with the socket feature if other Cargo commands have rebuilt it
with the hardware, mock, or emulator backend.

## Run

In the first PowerShell terminal, start the existing Windows TCP emulator server:

```powershell
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234
```

Wait for its listening message. In a second terminal, run five iterations:

```powershell
.\target\debug\tsra_api_sock_ecc384_loop_cpp.exe tcp://127.0.0.1:1234 5
```

Both arguments are optional. The defaults are `tcp://127.0.0.1:1234` and one
iteration. `COUNT` must be a positive integer. Use `--help` for a summary.
If the port is occupied, choose the same alternative port for server and client.

## Public API Flow

1. Configure `TSRA_DDI_SOCK` before making SDK calls.
2. Discover partitions with `tsra_part_get_list`, `tsra_part_get_count`, and
   `tsra_part_get_info`; preserve the returned UTF-16 path and select its maximum
   supported API revision.
3. Open the matching TCP partition with `tsra_part_open`.
4. Open an authenticated V2 CO session with `tsra_sess_ex_open`, then rotate
   the default PSK using `tsra_sess_ex_psk_change` or reconnect with the test PSK.
5. On each iteration, generate a session-scoped P-384 key pair using
   `tsra_key_gen_pair`, hash the message with CNG SHA-384, sign the digest using
   `tsra_crypt_sign`, and verify it using `tsra_crypt_verify`.
6. Release keys, the session, the partition, and the discovery list through
   RAII wrappers around their public cleanup functions.

The program exits with a nonzero status on invalid arguments or operation
failure. Successful iterations print a 32-byte public signature prefix.
Running it twice against the same server also exercises reconnecting with the
rotated PSK. Restarting the emulator server discards its state.

This example calls the public C API locally. The SDK's internal socket backend
talks to the DDI server; it is not an API-level RPC client. See the
[TCP socket guide](../api_sock_get_api_rev/README.md) for transport details.