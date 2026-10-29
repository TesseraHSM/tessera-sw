# Hosting TSRA API as a Socket Service

Status: design explanation only. The current example uses a DDI socket server;
it does not implement the API-level service described below.

## What It Means for a Service to Call tsra_api

`tsra_api` is a Rust library, not a server executable. Hosting it as a service
means creating an executable that links the library and accepts API requests
over TCP.

```text
User application
    |
    | API requests over TCP
    v
TSRA API service
    |
    | Normal, local Rust function calls
    v
tsra_api
    |
    +--> Windows HSM driver
    OR
    +--> In-process emulator
```

The service's request handlers call the existing public API locally. The
application uses a client library to send those requests to the service.

## Example: Opening a Partition

1. The application's client library sends an `OpenPartition` request.
2. The service receives it and calls the existing Rust API:

   ```rust
   HsmPartitionManager::open_partition(&device_path, revision)?;
   ```

3. The service stores the resulting partition object and returns an opaque
   remote handle to the client.
4. Subsequent requests refer to that handle for sessions, key generation,
   signing, and other operations.

The partition object stays inside the service process. A remote handle is an
identifier, not a pointer or a Rust object sent over the network. The same
ownership model is needed for sessions and keys.

## Where DDI Fits

DDI still exists internally because `tsra_api` uses it to reach its backend.
However, when the service uses the Windows driver or the in-process emulator
backend, there is no separate `ddi_sock_server` process to start.

Using the existing `sock` backend inside the service would still require a DDI
listener. To remove that separate dependency, the service must use its hardware
backend directly or host the emulator in its own process.

## Difference from the Current Example

| Current TCP Example | Proposed API Service |
|---|---|
| `tsra_api` runs in the user application. | `tsra_api` runs in the service. |
| TCP carries DDI commands. | TCP carries public API operations. |
| The server hosts the emulator below DDI. | The server owns API partitions, sessions, and keys. |
| The application owns its API objects. | The client refers to server-owned objects using remote handles. |

The current example's setup and commands are documented in [README.md](README.md).
Those commands start the DDI transport example, not the proposed API service.

## Exposing the Entire API

Linking `tsra_api` into an executable does not automatically make its functions
callable over TCP. Exposing the entire API requires defining remote operations
and providing a matching client library.

The service must translate requests into local API calls, serialize results and
errors, manage remote object lifetimes, and clean up client resources. It also
needs an appropriate authentication and access-control design before production
use. Rust objects, native pointers, and callbacks cannot simply be copied across
the TCP connection.