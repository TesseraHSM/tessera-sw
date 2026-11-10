// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tsra_ddi_sock_proto::ProtoError;
use tsra_ddi_sock_proto::ResponseFrame;

use super::Connection;
use super::SocketHsm;

async fn write_response(
    stream: &mut UnixStream,
    response: &ResponseFrame,
) -> Result<(), ProtoError> {
    let body = response.encode()?;
    stream.write_u32_le(body.len() as u32).await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn serve_connection(mut stream: UnixStream, hsm: Arc<SocketHsm>) -> Result<(), String> {
    let connection = Connection::new(hsm);
    loop {
        let Some(request) = super::read_request_with_timeout(&mut stream).await? else {
            return Ok(());
        };
        let response =
            match tokio::time::timeout(super::CONNECTION_READ_TIMEOUT, connection.execute(request))
                .await
            {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(()),
            };
        tokio::time::timeout(
            super::CONNECTION_READ_TIMEOUT,
            write_response(&mut stream, &response),
        )
        .await
        .map_err(|_elapsed| "failed to write DDI response: timed out".to_string())?
        .map_err(|error| format!("failed to write DDI response: {error}"))?;
    }
}

async fn run_server(listener: UnixListener, hsm: Arc<SocketHsm>) -> Result<(), String> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept Unix socket connection: {error}"))?;
        let hsm = Arc::clone(&hsm);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, hsm).await {
                eprintln!("Unix socket client failed: {error}");
            }
        });
    }
}

/// Bound on the connect probe in [`remove_stale_socket`]: long enough to
/// distinguish "busy but alive" from "stale", short enough that a live
/// listener with a momentarily full accept backlog doesn't hang server
/// startup indefinitely.
const STALE_SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Acquires an exclusive, cross-process lock serializing the
/// stale-socket-check-and-bind sequence for `path`.
///
/// Two server instances racing to start on the same `path` could otherwise
/// both see [`remove_stale_socket`]'s connect probe refused (both sockets
/// look stale before either has bound), then both proceed to remove and
/// bind: whichever binds second would silently steal the endpoint out from
/// under the first. Holding this lock across the whole check-then-bind
/// sequence (released once this process has bound, or failed to) makes a
/// second racing instance's probe correctly observe the first's listener
/// as live instead of racing its removal.
fn lock_startup(path: &str) -> Result<std::fs::File, String> {
    let lock_path = format!("{path}.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|error| format!("failed to open startup lock {lock_path}: {error}"))?;
    file.lock()
        .map_err(|error| format!("failed to acquire startup lock {lock_path}: {error}"))?;
    Ok(file)
}

/// Removes a stale Unix socket left behind by a previous server instance
/// at `path`, so `UnixListener::bind` can reuse the path.
///
/// A plain `remove_file` here would be unsafe to call unconditionally: if
/// another server is already listening on `path`, unlinking it would let
/// this process silently steal the path out from under it while existing
/// clients keep talking to the original (now orphaned) listener; if
/// `path` names an unrelated regular file (e.g. a typo'd endpoint), it
/// would delete that file instead of failing loudly. Only remove the
/// entry when it's confirmed to be a socket that nothing is listening on.
/// Callers must hold [`lock_startup`]'s lock across this call and the
/// subsequent bind, so a concurrently starting instance can't race the
/// check against this process's own not-yet-bound listener.
async fn remove_stale_socket(path: &str) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to stat {path}: {error}")),
    };
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "refusing to remove {path}: exists and is not a Unix socket"
        ));
    }
    // Probe whether a server is still listening: a stale socket from a
    // crashed/previous run refuses the connection, while a live listener
    // accepts it. Bound the probe (via a non-blocking async connect) so a
    // live-but-busy listener times out loudly rather than hanging startup.
    match tokio::time::timeout(STALE_SOCKET_PROBE_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(_)) => Err(format!(
            "refusing to bind Unix listener at {path}: another server is already listening"
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
                .map_err(|error| format!("failed to remove stale Unix socket at {path}: {error}"))
        }
        Ok(Err(error)) => Err(format!(
            "failed to probe existing socket at {path}: {error}"
        )),
        Err(_elapsed) => Err(format!(
            "refusing to bind Unix listener at {path}: timed out probing existing socket; it may be a live but busy listener"
        )),
    }
}

pub(super) fn run(path: &str) -> Result<(), String> {
    let path = path.to_owned();
    super::run_with_hsm(|hsm| async move {
        // `File::lock` is a blocking syscall; run it on a blocking-pool
        // thread rather than stalling an async worker.
        let lock_path = path.clone();
        let _lock = tokio::task::spawn_blocking(move || lock_startup(&lock_path))
            .await
            .map_err(|error| format!("startup lock task panicked: {error}"))??;
        remove_stale_socket(&path).await?;
        let listener = UnixListener::bind(&path)
            .map_err(|error| format!("failed to bind Unix listener at {path}: {error}"))?;
        // Release the startup lock as soon as the bind succeeds: holding it
        // for the server's entire lifetime would make a second, racing
        // instance block forever in `lock_startup` instead of having its
        // `remove_stale_socket` probe correctly observe this process's now-
        // bound listener as live and fail fast.
        drop(_lock);
        super::init_partition(&hsm).await?;
        println!("TSRA DDI server listening on unix://{path}; partition 10");
        run_server(listener, hsm).await
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_sock::DdiSock;
    use tsra_ddi_tbor_types::TborGetCertChainInfoReq;

    use super::*;

    fn socket_path() -> std::path::PathBuf {
        let unique = format!(
            "ddi-sock-server-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("monotonic clock")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn remove_stale_socket_removes_an_unconnected_socket_file() {
        let path = socket_path();
        // Bind and then drop the listener without ever accepting: the path
        // still exists on disk as a socket file, but nothing is listening,
        // exactly like a stale socket left behind by a crashed server.
        {
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
            drop(listener);
        }
        assert!(path.exists());
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime
            .block_on(remove_stale_socket(path.to_str().expect("utf8 path")))
            .expect("removes stale socket");
        assert!(!path.exists());
    }

    #[test]
    fn remove_stale_socket_refuses_a_non_socket_file() {
        let path = socket_path();
        std::fs::write(&path, b"not a socket").expect("write regular file");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let result = runtime.block_on(remove_stale_socket(path.to_str().expect("utf8 path")));
        assert!(result.is_err());
        // The regular file must be left untouched.
        assert!(path.exists());
        std::fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn remove_stale_socket_refuses_a_live_listener() {
        let path = socket_path();
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let result = runtime.block_on(remove_stale_socket(path.to_str().expect("utf8 path")));
        assert!(result.is_err());
        // The live listener's path must be left untouched.
        assert!(path.exists());
        drop(listener);
        std::fs::remove_file(&path).ok();
    }

    /// Two server instances starting on the same endpoint must not be able
    /// to both pass the stale-socket check before either binds: the
    /// cross-process startup lock must serialize them. This directly
    /// exercises the locking primitive (`lock_startup`), since reliably
    /// forcing the underlying race in `remove_stale_socket` itself would
    /// require saturating a Unix listener's accept backlog, which isn't
    /// practical to do deterministically in a unit test.
    #[test]
    fn lock_startup_serializes_concurrent_acquires() {
        let path = socket_path();
        let path_str = path.to_str().expect("utf8 path").to_owned();
        let lock_path = format!("{path_str}.lock");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let path_for_thread = path_str.clone();
        let handle = std::thread::spawn(move || {
            let _lock = lock_startup(&path_for_thread).expect("first lock");
            ready_tx.send(()).expect("send ready");
            release_rx.recv().expect("release signal");
            // `_lock` is released here, on drop.
        });
        ready_rx.recv().expect("first lock acquired");

        // A second, independently opened handle on the same lock file must
        // observe `WouldBlock` while the first lock is held, rather than
        // blocking or silently succeeding. Asserting on elapsed wall-clock
        // time instead would be flaky: a descheduled first thread can make
        // the second acquire appear to wait less than expected even though
        // locking is correct.
        let probe = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .expect("open lock file for probe");
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));

        release_tx.send(()).expect("signal release");
        handle.join().expect("first lock thread");

        // Once the first lock is released, the same probe handle must be
        // able to acquire it, proving the two acquisitions were genuinely
        // serialized rather than independent no-ops.
        probe.try_lock().expect("second lock after release");
        std::fs::remove_file(&lock_path).ok();
    }

    #[test]
    fn roundtrips_a_request_over_a_unix_socket() {
        let _guard = crate::test_partition_lock();
        let hsm = crate::test_hsm();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let path = socket_path();
        runtime.block_on(async {
            let listener = UnixListener::bind(&path).expect("listener");
            let endpoint = path.to_str().expect("utf-8 path").to_owned();
            let serving = tokio::spawn(run_server(listener, Arc::clone(&hsm)));
            let client = tokio::task::spawn_blocking(move || {
                let device = DdiSock::default()
                    .open_dev(&endpoint)
                    .expect("unix socket device");
                device
                    .exec_op_tbor(&TborGetCertChainInfoReq::new(0), None, &mut None)
                    .expect("cert chain info roundtrip");
            });
            tokio::time::timeout(Duration::from_secs(30), client)
                .await
                .expect("client completes")
                .expect("client task");
            serving.abort();
        });
        std::fs::remove_file(&path).ok();
    }
}
