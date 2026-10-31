// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for `StdHsm`'s shutdown/drain lifecycle.
//!
//! These build a real `StdHsm` (each in its own process, since only one
//! `StdHsm` may ever be built per process — see the `HSM` singleton doc
//! comment in `lib.rs`) and assert that shutdown actually completes in
//! bounded time. This is a regression test for the bug this crate's
//! shutdown protocol fixes: the Embassy executor thread previously never
//! stopped, hanging any process (e.g. a hypervisor) that waited for it
//! to exit.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;

use tsra_fw_hsm_std::test_hooks;
use tsra_fw_hsm_std::StdHsm;

const IO_PID: u8 = 1;

/// Build a minimal SQE with cmd_id and no DMA.
fn sqe(cmd_id: u16) -> [u32; 16] {
    let mut data = [0u32; 16];
    data[0] = (cmd_id as u32) << 16;
    data
}

/// Drives a handful of concurrent IOs through `hsm` so shutdown has
/// real in-flight work to drain, not just idle `poll_io`/`ipc_task`
/// loops.
async fn run_some_ios(hsm: &Arc<StdHsm>) {
    let _ = hsm.part_alloc(IO_PID, 1u128 << IO_PID).await;
    let _ = hsm.part_enable(IO_PID).await;

    let mut handles = Vec::new();
    for i in 0..16u16 {
        let hsm = Arc::clone(hsm);
        handles.push(tokio::spawn(async move {
            hsm.io(sqe(i), IO_PID, 0, 0).await.expect("io")
        }));
    }
    for h in handles {
        h.await.expect("io task panicked");
    }
}

/// `shutdown_async` must complete once in-flight IO drains, instead of
/// hanging forever waiting for the Embassy thread to stop.
///
/// Uses an HSM-owned tokio runtime (not an external one supplied via
/// `with_tokio`), so cancelling this future via `timeout` — if the
/// assertion below ever fires — stays within `shutdown_async`'s
/// documented safe-cancellation contract.
#[tokio::test]
async fn shutdown_async_completes_after_draining_in_flight_ios() {
    let hsm = Arc::new(StdHsm::new());
    run_some_ios(&hsm).await;

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));
    tokio::time::timeout(Duration::from_secs(10), hsm.shutdown_async())
        .await
        .expect("shutdown_async did not complete — Embassy thread hung");
}

/// The blocking `shutdown` must also complete once in-flight IO
/// drains, when called from a plain OS thread outside the tokio
/// runtime backing the HSM (its documented, non-deadlocking usage).
#[test]
fn shutdown_completes_after_draining_in_flight_ios() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));
    rt.block_on(run_some_ios(&hsm));

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        hsm.shutdown();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("shutdown did not complete — Embassy thread hung");

    drop(rt);
}

/// Regression test for the drain actually blocking on genuinely
/// in-flight work, not just on the submitter's own `io()` future having
/// returned: holds one IO inside the Embassy executor (past the point
/// its CQE reply has already reached the submitter, but before its
/// Embassy task reports itself done) via [`test_hooks`], confirms
/// `shutdown_async` does *not* complete while that hold is in effect,
/// then releases it and confirms `shutdown_async` completes promptly.
#[tokio::test]
async fn shutdown_async_waits_for_a_genuinely_in_flight_io_before_completing() {
    let hsm = Arc::new(StdHsm::new());
    let _ = hsm.part_alloc(IO_PID, 1u128 << IO_PID).await;
    let _ = hsm.part_enable(IO_PID).await;

    test_hooks::hold_next_io();
    hsm.io(sqe(0), IO_PID, 0, 0).await.expect("io");
    // The submitter-visible `io()` above has already completed (its CQE
    // reply was sent before the hold point), but the corresponding
    // Embassy task hasn't yet reported itself done — wait for it to
    // actually reach the hold before asserting on shutdown's behavior.
    test_hooks::wait_until_io_blocked().await;

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));
    let mut shutdown = tokio::spawn(hsm.shutdown_async());

    // Deterministic, not timing-dependent: the held task cannot report
    // itself done until `release_held_io` is called below, so this can
    // never flakily observe completion early.
    tokio::time::timeout(Duration::from_millis(200), &mut shutdown)
        .await
        .expect_err("shutdown_async completed while an IO was still genuinely in-flight");

    test_hooks::release_held_io();
    tokio::time::timeout(Duration::from_secs(10), shutdown)
        .await
        .expect("shutdown_async did not complete after the held IO was released")
        .expect("shutdown_async task panicked");
}

/// Same as [`shutdown_async_waits_for_a_genuinely_in_flight_io_before_completing`]
/// but for the blocking `shutdown()` path, called from a plain OS thread
/// outside the tokio runtime backing the HSM.
#[test]
fn shutdown_waits_for_a_genuinely_in_flight_io_before_completing() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));
    rt.block_on(async {
        let _ = hsm.part_alloc(IO_PID, 1u128 << IO_PID).await;
        let _ = hsm.part_enable(IO_PID).await;

        test_hooks::hold_next_io();
        hsm.io(sqe(0), IO_PID, 0, 0).await.expect("io");
        test_hooks::wait_until_io_blocked().await;
    });

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        hsm.shutdown();
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_millis(200))
        .expect_err("shutdown completed while an IO was still genuinely in-flight");

    test_hooks::release_held_io();
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("shutdown did not complete after the held IO was released");

    drop(rt);
}

/// Minimal, dependency-free "executor" that busy-polls a future, used only
/// to prove `shutdown_async` doesn't require its calling thread to already
/// be inside a Tokio runtime (unlike bare `tokio::task::spawn_blocking`,
/// which panics off-runtime).
fn block_on_bare_executor<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

/// `shutdown_async` is documented as executor-agnostic; it must not
/// require the thread polling it to already be inside a Tokio runtime.
/// Regression test for a bug where the fallback thread-join was
/// implemented via `tokio::task::spawn_blocking`, which panics unless
/// entered from within a Tokio context.
#[test]
fn shutdown_async_works_without_a_tokio_context_on_the_polling_thread() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));
    rt.block_on(run_some_ios(&hsm));

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Deliberately not inside any Tokio runtime on this thread.
        block_on_bare_executor(hsm.shutdown_async());
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("shutdown_async did not complete — needed a Tokio-context poller");

    drop(rt);
}
