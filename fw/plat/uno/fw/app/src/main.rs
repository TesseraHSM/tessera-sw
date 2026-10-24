// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno firmware application entry point.
//!
//! Wires the HSM core to the Uno PAL via Embassy tasks, following
//! the same task architecture as the std PAL platform crate.
//!
//! # Task architecture
//!
//! ```text
//!  main ──► init PAL ──► spawn poll_io      (executor loop polls NVIC)
//!                            │
//!                        poll_io ──► iic.recv() ──► signal io_worker[slot]
//!                                                       │
//!                                                   HSM core pipeline:
//!                                                   SQE parse → in-DMA
//!                                                   → DDI dispatch
//!                                                   → out-DMA → CQE
//!                                                   → complete_io
//! ```
//!
//! - **`main`**: Runs the executor, polling the PAL's peripherals
//!   between its passes; its first task initialises the PAL (timer,
//!   IIC/OIC/GDMA channels) and spawns the IO receive loop.
//! - **`poll_io`** (single instance): Awaits IOs from the IIC driver
//!   and hands each one to the `io_worker` of its IO slot.
//! - **`io_worker`** (one per IO slot, 32): Owns its slot's IO for the
//!   IO's lifetime, delegating to the HSM core for SQE parsing, DMA, and
//!   CQE delivery, then waits for the slot's next IO.
//!
//! # Interrupt handling
//!
//! Peripheral interrupts (IIC, OIC, GDMA) are enabled at the source
//! (`irq_enable` register) so the hardware asserts the NVIC pending bit.
//! No ISR handlers are installed for these — [`main`] calls
//! [`UnoHsmPal::poll_once`] after every executor pass, which polls
//! `Nvic::is_pending()` and wakes the appropriate driver. The
//! SysTick exception is handled internally by the systick driver crate.

#![no_std]
#![no_main]

mod trampoline;

use tsra_fw_hsm_core::Hsm;
use tsra_fw_hsm_core_tracing::info;
use tsra_fw_hsm_pal_traits::*;
use tsra_fw_uno_drivers_profile as _;
use tsra_fw_uno_fault as _;
use tsra_fw_uno_pac as _;
use tsra_fw_uno_pal::BootPhase;
use tsra_fw_uno_pal::UnoHsmIo;
use tsra_fw_uno_pal::UnoHsmPal;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;

// Placeholder so the linker emits a non-empty `.data` section.
//
// The 1SP bootloader that loads this image requires every loadable
// section to be at least 16 bytes long and a multiple of 16 bytes
// (it copies sections in 16-byte units during image staging). Until
// the firmware accumulates real mutable static state in `.data`,
// the section would otherwise be 0 bytes and the bootloader would
// reject the image. Once any genuine `.data` content lands and the
// section is naturally >= 16 bytes (and a multiple of 16 bytes in
// size), this dummy can be removed.
#[used]
#[unsafe(link_section = ".data")]
static mut DEFAULT_DATA: [u8; 16] = [0x1; 16];

/// Global HSM singleton, shared by all Embassy tasks.
///
/// Uses [`OnceLock`] for one-time initialisation in [`init`]. Subsequent
/// accesses via `HSM.get().await` are zero-cost after the first init.
static HSM: OnceLock<Hsm<UnoHsmPal>> = OnceLock::new();

/// Host IO slots, each served by its own [`io_worker`] task.
const IO_WORKERS: usize = 32;

/// Hands each received IO to the worker that owns its slot.
struct IoHandoff([Signal<NoopRawMutex, UnoHsmIo>; IO_WORKERS]);

// SAFETY: single-core Cortex-M7 with Embassy cooperative scheduling; only
// tasks, never an ISR, touch these signals.
unsafe impl Sync for IoHandoff {}

static IO_HANDOFF: IoHandoff = IoHandoff([const { Signal::new() }; IO_WORKERS]);

/// IO receive loop — runs forever as a single Embassy task.
///
/// Awaits [`HsmIoController::poll_io`] for the next inbound IO from
/// the IIC driver and hands it to the [`io_worker`] that owns its slot.
/// A slot is not handed out again until its IO is dropped, by which time
/// the slot's worker is waiting for the next one. An IO from a slot with
/// no worker is dropped and the loop retries on the next iteration.
///
/// # Returns
/// Never returns (`!`). This is a permanent receive-and-dispatch loop.
///
/// # Side Effects
/// - Continuously drains inbound IO work from PAL.
/// - Wakes the worker of each received IO's slot.
#[embassy_executor::task]
async fn poll_io() -> ! {
    let pal = HSM.get().await.pal();
    loop {
        let Ok(io) = pal.poll_io().await else {
            continue;
        };

        if let Some(slot) = IO_HANDOFF.0.get(usize::from(io.index())) {
            slot.signal(io);
        }
    }
}

/// Processes the IOs of one slot, one at a time, each to completion.
///
/// Waits for [`poll_io`] to hand over the slot's next [`UnoHsmIo`], keeping
/// the underlying IO_SQ slot reserved until the completion DMA finishes.
/// Delegates SQE parsing, inbound/outbound DMA, DDI dispatch, and CQE
/// population to [`Hsm::handle_io`]. A long-lived worker per slot spares
/// each IO a task spawn, which must search the pool for a free task.
///
/// # Parameters
/// - `slot`: The hand-off of the slot this worker serves.
///
/// # Returns
/// Never returns (`!`).
///
/// # Side Effects
/// - Advances the HSM request pipeline for each IO of its slot.
/// - Triggers DMA activity and CQE completion for those IOs.
#[embassy_executor::task(pool_size = IO_WORKERS)]
async fn io_worker(slot: &'static Signal<NoopRawMutex, UnoHsmIo>) -> ! {
    let hsm = HSM.get().await;
    loop {
        let io = slot.wait().await;
        hsm.handle_io(io).await;
    }
}

/// Dedicated core-liveliness heartbeat task.
///
/// Refreshes the SP-polled `CORE_RUN_STATUS` slot on its own independent
/// 250 ms timer, decoupled from IPC traffic. As a standalone
/// task, this timer is never raced by IPC and fires as long as the
/// cooperative executor makes forward progress — which is exactly the
/// liveness condition the SP is meant to observe.
///
/// # Returns
/// Never returns (`!`).
#[embassy_executor::task]
async fn heartbeat() -> ! {
    let hsm = HSM.get().await;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(250)).await;
        hsm.pal().update_liveliness();
    }
}

/// IPC message/event receive loop — runs forever as a single
/// Embassy task. PAL handles boot handshake internally;
/// app spawns the [`io_worker`]s and [`poll_io`] once boot completes.
///
/// # Parameters
/// - `spawner`: Embassy task spawner used to start the IO tasks after boot.
///
/// # Returns
/// Never returns (`!`). This is a permanent IPC servicing loop.
///
/// # Side Effects
/// - Drains IPC traffic by repeatedly calling [`UnoHsmPal::poll_ipc`].
/// - Starts IO ingestion exactly once when PAL enters [`BootPhase::Running`].
#[embassy_executor::task]
async fn poll_ipc(spawner: Spawner) -> ! {
    let hsm = HSM.get().await;
    let mut booted = false;

    loop {
        hsm.pal().poll_ipc().await;
        if !booted && hsm.pal().boot_phase() == BootPhase::Running {
            booted = true;
            info!("app", "boot complete, spawning poll_io");
            for slot in &IO_HANDOFF.0 {
                if let Ok(token) = io_worker(slot) {
                    spawner.spawn(token);
                }
            }
            if let Ok(token) = poll_io() {
                spawner.spawn(token);
            }
        }
    }
}

/// Firmware initialisation, the executor's first task.
///
/// 1. Initialises the HSM singleton with a default [`UnoHsmPal`].
/// 2. Calls [`HsmPal::init`] — sets up SysTick, RNG, IPC, signals Done.
/// 3. Spawns [`poll_ipc`] which drives boot handshake + steady-state IPC,
///    and the [`heartbeat`].
///
/// Neither step 1 nor 2 awaits, so [`main`]'s peripheral polling, which
/// starts once the singleton is set, never sees an uninitialised PAL.
///
/// # Parameters
/// - `spawner`: Embassy task spawner used to start long-lived background tasks.
#[embassy_executor::task]
async fn init(spawner: Spawner) {
    info!("app", "Tessera Integrated HSM firmware starting up...");
    let hsm = HSM.get_or_init(|| Hsm::new(UnoHsmPal::default()));
    hsm.pal().init();

    if let Ok(token) = poll_ipc(spawner) {
        spawner.spawn(token);
    }
    if let Ok(token) = heartbeat() {
        spawner.spawn(token);
    }
}

/// Firmware entry point: runs the Embassy executor, and between its passes
/// polls the PAL's peripherals ([`UnoHsmPal::poll_once`]), waking the tasks
/// whose interrupts are pending or whose engines have finished.
///
/// That polling used to be a task of its own ([`HsmPal::run`]), which the
/// run queue -- last woken, first polled -- placed early in each pass: a
/// completion landing later in the pass went unseen until the next one, and
/// its task ran in the pass after that. Polled once each pass ends, a
/// completion is seen within the pass it lands in, and the tasks it wakes,
/// being woken last, run first in the next.
#[cortex_m_rt::entry]
fn main() -> ! {
    // `usize::MAX` is the pender context of Embassy's thread-mode executor,
    // for which the pender only signals an event. This loop never sleeps,
    // so it has no use for the event.
    let executor = embassy_executor::raw::Executor::new(usize::MAX as *mut ());
    let executor_ptr: *const embassy_executor::raw::Executor = &raw const executor;
    // SAFETY: `main` never returns, so the executor outlives every use.
    let executor: &'static embassy_executor::raw::Executor = unsafe { &*executor_ptr };
    let spawner = executor.spawner();
    if let Ok(token) = init(spawner) {
        spawner.spawn(token);
    }

    loop {
        // SAFETY: `poll` is only ever called here, so never reentrantly.
        unsafe { executor.poll() };
        if let Some(hsm) = HSM.try_get() {
            hsm.pal().poll_once();
        }
    }
}
