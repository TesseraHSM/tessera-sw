// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Panic and CPU-exception handlers, and the FIPS error state, for the Uno
//! HSM firmware.
//!
//! Installs the firmware's single `#[panic_handler]` plus overrides for the
//! ARMv7-M `HardFault` and `DefaultHandler` exceptions. The goal is fault
//! *visibility*: the default `cortex-m-rt` HardFault handler is a silent
//! infinite loop, so a bus fault (for example, a stray write to a read-only
//! peripheral register) escalates to HardFault and hangs the core with no
//! output. These handlers instead dump the fault cause — decoded `CFSR`
//! bits, the faulting address (`BFAR`/`MMFAR`), the stacked register frame,
//! and `MSP` — so a fault is diagnosable from the serial log.
//!
//! # Output via the tracing facade
//!
//! Diagnostics are emitted through `tsra_fw_hsm_core_tracing`, the same
//! facade the rest of the firmware uses, rather than a bespoke sink. This
//! keeps faults on one logging path: they share the backend and formatting
//! with every other trace.
//!
//! The handlers log with `error!`, so a build with debug-log output also
//! records their lines in the debug log. Three kinds of line stay text only
//! (`error_text!`), because no record holds them: the panic message, the
//! exception frame, and the stack dump. No frame register is recorded on its
//! own line either: the crash dump keeps the PC and LR.
//!
//! The panic, HardFault, and explicit-crash handlers log after they save the
//! crash dump. A HardFault can be an escalated bus error in GSRAM, where the
//! log ring is, so writing a record can fault again; logging last keeps the
//! dump safe. Only `halt` follows these records, so they need no `dmb`. The
//! FIPS error-state paths log first, and then run `dmb`, before they save a
//! crash dump, notify the peer core, or set Mailbox0's error bit: those
//! writes lead the SP to drain the ring, so the record's `tail` write must
//! come first. For the same reason, the panic, HardFault, and explicit-crash
//! handlers run `dmb` before they notify the peer core, so a record written
//! before the crash, such as the pre-operational self-test's, comes first.
//!
//! Each handler logs at error level with an exception-specific `HsmError`
//! code — [`HsmError::Panic`], [`HsmError::HardFault`],
//! [`HsmError::UnexpectedException`], or [`HsmError::ExplicitCrash`] — so
//! fault output is greppable by code
//! and exception type. An error record holds one value next to the code, so
//! a line with more values splits into several error records. The
//! `trace-uart` / `trace-semihosting` features select `level-info`, which
//! compiles `error!` and `error_text!` in.
//!
//! # FIPS error state
//!
//! The PAL calls [`enter_error_state`] when a key pair that the module
//! generated, or the partition's unwrapping key, fails its pairwise
//! consistency test. It sets Mailbox0's error bit and halts through the same
//! `halt` as the handlers. Unlike the panic and HardFault handlers, it doesn't
//! save a crash dump or notify the peer core itself. The SP does both when it
//! enters its own FIPS error state: it fires TCON wakeup1 at every core, so
//! this core saves an `OtherCore` dump through the `tcon_wakeup1` receiver,
//! and then the SP resets the device.
//!
//! # Linking
//!
//! The panic and exception symbols only take effect if this crate is part
//! of the final binary's dependency graph. The application forces that with
//! `use tsra_fw_uno_fault as _;` (the `panic-halt` pattern).
//!
//! # Scope
//!
//! HardFault and Panic are full crash-recovery participants: besides
//! reporting the fault, they capture a persistent crash dump (into the
//! reserved HSM DTCM slot via [`tsra_fw_uno_crashdump`]) and notify the
//! peer core over TCON wakeup1. The same sequence is exposed deliberately as
//! [`explicit_crash`], a public entry point, which the DDI
//! `TriggerCrash` test hook uses to inject a crash that stays
//! distinguishable from a real panic in the dump. This crate also installs
//! the **`tcon_wakeup1` receiver** — a real NVIC-vectored assembly
//! trampoline (`drivers/pac` `__INTERRUPTS[89]`) that captures *this* core's
//! dump when a peer core signals a crash. The remaining exception handlers
//! (`MemManagement` and the peripheral-error ISRs) are wired in later units
//! of the crash-recovery port.

#![no_std]
#![allow(unsafe_code)]

mod decode;

use core::arch::global_asm;

use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
#[cfg(not(feature = "semihosting"))]
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tsra_fw_hsm_core_tracing::error;
#[cfg(not(feature = "semihosting"))]
use tsra_fw_static_ref::StaticRef;
use tsra_fw_uno_crashdump::crash_format::CpuRegisterContext;
use tsra_fw_uno_crashdump::crashdump_save;
use tsra_fw_uno_crashdump::crashdump_save_fmt;
use tsra_fw_uno_crashdump::failure_code::FailureCode;
use tsra_fw_uno_drivers_nvic::Nvic;
use tsra_fw_uno_drivers_tcon::Tcon;
use tsra_fw_uno_error::HsmError;
use tsra_fw_uno_pac::Interrupt;
use tsra_fw_uno_reg_cortex_m::scb::regs::ScbRegs;
use tsra_fw_uno_reg_cortex_m::scb::CFSR;
use tsra_fw_uno_reg_cortex_m::scb::HFSR;
use tsra_fw_uno_reg_cortex_m::scb::SCB_BASE;
#[cfg(not(feature = "semihosting"))]
use tsra_fw_uno_reg_soc::sys_mbx::regs::SysMbxRegs;
#[cfg(not(feature = "semihosting"))]
use tsra_fw_uno_reg_soc::sys_mbx::S2H_MBX_INSTS;
#[cfg(not(feature = "semihosting"))]
use tsra_fw_uno_reg_soc::sys_mbx::SYS_MBX_BASE;
use tsra_fw_uno_trace::error_text;

/// Mailbox0, which the SP watches for this core's error interrupt.
#[cfg(not(feature = "semihosting"))]
// SAFETY: `SYS_MBX_BASE` is the fixed MMIO address of Mailbox0, which is
// always mapped on Uno silicon.
const SYS_MBX: StaticRef<SysMbxRegs> = unsafe { StaticRef::new(SYS_MBX_BASE as *const SysMbxRegs) };

/// Borrow the System Control Block MMIO register block.
///
/// # Safety
///
/// `SCB_BASE` is a fixed architectural address that is always mapped on
/// ARMv7-M, so the dereference is sound. Called only from fault context
/// where the firmware is already halting, so aliasing is not a concern.
#[inline(always)]
fn scb() -> &'static ScbRegs {
    // SAFETY: SCB_BASE is architecturally mapped and aligned; fault handling only reads registers.
    unsafe { &*(SCB_BASE as *const ScbRegs) }
}

/// Terminate the firmware after a fault has been reported or the FIPS error
/// state entered.
///
/// On emulator builds (`semihosting`) this issues `SYS_EXIT(-1)` so the
/// host stops; on silicon it spins forever (the core is already wedged).
fn halt() -> ! {
    #[cfg(feature = "semihosting")]
    // Semihosting SYS_EXIT status -1 (failure).
    tsra_fw_uno_drivers_semihosting::sys_exit(u32::MAX);

    loop {
        cortex_m::asm::nop();
    }
}

/// Logs the failed periodic self-test, saves a crash dump, notifies the peer,
/// and enters the FIPS error state. The log carries the test and the error;
/// the dump tail preserves the test and engine identifiers.
pub fn enter_self_test_error_state(test: u32, engine: u32, reason: HsmError) -> ! {
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    // Log before the peer notification and the error bit, which lead the SP
    // to drain the ring and reset the device.
    error!("selftest", reason, "periodic self-test {} failed", test);
    // Order the record's `tail` write before the writes below, which lead
    // the SP to drain the ring.
    cortex_m::asm::dmb();
    crashdump_save_fmt(
        &capture_register_context(),
        FailureCode::ExplicitFailure,
        format_args!(
            "Self-test {test}, engine {engine}, error {:#x}",
            u32::from(reason)
        ),
    );
    Tcon::fire_wakeup_timer1();
    fips_halt()
}

/// Reports a crypto or IO timeout without releasing any active DMA buffers.
/// The log carries the error; the dump tail carries `detail`.
pub fn enter_crypto_timeout_error_state(detail: &'static str) -> ! {
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    // Log before the peer notification and the error bit, which lead the SP
    // to drain the ring and reset the device.
    error!("fips", HsmError::CryptoTimeout, "crypto command timed out");
    // Order the record's `tail` write before the writes below, which lead
    // the SP to drain the ring.
    cortex_m::asm::dmb();
    crashdump_save(
        &capture_register_context(),
        FailureCode::ExplicitFailure,
        Some(detail),
    );
    Tcon::fire_wakeup_timer1();
    fips_halt()
}

/// Capture the calling core's `sp` and `pc` for a crash dump.
///
/// Used by the *software*-initiated crash paths ([`panic`] and
/// [`explicit_crash`]) which, unlike a hardware exception, have no stacked
/// [`ExceptionFrame`] to recover the faulting context from.
///
/// `MSP` and `PC` are special registers that the compiler cannot allocate,
/// so reading them is well defined. `lr` is deliberately *not* read: it is
/// call-clobbered, so once the prologue has spilled it the compiler is free
/// to reuse it as scratch, and in [`panic`] it does — `lr` holds the
/// constant `1` for the wakeup-timer write by the time the dump is taken.
/// It is left zero, like the general purpose registers, which are not
/// architecturally readable from safe Rust either.
#[inline(always)]
fn capture_register_context() -> CpuRegisterContext {
    CpuRegisterContext {
        sp: cortex_m::register::msp::read(),
        pc: cortex_m::register::pc::read(),
        ..Default::default()
    }
}

/// Deliberately crash this core, recording it as an *explicit* crash.
///
/// This is the software-initiated crash path: it performs the same peer
/// notification and dump capture as [`panic`], but records
/// [`FailureCode::ExplicitFailure`] instead of [`FailureCode::Panic`] so the
/// shared SP-side parser can distinguish a crash that was *asked for* (the
/// DDI `TriggerCrash` test action with `CrashType::Explicit`) from a genuine
/// Rust panic. Conflating the two would make the firmware's own panics
/// indistinguishable from injected ones in the crash log.
///
/// Lives here rather than in `tsra_fw_uno_crashdump` because this crate
/// already owns the crash *policy* — the [`Nvic`]/[`Tcon`] peer-notification
/// sequence and the private [`halt`] — while `crashdump` is a pure
/// serializer. This is the crate's first public item; it is reached from
/// `pal`'s `trigger_crash` test hook.
///
/// `additional_info` is appended to the dump's free-text tail, truncated to
/// the region's remaining capacity.
///
/// Never returns: the core is halted (or exited, under `semihosting`).
pub fn explicit_crash(additional_info: Option<&str>) -> ! {
    // Disable our own wakeup1 receiver before firing it at the peer core, so
    // the notification we are about to raise cannot recurse back into this
    // already-crashing core.
    Nvic::disable(Interrupt::TCON_WAKEUP1);

    // Order any record written before the crash ahead of the notification:
    // see the module docs.
    cortex_m::asm::dmb();
    // Notify the peer core of the crash.
    Tcon::fire_wakeup_timer1();

    crashdump_save(
        &capture_register_context(),
        FailureCode::ExplicitFailure,
        additional_info,
    );

    // Log only after the dump is saved: see the module docs.
    error!(
        "explicit_crash",
        HsmError::ExplicitCrash,
        "#### EXPLICIT CRASH ####"
    );

    halt();
}

/// Enters the FIPS error state. Never returns.
///
/// Called when a key pair that the module generated, or the partition's
/// unwrapping key, fails its pairwise consistency test (PCT). Logs, runs
/// `dmb`, then sets `ERR_BIT` in Mailbox0's `S2H_MBX_INSTS` register, then
/// halts. The SP turns that interrupt into its own FIPS error state, which
/// stops SP output, saves crash dumps, and resets the device. Emulator
/// builds (`semihosting`) skip the mailbox write and exit through
/// semihosting instead.
///
/// `reason` names the check that failed; the log carries it as the error
/// code.
//
// `reason` is unused when logging is off, as in a build of this crate alone;
// allow keeps that build warning-free.
#[allow(unused_variables)]
#[cold]
#[inline(never)]
pub fn enter_error_state(reason: HsmError) -> ! {
    error!("fips", reason, "#### FIPS error state ####");
    // Order the record's `tail` write before `ERR_BIT`, which leads the SP
    // to drain the ring.
    cortex_m::asm::dmb();
    fips_halt()
}

/// Sets `ERR_BIT` in Mailbox0's `S2H_MBX_INSTS` register, then halts: the
/// last step of each path into the FIPS error state, after it logs. Emulator
/// builds (`semihosting`) skip the mailbox write.
fn fips_halt() -> ! {
    #[cfg(not(feature = "semihosting"))]
    SYS_MBX.s2h_mbx_insts.modify(S2H_MBX_INSTS::ERR_BIT::SET);
    halt();
}

/// Firmware panic handler.
///
/// Notifies the peer core of the crash over TCON wakeup1, captures a
/// persistent crash dump, and then reports the panic through the tracing
/// facade before halting.
///
/// # Why the dump carries real registers, not the panic site
///
/// The reference handler overloads the crash-dump register context
/// to carry [`core::panic::PanicInfo::location`] (`lr` = file-name pointer,
/// `pc` = line number). Uno does not: reading any `PanicInfo` field makes
/// every panic site in the image keep its own `&Location<'static>` alive,
/// which costs ~61 KiB of `.text` and does not fit the 512 KiB CP1 ITCM
/// budget that the firmware already nearly fills.
///
/// So the context carries the core's real `sp` and `pc` instead. That is
/// free, and it is also the better fit for the SP-side packet, which
/// declares these fields as a plain ARM register set (`struct
/// crash_dump_arm`). The dump identifies the crash as a panic via
/// [`FailureCode::Panic`], but it does not locate the panic *site*: `pc`
/// points into this handler, which the panic site reaches three frames down
/// through `core::panicking::panic_fmt`. On a `trace-uart` bring-up build
/// the `error_text!` below still prints the full panic message and source
/// location.
///
/// TODO: recover the panic site by unwinding the `r7` frame-pointer chain,
/// and/or capture it from `PanicInfo` once the ITCM budget allows — most
/// likely by relocating `.rodata` to GSRAM rather than by trimming code.
#[panic_handler]
// `info` is consumed only by `error_text!`, which compiles out unless a trace
// level is enabled. It is deliberately not read otherwise; see above.
#[allow(unused_variables)]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // Disable our own wakeup1 receiver before firing it at the peer core, so
    // the notification we are about to raise cannot recurse back into this
    // already-crashing core.
    Nvic::disable(Interrupt::TCON_WAKEUP1);

    // Order any record written before the crash ahead of the notification:
    // see the module docs.
    cortex_m::asm::dmb();
    // Notify the peer core of the crash.
    Tcon::fire_wakeup_timer1();

    crashdump_save(&capture_register_context(), FailureCode::Panic, None);

    // Log only after the dump is saved: see the module docs.
    error!("panic", HsmError::Panic, "#### PANIC ####");
    error_text!("panic", HsmError::Panic, "{}", info);

    halt();
}

/// HardFault exception handler.
///
/// Reads the SCB fault-status registers, classifies the fault, and dumps:
/// decoded `CFSR` bits, the faulting address when valid, the stacked
/// [`ExceptionFrame`] (R0-R3, R12, LR, PC, xPSR), and `MSP`. A stack
/// overflow (`HFSR.FORCED` + `CFSR.MSTKERR`/`STKERR`) is reported specially
/// because exception stacking failed and the frame is unreliable.
///
/// After it notifies the peer core over TCON wakeup1 and captures a
/// persistent crash dump (mirroring the reference handler), it reports the
/// fault and halts.
///
/// # Safety
///
/// Required to be an `unsafe fn` by `cortex-m-rt`. Invoked only by the
/// hardware exception mechanism on a HardFault and must never be called
/// directly; it reads fixed architectural SCB registers and the
/// hardware-supplied exception frame, then halts.
//
// Some register values below are used only by log calls, so they're unused
// when logging is off, as in a build of this crate alone; allow keeps that
// build warning-free. Persistent crash capture remains active.
#[allow(unused_variables)]
#[exception]
unsafe fn HardFault(ef: &ExceptionFrame) -> ! {
    let scb = scb();
    let cfsr = scb.cfsr.get();
    let hfsr = scb.hfsr.get();
    let msp = cortex_m::register::msp::read();

    let forced = scb.hfsr.is_set(HFSR::FORCED);
    // Exception-entry stacking can fail via either a MemManage fault
    // (MSTKERR, e.g. an MPU stack-guard hit on overflow) or a BusFault
    // (STKERR); both escalate to HardFault and leave the pushed register
    // frame unreliable.
    let mstkerr = scb.cfsr.is_set(CFSR::MSTKERR);
    let stkerr = scb.cfsr.is_set(CFSR::STKERR);

    // ---- Crash capture + cross-core notify -------------------------------
    // Mirrors the reference `exception_handlers::HardFault`.
    // Classification uses the reference's FORCED+MSTKERR predicate so the
    // shared SP parser records the same `failure_code`; note the diagnostic
    // logging below intentionally treats the broader FORCED+(MSTKERR|STKERR)
    // as an unreliable-frame overflow for operator visibility.
    let failure_code = if forced && mstkerr {
        FailureCode::MemoryFault
    } else {
        FailureCode::HardFault
    };

    // Disable our own wakeup1 receiver before firing it at the peer core, so
    // the notification cannot recurse back into this already-crashing core.
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    // Order any record written before the crash ahead of the notification:
    // see the module docs.
    cortex_m::asm::dmb();
    Tcon::fire_wakeup_timer1();

    let context = if forced && (mstkerr || stkerr) {
        // Exception stacking failed: the pushed frame is unreliable, so record
        // MSP (the approximate stack location at fault) instead.
        CpuRegisterContext {
            sp: msp,
            ..Default::default()
        }
    } else {
        // The `sp` inside the frame is post-stacking; the real SP at the fault
        // is the frame address plus the frame size. uno targets soft-float
        // (`thumbv7em-none-eabi`, FPU disabled), so the hardware always pushes
        // the basic 32-byte frame — `ef + size_of::<ExceptionFrame>()` is exact.
        let mut ctx = CpuRegisterContext::from_exception_frame(ef);
        ctx.sp = ef as *const _ as u32 + core::mem::size_of::<ExceptionFrame>() as u32;
        ctx
    };
    crashdump_save(&context, failure_code, None);

    // Log only after the dump is saved: see the module docs.
    error!("fault", HsmError::HardFault, "#### HardFault ####");

    if forced && (mstkerr || stkerr) {
        // Exception-entry stacking failed and escalated to HardFault: the
        // CPU could not push {R0-R3,R12,LR,PC,xPSR}, so `ef` is garbage. The
        // faulting PC/LR are unrecoverable on ARMv7-M; only MSP locates
        // where the stack was when it overran its guard region.
        error!(
            "fault",
            HsmError::HardFault,
            "cause: stack overflow (exception frame unreliable)"
        );
        error!(
            "fault",
            HsmError::HardFault,
            "stack overflow: MSP={:#010x}",
            msp
        );
        error!(
            "fault",
            HsmError::HardFault,
            "stack overflow: CFSR={:#010x}",
            cfsr
        );
        error!(
            "fault",
            HsmError::HardFault,
            "stack overflow: HFSR={:#010x}",
            hfsr
        );
    } else {
        decode::report_cfsr(scb, HsmError::HardFault);

        if scb.cfsr.is_set(CFSR::BFARVALID) {
            error!(
                "fault",
                HsmError::HardFault,
                "BFAR={:#010x}  (faulting bus address)",
                scb.bfar.get()
            );
        }
        if scb.cfsr.is_set(CFSR::MMARVALID) {
            error!(
                "fault",
                HsmError::HardFault,
                "MMFAR={:#010x} (faulting memory address)",
                scb.mmfar.get()
            );
        }

        error!(
            "fault",
            HsmError::HardFault,
            "HardFault: CFSR={:#010x}",
            cfsr
        );
        error!(
            "fault",
            HsmError::HardFault,
            "HardFault: HFSR={:#010x}",
            hfsr
        );
        error!("fault", HsmError::HardFault, "HardFault: MSP={:#010x}", msp);
        // The frame prints as text only, and none of its registers is
        // recorded: the general-purpose registers, the LR included, can hold
        // data words, and the xPSR's condition flags come from data. The
        // crash dump, saved above, keeps the PC and LR.
        error_text!("fault", HsmError::HardFault, "frame: {:#?}", ef);

        #[cfg(feature = "fault-stackdump")]
        // SAFETY: The development-only dump intentionally probes the faulting stack before halting.
        unsafe {
            stack_dump(msp);
        }
    }

    halt();
}

// tcon wakeup1 receiver ISR.
//
// This is the cross-core crash *receiver*: a peer core that faults arms TCON
// wakeup1 (see the `fire_wakeup_timer1` calls in the panic / HardFault
// handlers above), which raises IRQ89 on this core. The vector has to preempt
// a core that may be spinning or halted, so it is a real NVIC-vectored entry
// (`drivers/pac` `__INTERRUPTS[89]`) rather than a cooperatively-polled
// `WAKE_TABLE` driver.
//
// Implemented as an assembly trampoline (mirroring the reference
// `tcon_wakeup1_irq`) so it can capture the *interrupted* code's stack frame:
// EXC_RETURN bit 2 selects which stack (MSP/PSP) was active at preemption, and
// that stack pointer — the base of the hardware-stacked exception frame — is
// passed to `collect_crash_dump_tcon_irq` in `r0`.
global_asm!(
    ".global TCON_WAKEUP1
     .type TCON_WAKEUP1,%function
     .thumb_func
     .cfi_startproc
     TCON_WAKEUP1:",
    "mov r0, lr
     movs r1, #4
     tst r0, r1
     bne 0f
     mrs r0, MSP
     b collect_crash_dump_tcon_irq
     0:
     mrs r0, PSP
     b collect_crash_dump_tcon_irq",
    ".cfi_endproc
     .size TCON_WAKEUP1, . - TCON_WAKEUP1",
);

/// Collect a crash dump on receipt of a peer core's TCON wakeup1
/// notification, then halt.
///
/// Tail-called from the `TCON_WAKEUP1` assembly trampoline with `ef` pointing
/// at the exception frame stacked on whichever stack (MSP/PSP) was active when
/// the notification preempted this core. Disarms the wakeup timer and the IRQ
/// (so the notification cannot re-fire), records the interrupted context under
/// [`FailureCode::OtherCore`], and halts.
///
/// # ABI
///
/// `#[no_mangle]` + AAPCS: the single `&ExceptionFrame` argument arrives in
/// `r0`, matching the `b collect_crash_dump_tcon_irq` tail-call from the
/// trampoline. Must never be called from Rust directly.
#[allow(dead_code)]
#[no_mangle]
extern "C" fn collect_crash_dump_tcon_irq(ef: &ExceptionFrame) -> ! {
    // Disarm the wakeup timer and our own IRQ line so the peer's notification
    // cannot re-fire while (or after) we capture the dump.
    Tcon::disable_wakeup_timer1();
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    Nvic::unpend(Interrupt::TCON_WAKEUP1);

    // The `sp` inside the stacked frame is post-stacking; the real SP at
    // preemption is the frame address plus the frame size. uno targets
    // soft-float (`thumbv7em-none-eabi`, FPU disabled), so the hardware always
    // pushes the basic 32-byte frame — `ef + size_of::<ExceptionFrame>()` is
    // exact.
    let mut context = CpuRegisterContext::from_exception_frame(ef);
    context.sp = ef as *const _ as u32 + core::mem::size_of::<ExceptionFrame>() as u32;
    crashdump_save(&context, FailureCode::OtherCore, None);

    halt();
}

/// Catch-all handler for any exception/interrupt without a dedicated
/// handler. Reports the offending exception number so an unexpected or
/// spurious interrupt is no longer silent, then halts.
///
/// # Safety
///
/// Required to be an `unsafe fn` by `cortex-m-rt`. Invoked only by the
/// hardware exception mechanism for an otherwise-unhandled exception/IRQ
/// and must never be called directly.
//
// `irqn` is unused when logging is off, as in a build of this crate alone;
// allow keeps that build warning-free.
#[allow(unused_variables)]
#[exception]
unsafe fn DefaultHandler(irqn: i16) -> ! {
    // A record can't hold an `i16`, so log the exception number, which is
    // `irqn + 16` and never negative.
    error!(
        "fault",
        HsmError::UnexpectedException,
        "#### Unexpected exception {} ####",
        (i32::from(irqn) + 16) as u32
    );
    halt();
}

/// Dump 32 words of raw stack memory (four per line) starting at `sp`.
///
/// Development aid behind the `fault-stackdump` feature — useful for
/// eyeballing return addresses and locals near the fault, at the cost of
/// reading memory that may extend past the live stack.
///
/// # Safety
///
/// Performs volatile reads of arbitrary stack addresses; the range may run
/// past valid RAM. Intended for debug builds on hardware only.
//
// Reads are consumed only by `error_text!`, which compiles out unless a trace
// level is enabled; allow keeps a `fault-stackdump`-without-trace build clean.
#[cfg(feature = "fault-stackdump")]
#[allow(unused_variables)]
unsafe fn stack_dump(sp: u32) {
    const ROWS: u32 = 8;
    // `read_volatile::<u32>` requires a 4-byte-aligned pointer; `sp` may be
    // corrupted or misaligned at the fault, so align the base down first to
    // avoid undefined behaviour while keeping the dump word-oriented.
    let base = sp & !0b11;
    error_text!("fault", HsmError::HardFault, "stack dump @ {:#010x}:", base);
    for row in 0..ROWS {
        let addr = base.wrapping_add(row * 16);
        let p = addr as *const u32;
        // SAFETY: This debug-only fault probe uses aligned addresses under the caller's contract.
        let (w0, w1, w2, w3) = unsafe {
            (
                core::ptr::read_volatile(p),
                core::ptr::read_volatile(p.add(1)),
                core::ptr::read_volatile(p.add(2)),
                core::ptr::read_volatile(p.add(3)),
            )
        };
        error_text!(
            "fault",
            HsmError::HardFault,
            "  {:#010x}: {:08x} {:08x} {:08x} {:08x}",
            addr,
            w0,
            w1,
            w2,
            w3
        );
    }
}
