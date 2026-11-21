// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Configurable Fault Status Register (CFSR) decoding.
//!
//! Translates the bit fields of the ARMv7-M `CFSR` (MMFSR + BFSR + UFSR)
//! into human-readable lines so a HardFault report names the precise
//! fault cause instead of just a raw hex value. The bus/mem-fault address
//! registers (`BFAR`/`MMFAR`) are reported by the caller when the matching
//! `*VALID` bit is set.
//!
//! Output goes through the Uno trace crate's `error_text!`: text output
//! prints each line, and no build records it, because the crash dump keeps
//! `CFSR`.

use tock_registers::interfaces::Readable;
use tsra_fw_uno_error::HsmError;
use tsra_fw_uno_reg_cortex_m::scb::regs::ScbRegs;
use tsra_fw_uno_reg_cortex_m::scb::CFSR;
use tsra_fw_uno_trace::error_text;

/// Print one decoded line per set CFSR fault bit, grouped by fault unit.
///
/// Covers the MemManage (`MMFSR`), BusFault (`BFSR`) and UsageFault
/// (`UFSR`) sub-registers. Only set bits are printed; a clean register
/// produces no output.
// `err` is unused without text output; allow keeps that build warning-free.
#[allow(unused_variables)]
pub fn report_cfsr(scb: &ScbRegs, err: HsmError) {
    // MemManage faults (MMFSR, CFSR[7:0]).
    if scb.cfsr.is_set(CFSR::IACCVIOL) {
        error_text!(
            "fault",
            err,
            "  MemManage: IACCVIOL  instruction-fetch access violation"
        );
    }
    if scb.cfsr.is_set(CFSR::DACCVIOL) {
        error_text!("fault", err, "  MemManage: DACCVIOL  data access violation");
    }
    if scb.cfsr.is_set(CFSR::MUNSTKERR) {
        error_text!(
            "fault",
            err,
            "  MemManage: MUNSTKERR fault on exception return unstacking"
        );
    }
    if scb.cfsr.is_set(CFSR::MSTKERR) {
        error_text!(
            "fault",
            err,
            "  MemManage: MSTKERR   fault on exception entry stacking"
        );
    }
    if scb.cfsr.is_set(CFSR::MLSPERR) {
        error_text!(
            "fault",
            err,
            "  MemManage: MLSPERR   fault during FP lazy state preservation"
        );
    }

    // Bus faults (BFSR, CFSR[15:8]).
    if scb.cfsr.is_set(CFSR::IBUSERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  IBUSERR   instruction prefetch bus error"
        );
    }
    if scb.cfsr.is_set(CFSR::PRECISERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  PRECISERR precise data bus error (BFAR valid)"
        );
    }
    if scb.cfsr.is_set(CFSR::IMPRECISERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  IMPRECISERR imprecise data bus error (BFAR unreliable)"
        );
    }
    if scb.cfsr.is_set(CFSR::UNSTKERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  UNSTKERR  bus fault on exception return unstacking"
        );
    }
    if scb.cfsr.is_set(CFSR::STKERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  STKERR    bus fault on exception entry stacking"
        );
    }
    if scb.cfsr.is_set(CFSR::LSPERR) {
        error_text!(
            "fault",
            err,
            "  BusFault:  LSPERR    bus fault during FP lazy state preservation"
        );
    }

    // Usage faults (UFSR, CFSR[31:16]).
    if scb.cfsr.is_set(CFSR::UNDEFINSTR) {
        error_text!(
            "fault",
            err,
            "  UsageFault: UNDEFINSTR undefined instruction"
        );
    }
    if scb.cfsr.is_set(CFSR::INVSTATE) {
        error_text!(
            "fault",
            err,
            "  UsageFault: INVSTATE  invalid EPSR/Thumb state"
        );
    }
    if scb.cfsr.is_set(CFSR::INVPC) {
        error_text!(
            "fault",
            err,
            "  UsageFault: INVPC     invalid PC load (exception return)"
        );
    }
    if scb.cfsr.is_set(CFSR::NOCP) {
        error_text!(
            "fault",
            err,
            "  UsageFault: NOCP      coprocessor access denied/absent"
        );
    }
    if scb.cfsr.is_set(CFSR::UNALIGNED) {
        error_text!(
            "fault",
            err,
            "  UsageFault: UNALIGNED unaligned access trap"
        );
    }
    if scb.cfsr.is_set(CFSR::DIVBYZERO) {
        error_text!("fault", err, "  UsageFault: DIVBYZERO divide-by-zero trap");
    }
}
