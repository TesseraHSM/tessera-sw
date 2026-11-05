// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OIC driver configuration types.

/// Per-channel configuration for [`OicDriver::init`](super::OicDriver::init).
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    /// Controller index: 0 = Core0 (command path), 1 = fast path. Selects
    /// the register block at `OIC_BASE + controller * CONTROLLER_STRIDE`.
    pub controller: u8,

    /// Physical channel index (shared for OSQ and OCQ).
    pub channel: u8,

    /// Base address of the OSQ ring buffer (16B-aligned).
    pub osq_base: u32,

    /// Base address of the OCQ ring buffer (32B-aligned).
    pub ocq_base: u32,

    /// Address where HW writes the OCQ tail shadow (32B-aligned).
    pub ocq_tail_shadow: u32,

    /// Base address of the IO_CQ array in DTCM.
    pub io_cq_base: u32,

    /// Stride between IO_CQ entries in bytes (e.g. 16, or 64 for bulk).
    pub io_cq_size: u32,

    /// Base address of the IO_META sidecar array in DTCM.
    pub io_meta_base: u32,

    /// Enable interrupt for this channel during init.
    pub interrupt: bool,

    /// Return one inbound-queue credit with each completion, through the OSQ
    /// entry's `RX_CREDIT` field: hardware applies it atomically, unlike a
    /// firmware read-modify-write of the credit register, which can lose a
    /// concurrent hardware decrement.
    pub return_credit: bool,
}
