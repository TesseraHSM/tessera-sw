// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Borrowed DMA storage for an HSM command's request, response, and live inputs.

use crate::HsmDmaBuf;
use crate::HsmError;
use crate::HsmResult;

/// Borrowed storage for an HSM request and response in one DMA allocation.
///
/// The request occupies the initial `request_len` bytes. A response is
/// published from the same allocation's prefix. Handlers may reclaim request
/// storage only after its inputs are no longer live, or borrow disjoint regions
/// while producing output. Crypto scratch and the undo log remain independent.
///
/// No memory is allocated or copied by this wrapper. The per-IO
/// allocator retains ownership through DMA and completion, including teardown
/// scrubbing. Handlers must initialize every published byte and explicitly
/// zeroize secret inputs before reclaiming their regions.
pub struct HsmCmdBuf<'a> {
    buffer: &'a mut HsmDmaBuf,
    request_len: usize,
    response_capacity: usize,
}

impl<'a> HsmCmdBuf<'a> {
    /// Borrow an allocation and record the received and host destination lengths.
    pub fn new(
        buffer: &'a mut HsmDmaBuf,
        request_len: usize,
        response_capacity: usize,
    ) -> HsmResult<Self> {
        if request_len > buffer.len() {
            return Err(HsmError::InvalidArg);
        }
        Ok(Self {
            buffer,
            request_len,
            response_capacity,
        })
    }

    /// The original request length, excluding allocation capacity.
    pub fn request(&self) -> &HsmDmaBuf {
        &self.buffer[..self.request_len]
    }

    /// Mutable request access for in-place envelope decoding.
    pub fn request_mut(&mut self) -> &mut HsmDmaBuf {
        &mut self.buffer[..self.request_len]
    }

    /// Reclaim the allocation for encoding or explicitly supported in-place crypto.
    ///
    /// Existing input borrows must end before this exclusive borrow is available.
    pub fn buffer_mut(&mut self) -> &mut HsmDmaBuf {
        self.buffer
    }

    /// The host destination bound, independent of local live-input capacity.
    pub fn response_capacity(&self) -> usize {
        self.response_capacity
    }

    /// Encode directly into reclaimed exchange storage and validate its length.
    pub fn encode_response(
        &mut self,
        encode: impl FnOnce(&mut HsmDmaBuf) -> HsmResult<usize>,
    ) -> HsmResult<usize> {
        let len = encode(self.buffer)?;
        self.response(len)?;
        Ok(len)
    }

    /// Validate a response prefix against both local and host capacities.
    pub fn response(&self, len: usize) -> HsmResult<&HsmDmaBuf> {
        if len == 0 || len > self.buffer.len() || len > self.response_capacity {
            return Err(HsmError::TborBufferTooSmall);
        }
        Ok(&self.buffer[..len])
    }

    /// Validate completed output without modifying the backing storage.
    ///
    /// IO teardown performs final scrubbing after DMA, CQE completion, and
    /// the undo/commit walk.
    pub fn finish_response(&self, outcome: HsmResult<usize>) -> HsmResult<usize> {
        outcome.and_then(|len| self.response(len).map(|_| len))
    }
}
