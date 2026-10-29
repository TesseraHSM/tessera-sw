// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAlloc`] implementation for the standard PAL.
//!
//! Per-IO bump allocator over the [`BufferPool`]'s pre-allocated
//! NonDma (`NONDMA_BUF_SIZE`) and Dma (`DMA_BUF_SIZE`) buffers.  One
//! watermark per (slot, heap) pair lives in the pool itself; the
//! allocator only advances them.
//!
//! ## Aliasing
//!
//! [`BufferPool`] exposes raw pointers + capacity (no whole-slab
//! `&mut` views).  Each bump allocation constructs a `&mut [u8]`
//! covering only the freshly allocated, disjoint range, so successive
//! allocations from the same `&self` never alias.
//!
//! ## Lifetime gotcha
//!
//! Allocations made *directly* on the PAL inside an
//! [`HsmAlloc::alloc_scoped`] / [`HsmAlloc::alloc_scoped_async`]
//! closure will be silently freed when the scope's watermark is
//! restored on drop.  Direct PAL allocations should be made before the
//! scope opens or after it closes.
//!
//! No atomics — single-threaded Embassy executor with cooperative
//! scheduling.

use core::cell::Cell;
use core::mem;
use core::ops::AsyncFnOnce;

use tsra_fw_hsm_pal_traits::*;

use crate::buf_pool::BufferPool;
use crate::buf_pool::DMA_BUF_SIZE;
use crate::buf_pool::NONDMA_BUF_SIZE;
use crate::StdHsmIo;
use crate::StdHsmPal;

// ── Heap identifiers (PAL-internal) ───────────────────────────────

#[derive(Copy, Clone)]
enum Heap {
    NonDma,
    Dma,
}

impl Heap {
    #[inline(always)]
    fn capacity(self) -> usize {
        match self {
            Heap::NonDma => NONDMA_BUF_SIZE,
            Heap::Dma => DMA_BUF_SIZE,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

#[inline(always)]
fn ptr_for(pool: &BufferPool, slot: u16, heap: Heap) -> *mut u8 {
    match heap {
        Heap::NonDma => pool.nondma_ptr(slot),
        Heap::Dma => pool.dma_ptr(slot),
    }
}

#[inline(always)]
fn mark_for(pool: &BufferPool, slot: u16, heap: Heap) -> &Cell<usize> {
    match heap {
        Heap::NonDma => pool.nondma_mark(slot),
        Heap::Dma => pool.dma_mark(slot),
    }
}

/// Bump-allocate `size` bytes with the given alignment from `(slot,
/// heap)`. Returns the new `&mut [u8]` view over the freshly
/// allocated region (disjoint from any prior allocation).
#[allow(clippy::needless_lifetimes, clippy::mut_from_ref)]
fn bump<'a>(
    pool: &'a BufferPool,
    slot: u16,
    heap: Heap,
    size: usize,
    align: usize,
) -> HsmResult<&'a mut [u8]> {
    let cap = heap.capacity();
    let mark_cell = mark_for(pool, slot, heap);
    let mark = mark_cell.get().min(cap);

    let base = ptr_for(pool, slot, heap) as usize;
    let aligned = (base + mark + align - 1) & !(align - 1);
    let start = aligned - base;
    let end = start.checked_add(size).ok_or(HsmError::NotEnoughSpace)?;

    if end > cap {
        return Err(HsmError::NotEnoughSpace);
    }

    mark_cell.set(end);
    let peak = match heap {
        Heap::NonDma => pool.nondma_peak(slot),
        Heap::Dma => pool.dma_peak(slot),
    };
    peak.set(peak.get().max(end));

    // SAFETY: the BufferPool gives the caller exclusive access to its slot's
    // raw pointer for the lifetime of the allocated IO. The bump watermark
    // ensures every returned slice covers a disjoint range, and the pool only
    // reuses the slot after the IO completes (which freezes any prior
    // borrows). The returned `&mut [u8]` therefore aliases nothing.
    let ptr = unsafe { ptr_for(pool, slot, heap).add(start) };
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, size) })
}

// ── Scoped allocator handle ───────────────────────────────────────

/// Scoped allocator handle for the standard PAL.
///
/// Snapshots both per-slot watermarks on construction and restores
/// them on drop, freeing every allocation made through the handle in
/// LIFO order.
pub struct StdScopedAlloc<'a> {
    pool: &'a BufferPool,
    slot: u16,
    nondma_mark: usize,
    dma_mark: usize,
}

impl HsmScopedAlloc for StdScopedAlloc<'_> {
    #[inline(always)]
    fn alloc(&self, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.pool, self.slot, Heap::NonDma, size, 4)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, value: T) -> HsmResult<&mut T> {
        let s = bump(
            self.pool,
            self.slot,
            Heap::NonDma,
            mem::size_of::<T>(),
            mem::align_of::<T>().max(1),
        )?;
        let ptr = s.as_mut_ptr().cast::<T>();
        // SAFETY: bump() reserved exactly size_of::<T>() bytes with
        // align_of::<T>() alignment. The pointer is non-null and writable.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, size: usize) -> HsmResult<&mut HsmDmaBuf> {
        let s = bump(self.pool, self.slot, Heap::Dma, size, 4)?;
        // SAFETY: the Dma heap is DMA-accessible by construction.
        Ok(unsafe { HsmDmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    fn dma_alloc_zeroed(&self, size: usize) -> HsmResult<&mut HsmDmaBuf> {
        let s = self.dma_alloc(size)?;
        s.fill(0);
        Ok(s)
    }
}

impl Drop for StdScopedAlloc<'_> {
    fn drop(&mut self) {
        self.pool.nondma_mark(self.slot).set(self.nondma_mark);
        self.pool.dma_mark(self.slot).set(self.dma_mark);
    }
}

// ── HsmAlloc impl ─────────────────────────────────────────────────

impl HsmAlloc for StdHsmPal {
    type Scoped<'a> = StdScopedAlloc<'a>;

    #[inline(always)]
    fn alloc(&self, io: &StdHsmIo, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.iic.pool(), io.slot, Heap::NonDma, size, 4)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, io: &StdHsmIo, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, io: &StdHsmIo, value: T) -> HsmResult<&mut T> {
        let s = bump(
            self.iic.pool(),
            io.slot,
            Heap::NonDma,
            mem::size_of::<T>(),
            mem::align_of::<T>().max(1),
        )?;
        let ptr = s.as_mut_ptr().cast::<T>();
        // SAFETY: see StdScopedAlloc::alloc_val.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, io: &StdHsmIo, size: usize) -> HsmResult<&mut HsmDmaBuf> {
        let s = bump(self.iic.pool(), io.slot, Heap::Dma, size, 4)?;
        // SAFETY: the Dma heap is DMA-accessible by construction.
        Ok(unsafe { HsmDmaBuf::from_raw_mut(s) })
    }

    fn dma_alloc_exchange(&self, io: &StdHsmIo, size: usize) -> HsmResult<DmaAllocation<'_>> {
        let pool = self.iic.pool();
        bump(pool, io.slot, Heap::Dma, size, 4)?;
        let start = pool.dma_mark(io.slot).get() - size;
        // SAFETY: bump reserved this exclusive range. Use the heap's raw pointer
        // rather than deriving growth provenance from a fixed-length slice.
        Ok(unsafe { DmaAllocation::from_raw_parts(pool.dma_ptr(io.slot).add(start), size) })
    }

    fn dma_grow(
        &self,
        io: &StdHsmIo,
        allocation: &mut DmaAllocation<'_>,
        size: usize,
    ) -> HsmResult<()> {
        let pool = self.iic.pool();
        let base = pool.dma_ptr(io.slot);
        let start = (allocation.as_ptr() as usize)
            .checked_sub(base as usize)
            .ok_or(HsmError::InvalidArg)?;
        let mark = pool.dma_mark(io.slot);
        if size < allocation.len()
            || start.checked_add(allocation.len()) != Some(mark.get())
            || mark.get() > DMA_BUF_SIZE
        {
            return Err(HsmError::InvalidArg);
        }
        let end = start.checked_add(size).ok_or(HsmError::NotEnoughSpace)?;
        if end > DMA_BUF_SIZE {
            return Err(HsmError::NotEnoughSpace);
        }
        mark.set(end);
        let peak = pool.dma_peak(io.slot);
        peak.set(peak.get().max(end));
        // SAFETY: no views can survive this exclusive handle borrow. The tail
        // extension is unallocated and the pointer retains heap provenance.
        *allocation = unsafe { DmaAllocation::from_raw_parts(base.add(start), size) };
        Ok(())
    }

    #[inline(always)]
    fn dma_alloc_zeroed(&self, io: &StdHsmIo, size: usize) -> HsmResult<&mut HsmDmaBuf> {
        let s = self.dma_alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    fn dma_alloc_var<F>(&self, io: &StdHsmIo, f: F) -> HsmResult<&mut HsmDmaBuf>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<usize>,
    {
        let pool = self.iic.pool();
        let slot = io.slot;
        let cap = Heap::Dma.capacity();
        let mark_cell = pool.dma_mark(slot);
        let saved_mark = mark_cell.get().min(cap);
        let aligned = (saved_mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let peak_before = pool.dma_peak(slot).get();
        let buf = bump(pool, slot, Heap::Dma, cap - aligned, 4)?;
        match f(buf) {
            Ok(len) => {
                if len > buf.len() {
                    // Closure overran the buffer it was handed; refuse to
                    // expose a longer slice than we actually own. This is a
                    // firmware bug (an encoder mis-reporting its length), not
                    // a malformed request, hence the dedicated status.
                    mark_cell.set(saved_mark);
                    return Err(HsmError::DmaAllocLenOverrun);
                }
                let final_end = aligned + len;
                mark_cell.set(final_end);
                pool.dma_peak(slot).set(peak_before.max(final_end));
                // SAFETY: the Dma heap is DMA-accessible by construction.
                Ok(unsafe { HsmDmaBuf::from_raw_mut(&mut buf[..len]) })
            }
            Err(e) => {
                mark_cell.set(saved_mark);
                Err(e)
            }
        }
    }

    fn dma_alloc_var_with<F, T>(&self, io: &StdHsmIo, f: F) -> HsmResult<(&mut HsmDmaBuf, T)>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<(usize, T)>,
    {
        let pool = self.iic.pool();
        let slot = io.slot;
        let cap = Heap::Dma.capacity();
        let mark_cell = pool.dma_mark(slot);
        let saved_mark = mark_cell.get().min(cap);
        let aligned = (saved_mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let peak_before = pool.dma_peak(slot).get();
        let buf = bump(pool, slot, Heap::Dma, cap - aligned, 4)?;
        match f(buf) {
            Ok((len, extra)) => {
                if len > buf.len() {
                    // See `dma_alloc_var`: a firmware bug, not a malformed
                    // request.
                    mark_cell.set(saved_mark);
                    return Err(HsmError::DmaAllocLenOverrun);
                }
                let final_end = aligned + len;
                mark_cell.set(final_end);
                pool.dma_peak(slot).set(peak_before.max(final_end));
                // SAFETY: the Dma heap is DMA-accessible by construction.
                Ok((unsafe { HsmDmaBuf::from_raw_mut(&mut buf[..len]) }, extra))
            }
            Err(e) => {
                mark_cell.set(saved_mark);
                Err(e)
            }
        }
    }

    #[inline]
    fn alloc_scoped<R>(&self, io: &StdHsmIo, f: impl FnOnce(&Self::Scoped<'_>) -> R) -> R {
        let pool = self.iic.pool();
        let slot = io.slot;
        let scope = StdScopedAlloc {
            pool,
            slot,
            nondma_mark: pool.nondma_mark(slot).get(),
            dma_mark: pool.dma_mark(slot).get(),
        };
        f(&scope)
    }

    async fn alloc_scoped_async<R, F>(&self, io: &StdHsmIo, f: F) -> R
    where
        F: for<'a> AsyncFnOnce(&'a Self::Scoped<'a>) -> R,
    {
        let pool = self.iic.pool();
        let slot = io.slot;
        let scope = StdScopedAlloc {
            pool,
            slot,
            nondma_mark: pool.nondma_mark(slot).get(),
            dma_mark: pool.dma_mark(slot).get(),
        };
        f(&scope).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::HsmPartId;

    fn io(slot: u16) -> StdHsmIo {
        let (tx, _) = tokio::sync::oneshot::channel();
        StdHsmIo::admin(HsmPartId::from(0u8), slot, tx)
    }

    #[tokio::test]
    async fn teardown_scrubs_nested_scopes_and_grown_allocations() {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let slot = pal.iic.pool().alloc().await;
        let first = io(slot);
        pal.alloc_scoped(&first, |outer| {
            outer.dma_alloc(12).unwrap().fill(0x17);
            outer.alloc(12).unwrap().fill(0x27);
            pal.alloc_scoped(&first, |inner| {
                inner.alloc(116).unwrap().fill(0x37);
                let mut allocation = pal.dma_alloc_exchange(&first, 4).unwrap();
                pal.dma_grow(&first, &mut allocation, 244).unwrap();
                allocation.buffer_mut().fill(0x47);
            });
        });
        let reused = pal.dma_alloc(&first, 16).unwrap();
        assert_eq!(&reused[..12], &[0x17; 12]);
        assert_eq!(&reused[12..], &[0x47; 4]);
        let reused = pal.alloc(&first, 16).unwrap();
        assert_eq!(&reused[..12], &[0x27; 12]);
        assert_eq!(&reused[12..], &[0x37; 4]);
        pal.drop_io(first).await.unwrap();

        assert_eq!(pal.iic.pool().alloc().await, slot);
        let second = io(slot);
        assert!(pal.dma_alloc(&second, 256).unwrap().iter().all(|&b| b == 0));
        assert!(pal.alloc(&second, 128).unwrap().iter().all(|&b| b == 0));
        pal.drop_io(second).await.unwrap();
    }

    #[tokio::test]
    async fn teardown_scrubs_variable_allocation_rewinds() {
        for (fail, with_extra) in [(false, false), (true, false), (false, true), (true, true)] {
            let (_, rx) = async_channel::bounded(1);
            let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
            let slot = pal.iic.pool().alloc().await;
            let first = io(slot);
            pal.alloc_scoped(&first, |scope| {
                scope.dma_alloc(256).unwrap().fill(0x35);
            });
            let write = |out: &mut [u8]| {
                if fail {
                    out.fill(0xA5);
                    Err(HsmError::InvalidArg)
                } else {
                    out[..4].fill(0xA5);
                    Ok(4)
                }
            };
            let result = if with_extra {
                pal.dma_alloc_var_with(&first, |out| write(out).map(|len| (len, ())))
                    .map(|(out, ())| out)
            } else {
                pal.dma_alloc_var(&first, write)
            };
            assert_eq!(result.err(), fail.then_some(HsmError::InvalidArg));
            pal.drop_io(first).await.unwrap();
            assert_eq!(pal.iic.pool().alloc().await, slot);
            let second = io(slot);
            assert!(pal
                .dma_alloc(&second, DMA_BUF_SIZE)
                .unwrap()
                .iter()
                .all(|&b| b == 0));
            pal.drop_io(second).await.unwrap();
        }
    }

    #[test]
    fn dma_growth_preserves_request_and_does_not_move_undo_or_scratch() {
        let pal = StdHsmPal::default();
        let io = io(0);
        let undo = pal.dma_alloc(&io, 32).unwrap();
        undo.fill(0x17);
        let mut request = pal.dma_alloc_exchange(&io, 12).unwrap();
        request.buffer_mut().fill(0x42);
        let address = request.as_ptr();
        pal.dma_grow(&io, &mut request, 36).unwrap();
        let exchange = request.buffer_mut();
        assert_eq!(exchange.as_ptr(), address);
        assert_eq!(&exchange[..12], &[0x42; 12]);
        exchange[12..].fill(0xA5);
        let scratch = pal.dma_alloc(&io, 4).unwrap();
        assert_eq!(scratch.as_ptr() as usize, address as usize + 36);
        scratch.fill(0x33);
        assert_eq!(undo, &[0x17; 32]);
        assert_eq!(&exchange[12..], &[0xA5; 24]);
    }

    #[test]
    fn dma_growth_rejects_non_tail_and_foreign_buffers_without_advancing() {
        let pal = StdHsmPal::default();
        let first = io(0);
        let second = io(1);
        let mut request = pal.dma_alloc_exchange(&first, 12).unwrap();
        let tail = pal.dma_alloc(&first, 4).unwrap();
        let mut foreign = pal.dma_alloc_exchange(&second, 4).unwrap();
        assert_eq!(
            pal.dma_grow(&first, &mut request, 24).err(),
            Some(HsmError::InvalidArg)
        );
        assert_eq!(
            pal.dma_grow(&first, &mut foreign, 24).err(),
            Some(HsmError::InvalidArg)
        );
        let next = pal.dma_alloc(&first, 4).unwrap();
        assert_eq!(next.as_ptr() as usize, tail.as_ptr() as usize + 4);
    }

    #[test]
    fn dma_growth_failure_preserves_the_original_allocation() {
        let pal = StdHsmPal::default();
        let io = io(0);
        let mut request = pal.dma_alloc_exchange(&io, 12).unwrap();
        request.buffer_mut().fill(0x42);
        assert_eq!(
            pal.dma_grow(&io, &mut request, 8).err(),
            Some(HsmError::InvalidArg)
        );
        assert_eq!(
            pal.dma_grow(&io, &mut request, usize::MAX).err(),
            Some(HsmError::NotEnoughSpace)
        );
        assert_eq!(
            pal.dma_grow(&io, &mut request, DMA_BUF_SIZE + 1).err(),
            Some(HsmError::NotEnoughSpace)
        );
        pal.dma_grow(&io, &mut request, DMA_BUF_SIZE).unwrap();
        let grown = request.buffer_mut();
        assert_eq!(&grown[..12], &[0x42; 12]);
        assert_eq!(grown.len(), DMA_BUF_SIZE);
        assert_eq!(pal.dma_alloc(&io, 1).err(), Some(HsmError::NotEnoughSpace));
    }
}
