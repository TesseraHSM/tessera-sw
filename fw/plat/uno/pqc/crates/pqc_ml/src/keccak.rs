// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Keccak-f[1600] permutation and SHAKE-128/256 sponge.
//
// On ARM (thumbv7em) targets: uses pqm4 assembly from
// https://github.com/mupq/pqm4 (common/keccakf1600.S), with the permutation
// rescheduled for Cortex-M7 by SLOTHY (see asm/keccakf1600.S).
// On host targets: pure Rust fallback for testing.
// SHAKE-128 rate = 168 bytes, SHAKE-256 rate = 136 bytes
pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;
// ======== Platform-specific Keccak state ========

/// Keccak state: 200 bytes.
/// On ARM: bit-interleaved [u32; 50], managed by pqm4 assembly.
/// On host: standard [u64; 25], managed by pure Rust.
#[derive(Clone)]
pub struct KeccakState {
    #[cfg(target_arch = "arm")]
    state: [u32; 50],
    #[cfg(not(target_arch = "arm"))]
    state: [u64; 25],
}

// ---- ARM: pqm4 FFI ----

#[cfg(target_arch = "arm")]
extern "C" {
    fn KeccakF1600_StateXORBytes(state: *mut u32, data: *const u8, offset: u32, length: u32);
    fn KeccakF1600_StateExtractBytes(state: *const u32, data: *mut u8, offset: u32, length: u32);
    fn KeccakF1600_StatePermute(state: *mut u32);
}

#[cfg(target_arch = "arm")]
impl KeccakState {
    // A hardware sponge state has no meaningful `Default`; `new` zeroes it
    // explicitly for the callers that want a fresh sponge.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // `KeccakF1600_Initialize` is `bx lr` in this port -- the zeroing was
        // always the array initialiser's, which compiles to a `memset` at
        // four instructions per word. Signing builds about sixty-eight
        // sponges, so the 200 bytes are cleared eight words at a time
        // instead and the no-op call is gone.
        //
        // SAFETY: written in full by `fast_zero` before any read.
        let mut s = core::mem::MaybeUninit::<KeccakState>::uninit();
        unsafe {
            crate::fast_zero(s.as_mut_ptr().cast(), core::mem::size_of::<KeccakState>());
            s.assume_init()
        }
    }

    pub fn xor_bytes(&mut self, data: &[u8], offset: usize) {
        if data.is_empty() {
            return;
        }
        unsafe {
            KeccakF1600_StateXORBytes(
                self.state.as_mut_ptr(),
                data.as_ptr(),
                offset as u32,
                data.len() as u32,
            );
        }
    }

    pub fn extract_bytes(&self, out: &mut [u8], offset: usize) {
        if out.is_empty() {
            return;
        }
        unsafe {
            KeccakF1600_StateExtractBytes(
                self.state.as_ptr(),
                out.as_mut_ptr(),
                offset as u32,
                out.len() as u32,
            );
        }
    }

    pub fn permute(&mut self) {
        unsafe { KeccakF1600_StatePermute(self.state.as_mut_ptr()) };
    }
}

// ---- Host: pure Rust ----

#[cfg(not(target_arch = "arm"))]
impl Default for KeccakState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "arm"))]
impl KeccakState {
    pub fn new() -> Self {
        KeccakState { state: [0u64; 25] }
    }

    pub fn xor_bytes(&mut self, data: &[u8], offset: usize) {
        for i in 0..data.len() {
            let pos = offset + i;
            let lane = pos / 8;
            let byte_in_lane = pos % 8;
            self.state[lane] ^= (data[i] as u64) << (byte_in_lane * 8);
        }
    }

    pub fn extract_bytes(&self, out: &mut [u8], offset: usize) {
        for i in 0..out.len() {
            let pos = offset + i;
            let lane = pos / 8;
            let byte_in_lane = pos % 8;
            out[i] = (self.state[lane] >> (byte_in_lane * 8)) as u8;
        }
    }

    pub fn permute(&mut self) {
        keccakf1600_rust(&mut self.state);
    }
}

#[cfg(not(target_arch = "arm"))]
fn keccakf1600_rust(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    for round in 0..24 {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= RC[round];
    }
}

// ======== SHAKE sponge (platform-independent) ========

pub struct ShakeCtx {
    st: KeccakState,
    rate: usize,
    pos: usize,
}

impl ShakeCtx {
    fn new(rate: usize) -> Self {
        ShakeCtx {
            st: KeccakState::new(),
            rate,
            pos: 0,
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut remaining = data.len();

        if self.pos > 0 {
            let space = self.rate - self.pos;
            let take = if remaining < space { remaining } else { space };
            self.st.xor_bytes(&data[offset..offset + take], self.pos);
            self.pos += take;
            offset += take;
            remaining -= take;
            if self.pos == self.rate {
                self.st.permute();
                self.pos = 0;
            }
        }

        while remaining >= self.rate {
            self.st.xor_bytes(&data[offset..offset + self.rate], 0);
            self.st.permute();
            offset += self.rate;
            remaining -= self.rate;
        }

        if remaining > 0 {
            self.st.xor_bytes(&data[offset..offset + remaining], 0);
            self.pos = remaining;
        }
    }

    pub fn finalize(&mut self) {
        self.st.xor_bytes(&[0x1F], self.pos);
        self.st.xor_bytes(&[0x80], self.rate - 1);
        self.st.permute();
        self.pos = 0;
    }

    /// Squeeze `out.len()` bytes, permuting only when the current block is
    /// exhausted **and** more output is still wanted.
    ///
    /// Permuting eagerly after the last extracted block, as the obvious
    /// formulation does, wastes a whole Keccak-f[1600] on every XOF whose
    /// output is a multiple of the rate -- which is every rejection sampler
    /// here, and one permutation in six for ExpandA.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut offset = 0;
        while offset < out.len() {
            if self.pos == self.rate {
                self.st.permute();
                self.pos = 0;
            }
            let avail = self.rate - self.pos;
            let remaining = out.len() - offset;
            let take = if remaining < avail { remaining } else { avail };
            self.st
                .extract_bytes(&mut out[offset..offset + take], self.pos);
            self.pos += take;
            offset += take;
        }
    }
}

pub fn shake128_init() -> ShakeCtx {
    ShakeCtx::new(SHAKE128_RATE)
}
pub fn shake256_init() -> ShakeCtx {
    ShakeCtx::new(SHAKE256_RATE)
}

pub fn shake256(input: &[u8], out: &mut [u8]) {
    let mut ctx = shake256_init();
    ctx.absorb(input);
    ctx.finalize();
    ctx.squeeze(out);
}

pub fn shake128(input: &[u8], out: &mut [u8]) {
    let mut ctx = shake128_init();
    ctx.absorb(input);
    ctx.finalize();
    ctx.squeeze(out);
}

// ======== SHA3-256 / SHA3-512 (FIPS 202, padding 0x06) ========

// SHA3-256 rate = 136 bytes, SHA3-512 rate = 72 bytes
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;

/// SHA3 context — identical to SHAKE but with different padding byte.
pub struct Sha3Ctx {
    st: KeccakState,
    rate: usize,
    pos: usize,
}

impl Sha3Ctx {
    fn new(rate: usize) -> Self {
        Sha3Ctx {
            st: KeccakState::new(),
            rate,
            pos: 0,
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut remaining = data.len();

        if self.pos > 0 {
            let space = self.rate - self.pos;
            let take = if remaining < space { remaining } else { space };
            self.st.xor_bytes(&data[offset..offset + take], self.pos);
            self.pos += take;
            offset += take;
            remaining -= take;
            if self.pos == self.rate {
                self.st.permute();
                self.pos = 0;
            }
        }

        while remaining >= self.rate {
            self.st.xor_bytes(&data[offset..offset + self.rate], 0);
            self.st.permute();
            offset += self.rate;
            remaining -= self.rate;
        }

        if remaining > 0 {
            self.st.xor_bytes(&data[offset..offset + remaining], 0);
            self.pos = remaining;
        }
    }

    /// Finalize with SHA3 padding (0x06) instead of SHAKE (0x1F).
    pub fn finalize(&mut self, out: &mut [u8]) {
        self.st.xor_bytes(&[0x06], self.pos);
        self.st.xor_bytes(&[0x80], self.rate - 1);
        self.st.permute();
        self.st.extract_bytes(out, 0);
    }
}

/// SHA3-256: absorb input, produce 32-byte hash.
pub fn sha3_256(input: &[u8], out: &mut [u8; 32]) {
    let mut ctx = Sha3Ctx::new(SHA3_256_RATE);
    ctx.absorb(input);
    ctx.finalize(out);
}

/// SHA3-512: absorb input, produce 64-byte hash.
pub fn sha3_512(input: &[u8], out: &mut [u8; 64]) {
    let mut ctx = Sha3Ctx::new(SHA3_512_RATE);
    ctx.absorb(input);
    ctx.finalize(out);
}

/// SHA3-256 incremental context.
pub fn sha3_256_init() -> Sha3Ctx {
    Sha3Ctx::new(SHA3_256_RATE)
}
/// SHA3-512 incremental context.
pub fn sha3_512_init() -> Sha3Ctx {
    Sha3Ctx::new(SHA3_512_RATE)
}
