use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

struct Pcg64 {
    state: u128,
    inc: u128,
}

impl Pcg64 {
    #[inline(always)]
    fn new() -> Self {
        let mut seed = [0u8; 16];
        
        let (s, r) = if getrandom::getrandom(&mut seed).is_ok() {
            (
                u64::from_ne_bytes(seed[0..8].try_into().unwrap()),
                u64::from_ne_bytes(seed[8..16].try_into().unwrap())
            )
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            (now.as_nanos() as u64, 0x5851F42D4C957F2D)
        };

        #[cfg(target_arch = "x86_64")]
        let tsc = unsafe {
            core::arch::x86_64::_mm_lfence();
            core::arch::x86_64::_rdtsc()
        };
        #[cfg(not(target_arch = "x86_64"))]
        let tsc = 0u64;

        Self {
            state: (s as u128) ^ (tsc as u128),
            inc: (r as u128) | 1,
        }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        const PCG_MULT: u128 = 47026247687942121848144207491837523525u128;
        let old_state = self.state;
        self.state = old_state.wrapping_mul(PCG_MULT).wrapping_add(self.inc);
        let xorshifted = (((old_state >> 18) ^ old_state) >> 27) as u32;
        let rot = (old_state >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    #[inline(always)]
    fn next_below(&mut self, n: u32) -> u32 {
        let threshold = n.wrapping_neg() % n;
        loop {
            let r = self.next_u32();
            if r >= threshold {
                return r % n;
            }
        }
    }
}

pub fn shuffle_headers<'a>(headers: &HashMap<&'a [u8], &'a [u8]>) -> Vec<(&'a [u8], &'a [u8])> {
    let n = headers.len();
    if n == 0 { return Vec::new(); }

    let mut pairs: Vec<(&[u8], &[u8])> = headers.iter().map(|(&k, &v)| (k, v)).collect();
    let mut rng = Pcg64::new();

    for i in (1..n).rev() {
        let j = rng.next_below((i + 1) as u32) as usize;
        pairs.swap(i, j);
    }

    pairs
}

pub fn serialize_headers(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    if pairs.is_empty() { return Vec::new(); }

    let total_capacity: usize = pairs.iter().map(|(n, v)| n.len() + v.len() + 4).sum();
    let mut buf = Vec::with_capacity(total_capacity);

    for (name, value) in pairs {
        buf.extend_from_slice(name);
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value);
        buf.extend_from_slice(b"\r\n");
    }

    buf
}
