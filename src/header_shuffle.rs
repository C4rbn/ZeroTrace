use std::collections::HashMap;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A branchless PCG-XSH-RR implementation using hardware-seeded entropy.
struct Pcg64 {
    state: u128, 
    inc: u128,
}

impl Pcg64 {
    #[inline(always)]
    fn from_hardware() -> Self {
        let mut tsc: u64 = 0;
        let mut rdrand_val: u64 = 0;

        // Use hardware entropy (RDRAND/RDTSC) on x86_64 if available
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("rdrand") {
                unsafe {
                    core::arch::x86_64::_mm_lfence();
                    core::arch::asm!(
                        "rdtsc",
                        "shl rdx, 32",
                        "or rax, rdx",
                        "mov {0}, rax",
                        "rdrand {1}",
                        out(reg) tsc,
                        out(reg) rdrand_val,
                        options(nomem, nostack)
                    );
                }
            }
        }

        // Fallback to SystemTime if hardware entropy is unavailable
        if rdrand_val == 0 {
            tsc = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            rdrand_val = 0xDEADC0DEFEADBEAF ^ tsc; 
        }
        
        let stack_ptr = &tsc as *const u64 as u64;
        let combined_seed = (tsc as u128) << 64 | (rdrand_val as u128);
        
        Self {
            state: combined_seed ^ (stack_ptr as u128).wrapping_mul(0xda942042e4dd58b5),
            inc: ((stack_ptr as u128) << 64 | 1),
        }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        let old_state = self.state;
        self.state = old_state.wrapping_mul(6364136223846793005u128).wrapping_add(self.inc);
        let xorshifted = (((old_state >> 18) ^ old_state) >> 27) as u32;
        let rot = (old_state >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    #[inline(always)]
    fn next_below(&mut self, n: u32) -> u32 {
        let r = self.next_u32();
        let m = (r as u64).wrapping_mul(n as u64);
        (m >> 32) as u32
    }
}

/// Shuffles HTTP headers in-place using a Fisher-Yates algorithm
/// seeded by hardware entropy.
pub fn shuffle_headers<'a>(
    headers: &'a HashMap<&'a [u8], &'a [u8]>,
) -> Vec<(&'a [u8], &'a [u8])> {
    let n = headers.len();
    if n == 0 { return Vec::new(); }

    let mut pairs: Vec<(&[u8], &[u8])> = Vec::with_capacity(n);
    
    for (&k, &v) in headers {
        pairs.push((k, v));
    }

    let mut rng = Pcg64::from_hardware();
    for i in (1..n).rev() {
        let j = rng.next_below((i + 1) as u32) as usize;
        pairs.swap(i, j);
    }

    pairs
}

/// Serializes header pairs into a raw byte buffer using non-overlapping 
/// memory copies for performance.
pub fn serialize_headers(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    if pairs.is_empty() { return Vec::new(); }

    let capacity: usize = pairs
        .iter()
        .fold(0, |acc, (n, v)| acc + n.len() + v.len() + 4);

    let mut buf = Vec::with_capacity(capacity);
    let curr_ptr: *mut u8 = buf.as_mut_ptr();
    
    unsafe {
        let mut offset = 0;
        for (name, value) in pairs {
            ptr::copy_nonoverlapping(name.as_ptr(), curr_ptr.add(offset), name.len());
            offset += name.len();

            ptr::copy_nonoverlapping(b": ".as_ptr(), curr_ptr.add(offset), 2);
            offset += 2;

            ptr::copy_nonoverlapping(value.as_ptr(), curr_ptr.add(offset), value.len());
            offset += value.len();

            ptr::copy_nonoverlapping(b"\r\n".as_ptr(), curr_ptr.add(offset), 2);
            offset += 2;
        }
        buf.set_len(capacity);
    }
    
    #[cfg(target_arch = "x86_64")]
    unsafe { 
        if is_x86_feature_detected!("sse2") {
            core::arch::x86_64::_mm_sfence(); 
        }
    }
    
    buf
}
