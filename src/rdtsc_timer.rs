// src/rdtsc_timer.rs
#![allow(unsafe_code)]
use std::time::{Duration, Instant};

/// Generic interface for reading the Time-Stamp Counter.
#[inline(always)]
pub fn rdtsc() -> u64 {
    rdtsc_serialized()
}

/// Read the Time-Stamp Counter with serialization.
/// Uses CPUID to ensure all previous instructions have completed before reading.
#[inline(always)]
pub fn rdtsc_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",      
            "cpuid",         
            "rdtsc",
            "pop rbx",       
            in("eax") 0,     
            lateout("eax") lo,
            out("edx") hi,
            out("ecx") _,    
            options(nostack, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Read TSC and Processor ID with memory fencing.
/// Uses MFENCE to ensure memory ordering before the RDTSCP instruction.
#[inline(always)]
pub fn rdtscp_mfence() -> (u64, u32) {
    let lo: u32;
    let hi: u32;
    let aux: u32;
    unsafe {
        core::arch::asm!(
            "mfence",        
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, nomem)
        );
    }
    (((hi as u64) << 32) | (lo as u64), aux)
}

/// High-precision busy-wait loop using hardware fencing.
/// Blocks the current thread for the specified number of CPU cycles.
#[inline(always)]
pub fn absolute_peak_wait(cycles: u64) {
    if cycles == 0 { return; }
    
    let start = rdtsc_serialized();
    unsafe {
        core::arch::asm!(
            "3:",
            "pause",          
            "lfence",         
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            "sub rax, {0}",
            "cmp rax, {1}",
            "jl 3b",
            in(reg) start,
            in(reg) cycles,
            out("rax") _,
            out("rdx") _,
            options(nostack, nomem)
        );
    }
}

pub fn calibrate_tsc() -> u64 {
    calibrate_tsc_frequency()
}

/// Calibrates the TSC frequency using a median-of-five strategy.
/// Filters out jitter caused by context switches or interrupts during the timing window.
pub fn calibrate_tsc_frequency() -> u64 {
    let mut samples = [0u64; 5];
    
    for i in 0..5 {
        let start_time = Instant::now();
        let start_tsc = rdtsc_serialized();
        
        // 20ms calibration window
        while start_time.elapsed() < Duration::from_millis(20) {
            core::hint::spin_loop();
        }
        
        let end_tsc = rdtsc_serialized();
        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        
        if elapsed_ns > 0 {
            samples[i] = (end_tsc - start_tsc) * 1_000_000_000 / elapsed_ns;
        }
    }
    
    samples.sort();
    samples[2] 
}

#[inline(always)]
pub fn ticks_to_ns(ticks: u64, tsc_hz: u64) -> u64 {
    if tsc_hz == 0 { return 0; }
    ((ticks as u128 * 1_000_000_000) / tsc_hz as u128) as u64
}

/// Lightweight RAII profiler for hardware cycle measurements.
pub struct PeakTimer {
    label: &'static str,
    start: u64,
    hz: u64,
}

impl PeakTimer {
    #[inline(always)]
    pub fn new(label: &'static str, hz: u64) -> Self {
        Self { label, start: rdtsc_serialized(), hz }
    }
}

impl Drop for PeakTimer {
    fn drop(&mut self) {
        let (end, core) = rdtscp_mfence();
        let delta = end.wrapping_sub(self.start);
        let ns = ticks_to_ns(delta, self.hz);
        println!("\x1b[33m[PROFILE]\x1b[0m {} took {}ns ({} cycles) on CORE {}", 
                 self.label, ns, delta, core);
    }
}
