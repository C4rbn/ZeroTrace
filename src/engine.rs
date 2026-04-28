use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::hint::spin_loop;

use crate::tcp_syn_crafter;
use crate::header_shuffle;
use crate::tls_grease;

/// ZeroTrace Core Stealth Engine
/// Handles L4/L7 mutation logic and high-precision packet orchestration.
pub struct StealthEngine {
    target_ip: Option<Ipv4Addr>,
    target_port: u16,
    base_delay_ns: u64,
}

impl StealthEngine {
    /// Initialize a new engine instance.
    /// If target is None, the engine operates in Global Passive Mode.
    pub fn new(target: Option<&str>, port: u16) -> Self {
        Self {
            target_ip: target.and_then(|t| t.parse().ok()),
            target_port: port,
            base_delay_ns: 500_000, 
        }
    }

    /// Primary dispatcher for stealth operations.
    /// Sequence: Identity Mutation -> Entropy Generation -> Precision Timing -> Handoff.
    pub fn dispatch_stealth_packet(&self, raw_headers: &HashMap<&[u8], &[u8]>) -> Result<(), String> {
        
        // 1. Layer 7 Identity Mutation
        let shuffled = header_shuffle::shuffle_headers(raw_headers);
        let _payload = header_shuffle::serialize_headers(&shuffled);
        let _grease = tls_grease::peak_grease_u16(); 

        // 2. Jitter Entropy Generation
        let chaos_seed = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() % 4096) as u64;
            
        let target_delay = self.base_delay_ns + chaos_seed;

        // 3. Execution Path Selection
        match self.target_ip {
            Some(ip) => {
                let packet_cfg = tcp_syn_crafter::Config {
                    src_ip: [0, 0, 0, 0],
                    dst_ip: ip.octets(),
                    sport: 0,
                    dport: self.target_port,
                    window: 64240,        
                };
                
                let packet = tcp_syn_crafter::create_syn_packet(&packet_cfg);

                // Nanosecond Precision Spin-Lock
                let start = Instant::now();
                while start.elapsed().as_nanos() < target_delay as u128 {
                    spin_loop();
                }

                tcp_syn_crafter::send_raw_packet(ip.octets(), &packet)
                    .map_err(|e| format!("Dispatch Failure: {:?}", e))
            },
            None => {
                let start = Instant::now();
                while start.elapsed().as_nanos() < target_delay as u128 {
                    spin_loop(); 
                }
                Ok(())
            }
        }
    }
}

/// Unified Telemetry and Event Logging
pub fn log_event(event_type: &str, message: &str, quiet: bool) {
    if quiet && !["BYPASS", "CRITICAL", "SHIELD", "BOOT", "EXIT"].contains(&event_type) {
        return;
    }
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let color = match event_type {
        "BOOT" => "\x1b[36m",    
        "SHIELD" => "\x1b[32m",  
        "CRITICAL" => "\x1b[31m",
        "BYPASS" => "\x1b[35m",   
        "IDLE" => "\x1b[34m",     
        "EXIT" => "\x1b[33m",     
        _ => "\x1b[0m",
    };

    println!(
        "[{}.{:03}] [{}{:<8}\x1b[0m] {}", 
        now.as_secs(), 
        now.subsec_millis(),
        color,
        event_type, 
        message
    );
}
