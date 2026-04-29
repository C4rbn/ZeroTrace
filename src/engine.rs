use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread::sleep;
use anyhow::{Result, anyhow};
use rand::Rng;

use crate::tcp_syn_crafter;
use crate::header_shuffle;
use crate::tls_grease;

pub struct StealthEngine {
    pub target_domain: String,
    pub base_delay_ns: u64,
}

impl StealthEngine {
    pub fn new(domain: &str, base_delay_ns: u64) -> Self {
        Self {
            target_domain: domain.to_string(),
            base_delay_ns,
        }
    }

    pub fn dispatch_stealth_sequence(&self, dynamic_ip: Ipv4Addr, raw_headers: &HashMap<&[u8], &[u8]>) -> Result<()> {
        let shuffled = header_shuffle::shuffle_headers(raw_headers);
        let _payload = header_shuffle::serialize_headers(&shuffled);
        
        tls_grease::execute_stealth_request(&self.target_domain);

        let chaos_seed = rand::thread_rng().gen_range(0..4096);
        let target_delay = self.base_delay_ns + chaos_seed;

        sleep(Duration::from_nanos(target_delay));

        let packet_cfg = tcp_syn_crafter::Config {
            src_ip: [0, 0, 0, 0], 
            dst_ip: dynamic_ip.octets(),
            dport: 443,
            window: 64240,
        };
        
        let packet = tcp_syn_crafter::create_syn_packet(&packet_cfg);

        tcp_syn_crafter::send_raw_packet(dynamic_ip.octets(), &packet)
            .map_err(|e| anyhow!("Global Dispatch Error: {}", e))?;

        Ok(())
    }
}

pub fn log_event(status: &str, message: &str, quiet: bool) {
    if quiet && !["CRIT", "BOOT", "EXIT"].contains(&status) {
        return;
    }
    
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let timestamp = now.as_secs();

    let status_text = match status {
        "BOOT"    => "INITIALIZING",
        "BYPASS"  => "TUN:UP",
        "SHIELD"  => "PROTECT",
        "CRIT"    => "ERROR",
        "EXIT"    => "SIGTERM",
        _         => status,
    };

    println!("{:>10} [{}] {}", timestamp, status_text, message);
}
