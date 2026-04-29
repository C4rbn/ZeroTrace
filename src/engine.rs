use std::net::{Ipv4Addr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread::sleep;
use anyhow::{Result, anyhow};
use rand::Rng;

use crate::tcp_syn_crafter;

pub struct StealthEngine {
    pub base_delay_ns: u64,
}

impl StealthEngine {
    pub fn new(base_delay_ns: u64) -> Self {
        Self { base_delay_ns }
    }

    // Industrial Standard: Use kernel UDP connect to dynamically resolve the egress IP
    fn get_egress_ip(target: Ipv4Addr) -> Result<Ipv4Addr> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect((target, 53))?;
        match socket.local_addr()? {
            std::net::SocketAddr::V4(addr) => Ok(*addr.ip()),
            _ => Err(anyhow!("Failed to resolve IPv4 egress")),
        }
    }

    pub fn dispatch_stealth_sequence(&self, dynamic_ip: Ipv4Addr) -> Result<()> {
        // Resolve correct local IP based on the kernel's routing table dynamically
        let local_ip = Self::get_egress_ip(dynamic_ip).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        
        if local_ip.is_unspecified() {
            return Err(anyhow!("Routing failed for target {}", dynamic_ip));
        }

        let chaos_seed = rand::thread_rng().gen_range(0..4096);
        let target_delay = self.base_delay_ns + chaos_seed;

        sleep(Duration::from_nanos(target_delay));

        let packet_cfg = tcp_syn_crafter::Config {
            src_ip: local_ip.octets(), 
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
