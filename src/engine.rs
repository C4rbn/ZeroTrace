use std::net::{IpAddr, UdpSocket};
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

    fn get_egress_ip(target: IpAddr) -> Result<IpAddr> {
        let bind_addr = match target {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect((target, 53))?;
        Ok(socket.local_addr()?.ip())
    }

    pub fn dispatch_stealth_sequence(&self, dynamic_ip: IpAddr) -> Result<()> {
        let local_ip = Self::get_egress_ip(dynamic_ip).map_err(|e| anyhow!("Routing Error: {}", e))?;
        
        let chaos_seed = rand::thread_rng().gen_range(0..4096);
        sleep(Duration::from_nanos(self.base_delay_ns + chaos_seed));

        match (local_ip, dynamic_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let packet = tcp_syn_crafter::create_syn_packet_v4(src.octets(), dst.octets(), 443, 64240);
                tcp_syn_crafter::send_raw_packet_v4(dst.octets(), &packet)?;
            },
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let packet = tcp_syn_crafter::create_syn_packet_v6(src.octets(), dst.octets(), 443, 64240);
                tcp_syn_crafter::send_raw_packet_v6(dst.octets(), &packet)?;
            },
            _ => return Err(anyhow!("IP Version Mismatch")),
        }

        Ok(())
    }
}

pub fn log_event(status: &str, message: &str, quiet: bool) {
    if quiet && !["CRIT", "BOOT", "EXIT"].contains(&status) { return; }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    println!("{:>10} [{}] {}", ts, status, message);
}
