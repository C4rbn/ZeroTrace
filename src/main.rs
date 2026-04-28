mod engine;
mod tcp_syn_crafter;
mod header_shuffle;
mod tls_grease;

use clap::Parser;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

use aya::{include_bytes_aligned, Ebpf}; 
use aya::programs::{Xdp, XdpFlags};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use nix::ifaddrs::getifaddrs;

use xdp_interceptor::PacketInfo;

#[derive(Parser)]
#[command(name = "zerotrace", about = "Universal Stealth Shield")]
struct Cli {
    #[arg(short, long)]
    quiet: bool,
    #[arg(short, long)]
    remove: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();
    if let Err(_) = rlimit::setrlimit(rlimit::Resource::MEMLOCK, rlimit::INFINITY, rlimit::INFINITY) {}

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;

    let mut interfaces = Vec::new();
    if let Ok(addrs) = getifaddrs() {
        for ifaddr in addrs {
            let name = ifaddr.interface_name;
            if !ifaddr.flags.contains(nix::net::ifreq::InterfaceFlags::IFF_LOOPBACK) && ifaddr.address.is_some() {
                if !interfaces.contains(&name) {
                    interfaces.push(name.clone());
                    let _ = Command::new("ip").args(["link", "set", "dev", &name, "xdp", "off"]).output();
                }
            }
        }
    }

    if args.remove {
        engine::log_event("EXIT", "ZeroTrace Shields detached.", false);
        return Ok(());
    }

    engine::log_event("BOOT", "ZeroTrace Active: Universal Global Mode", args.quiet);

    // Initializing Global Orchestrator
    let engine = Arc::new(engine::StealthEngine::new("google.com", 500_000));

    let mut bpf = Ebpf::load(include_bytes_aligned!("../target/bpfel-unknown-none/release/xdp-interceptor"))?;
    let program: &mut Xdp = bpf.program_mut("xdp_mutate").unwrap().try_into()?;
    program.load()?;

    for iface in interfaces.clone() {
        let _ = program.attach(&iface, XdpFlags::SKB_MODE);
    }

    let cpus = online_cpus()?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("PACKET_EVENTS").unwrap())?;

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, Some(2))?;
        let quiet = args.quiet;
        let engine_local = engine.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(64)).collect::<Vec<_>>();
            let mut headers = HashMap::new();
            headers.insert(b"User-Agent".as_slice(), b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)".as_slice());

            while let Ok(events) = buf.read_events(&mut buffers).await {
                for i in 0..events.read {
                    if buffers[i].len() < std::mem::size_of::<PacketInfo>() { continue; }
                    let info = unsafe { &*(buffers[i].as_ptr() as *const PacketInfo) };
                    
                    let dst_ip = Ipv4Addr::from(info.fast_host_dst_addr());
                    
                    // DYNAMIC TARGET PICKUP: Pick up the destination from the kernel event
                    let engine_task = engine_local.clone();
                    let h_clone = headers.clone();
                    
                    tokio::task::spawn_blocking(move || {
                        let _ = engine_task.dispatch_stealth_sequence(dst_ip, &h_clone);
                    });

                    if !quiet {
                        println!("[\x1b[35mBYPASS\x1b[0m] Found Target: {} | Sequence Dispatched", dst_ip);
                    }
                }
            }
        });
    }

    while running.load(Ordering::SeqCst) { sleep(Duration::from_millis(200)).await; }

    for iface in interfaces {
        let _ = Command::new("ip").args(["link", "set", "dev", &iface, "xdp", "off"]).output();
    }

    Ok(())
}
