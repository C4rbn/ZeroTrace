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
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut interfaces = Vec::new();
    if let Ok(addrs) = getifaddrs() {
        for ifaddr in addrs {
            if let Some(name) = ifaddr.interface_name.get(..).map(|s| s.to_string()) {
                let is_valid = name.starts_with("eth") || name.starts_with("en") || name.starts_with("wl");
                if is_valid && !interfaces.contains(&name) {
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

    engine::log_event("BOOT", "ZeroTrace Active: Universal Portable Mode", args.quiet);

    // --- ORCHESTRATION FIX ---
    let engine = Arc::new(engine::StealthEngine::new(Some("8.8.8.8"), 443, 500_000));
    let engine_task = engine.clone();
    
    tokio::task::spawn_blocking(move || {
        let mut headers = HashMap::new();
        headers.insert(b"User-Agent".as_slice(), b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)".as_slice());
        
        if let Err(e) = engine_task.dispatch_stealth_packet(&headers) {
            engine::log_event("CRITICAL", &format!("Engine Dispatch Error: {}", e), false);
        } else {
            engine::log_event("SHIELD", "Stealth Dispatch Sequence Complete", false);
        }
    }).await?;

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
        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(64)).collect::<Vec<_>>();
            while let Ok(events) = buf.read_events(&mut buffers).await {
                for i in 0..events.read {
                    let info = unsafe { &*(buffers[i].as_ptr() as *const PacketInfo) };
                    if !quiet {
                        println!("[\x1b[35mBYPASS\x1b[0m] {} -> {} | Mutated", 
                            Ipv4Addr::from(info.fast_host_src_addr()), 
                            Ipv4Addr::from(info.fast_host_dst_addr()));
                    }
                }
            }
        });
    }

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(200)).await;
    }

    for iface in interfaces {
        let _ = Command::new("ip").args(["link", "set", "dev", &iface, "xdp", "off"]).output();
    }

    Ok(())
}
