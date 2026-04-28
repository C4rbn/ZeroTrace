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
#[command(
    name = "zerotrace", 
    about = "Universal Stealth Shield",
    disable_version_flag = true
)]
struct Cli {
    #[arg(short, long)]
    quiet: bool,

    #[arg(short, long)]
    remove: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();

    if let Err(e) = rlimit::setrlimit(rlimit::Resource::MEMLOCK, rlimit::INFINITY, rlimit::INFINITY) {
        if !args.quiet {
            eprintln!("[\x1b[33m!\x1b[0m] Warning: Could not lift MEMLOCK limits: {}", e);
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting signal handler");

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
        engine::log_event("EXIT", "ZeroTrace Shields detached. System restored.", false);
        return Ok(());
    }

    if !args.quiet {
        engine::log_event("BOOT", "ZeroTrace Active: Universal Portable Mode", false);
    }

    let _engine = Arc::new(engine::StealthEngine::new(None, 443));
    
    tokio::task::spawn_blocking(|| {
        tls_grease::execute_stealth_request("google.com"); 
        let mut headers = HashMap::new();
        headers.insert(b"User-Agent".as_slice(), b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".as_slice());
        let shuffled = header_shuffle::shuffle_headers(&headers);
        let _ = header_shuffle::serialize_headers(&shuffled);
        let _ = engine::log_event("SHIELD", "L7 Header Shuffling Initialized", false);
    }).await?;

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/xdp-interceptor"
    ))?;
    
    let program: &mut Xdp = bpf.program_mut("xdp_mutate").unwrap().try_into()?;
    program.load()?;

    for iface in interfaces.clone() {
        if let Err(_) = program.attach(&iface, XdpFlags::SKB_MODE) {
            if !args.quiet { println!("[\x1b[31m!\x1b[0m] Interface {} rejected shield.", iface); }
        } else if !args.quiet {
            println!("[\x1b[32m+\x1b[0m] Shield locked on {}", iface);
        }
    }

    let cpus = online_cpus().map_err(|_| anyhow::anyhow!("Failed to list CPUs"))?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("PACKET_EVENTS").unwrap())?;

    for cpu_id in cpus {
        let mut buf = match perf_array.open(cpu_id, Some(2)) {
            Ok(b) => b,
            Err(e) => {
                if !args.quiet { eprintln!("[\x1b[31m!\x1b[0m] CPU {} map init failed: {}", cpu_id, e); }
                continue;
            }
        };

        let quiet = args.quiet;

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(64)).collect::<Vec<_>>();

            while let Ok(events) = buf.read_events(&mut buffers).await {
                for i in 0..events.read {
                    if buffers[i].len() < std::mem::size_of::<PacketInfo>() { continue; }
                    let info = unsafe { &*(buffers[i].as_ptr() as *const PacketInfo) };
                    
                    if !quiet {
                        let src = Ipv4Addr::from(info.fast_host_src_addr());
                        let dst = Ipv4Addr::from(info.fast_host_dst_addr());
                        println!("[\x1b[35mBYPASS\x1b[0m] {} -> {} | L3/L4 Mutated", src, dst);
                    }
                }
            }
        });
    }

    if !args.quiet {
        engine::log_event("IDLE", "Stealth Active. Universal bypass engaged.", false);
        println!("\x1b[2mPress Ctrl+C to exit or use --remove.\x1b[0m\n");
    }

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(200)).await;
    }

    if !args.quiet { 
        println!("\n\x1b[33mDetaching shields and restoring network path...\x1b[0m"); 
    }

    for iface in interfaces {
        let _ = Command::new("ip").args(["link", "set", "dev", &iface, "xdp", "off"]).output();
    }

    if !args.quiet {
        println!("[\x1b[32mOK\x1b[0m] ZeroTrace successfully detached.");
    }

    Ok(())
}
