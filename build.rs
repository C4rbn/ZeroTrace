use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir).join("interceptor.o");

    println!("cargo:rerun-if-changed=src/xdp-interceptor/interceptor.bpf.c");

    let status = Command::new("clang")
        .args([
            "-O2",
            "-target", "bpf",
            "-D__TARGET_ARCH_x86",
            "-c", "src/xdp-interceptor/interceptor.bpf.c",
            "-o", out_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute clang. Ensure clang is installed and in PATH.");

    if !status.success() {
        panic!("Clang failed to compile the BPF program.");
    }
}
