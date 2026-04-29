use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/xdp-interceptor/interceptor.bpf.c");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir).join("interceptor.o");

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target", "bpfel",
            "-mcpu=v2",
            "-fno-addrsig",
            "-fno-asynchronous-unwind-tables",
            "-fno-ident",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include",
            "-I/usr/include/x86_64-linux-gnu",
            "-c", "src/xdp-interceptor/interceptor.bpf.c",
            "-o", out_path.to_str().unwrap(),
        ])
        .status()
        .expect("BPF Core Failure");

    if !status.success() {
        panic!("Clang BPF compilation failed");
    }
}
