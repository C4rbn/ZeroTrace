use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("zerotrace.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/zerotrace.bpf.c")
        .debug(false)
        .build_and_generate(&out)
        .unwrap();
}
