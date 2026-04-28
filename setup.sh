#!/bin/bash
set -e 

echo -e "\x1b[36m--- [1/4] System & Dependency Sync ---\x1b[0m"

sudo apt-get update
sudo apt-get install -y \
    git build-essential pkg-config libssl-dev libelf-dev m4 \
    curl cmake g++ linux-headers-$(uname -r) libc6-dev-i386 \
    golang-go ninja-build libunwind-dev python3 \
    clang llvm lld

echo -e "\x1b[36m--- [2/4] Rust Toolchain Setup ---\x1b[0m"
if ! command -v rustup &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

source "$HOME/.cargo/env" || true

rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker || true

echo -e "\x1b[36m--- [3/4] Source Preparation ---\x1b[0m"
mkdir -p third_party
if [ ! -d "third_party/boring" ]; then
    git clone --recursive https://github.com/cloudflare/boring.git third_party/boring
fi

echo -e "\x1b[36m--- [4/4] Compilation & Deployment ---\x1b[0m"

echo -e "\x1b[33mCompiling XDP Interceptor...\x1b[0m"
cd src/xdp-interceptor
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
cd ../..

echo -e "\x1b[33mCompiling Orchestrator...\x1b[0m"
BORING_BSSL_NO_ASM=1 cargo build --release

if [ -f "target/release/zerotrace" ]; then
    sudo ln -sf "$(pwd)/target/release/zerotrace" /usr/local/bin/zerotrace
    echo -e "\n\x1b[32m[SUCCESS] ZeroTrace Linked Globally.\x1b[0m"
    echo -e "\x1b[2mRun with: sudo zerotrace\x1b[0m"
else
    echo -e "\n\x1b[31m[ERROR] Build failed. Binary not found.\x1b[0m"
    exit 1
fi
