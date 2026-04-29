#!/bin/bash
set -e

# ZeroTrace Industrial Setup Script
# Target: x86_64 Linux (Kernel 5.4+)

export DEBIAN_FRONTEND=noninteractive

# Colors for status reporting
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}--- [1/3] Environment Validation & Dependencies ---${NC}"

# Ensure running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[ERROR] ZeroTrace requires a Linux environment for XDP/eBPF.${NC}"
    exit 1
fi

sudo apt-get update -y
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libelf-dev \
    clang \
    llvm \
    m4 \
    curl \
    linux-headers-$(uname -r) \
    libunwind-dev \
    bpftool

echo -e "${CYAN}--- [2/3] Rust Toolchain Provisioning ---${NC}"

if ! command -v rustup &> /dev/null; then
    echo -e "${YELLOW}Rust not found. Installing...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

source "$HOME/.cargo/env" || true

# We use stable for the orchestrator, build.rs handles the BPF C compilation
rustup toolchain install stable
rustup default stable

echo -e "${CYAN}--- [3/3] Industrial Build & Deployment ---${NC}"

# Clean old artifacts if they exist
cargo clean

echo -e "${YELLOW}Compiling ZeroTrace Engine...${NC}"
# build.rs will automatically invoke clang to compile src/xdp-interceptor/interceptor.bpf.c
cargo build --release

if [ -f "target/release/zerotrace" ]; then
    # Link to /usr/local/bin for global access
    sudo ln -sf "$(pwd)/target/release/zerotrace" /usr/local/bin/zerotrace
    
    # Grant net_admin capabilities so it can manage XDP/Raw Sockets
    sudo setcap cap_net_admin,cap_net_raw,cap_ipc_lock+ep "$(pwd)/target/release/zerotrace"
    
    echo -e "\n${GREEN}[SUCCESS] ZeroTrace binary deployed to /usr/local/bin/zerotrace${NC}"
    echo -e "${GREEN}[SUCCESS] Capabilities granted. Run without full sudo if preferred.${NC}"
    echo -e "\n${YELLOW}Usage: zerotrace --quiet${NC}"
else
    echo -e "\n${RED}[ERROR] Build failed. Check clang/rustc output above.${NC}"
    exit 1
fi
