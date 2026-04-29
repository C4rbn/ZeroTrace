#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

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
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-tools-generic

if ! command -v rustup &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

source "$HOME/.cargo/env" || true

rustup toolchain install stable
rustup default stable

cargo clean
cargo build --release

if [ -f "target/release/zerotrace" ]; then
    sudo ln -sf "$(pwd)/target/release/zerotrace" /usr/local/bin/zerotrace
    sudo setcap cap_net_admin,cap_net_raw,cap_ipc_lock+ep "$(pwd)/target/release/zerotrace"
    echo "ZeroTrace deployed to /usr/local/bin/zerotrace"
else
    echo "Build failed"
    exit 1
fi
