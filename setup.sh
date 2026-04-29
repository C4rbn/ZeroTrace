#!/bin/bash
set -e
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_LIKE=$ID_LIKE
else
    OS=$(uname -s)
fi
if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "kali" || "$OS_LIKE" == *"debian"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev libelf-dev \
        clang llvm m4 curl libbpf-dev linux-tools-common linux-tools-generic
    if [[ "$OS" == "kali" ]]; then
        sudo apt-get install -y linux-headers-amd64
    else
        sudo apt-get install -y linux-headers-$(uname -r)
    fi
elif [[ "$OS" == "arch" || "$OS_LIKE" == *"arch"* ]]; then
    sudo pacman -Syu --needed base-devel clang llvm libelf libbpf bpftool linux-headers curl
elif [[ "$OS" == "fedora" ]]; then
    sudo dnf install -y gcc make pkgconf-pkg-config openssl-devel elfutils-libelf-devel \
        clang llvm m4 curl libbpf-devel bpftool kernel-devel
fi
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    rustup update
fi
