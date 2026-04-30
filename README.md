# ZeroTrace

**ZeroTrace** is a high-performance eBPF/XDP stealth engine designed for driver-level network orchestration. It enables hardware-synchronized packet mutation and protocol obfuscation, bypassing the standard Linux networking stack to neutralize Deep Packet Inspection (DPI) and fingerprinting.

## Key Features

*   **Ghost Memory Execution:** Runs entirely in RAM via `memfd_create`. The binary unlinks itself from the disk immediately upon execution.
*   **XDP Shield:** Attaches anonymous BPF interceptors to all active interfaces for line-rate packet mutation.
*   **Kernel Masking:** Leverages `prctl` to camouflage the userspace process as a legitimate kernel worker (`kworker`).
*   **Static & Portable:** Built with a self-contained `libelf` pipeline. Runs on any Kernel 5.x+ without external library dependencies.
*   **Remote Kill-Switch:** Integrated mechanism to instantly purge all BPF programs and memory footprints via a trigger packet.

## Technical Architecture



1.  **The Engine (Loader):** A C-based orchestrator that handles ELF relocation, memory encryption, and BPF lifecycle management.
2.  **The Shield (XDP):** A driver-level program that performs packet modification and signal neutralization at the NIC level.

## Deployment

### 1. Prerequisites
Install the toolchain required for static compilation:
```bash
sudo apt update && sudo apt install clang llvm libelf-dev zlib1g-dev libzstd-dev
```

### 2. Build
Every build utilizes a seed-based XOR obfuscator to randomize the BPF bytecode, ensuring no two binaries share the same signature.
```bash
git clone https://github.com/your-repo/ZeroTrace.git
cd ZeroTrace
make
```

### 3. Execution
Run the engine with root privileges to attach the XDP shields:
```bash
sudo ./target/systemd-update
```

## Operational Security (OPSEC)

*   **Self-Deletion:** The physical binary is deleted from the filesystem once the process is resident in memory.
*   **Anonymous Progs:** XDP programs are loaded without names to minimize visibility in standard BPF profiling tools.
*   **Zero-Dependency:** Static linking ensures the engine remains environment-agnostic.

## Disclaimer
This framework is intended for authorized security auditing and network research only. The developers assume no liability for misuse. Use responsibly.
