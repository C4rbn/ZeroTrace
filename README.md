# ZeroTrace

ZeroTrace is a high-performance network orchestration framework designed for deep-packet stealth and protocol obfuscation. By utilizing eBPF and XDP at the driver level, it enables hardware-synchronized packet mutation before traffic enters the standard Linux networking stack.

The software is designed for security researchers and network engineers who require precise control over Layer 3/4 fingerprints and Layer 7 header transparency.

## Capabilities

* **XDP Mutation:** Driver-level packet modification for bypassing deep packet inspection.
* **Hardware Synchronization:** Timing-accurate dispatching utilizing CPU cycles for stealth.
* **Multi-CPU Telemetry:** Asynchronous monitoring of mutated traffic via BPF perf arrays.
* **L7 Shuffling:** Dynamic header randomization and TLS GREASE implementation to prevent fingerprinting.
* **Portable Execution:** Self-contained orchestrator with automated environment hardening and dependency sync.

## Installation

The project includes a unified setup script to handle toolchain hardening and BPF compilation.

```bash
git clone https://github.com/your-repo/ZeroTrace.git
cd ZeroTrace
chmod +x setup.sh
./setup.sh
```

## Usage

Running ZeroTrace requires root privileges to attach XDP programs to network interfaces.

```bash
sudo zerotrace
```

### Options

* `-h, --help`: Display the help menu and exit.
* `-q, --quiet`: Silence non-critical telemetry logs.
* `-r, --remove`: Detach all ZeroTrace shields and restore default network paths.

## Technical Architecture

ZeroTrace operates by injecting an XDP interceptor into the network driver. This interceptor utilizes a BPF map (`PACKET_EVENTS`) to communicate with the Rust-based orchestrator. The orchestrator manages the lifecycle of the BPF programs and provides real-time telemetry of mutated traffic.

## Licensing

ZeroTrace is released for authorized security auditing and research purposes. Users are responsible for ensuring compliance with local regulations and network policies.

## Contributing

Technical contributions regarding BPF optimization or new protocol crafters are welcome. Please refer to the source documentation for information on the `PacketInfo` synchronization struct and the stealth engine logic.
