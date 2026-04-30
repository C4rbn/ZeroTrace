TARGET_BIN = target/release/zerotrace

all: build obfuscate finalize

build:
	@echo "[*] Generating BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
	@echo "[*] Compiling with Cargo..."
	cargo build --release

obfuscate:
	@echo "[!] Scrambling BPF Map Names in Rust Skeleton..."
	# Replace map names 'c_m' and 'p_m' with random identifiers in the generated skeleton
	find target/release/build/ -name "zerotrace.skel.rs" -exec sed -i 's/c_m/x1_map/g' {} +
	find target/release/build/ -name "zerotrace.skel.rs" -exec sed -i 's/p_m/x2_map/g' {} +
	@echo "[!] Running XOR Obfuscator on Binary..."
	python3 obfuscate_strings.py $(TARGET_BIN)

finalize:
	@echo "[*] Stripping and Hardening..."
	strip --strip-all $(TARGET_BIN)
	sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_sys_ptrace,cap_bpf+ep $(TARGET_BIN)
