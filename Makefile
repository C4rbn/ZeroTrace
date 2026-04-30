TARGET_BIN = target/release/zerotrace

all: build scramble finalize

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
	cargo build --release

scramble:
	find target/release/build/ -name "zerotrace.skel.rs" -exec sed -i 's/c_m/x1/g' {} +
	find target/release/build/ -name "zerotrace.skel.rs" -exec sed -i 's/p_m/x2/g' {} +
	python3 obfuscate_metadata.py $(TARGET_BIN)

finalize:
	strip --strip-all $(TARGET_BIN)
	sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_sys_ptrace,cap_bpf+ep $(TARGET_BIN)
