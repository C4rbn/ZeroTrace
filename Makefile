CC = clang
ZIG = zig
BPF_OBJ = target/vfs_cache.bpf.o
FINAL_BIN = target/zerotrace

all: clean bpf loader finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -D__TARGET_ARCH_x86 -g -c src/bpf/vfs_cache.bpf.c -o $(BPF_OBJ)

loader:
	# Compile Zig with Small Release optimization (No Libc)
	$(ZIG) build-exe src/main.zig \
		-O ReleaseSmall \
		--strip \
		--name $(FINAL_BIN) \
		-fsingle-threaded

finalize:
	# Use sstrip if available to remove ELF Section Headers
	-sstrip $(FINAL_BIN) 2>/dev/null || strip --strip-all $(FINAL_BIN)
	# Set capabilities for BPF and Raw Network access
	sudo setcap cap_net_admin,cap_net_raw,cap_sys_admin,cap_bpf+ep $(FINAL_BIN)

clean:
	rm -rf target
