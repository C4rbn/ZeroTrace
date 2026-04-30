CC = clang
ZIG = zig
BPF_OBJ = target/ghost_gate.bpf.o
FINAL_BIN = target/zt_injector

all: clean bpf injector finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -g -c src/bpf/ghost_gate.bpf.c -o $(BPF_OBJ)

injector:
	# Static musl target for zero-dependency portability
	$(ZIG) build-exe src/main.zig \
		-O ReleaseSmall \
		-target x86_64-linux-musl \
		--name $(FINAL_BIN) \
		-fsingle-threaded

finalize:
	# Advanced stripping: Remove all headers and non-critical sections
	strip --strip-all --remove-section=.comment --remove-section=.note $(FINAL_BIN)
	# UPX Brute compression for minimum size
	upx --ultra-brute $(FINAL_BIN)
	# Cap-set for kernel injection
	sudo setcap cap_net_admin,cap_sys_admin,cap_bpf+ep $(FINAL_BIN)

clean:
	rm -rf target
