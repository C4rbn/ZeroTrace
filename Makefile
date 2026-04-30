CC = clang
ZIG = zig
BPF_OBJ = target/ghost.o
SEED = $(shell head -c 4 /dev/urandom | xxd -p)

all: clean bpf injector key finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -DSEED=0x$(SEED) -g0 -c src/bpf/ghost.c -o $(BPF_OBJ)
	python3 -c "d=open('$(BPF_OBJ)','rb').read();open('$(BPF_OBJ)','wb').write(bytearray([b^0x7A for b in d]))"

injector:
	$(ZIG) build-exe src/main.zig -target x86_64-linux-musl -O ReleaseSmall --strip --name target/zt

key:
	$(CC) -O3 src/key.c -DSEED=0x$(SEED) -o target/key

finalize:
	strip --strip-all target/zt
	strip --strip-all target/key

clean:
	rm -rf target
