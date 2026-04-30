CC = clang
ZIG = zig
BPF_OBJ = target/ghost.o
FINAL = target/zt
SEED = $(shell head -c 4 /dev/urandom | xxd -p)

all: clean bpf injector finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -DSEED=0x$(SEED) -g0 -c src/bpf/ghost.c -o $(BPF_OBJ)
	python3 -c "d=open('$(BPF_OBJ)','rb').read();open('$(BPF_OBJ)','wb').write(bytearray([b^0x7A for b in d]))"

injector:
	$(ZIG) build-exe src/main.zig \
		-Dseed=0x$(SEED) \
		-target x86_64-linux-musl \
		-O ReleaseSmall \
		--strip \
		-fno-compiler-rt \
		-fno-stack-check \
		--name $(FINAL)

finalize:
	strip --strip-all --remove-section=.comment --remove-section=.note $(FINAL)
	# No setcap here; use sudo ./zt to execute

clean:
	rm -rf target
