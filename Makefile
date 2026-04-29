BINARY_NAME=zerotrace
TARGET_PATH=target/release/$(BINARY_NAME)
INSTALL_PATH=/usr/local/bin/$(BINARY_NAME)

all: build

build:
	cargo build --release
	strip $(TARGET_PATH)

install: build
	sudo rm -f $(INSTALL_PATH)
	sudo cp $(TARGET_PATH) $(INSTALL_PATH)
	sudo chmod 755 $(INSTALL_PATH)
	sudo setcap cap_net_raw,cap_net_admin,cap_bpf+ep $(INSTALL_PATH)

uninstall:
	sudo rm -f $(INSTALL_PATH)

clean:
	cargo clean
