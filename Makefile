BINARY_NAME=zerotrace
BUILD_DIR=target/release
DEST_DIR=/usr/local/bin

all: build

build:
	cargo build --release
	strip $(BUILD_DIR)/$(BINARY_NAME)

install: build
	sudo rm -f $(DEST_DIR)/$(BINARY_NAME)
	sudo install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(DEST_DIR)/$(BINARY_NAME)
	sudo setcap cap_net_raw,cap_net_admin,cap_bpf+ep $(DEST_DIR)/$(BINARY_NAME)

uninstall:
	sudo rm -f $(DEST_DIR)/$(BINARY_NAME)

clean:
	cargo clean
