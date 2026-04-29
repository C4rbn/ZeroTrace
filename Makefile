BINARY_NAME=zerotrace
TARGET_DIR=target/release
INSTALL_PATH=/usr/local/bin

all: build

build:
	cargo build --release

install: build
	sudo cp $(TARGET_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	sudo setcap cap_net_raw,cap_net_admin,cap_bpf+ep $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "[SUCCESS] $(BINARY_NAME) installed to $(INSTALL_PATH)"
	@echo "[INFO] You can now run it by simply typing: $(BINARY_NAME)"

uninstall:
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)

clean:
	cargo clean
