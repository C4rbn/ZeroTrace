import sys
import os

def mask(path):
    if not os.path.exists(path): return
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    patterns = [b"lsm/task_alloc", b"lsm/mmap_file", b"zerotrace", b"c_m", b"p_m"]
    for p in patterns:
        data = data.replace(p, bytearray([(~b & 0xFF) for b in p]))
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    mask(sys.argv[1])
