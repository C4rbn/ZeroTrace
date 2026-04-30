#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void xor_cipher(uint8_t *data, size_t len, uint32_t seed) {
    uint32_t k = seed;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k + 0x9E3779B9;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    
    FILE *f = fopen(argv[1], "rb+");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    uint8_t *buf = malloc(size);
    fread(buf, 1, size, f);

    uint32_t seed = (uint32_t)strtoul(argv[2], NULL, 16);
    xor_cipher(buf, size, seed);

    rewind(f);
    fwrite(buf, 1, size, f);
    fclose(f);
    free(buf);
    return 0;
}
