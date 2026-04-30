#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void x(uint8_t *d, size_t l, uint32_t s) {
    uint32_t k = s;
    for (size_t i = 0; i < l; i++) {
        d[i] ^= (uint8_t)(k & 0xFF);
        k = (k >> 8) | (k << 24);
        k = k + 0x9E3779B9;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    FILE *f = fopen(argv[1], "rb+");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    size_t s = ftell(f);
    rewind(f);
    uint8_t *b = malloc(s);
    if (fread(b, 1, s, f)) {
        x(b, s, (uint32_t)strtoul(argv[2], NULL, 16));
        rewind(f);
        fwrite(b, 1, s, f);
    }
    fclose(f);
    return 0;
}
