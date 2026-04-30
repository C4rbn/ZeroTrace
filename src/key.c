#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 4) return 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in t = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[3])), .sin_addr.s_addr = inet_addr(argv[1]) };
    sendto(s, "\x01", 1, 0, (struct sockaddr *)&t, sizeof(t));
    close(s);
    return 0;
}
