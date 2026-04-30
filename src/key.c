#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    uint16_t secret = (uint16_t)((now_ns >> 35) ^ SEED);

    char pkt[1024];
    struct iphdr *ip = (struct iphdr *)pkt;
    memset(pkt, 0, 1024);

    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = sizeof(struct iphdr);
    ip->id = htons(secret);
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr("1.1.1.1");
    ip->daddr = sin.sin_addr.s_addr;

    sendto(fd, pkt, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    printf("[+] Knock sent to %s (ID: 0x%X)\n", argv[1], secret);
    return 0;
}
