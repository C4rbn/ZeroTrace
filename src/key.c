#include <stdio.h>
#include <stdint.h>
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

    uint16_t secret = (uint16_t)((time(NULL) / 30) ^ SEED);

    char pkt[64];
    struct iphdr *ip = (struct iphdr *)pkt;
    memset(pkt, 0, 64);
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = sizeof(struct iphdr);
    ip->id = htons(secret);
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr("8.8.8.8");
    ip->daddr = sin.sin_addr.s_addr;

    sendto(fd, pkt, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    return 0;
}
