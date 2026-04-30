#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// Usage: ./key <target_ip> <port>
// Ports: 1337 (Authorize), 65535 (Self-Destruct)

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(atoi(argv[2]));
    target.sin_addr.s_addr = inet_addr(argv[1]);

    const char *payload = "\xde\xad\xbe\xef"; // Dummy data
    sendto(sock, payload, strlen(payload), 0, (struct sockaddr *)&target, sizeof(target));

    printf("[+] Packet sent to %s:%s\n", argv[1], argv[2]);
    close(sock);
    return 0;
}
