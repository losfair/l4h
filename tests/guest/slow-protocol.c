// Exercise Slow Protocol isolation through a real guest port.
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long milliseconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void event(const char *name, int index) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    printf("SLOWPROTO: %s ifindex=%d time=%ld.%03ld\n", name, index, ts.tv_sec, ts.tv_nsec / 1000000);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int probe = !strcmp(argv[2], "probe");
    int physical = !strcmp(argv[2], "physical-watch");
    int fd = socket(AF_PACKET, SOCK_RAW, htons(3));
    if (fd < 0) { perror("socket"); return 2; }
    struct ifreq req = {0};
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", argv[1]);
    if (ioctl(fd, SIOCGIFHWADDR, &req)) { perror("MAC"); return 2; }
    struct sockaddr_ll addr = {.sll_family = AF_PACKET, .sll_protocol = htons(3),
                              .sll_ifindex = if_nametoindex(argv[1])};
    if (!addr.sll_ifindex || bind(fd, (void *)&addr, sizeof(addr))) { perror("bind"); return 2; }
    event("READY", addr.sll_ifindex);
    unsigned char frame[60] = {1, 0x80, 0xc2, 0, 0, 2};
    memcpy(frame + 6, req.ifr_hwaddr.sa_data, 6);
    frame[12] = 0x88; frame[13] = 9; frame[14] = 2; frame[15] = 1;
    static const char marker[] = "l4h-slow-probe";
    memcpy(frame + 16, marker, sizeof(marker));
    long end = milliseconds() + 30000, next = 0;
    int armed = 0;
    unsigned received = 0, sent = 0, peer = 0, control_tx = 0, control_rx = 0;
    while (milliseconds() < end) {
        if (probe && milliseconds() >= next) {
            unsigned char output[60]; memcpy(output, frame, sizeof(output));
            if (!armed) {
                memset(output, 0xff, 6); output[13] = 0xb5; output[14] = 1;
            }
            if (send(fd, output, sizeof(output), 0) != sizeof(output)) { perror("send"); return 2; }
            if (armed) ++sent;
            else if (control_tx++ == 0) event("control-ready-tx", addr.sll_ifindex);
            next = milliseconds() + 200;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, 100);
        if (ready < 0 && errno != EINTR) { perror("poll"); return 2; }
        if (ready <= 0) continue;
        unsigned char input[2048]; struct sockaddr_ll from; socklen_t len = sizeof(from);
        ssize_t n = recvfrom(fd, input, sizeof(input), 0, (void *)&from, &len);
        if (n < 14 || from.sll_pkttype == PACKET_OUTGOING) continue;
        if ((size_t)n >= sizeof(frame) && input[12] == 0x88 && input[13] == 0xb5 &&
            !memcmp(input + 16, marker, sizeof(marker))) {
            if (!probe && input[14] == 1) {
                if (control_rx++ == 0) event("control-ready-rx", from.sll_ifindex);
                unsigned char ack[60]; memcpy(ack, input, sizeof(ack));
                memcpy(ack, input + 6, 6); memcpy(ack + 6, req.ifr_hwaddr.sa_data, 6); ack[14] = 2;
                if (send(fd, ack, sizeof(ack), 0) != sizeof(ack)) { perror("ack"); return 2; }
                if (!armed) event("control-ack-tx", addr.sll_ifindex);
                if (!armed) end = milliseconds() + (atoi(argv[3]) + 2) * 1000;
                armed = 1;
            } else if (probe && input[14] == 2 && !armed) {
                event("control-ack-rx", from.sll_ifindex);
                armed = 1; end = milliseconds() + atoi(argv[3]) * 1000;
            }
            continue;
        }
        if (input[12] != 0x88 || input[13] != 9) continue;
        if (memcmp(input, frame, 6)) continue;
        if (n >= 54 && input[14] == 1 && input[15] == 1) ++peer;
        if (probe || ((size_t)n >= 16 + sizeof(marker) && !memcmp(input + 16, marker, sizeof(marker)))) ++received;
    }
    printf("SLOWPROTO: %s handshake=%d sent=%u received=%u peer=%u\n", probe ? "guest" : "dom0", armed, sent, received, peer);
    printf("SLOWPROTO: control-tx=%u control-rx=%u\n", control_tx, control_rx);
    close(fd);
    return !armed || received || (probe && !sent) || (physical && !peer) ? 1 : 0;
}
