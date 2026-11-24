/* Count non-zero bytes in a file (used by init-vm dmacheck). */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    static uint64_t buf[131072]; /* 1 MiB */
    int fd;
    ssize_t n;
    unsigned long long count = 0;

    if (argc != 2)
        return 2;
    fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 1;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        size_t words = (size_t)n / sizeof(uint64_t);
        size_t tail = (size_t)n % sizeof(uint64_t);
        const uint8_t *p;
        for (size_t i = 0; i < words; i++) {
            uint64_t v = buf[i];
            if (v) {
                for (int b = 0; b < 8; b++)
                    count += ((v >> (b * 8)) & 0xff) != 0;
            }
        }
        p = (const uint8_t *)(buf + words);
        for (size_t i = 0; i < tail; i++)
            count += p[i] != 0;
    }
    close(fd);
    if (n < 0)
        return 1;
    printf("%llu\n", count);
    return 0;
}
