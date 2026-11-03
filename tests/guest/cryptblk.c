// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SIZE (14 * 256 * 1024)
static unsigned char pattern(size_t i) { return (i * 7 + (i / 4096) * 19 + (i >> 8)) & 255; }
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int bench = !strncmp(argv[2], "bench-", 6);
    int write_mode = bench || !strcmp(argv[2], "write") || !strcmp(argv[2], "hammer");
    int wrong = !strcmp(argv[2], "wrong");
    int fd = open(argv[1], (write_mode ? O_RDWR : O_RDONLY) | O_DIRECT);
    if (fd < 0) { perror("open"); return 1; }
    unsigned char *buf, *readback;
    if (posix_memalign((void **)&buf, 4096, SIZE) || posix_memalign((void **)&readback, 4096, SIZE)) return 1;
    for (size_t i = 0; i < SIZE; i++) buf[i] = pattern(i);
    if (bench) {
        // Allocate and warm the same 56 MiB extent before either timing.
        for (int n = 0; n < 16; n++) {
            if (pwrite(fd, buf, SIZE, (off_t)n * SIZE) != SIZE) { perror("benchmark warmup"); return 1; }
        }
        if (fsync(fd)) { perror("benchmark warmup flush"); return 1; }
        for (int write = 1; write >= 0; write--) {
            double start = now();
            for (int n = 0; n < 64; n++) {
                off_t offset = (off_t)(n % 16) * SIZE;
                ssize_t done = write ? pwrite(fd, buf, SIZE, offset) : pread(fd, readback, SIZE, offset);
                if (done != SIZE) { perror("benchmark I/O"); return 1; }
            }
            if (write && fsync(fd)) { perror("benchmark flush"); return 1; }
            double elapsed = now() - start;
            printf("BENCH: disk %s sequential %s: %.1f MiB/s (224 MiB, O_DIRECT)\n",
                argv[2] + 6, write ? "write" : "read", 224.0 / elapsed);
        }
        return memcmp(buf, readback, SIZE) != 0;
    }
    size_t bytes = !strcmp(argv[2], "probe") ? 4096 : SIZE;
    do {
        if (write_mode && (pwrite(fd, buf, bytes, 0) != (ssize_t)bytes || fsync(fd))) { perror("write/flush"); return 1; }
        if (pread(fd, readback, bytes, 0) != (ssize_t)bytes) { perror("read"); return 1; }
        int equal = !memcmp(buf, readback, bytes);
        if (equal == wrong) { fprintf(stderr, "unexpected data with %s key\n", wrong ? "wrong" : "right"); return 1; }
        puts("CRYPTVM: data ok"); fflush(stdout);
    } while (!strcmp(argv[2], "hammer"));
    free(buf); free(readback); close(fd);
    return 0;
}
