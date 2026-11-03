// SPDX-License-Identifier: GPL-2.0-only
// Sequential (3.5 MiB O_DIRECT) and 4 KiB QD1 random I/O, with guest CPU use.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SIZE (14 * 256 * 1024)
#define EXTENT 16
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
static void cpu(unsigned long long *busy, unsigned long long *total) {
    unsigned long long v[10] = {0};
    FILE *f = fopen("/proc/stat", "r");
    if (!f || fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) != 8) exit(3);
    fclose(f);
    *total = 0;
    for (int i = 0; i < 8; i++) *total += v[i];
    *busy = *total - v[3] - v[4];
}
static unsigned long long b0, t0;
static void start_cpu(void) { cpu(&b0, &t0); }
static double cpu_pct(void) {
    unsigned long long b, t;
    cpu(&b, &t);
    // Percent of one vCPU.
    return t == t0 ? 0 : 100.0 * (b - b0) / (t - t0) * sysconf(_SC_NPROCESSORS_ONLN);
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const char *tag = argv[2];
    int fd = open(argv[1], O_RDWR | O_DIRECT);
    if (fd < 0) { perror("open"); return 1; }
    unsigned char *buf, *rb;
    if (posix_memalign((void **)&buf, 4096, SIZE) || posix_memalign((void **)&rb, 4096, SIZE)) return 1;
    for (size_t i = 0; i < SIZE; i++) buf[i] = (i * 7 + (i >> 12) * 19) & 255;
    for (int n = 0; n < EXTENT; n++)
        if (pwrite(fd, buf, SIZE, (off_t)n * SIZE) != SIZE) { perror("warmup"); return 1; }
    if (fsync(fd)) { perror("fsync"); return 1; }
    for (int write = 1; write >= 0; write--) {
        start_cpu();
        double s = now();
        for (int n = 0; n < 64; n++) {
            off_t off = (off_t)(n % EXTENT) * SIZE;
            if ((write ? pwrite(fd, buf, SIZE, off) : pread(fd, rb, SIZE, off)) != SIZE) { perror("seq"); return 1; }
        }
        if (write && fsync(fd)) return 1;
        double e = now() - s;
        printf("RESULT %s seq-%s %.1f MiB/s cpu=%.0f%%\n", tag, write ? "write" : "read", 224.0 / e, cpu_pct());
        fflush(stdout);
    }
    if (memcmp(buf, rb, SIZE)) { printf("RESULT %s MISMATCH\n", tag); return 1; }
    unsigned seed = 1;
    for (int write = 0; write <= 1; write++) {
        start_cpu();
        double s = now(), e;
        long ops = 0;
        do {
            for (int k = 0; k < 256; k++, ops++) {
                seed = seed * 1103515245 + 12345;
                off_t off = (off_t)((seed >> 8) % (EXTENT * SIZE / 4096)) * 4096;
                if ((write ? pwrite(fd, buf, 4096, off) : pread(fd, rb, 4096, off)) != 4096) { perror("rand"); return 1; }
            }
        } while ((e = now() - s) < 3.0);
        printf("RESULT %s rand4k-%s %.0f IOPS %.1f us cpu=%.0f%%\n", tag, write ? "write" : "read", ops / e, e / ops * 1e6, cpu_pct());
        fflush(stdout);
    }
    return 0;
}
