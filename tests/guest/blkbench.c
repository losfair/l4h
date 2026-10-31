// SPDX-License-Identifier: GPL-2.0-only
// Compare direct block I/O on the same disposable disk and CPU placement.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libaio.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define BS 4096
#define REGION (8 * 1024 * 1024)
#define JOBS 4
static pthread_barrier_t barrier;
static const char *device;
static int depth, seconds, first_cpu, write_io;
struct job { int id, error; uint64_t ops; double elapsed; };
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static void die(const char *s) { perror(s); exit(1); }
static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static void sync_bench(const char *op, int duration, int cpu) {
    enum { LIMIT = 1000000 };
    int direct = !strcmp(op, "direct-fsync");
    int data_only = !strcmp(op, "fdatasync");
    int metadata = !strcmp(op, "metadata-fsync");
    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) die("CPU affinity");
    int fd = open(device, O_RDWR | (direct ? O_DIRECT : 0));
    void *buf = NULL;
    double *samples = calloc(LIMIT, 3 * sizeof(double));
    if (fd < 0 || !samples || posix_memalign(&buf, BS, BS)) die("sync setup");
    memset(buf, 0x6d, BS);
    printf("BLKPHASE: BEGIN %s %s cpu%d\n", op, device, cpu); fflush(stdout);
    usleep(250000); /* Allow the host to snapshot block counters before I/O. */
    size_t n = 0;
    double write_sum = 0, sync_sum = 0, cycle_sum = 0;
    double start = now();
    do {
        ((uint64_t *)buf)[0] = n;
        double a = now();
        if (pwrite(fd, buf, BS, 0) != BS) die("sync write");
        if (metadata) {
            const struct timespec times[2] = {{0, UTIME_OMIT}, {1700000000, (long)n}};
            if (futimens(fd, times)) die("sync metadata");
        }
        double b = now();
        if (data_only ? fdatasync(fd) : fsync(fd)) die("sync");
        double c = now();
        samples[n] = (b - a) * 1e6;
        samples[LIMIT + n] = (c - b) * 1e6;
        samples[2 * LIMIT + n] = (c - a) * 1e6;
        write_sum += samples[n]; sync_sum += samples[LIMIT + n]; cycle_sum += samples[2 * LIMIT + n];
        n++;
    } while (n < LIMIT && now() - start < duration);
    double elapsed = now() - start;
    for (int i = 0; i < 3; i++) qsort(samples + i * LIMIT, n, sizeof(double), compare_double);
    printf("BLKBENCH: {\"op\":\"%s\",\"target\":\"%s\",\"cpu\":%d,\"block_bytes\":4096,\"offset\":0,\"operations\":%zu,\"seconds\":%.6f,\"iops\":%.1f,\"write_mean_us\":%.3f,\"sync_mean_us\":%.3f,\"cycle_mean_us\":%.3f,\"sync_p50_us\":%.3f,\"sync_p95_us\":%.3f,\"sync_p99_us\":%.3f,\"cycle_p50_us\":%.3f,\"cycle_p95_us\":%.3f,\"cycle_p99_us\":%.3f,\"sample_limit_reached\":%s,\"ok\":true}\n",
           op, device, cpu, n, elapsed, n / elapsed, write_sum / n, sync_sum / n, cycle_sum / n,
           samples[LIMIT + (n - 1) * 50 / 100], samples[LIMIT + (n - 1) * 95 / 100],
           samples[LIMIT + (n - 1) * 99 / 100], samples[2 * LIMIT + (n - 1) * 50 / 100],
           samples[2 * LIMIT + (n - 1) * 95 / 100], samples[2 * LIMIT + (n - 1) * 99 / 100], n == LIMIT ? "true" : "false");
    printf("BLKPHASE: END %s %s cpu%d\n", op, device, cpu); fflush(stdout);
    usleep(250000);
    close(fd); free(buf); free(samples);
}
static void pattern(uint64_t *buf, int job, size_t page) {
    for (int i = 0; i < BS / 8; i++) buf[i] = UINT64_C(0x123456789abc0000) ^ ((uint64_t)job << 48) ^ (page * 512 + i);
}
static void *check(void *arg) {
    struct job *j = arg;
    int fd = open(device, O_RDWR | O_DIRECT);
    void *buf = NULL, *expected = NULL;
    if (fd < 0 || posix_memalign(&buf, BS, BS) || posix_memalign(&expected, BS, BS)) die("check setup");
    for (size_t p = 0; p < REGION / BS; p++) {
        pattern(expected, j->id, p);
        off_t offset = (off_t)j->id * REGION + p * BS;
        if (write_io && pwrite(fd, expected, BS, offset) != BS) die("pattern write");
        if (pread(fd, buf, BS, offset) != BS || memcmp(buf, expected, BS)) { j->error = 1; break; }
    }
    if (write_io && fdatasync(fd)) die("pattern sync");
    close(fd); free(buf); free(expected); return NULL;
}
static void *run(void *arg) {
    struct job *j = arg;
    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(first_cpu + j->id, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) die("CPU affinity");
    int fd = open(device, O_RDWR | O_DIRECT);
    io_context_t ctx = 0;
    void *data = NULL;
    if (fd < 0 || io_setup(depth, &ctx) || posix_memalign(&data, BS, (size_t)depth * BS)) die("AIO setup");
    memset(data, 0x5a, (size_t)depth * BS);
    struct iocb *requests = calloc(depth, sizeof(*requests));
    struct iocb **pending = calloc(depth, sizeof(*pending));
    struct io_event *events = calloc(depth, sizeof(*events));
    if (!requests || !pending || !events) die("AIO allocations");
    uint64_t rng = 0xdeadbeef + j->id;
    pthread_barrier_wait(&barrier);
    double start = now(), end = start + seconds;
    int active = 0, count = depth;
    for (int i = 0; i < depth; i++) pending[i] = &requests[i];
    while (count || active) {
        for (int i = 0; i < count; i++) {
            struct iocb *r = pending[i];
            size_t slot = (size_t)(r - requests);
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            off_t offset = (off_t)j->id * REGION + (rng % (REGION / BS)) * BS;
            if (write_io) io_prep_pwrite(r, fd, (char *)data + slot * BS, BS, offset);
            else io_prep_pread(r, fd, (char *)data + slot * BS, BS, offset);
        }
        int submitted = 0;
        while (submitted < count) {
            int n = io_submit(ctx, count - submitted, pending + submitted);
            if (n <= 0) { fprintf(stderr, "io_submit: %d\n", n); exit(1); }
            submitted += n; active += n;
        }
        count = 0;
        if (!active) break;
        int n = io_getevents(ctx, 1, depth, events, NULL);
        if (n <= 0) { fprintf(stderr, "io_getevents: %d\n", n); exit(1); }
        active -= n;
        int again = now() < end;
        for (int i = 0; i < n; i++) {
            if ((long)events[i].res != BS || events[i].res2) { fprintf(stderr, "I/O result: %ld\n", (long)events[i].res); exit(1); }
            j->ops++;
            if (again) pending[count++] = events[i].obj;
        }
    }
    j->elapsed = now() - start;
    if (io_destroy(ctx)) die("io_destroy");
    close(fd); free(data); free(requests); free(pending); free(events); return NULL;
}
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: blkbench read|write|check|verify PATH [jobs depth seconds first_cpu]\n       blkbench fsync|direct-fsync|fdatasync|metadata-fsync PATH seconds cpu\n"); return 2; }
    device = argv[2];
    if (!strcmp(argv[1], "fsync") || !strcmp(argv[1], "direct-fsync") || !strcmp(argv[1], "fdatasync") || !strcmp(argv[1], "metadata-fsync")) {
        int duration = argc == 5 ? atoi(argv[3]) : 0;
        int cpu = argc == 5 ? atoi(argv[4]) : -1;
        if (duration < 1 || cpu < 0 || cpu >= 4) return 2;
        sync_bench(argv[1], duration, cpu);
        return 0;
    }
    int checking = !strcmp(argv[1], "check") || !strcmp(argv[1], "verify");
    write_io = !strcmp(argv[1], "write") || !strcmp(argv[1], "check");
    int jobs = checking ? JOBS : argc == 7 ? atoi(argv[3]) : 0;
    depth = checking ? 1 : argc == 7 ? atoi(argv[4]) : 0;
    seconds = argc == 7 ? atoi(argv[5]) : 0;
    first_cpu = argc == 7 ? atoi(argv[6]) : 0;
    if (jobs < 1 || jobs > JOBS || depth < 1 || depth > 32 || (!checking && (seconds < 1 || first_cpu < 0 || first_cpu + jobs > 4))) return 2;
    pthread_t threads[JOBS]; struct job state[JOBS] = {0};
    pthread_barrier_init(&barrier, NULL, jobs);
    for (int i = 0; i < jobs; i++) { state[i].id = i; if (pthread_create(&threads[i], NULL, checking ? check : run, &state[i])) die("pthread_create"); }
    double iops = 0;
    for (int i = 0; i < jobs; i++) { pthread_join(threads[i], NULL); if (state[i].error) { fprintf(stderr, "pattern mismatch job %d\n", i); return 1; } if (!checking) iops += state[i].ops / state[i].elapsed; }
    printf("BLKBENCH: {\"op\":\"%s\",\"jobs\":%d,\"depth\":%d,\"cpu\":%d,\"iops\":%.1f,\"ok\":true}\n", argv[1], jobs, depth, first_cpu, iops);
    return 0;
}
