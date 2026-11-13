/* An interactive guest must wake between a guarded spinner's refills,
 * including when the manager sampled it asleep. Run before starting HOG. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(1); }
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int compare(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    enum { N = 200 };
    uint64_t delay[N], start = now_ns();
    for (unsigned i = 0; i < N; i++) {
        uint64_t deadline = start + (i + 1) * UINT64_C(10000000);
        struct timespec ts = { .tv_sec = deadline / 1000000000, .tv_nsec = deadline % 1000000000 };
        int error;
        while ((error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL)) == EINTR) {}
        if (error) { fprintf(stderr, "VMMWAKE: clock_nanosleep error %d\n", error); return 1; }
        uint64_t now = now_ns();
        delay[i] = now > deadline ? now - deadline : 0;
    }
    qsort(delay, N, sizeof(delay[0]), compare);
    printf("VMMWAKE: p99=%" PRIu64 " us max=%" PRIu64 " us\n", delay[N*99/100-1]/1000, delay[N-1]/1000);
    if (delay[N-1] >= UINT64_C(50000000)) {
        puts("VMMWAKE: FAIL: guest waited for the manager's 100 ms sample");
        return 1;
    }
    puts("VMMWAKE: PASS");
    return 0;
}
