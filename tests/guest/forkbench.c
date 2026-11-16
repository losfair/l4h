// Fork lifecycle controls for the FL4 contention investigation.
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_WORKERS 16
#define PROFILE_SYSCALL 0x4c344650
struct result { uint64_t start, end, fork_ticks, wait_ticks; };
static int cpus[MAX_WORKERS];
static int mode;
static void check(int ok, const char *what)
{
    if (!ok) { fprintf(stderr, "FORKBENCH: FAIL %s: %s\n", what, strerror(errno)); exit(1); }
}
static uint64_t ticks(void)
{
    unsigned lo, hi;
    __asm__ volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi) :: "memory");
    return (uint64_t)hi << 32 | lo;
}
static uint64_t now(void)
{
    struct timespec t;
    check(!clock_gettime(CLOCK_MONOTONIC, &t), "clock");
    return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static void transfer(int fd, int writing)
{
    char x = 1;
    ssize_t n;
    do { n = writing ? write(fd, &x, 1) : read(fd, &x, 1); } while (n < 0 && errno == EINTR);
    check(n == 1, "barrier");
}
static void reap(pid_t pid)
{
    int status;
    check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status), "waitpid/status");
}
static int child_fn(void *arg) { (void)arg; return 0; }
static void cycle(char *stack, uint64_t *creation, uint64_t *waiting)
{
    uint64_t begin = ticks();
    pid_t child;
    if (mode == 2) child = clone(child_fn, stack + 65536, CLONE_VM | SIGCHLD, NULL);
    else if (mode == 1) child = vfork();
    else child = fork();
    if (!child) _exit(0);
    check(child >= 0, "fork/clone");
    uint64_t middle = ticks();
    reap(child);
    uint64_t end = ticks();
    *creation += middle-begin;
    *waiting += end-middle;
}
int main(int argc, char **argv)
{
    unsigned workers = argc > 1 ? strtoul(argv[1], NULL, 10) : 2;
    unsigned count = argc > 2 ? strtoul(argv[2], NULL, 10) : 2000;
    mode = argc > 3 ? atoi(argv[3]) : 0;
    unsigned force_mask = argc > 4 ? strtoul(argv[4],NULL,0) : 0;
    unsigned profiling = argc > 5 ? strtoul(argv[5],NULL,0) : 1;
    check(workers && workers <= MAX_WORKERS && count && mode >= 0 && mode <= 2, "arguments");
    cpu_set_t available;
    check(!sched_getaffinity(0,sizeof(available),&available), "affinity");
    unsigned found=0;
    for (int cpu=0; cpu<CPU_SETSIZE && found<workers; cpu++)
        if (CPU_ISSET(cpu,&available)) cpus[found++]=cpu;
    check(found == workers,"available CPUs");
    struct result *r=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    check(r!=MAP_FAILED,"shared results");
    memset(r,0,4096);
    pid_t pids[MAX_WORKERS];
    int gates[MAX_WORKERS][2],ready[2];
    check(!pipe(ready),"ready pipe");
    for (unsigned i=0;i<workers;i++) {
        check(!pipe(gates[i]),"gate pipe");
        pids[i]=fork();
        check(pids[i]>=0,"worker fork");
        if(pids[i]) continue;
        cpu_set_t one;
        CPU_ZERO(&one);CPU_SET(cpus[i],&one);
        check(!sched_setaffinity(0,sizeof(one),&one),"pin worker");
        char *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        check(stack!=MAP_FAILED,"child stack");
        memset(stack,0,65536);
        uint64_t a=0,b=0;
        for(unsigned j=0;j<100;j++) cycle(stack,&a,&b);
        transfer(ready[1],1);
        transfer(gates[i][0],0);
        a=b=0;
        r[i].start=now();
        for(unsigned j=0;j<count;j++) cycle(stack,&a,&b);
        r[i].end=now();r[i].fork_ticks=a;r[i].wait_ticks=b;
        check(sched_getcpu()==cpus[i],"worker migration");
        _exit(0);
    }
    for(unsigned i=0;i<workers;i++)transfer(ready[0],0);
    // Diagnostic FL4 handles this marker directly. Other kernels return ENOSYS.
    syscall(PROFILE_SYSCALL,3,force_mask);
    long profile=syscall(PROFILE_SYSCALL,profiling ? 1 : 0,mode);
    for(unsigned i=0;i<workers;i++)transfer(gates[i][1],1);
    uint64_t start=UINT64_MAX,end=0,creation=0,waiting=0;
    for(unsigned i=0;i<workers;i++) {
        reap(pids[i]);
        check(r[i].end>r[i].start,"elapsed");
        if(r[i].start<start)start=r[i].start;
        if(r[i].end>end)end=r[i].end;
        creation+=r[i].fork_ticks; waiting+=r[i].wait_ticks;
    }
    syscall(PROFILE_SYSCALL,2,mode);
    const char *names[]={"fork","vfork","clone_vm"};
    printf("FORKBENCH: metric=%s workers=%u operations=%u elapsed_ns=%"PRIu64
           " value=%.6f fork_ticks=%"PRIu64" wait_ticks=%"PRIu64" profile=%ld profiling=%u force_mask=%u\n",
           names[mode],workers,count*workers,end-start,(double)(count*workers)*1e9/(end-start),creation,waiting,profile,profiling,force_mask);
    for(unsigned i=0;i<workers;i++)
        printf("FORKWORKER: cpu=%d elapsed_ns=%"PRIu64" fork_ticks=%"PRIu64" wait_ticks=%"PRIu64"\n",
               cpus[i],r[i].end-r[i].start,r[i].fork_ticks,r[i].wait_ticks);
    puts("FORKBENCH: PASS");
    return 0;
}
