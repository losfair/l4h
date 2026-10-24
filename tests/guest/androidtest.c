/*
 * The guest kernel's support for Android (DESIGN.md §5.8).  Booted with
 * the command line of an Android guest (lsm=selinux psi=1 bootconfig) it
 * exercises what Android userspace relies on: Binder through binderfs,
 * userfaultfd with MREMAP_DONTUNMAP and UFFDIO_MOVE (ART's garbage
 * collector), alarm timers and the RTC, memfd code mapped twice (ART's
 * JIT), dma-buf heaps, PSI triggers (lmkd), SELinux, bootconfig, uinput
 * and zram swap.  Booted with androidtest=default, it checks that a guest
 * which does not ask for them sees none of SELinux, PSI or bootconfig.
 * Prints "ANDROIDTEST: PASS" or "ANDROIDTEST: FAIL".
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/rtc.h>
#include <linux/uinput.h>
#include <linux/userfaultfd.h>

#define PAGE 4096

static int failures;

#define CHECK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __func__, __LINE__); \
		printf(__VA_ARGS__); \
		printf(" (errno %d)\n", errno); \
		failures++; \
		return; \
	} \
} while (0)

static double now(clockid_t clk)
{
	struct timespec ts;

	clock_gettime(clk, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int read_file(const char *path, char *buf, size_t n)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0)
		return -1;
	buf[r] = 0;
	return r;
}

static int write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = write(fd, s, strlen(s));
	close(fd);
	return r == (ssize_t)strlen(s) ? 0 : -1;
}

static void fill(unsigned char *p, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (unsigned char)(seed * 131 + i * 7 + (i >> 9));
}

static int filled(const unsigned char *p, size_t n, unsigned seed)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != (unsigned char)(seed * 131 + i * 7 + (i >> 9)))
			return 0;
	return 1;
}

/* ---- Binder: a context manager and a client, as servicemanager and an
 * app.  Payloads span several pages of the receiver's Binder mapping,
 * which the kernel fills page by page (vm_insert_page). */

#define BINDER_MAP (1 << 20)
#define TX_ECHO 1	/* reply with the payload inverted */
#define TX_FD 2		/* reply with a pipe that holds "fd" */
#define TX_QUIT 3	/* one way: the server exits */
#define TX_COUNT 300

static int binder_open(void **map)
{
	struct binder_version ver;
	int fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		return -1;
	if (ioctl(fd, BINDER_VERSION, &ver) < 0 ||
	    ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)
		return -1;
	*map = mmap(NULL, BINDER_MAP, PROT_READ, MAP_PRIVATE, fd, 0);
	return *map == MAP_FAILED ? -1 : fd;
}

static int binder_write(int fd, const void *buf, size_t n)
{
	struct binder_write_read bwr = {
		.write_size = n,
		.write_buffer = (uintptr_t)buf,
	};

	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

/* Reads until a BR_TRANSACTION or BR_REPLY; 0, or -1 on a failed reply. */
static int binder_wait(int fd, uint32_t want, struct binder_transaction_data *tr)
{
	uint32_t buf[128];

	for (;;) {
		struct binder_write_read bwr = {
			.read_size = sizeof(buf),
			.read_buffer = (uintptr_t)buf,
		};
		size_t off = 0;

		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (off < bwr.read_consumed) {
			uint32_t cmd = *(uint32_t *)((char *)buf + off);

			off += sizeof(cmd);
			if (cmd == want) {
				memcpy(tr, (char *)buf + off, sizeof(*tr));
				/* Nothing else is in flight: one command per wait. */
				return 0;
			}
			if (cmd == BR_DEAD_REPLY || cmd == BR_FAILED_REPLY || cmd == BR_ERROR)
				return -1;
			off += _IOC_SIZE(cmd);
		}
	}
}

static int binder_free(int fd, binder_uintptr_t buffer)
{
	struct {
		uint32_t cmd;
		binder_uintptr_t buffer;
	} __attribute__((packed)) req = { BC_FREE_BUFFER, buffer };

	return binder_write(fd, &req, sizeof(req));
}

static int binder_send(int fd, uint32_t cmd, uint32_t code, uint32_t flags,
		       const void *data, size_t size, const binder_size_t *offs, size_t noffs)
{
	struct {
		uint32_t cmd;
		struct binder_transaction_data tr;
	} __attribute__((packed)) req = { .cmd = cmd };

	req.tr.target.handle = 0;
	req.tr.code = code;
	req.tr.flags = flags;
	req.tr.data_size = size;
	req.tr.offsets_size = noffs * sizeof(binder_size_t);
	req.tr.data.ptr.buffer = (uintptr_t)data;
	req.tr.data.ptr.offsets = (uintptr_t)offs;
	return binder_write(fd, &req, sizeof(req));
}

static void binder_server(int ready)
{
	static unsigned char reply[4 * PAGE];
	uint32_t looper = BC_ENTER_LOOPER;
	void *map;
	int fd = binder_open(&map), mgr = 0;

	if (fd < 0 || ioctl(fd, BINDER_SET_CONTEXT_MGR, &mgr) < 0 ||
	    binder_write(fd, &looper, sizeof(looper)) < 0)
		_exit(1);
	if (write(ready, "r", 1) != 1)
		_exit(1);
	for (;;) {
		struct binder_transaction_data tr;
		const unsigned char *in;

		if (binder_wait(fd, BR_TRANSACTION, &tr) < 0)
			_exit(2);
		in = (const unsigned char *)(uintptr_t)tr.data.ptr.buffer;
		if (tr.code == TX_QUIT) {
			binder_free(fd, tr.data.ptr.buffer);
			_exit(0);
		}
		if (tr.code == TX_FD) {
			/* A pipe's read end, to a caller that accepts fds. */
			struct binder_fd_object obj = { .hdr.type = BINDER_TYPE_FD };
			binder_size_t off = 0;
			int p[2];

			if (pipe(p) < 0 || write(p[1], "fd", 2) != 2)
				_exit(3);
			close(p[1]);
			obj.fd = p[0];
			if (binder_free(fd, tr.data.ptr.buffer) < 0 ||
			    binder_send(fd, BC_REPLY, tr.code, 0, &obj, sizeof(obj), &off, 1) < 0)
				_exit(4);
			close(p[0]);
			continue;
		}
		for (size_t i = 0; i < tr.data_size; i++)
			reply[i] = ~in[i];
		if (binder_free(fd, tr.data.ptr.buffer) < 0 ||
		    binder_send(fd, BC_REPLY, tr.code, 0, reply, tr.data_size, NULL, 0) < 0)
			_exit(4);
	}
}

static void test_binder(void)
{
	static unsigned char req[4 * PAGE];
	struct binderfs_device dev = { .name = "binder" };
	struct binder_transaction_data tr;
	const struct binder_fd_object *obj;
	int ctl, fd, ready[2], status;
	char got[3] = { 0 };
	void *map;
	pid_t pid;

	CHECK(access("/dev/binder", F_OK) < 0, "/dev/binder exists without binderfs");
	mkdir("/dev/binderfs", 0755);
	CHECK(mount("binder", "/dev/binderfs", "binder", 0, NULL) == 0, "mount binderfs");
	ctl = open("/dev/binderfs/binder-control", O_RDWR | O_CLOEXEC);
	CHECK(ctl >= 0 && ioctl(ctl, BINDER_CTL_ADD, &dev) == 0, "BINDER_CTL_ADD");
	close(ctl);
	CHECK(pipe(ready) == 0, "pipe");
	pid = fork();
	CHECK(pid >= 0, "fork");
	if (!pid)
		binder_server(ready[1]);
	CHECK(read(ready[0], got, 1) == 1, "server did not start");
	fd = binder_open(&map);
	CHECK(fd >= 0, "client open");
	for (int i = 0; i < TX_COUNT; i++) {
		size_t n = 8 + (i * 997) % (3 * PAGE + 100);
		const unsigned char *out;

		fill(req, n, i);
		CHECK(binder_send(fd, BC_TRANSACTION, TX_ECHO, 0, req, n, NULL, 0) == 0 &&
		      binder_wait(fd, BR_REPLY, &tr) == 0, "transaction %d", i);
		out = (const unsigned char *)(uintptr_t)tr.data.ptr.buffer;
		CHECK(tr.data_size == n, "reply %d: %llu bytes, sent %zu", i,
		      (unsigned long long)tr.data_size, n);
		for (size_t j = 0; j < n; j++)
			CHECK(out[j] == (unsigned char)~req[j], "reply %d byte %zu", i, j);
		CHECK(binder_free(fd, tr.data.ptr.buffer) == 0, "BC_FREE_BUFFER");
	}
	CHECK(binder_send(fd, BC_TRANSACTION, TX_FD, TF_ACCEPT_FDS, NULL, 0, NULL, 0) == 0 &&
	      binder_wait(fd, BR_REPLY, &tr) == 0, "fd transaction");
	obj = (const void *)(uintptr_t)tr.data.ptr.buffer;
	CHECK(tr.offsets_size == sizeof(binder_size_t) && obj->hdr.type == BINDER_TYPE_FD &&
	      read(obj->fd, got, 2) == 2 && !strcmp(got, "fd"), "fd passed by Binder");
	close(obj->fd);
	binder_free(fd, tr.data.ptr.buffer);
	CHECK(binder_send(fd, BC_TRANSACTION, TX_QUIT, TF_ONE_WAY, NULL, 0, NULL, 0) == 0,
	      "one-way transaction");
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status),
	      "server status %#x", status);
	close(fd);
}

/* ---- userfaultfd */

static int uffd_open(int flags, uint64_t features)
{
	struct uffdio_api api = { .api = UFFD_API, .features = features };
	int fd = syscall(SYS_userfaultfd, O_CLOEXEC | flags);

	if (fd < 0 || ioctl(fd, UFFDIO_API, &api) < 0)
		return -1;
	return fd;
}

static int uffd_register(int fd, void *addr, size_t len)
{
	struct uffdio_register reg = {
		.range = { (uintptr_t)addr, len },
		.mode = UFFDIO_REGISTER_MODE_MISSING,
	};

	return ioctl(fd, UFFDIO_REGISTER, &reg);
}

struct uffd_server {
	int fd, stop;
	unsigned char *base;
	/* Missing pages are copied from here, or filled by page index. */
	const unsigned char *from;
	atomic_int faults;
};

static void *uffd_serve(void *arg)
{
	struct uffd_server *s = arg;
	static unsigned char page[PAGE];

	for (;;) {
		struct pollfd p[2] = { { s->fd, POLLIN, 0 }, { s->stop, POLLIN, 0 } };
		struct uffd_msg msg;
		struct uffdio_copy copy;
		size_t idx;

		if (poll(p, 2, -1) < 0 || p[1].revents)
			return NULL;
		if (read(s->fd, &msg, sizeof(msg)) != sizeof(msg) || msg.event != UFFD_EVENT_PAGEFAULT)
			continue;
		idx = (msg.arg.pagefault.address - (uintptr_t)s->base) / PAGE;
		if (s->from)
			memcpy(page, s->from + idx * PAGE, PAGE);
		else
			fill(page, PAGE, idx);
		copy = (struct uffdio_copy){
			.dst = (uintptr_t)s->base + idx * PAGE,
			.src = (uintptr_t)page,
			.len = PAGE,
		};
		if (ioctl(s->fd, UFFDIO_COPY, &copy) == 0)
			atomic_fetch_add(&s->faults, 1);
	}
}

static unsigned char *user_only_src;
static int user_only_pipe;

static void *user_only_write(void *arg)
{
	(void)arg;
	errno = 0;
	return (void *)(uintptr_t)(write(user_only_pipe, user_only_src, PAGE) < 0 && errno == EFAULT);
}

static void test_userfaultfd(void)
{
	static unsigned char buf[PAGE];
	struct uffd_server s = { 0 };
	struct timespec deadline;
	int stop[2], pfd[2];
	pthread_t th;
	void *res;

	s.fd = uffd_open(O_NONBLOCK, 0);
	CHECK(s.fd >= 0, "userfaultfd");
	s.base = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(s.base != MAP_FAILED && uffd_register(s.fd, s.base, 4 * PAGE) == 0, "register");
	CHECK(pipe(stop) == 0 && pipe(pfd) == 0, "pipe");
	s.stop = stop[0];
	pthread_create(&th, NULL, uffd_serve, &s);

	/* A user access, and kernel copies from and to missing pages. */
	CHECK(filled(s.base, PAGE, 0), "user read of a missing page");
	CHECK(write(pfd[1], s.base + PAGE, PAGE) == PAGE && read(pfd[0], buf, PAGE) == PAGE &&
	      filled(buf, PAGE, 1), "write() from a missing page");
	fill(buf, PAGE, 99);
	CHECK(write(pfd[1], buf, PAGE) == PAGE && read(pfd[0], s.base + 2 * PAGE, PAGE) == PAGE &&
	      filled(s.base + 2 * PAGE, PAGE, 99), "read() into a missing page");
	CHECK(write(stop[1], "x", 1) == 1, "stop");
	pthread_join(th, NULL);
	/* Counted after each UFFDIO_COPY, which wakes the faulting thread. */
	CHECK(atomic_load(&s.faults) == 3, "%d faults, expected 3", atomic_load(&s.faults));
	close(s.fd);
	munmap(s.base, 4 * PAGE);
	close(stop[0]);
	close(stop[1]);

	/* UFFD_USER_MODE_ONLY, all that vm.unprivileged_userfaultfd=0 leaves
	 * unprivileged users, must not hold up the kernel's own copies. */
	s.fd = uffd_open(UFFD_USER_MODE_ONLY, 0);
	CHECK(s.fd >= 0, "UFFD_USER_MODE_ONLY");
	s.base = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(s.base != MAP_FAILED && uffd_register(s.fd, s.base, PAGE) == 0, "register user-mode only");
	user_only_src = s.base;
	user_only_pipe = pfd[1];
	pthread_create(&th, NULL, user_only_write, NULL);
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 5;
	if (pthread_timedjoin_np(th, &res, &deadline)) {
		struct uffdio_zeropage zp = { .range = { (uintptr_t)s.base, PAGE } };

		/* Let the copy go on, to fail. */
		ioctl(s.fd, UFFDIO_ZEROPAGE, &zp);
		pthread_join(th, &res);
		CHECK(0, "a kernel copy waited for a user-mode-only userfaultfd");
	}
	CHECK(res, "a kernel copy from a user-mode-only range did not fail with EFAULT");
	close(s.fd);
	munmap(s.base, PAGE);
	close(pfd[0]);
	close(pfd[1]);
}

/* A thread waiting for a missing page takes its signals meanwhile, as
 * on other architectures: ART suspends threads with signals, and the GC
 * thread that would fill the page may be waiting for them. */
static atomic_int uffd_sig_seen;
static unsigned char *volatile uffd_sig_page;

static void uffd_sig_handler(int sig)
{
	(void)sig;
	atomic_store(&uffd_sig_seen, 1);
}

static void *uffd_sig_reader(void *arg)
{
	(void)arg;
	return (void *)(uintptr_t)filled(uffd_sig_page, PAGE, 5);
}

static void test_uffd_signal(void)
{
	static unsigned char page[PAGE];
	struct sigaction sa = { .sa_handler = uffd_sig_handler };
	struct pollfd p;
	struct uffd_msg msg;
	struct uffdio_copy copy;
	pthread_t th;
	void *ok;
	int seen, fd = uffd_open(0, 0);

	CHECK(fd >= 0, "userfaultfd");
	uffd_sig_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(uffd_sig_page != MAP_FAILED && uffd_register(fd, uffd_sig_page, PAGE) == 0, "register");
	CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
	pthread_create(&th, NULL, uffd_sig_reader, NULL);
	p = (struct pollfd){ fd, POLLIN, 0 };
	CHECK(poll(&p, 1, 5000) == 1 && read(fd, &msg, sizeof(msg)) == sizeof(msg),
	      "no page fault message");
	pthread_kill(th, SIGUSR1);
	for (int i = 0; i < 200 && !atomic_load(&uffd_sig_seen); i++)
		usleep(10000);
	seen = atomic_load(&uffd_sig_seen);
	fill(page, PAGE, 5);
	copy = (struct uffdio_copy){ (uintptr_t)uffd_sig_page, (uintptr_t)page, PAGE, 0, 0 };
	ioctl(fd, UFFDIO_COPY, &copy);
	pthread_join(th, &ok);
	CHECK(seen, "the signal waited for the page");
	CHECK(ok, "page contents");
	signal(SIGUSR1, SIG_DFL);
	close(fd);
	munmap(uffd_sig_page, PAGE);
}

/* ART's compaction: the heap moves aside with MREMAP_DONTUNMAP, and the
 * old range, registered with userfaultfd, is filled back page by page. */
static void test_mremap_dontunmap(void)
{
	struct uffd_server s = { 0 };
	unsigned char *heap, *moved;
	int stop[2];
	pthread_t th;

	heap = mmap(NULL, 8 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(heap != MAP_FAILED, "mmap");
	for (int i = 0; i < 8; i++)
		fill(heap + i * PAGE, PAGE, 50 + i);
	/* With MREMAP_DONTUNMAP the new address is read, as a hint. */
	moved = mremap(heap, 8 * PAGE, 8 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, NULL);
	CHECK(moved != MAP_FAILED && moved != heap, "MREMAP_DONTUNMAP");
	for (int i = 0; i < 8; i++)
		CHECK(filled(moved + i * PAGE, PAGE, 50 + i), "moved page %d", i);
	s.fd = uffd_open(O_NONBLOCK, 0);
	CHECK(s.fd >= 0 && uffd_register(s.fd, heap, 8 * PAGE) == 0, "register the old range");
	s.base = heap;
	s.from = moved;
	CHECK(pipe(stop) == 0, "pipe");
	s.stop = stop[0];
	pthread_create(&th, NULL, uffd_serve, &s);
	for (int i = 7; i >= 0; i--)
		CHECK(filled(heap + i * PAGE, PAGE, 50 + i), "page %d filled back", i);
	CHECK(write(stop[1], "x", 1) == 1, "stop");
	pthread_join(th, NULL);
	CHECK(atomic_load(&s.faults) == 8, "%d faults, expected 8", atomic_load(&s.faults));
	close(s.fd);
	close(stop[0]);
	close(stop[1]);
	munmap(heap, 8 * PAGE);
	munmap(moved, 8 * PAGE);
}

/* UFFDIO_MOVE takes the page itself, which must leave the source's seL4
 * mapping too. */
static void test_uffdio_move(void)
{
#ifdef UFFDIO_MOVE
	unsigned char *src, *dst;
	struct uffdio_move mv;
	int fd = uffd_open(0, UFFD_FEATURE_MOVE);

	CHECK(fd >= 0, "userfaultfd with UFFD_FEATURE_MOVE");
	src = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	dst = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(src != MAP_FAILED && dst != MAP_FAILED && uffd_register(fd, dst, 2 * PAGE) == 0, "mmap");
	fill(src, 2 * PAGE, 7);
	mv = (struct uffdio_move){ (uintptr_t)dst, (uintptr_t)src, 2 * PAGE, 0, 0 };
	CHECK(ioctl(fd, UFFDIO_MOVE, &mv) == 0 && mv.move == 2 * PAGE, "UFFDIO_MOVE");
	CHECK(filled(dst, 2 * PAGE, 7), "moved pages");
	for (int i = 0; i < 2 * PAGE; i++)
		CHECK(src[i] == 0, "source still maps the moved page");
	close(fd);
	munmap(src, 2 * PAGE);
	munmap(dst, 2 * PAGE);
#else
	printf("  (UFFDIO_MOVE not in these headers)\n");
#endif
}

/* ---- alarm timers and the RTC */

static time_t rtc_seconds(const struct rtc_time *r)
{
	struct tm t = { .tm_sec = r->tm_sec, .tm_min = r->tm_min, .tm_hour = r->tm_hour,
			.tm_mday = r->tm_mday, .tm_mon = r->tm_mon, .tm_year = r->tm_year };

	return timegm(&t);
}

static void test_rtc(void)
{
	struct rtc_time tm, tm2;
	struct rtc_wkalrm alrm = { 0 };
	unsigned long data;
	struct tm a;
	time_t t, rt;
	double t0;
	int fd = open("/dev/rtc0", O_RDWR | O_CLOEXEC);

	CHECK(fd >= 0, "/dev/rtc0");
	CHECK(ioctl(fd, RTC_RD_TIME, &tm) == 0, "RTC_RD_TIME");
	rt = rtc_seconds(&tm);
	t = time(NULL);
	CHECK(rt >= t - 5 && rt <= t + 5, "RTC %ld, system clock %ld", (long)rt, (long)t);

	/* Setting it moves only the RTC. */
	tm2 = tm;
	tm2.tm_year += 1;
	CHECK(ioctl(fd, RTC_SET_TIME, &tm2) == 0 && ioctl(fd, RTC_RD_TIME, &tm2) == 0 &&
	      tm2.tm_year == tm.tm_year + 1, "RTC_SET_TIME");
	CHECK(time(NULL) - t < 5, "setting the RTC moved the system clock");
	CHECK(ioctl(fd, RTC_SET_TIME, &tm) == 0, "RTC_SET_TIME back");

	/* An alarm 2 s ahead. */
	CHECK(ioctl(fd, RTC_RD_TIME, &tm) == 0, "RTC_RD_TIME");
	rt = rtc_seconds(&tm) + 2;
	gmtime_r(&rt, &a);
	alrm.time.tm_sec = a.tm_sec;
	alrm.time.tm_min = a.tm_min;
	alrm.time.tm_hour = a.tm_hour;
	alrm.time.tm_mday = a.tm_mday;
	alrm.time.tm_mon = a.tm_mon;
	alrm.time.tm_year = a.tm_year;
	alrm.enabled = 1;
	t0 = now(CLOCK_MONOTONIC);
	CHECK(ioctl(fd, RTC_WKALM_SET, &alrm) == 0, "RTC_WKALM_SET");
	CHECK(read(fd, &data, sizeof(data)) == sizeof(data) && (data & RTC_AF), "alarm event %#lx", data);
	t0 = now(CLOCK_MONOTONIC) - t0;
	CHECK(t0 > 0.9 && t0 < 4, "alarm after %.2f s, expected 1-3", t0);
	close(fd);
}

static void test_alarm_timers(void)
{
	const clockid_t clocks[] = { CLOCK_BOOTTIME_ALARM, CLOCK_REALTIME_ALARM };

	for (int i = 0; i < 2; i++) {
		struct itimerspec its = { .it_value = { 0, 100 * 1000 * 1000 } };
		uint64_t n = 0;
		int fd = timerfd_create(clocks[i], TFD_CLOEXEC);
		double t0;

		struct timespec ts = { 0, 50 * 1000 * 1000 };

		/* Unlike timerfd, these need an RTC with alarms. */
		CHECK(clock_getres(clocks[i], &ts) == 0, "clock_getres(%d): no RTC with alarms",
		      clocks[i]);
		ts = (struct timespec){ 0, 50 * 1000 * 1000 };
		CHECK(clock_nanosleep(clocks[i], 0, &ts, NULL) == 0, "clock_nanosleep(%d)", clocks[i]);
		CHECK(fd >= 0, "timerfd_create(%d)", clocks[i]);
		t0 = now(CLOCK_MONOTONIC);
		CHECK(timerfd_settime(fd, 0, &its, NULL) == 0, "timerfd_settime");
		CHECK(read(fd, &n, sizeof(n)) == sizeof(n) && n == 1, "expirations %llu",
		      (unsigned long long)n);
		t0 = now(CLOCK_MONOTONIC) - t0;
		CHECK(t0 >= 0.1 && t0 < 1, "alarm timer after %.3f s", t0);
		close(fd);
	}
}

/* ---- ART's JIT: code written through one mapping of a memfd and run
 * through another. */

static void put_code(unsigned char *rw, int value)
{
#ifdef __x86_64__
	unsigned char code[] = { 0xb8, value, 0, 0, 0, 0xc3 };	/* mov $value, %eax; ret */
#else
	uint32_t code[] = { 0x52800000 | (value << 5), 0xd65f03c0 };	/* mov w0, #value; ret */
#endif
	memcpy(rw, code, sizeof(code));
}

static void test_memfd_jit(void)
{
	int fd = memfd_create("jit-cache", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	unsigned char *rw, *rx;
	int (*fn)(void);

	CHECK(fd >= 0 && ftruncate(fd, PAGE) == 0, "memfd_create");
	rw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	rx = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
	CHECK(rw != MAP_FAILED && rx != MAP_FAILED, "mmap");
	fn = (int (*)(void))rx;
	put_code(rw, 42);
	__builtin___clear_cache((char *)rx, (char *)rx + 16);
	CHECK(fn() == 42, "first code");
	put_code(rw, 43);
	__builtin___clear_cache((char *)rx, (char *)rx + 16);
	CHECK(fn() == 43, "rewritten code");
	CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW) == 0 &&
	      ftruncate(fd, 2 * PAGE) < 0 && errno == EPERM, "seals");
	munmap(rw, PAGE);
	munmap(rx, PAGE);
	close(fd);
}

/* ---- gralloc's buffers */

static void test_dma_heap(void)
{
	struct dma_heap_allocation_data alloc = {
		.len = 16 * PAGE,
		.fd_flags = O_RDWR | O_CLOEXEC,
	};
	struct dma_buf_sync sync;
	unsigned char *p;
	int heap = open("/dev/dma_heap/system", O_RDONLY | O_CLOEXEC);

	CHECK(heap >= 0, "/dev/dma_heap/system");
	CHECK(ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &alloc) == 0, "DMA_HEAP_IOCTL_ALLOC");
	p = mmap(NULL, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, alloc.fd, 0);
	CHECK(p != MAP_FAILED, "mmap dma-buf");
	sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW;
	CHECK(ioctl(alloc.fd, DMA_BUF_IOCTL_SYNC, &sync) == 0, "sync start");
	fill(p, 16 * PAGE, 3);
	sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
	CHECK(ioctl(alloc.fd, DMA_BUF_IOCTL_SYNC, &sync) == 0, "sync end");
	munmap(p, 16 * PAGE);
	p = mmap(NULL, 16 * PAGE, PROT_READ, MAP_SHARED, alloc.fd, 0);
	CHECK(p != MAP_FAILED && filled(p, 16 * PAGE, 3), "buffer contents");
	munmap(p, 16 * PAGE);
	close(alloc.fd);
	close(heap);
}

/* ---- lmkd: memory pressure triggers and zram swap */

static void test_psi(void)
{
	const char *trig = "some 150000 1000000";
	struct pollfd p;
	char buf[256];
	int fd;

	CHECK(read_file("/proc/pressure/cpu", buf, sizeof(buf)) > 0 &&
	      !strncmp(buf, "some avg10=", 11), "/proc/pressure/cpu");
	fd = open("/proc/pressure/memory", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	CHECK(fd >= 0 && write(fd, trig, strlen(trig) + 1) > 0, "memory pressure trigger");
	p = (struct pollfd){ fd, POLLPRI, 0 };
	CHECK(poll(&p, 1, 10) >= 0 && !(p.revents & POLLERR), "poll on the trigger");
	close(fd);
}

static void test_zram(void)
{
	static unsigned char buf[64 * PAGE];
	const size_t size = 16 << 20;
	int fd;

	CHECK(write_file("/sys/block/zram0/comp_algorithm", "lz4") == 0, "lz4 for zram");
	CHECK(write_file("/sys/block/zram0/disksize", "16M") == 0, "zram disksize");
	fd = open("/dev/zram0", O_RDWR | O_CLOEXEC);
	CHECK(fd >= 0, "/dev/zram0");
	for (int i = 0; i < 64; i++)
		fill(buf + i * PAGE, PAGE, i & 3 ? 9 : i);
	CHECK(pwrite(fd, buf, sizeof(buf), 0) == sizeof(buf) && fsync(fd) == 0, "zram write");
	memset(buf, 0, sizeof(buf));
	CHECK(pread(fd, buf, sizeof(buf), 0) == sizeof(buf), "zram read");
	for (int i = 0; i < 64; i++)
		CHECK(filled(buf + i * PAGE, PAGE, i & 3 ? 9 : i), "zram page %d", i);
	/* A swap header (mkswap's), then swapon and swapoff. */
	memset(buf, 0, PAGE);
	((uint32_t *)(buf + 1024))[0] = 1;
	((uint32_t *)(buf + 1024))[1] = size / PAGE - 1;
	memcpy(buf + PAGE - 10, "SWAPSPACE2", 10);
	CHECK(pwrite(fd, buf, PAGE, 0) == PAGE && fsync(fd) == 0, "swap header");
	close(fd);
	CHECK(swapon("/dev/zram0", 0) == 0, "swapon zram");
	CHECK(swapoff("/dev/zram0") == 0, "swapoff zram");
	CHECK(write_file("/sys/block/zram0/reset", "1") == 0, "zram reset");
}

/* ---- the rest of init's needs */

static void test_selinux(int android)
{
	char buf[64];
	int r;

	mkdir("/sys/fs/selinux", 0755);
	r = mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL);
	if (!android) {
		CHECK(r < 0, "SELinux runs without lsm=selinux");
		return;
	}
	CHECK(r == 0, "mount selinuxfs");
	/* No policy is loaded: permissive, and every task "kernel". */
	CHECK(read_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) > 0 && buf[0] == '0',
	      "enforce: %s", buf);
	CHECK(read_file("/proc/self/attr/current", buf, sizeof(buf)) > 0 &&
	      !strncmp(buf, "kernel", 6), "context %s", buf);
	umount("/sys/fs/selinux");
}

static void test_defaults(void)
{
	char buf[256];

	CHECK(access("/proc/pressure", F_OK) < 0, "PSI is on without psi=1");
	CHECK(read_file("/proc/bootconfig", buf, sizeof(buf)) == 0,
	      "bootconfig without the bootconfig parameter: %s", buf);
}

static void test_bootconfig(void)
{
	char buf[1024];

	CHECK(read_file("/proc/bootconfig", buf, sizeof(buf)) > 0, "/proc/bootconfig");
	CHECK(strstr(buf, "androidboot.l4htest = \"ok\""), "/proc/bootconfig: %s", buf);
}

static void test_uinput(void)
{
	struct uinput_setup setup = { .id = { .bustype = BUS_VIRTUAL }, .name = "l4h-test" };
	struct input_event ev[2] = {
		{ .type = EV_KEY, .code = KEY_A, .value = 1 },
		{ .type = EV_SYN, .code = SYN_REPORT },
	}, in;
	char sys[64], path[320];
	struct dirent *de;
	int fd, evfd = -1;
	DIR *d;

	fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	CHECK(fd >= 0, "/dev/uinput");
	CHECK(ioctl(fd, UI_SET_EVBIT, EV_KEY) == 0 && ioctl(fd, UI_SET_KEYBIT, KEY_A) == 0 &&
	      ioctl(fd, UI_DEV_SETUP, &setup) == 0 && ioctl(fd, UI_DEV_CREATE) == 0, "UI_DEV_CREATE");
	CHECK(ioctl(fd, UI_GET_SYSNAME(sizeof(sys)), sys) >= 0, "UI_GET_SYSNAME");
	snprintf(path, sizeof(path), "/sys/devices/virtual/input/%s", sys);
	d = opendir(path);
	CHECK(d, "%s", path);
	while ((de = readdir(d)))
		if (!strncmp(de->d_name, "event", 5)) {
			snprintf(path, sizeof(path), "/dev/input/%s", de->d_name);
			/* devtmpfs makes the node as the device appears. */
			for (int i = 0; i < 100 && evfd < 0; i++, usleep(10000))
				evfd = open(path, O_RDONLY | O_CLOEXEC);
		}
	closedir(d);
	CHECK(evfd >= 0, "evdev node of %s", sys);
	CHECK(write(fd, ev, sizeof(ev)) == sizeof(ev), "write events");
	CHECK(read(evfd, &in, sizeof(in)) == sizeof(in) && in.type == EV_KEY && in.code == KEY_A &&
	      in.value == 1, "event %d/%d/%d", in.type, in.code, in.value);
	close(evfd);
	CHECK(ioctl(fd, UI_DEV_DESTROY) == 0, "UI_DEV_DESTROY");
	close(fd);
}

static void run(const char *name, void (*fn)(void))
{
	int before = failures;
	double t0 = now(CLOCK_MONOTONIC);

	fn();
	printf("  %-18s %s (%.3f s)\n", name, failures == before ? "ok" : "FAILED",
	       now(CLOCK_MONOTONIC) - t0);
	fflush(stdout);
}

static void test_selinux_android(void) { test_selinux(1); }
static void test_selinux_default(void) { test_selinux(0); }

int main(void)
{
	char cmdline[1024] = "";
	int android;

	setvbuf(stdout, NULL, _IOLBF, 0);
	read_file("/proc/cmdline", cmdline, sizeof(cmdline));
	android = !strstr(cmdline, "androidtest=default");
	printf("ANDROIDTEST: start (%s)\n", android ? "Android command line" : "defaults");
	if (android) {
		run("binder", test_binder);
		run("userfaultfd", test_userfaultfd);
		run("uffd_signal", test_uffd_signal);
		run("mremap_dontunmap", test_mremap_dontunmap);
		run("uffdio_move", test_uffdio_move);
		run("rtc", test_rtc);
		run("alarm_timers", test_alarm_timers);
		run("memfd_jit", test_memfd_jit);
		run("dma_heap", test_dma_heap);
		run("psi", test_psi);
		run("zram", test_zram);
		run("selinux", test_selinux_android);
		run("bootconfig", test_bootconfig);
		run("uinput", test_uinput);
	} else {
		run("selinux_off", test_selinux_default);
		run("defaults", test_defaults);
		run("binder", test_binder);
		run("alarm_timers", test_alarm_timers);
	}
	printf("ANDROIDTEST: %s\n", failures ? "FAIL" : "PASS");
	return failures != 0;
}
