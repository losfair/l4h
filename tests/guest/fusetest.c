/*
 * l4h guest FUSE test: the kernel paths an SQLite database in WAL mode
 * takes on a FUSE mount.
 *
 * The process mounts a small in-memory file system served from
 * /dev/fuse by a thread of its own, with the page cache in use (no
 * FOPEN_DIRECT_IO) and POSIX and flock locks passed to the server, then
 * runs the tests in a child process:
 *   - MAP_SHARED mappings of one file in two processes (the -shm
 *     WAL index): stores through either mapping and pwrite are seen by
 *     the other process's mapping and pread, and msync(MS_SYNC) brings
 *     the dirty pages to the server;
 *   - fcntl byte range locks (SQLite's lock bytes): conflicts, shared
 *     read locks, F_SETLKW mutual exclusion and wakeup, release when a
 *     holder exits or closes any descriptor of the file, a signal
 *     interrupting F_SETLKW, and flock alongside them;
 *   - WAL frames appended and synced with fdatasync, a checkpoint, the
 *     WAL truncated to zero, and a file atomically replaced by rename.
 *
 * Usage: fusetest <mountpoint>.  Needs CAP_SYS_ADMIN.  Prints
 * "FUSETEST: PASS" and exits 0, or "FUSETEST: FAIL <where>" and exits 1.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

_Static_assert(sizeof(struct fuse_init_out) == 64, "fuse_init_out is 64 bytes since 7.23");

#define FAIL(...) fail_at(__func__, __LINE__, __VA_ARGS__)
#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)
/* A system call that must succeed. */
#define SYS(call) ({ \
	__typeof__(call) r_ = (call); \
	if (r_ < 0) \
		FAIL("%s", #call); \
	r_; \
})

static void __attribute__((noreturn, format(printf, 3, 4)))
fail_at(const char *fn, int line, const char *fmt, ...)
{
	int e = errno;
	char msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	printf("FUSETEST: FAIL %s:%d: %s (errno %d: %s) [pid %d]\n",
	       fn, line, msg, e, strerror(e), (int)getpid());
	_exit(1);
}

/* ---- statistics the server keeps for the tests (shared memory) */

#define NOPS 64
struct stats {
	atomic_ullong ops[NOPS];
	atomic_ullong cache_writes;	/* FUSE_WRITE from page writeback */
	atomic_ullong fsyncs, fdatasyncs;
	atomic_ullong flock_ops;	/* SETLK/SETLKW with FUSE_LK_FLOCK */
	atomic_ullong lock_waits;	/* F_SETLKW requests that had to wait */
	atomic_ullong lock_wakeups;	/* waiting F_SETLKW requests granted */
	atomic_ullong lock_interrupted;	/* waiting requests ended by FUSE_INTERRUPT */
	atomic_int waiting;		/* F_SETLKW requests waiting now */
	atomic_uint init_flags;		/* flags both sides agreed on */
	atomic_uint minor;
	/* The file and its contents at the last FUSE_FSYNC. */
	atomic_ullong sync_node, sync_size, sync_sum;
};

static struct stats *st;

static unsigned long long nops(unsigned op)
{
	return atomic_load(&st->ops[op]);
}

/* FNV-1a, enough to tell the server's bytes from the client's. */
static uint64_t checksum(const void *p, size_t n)
{
	const unsigned char *b = p;
	uint64_t h = 0xcbf29ce484222325ull;

	for (size_t i = 0; i < n; i++)
		h = (h ^ b[i]) * 0x100000001b3ull;
	return h;
}

/* ---- the file system: one directory of regular files */

#define NNODES 128
#define MAXSIZE (64u << 20)
#define MAX_WRITE (128u << 10)
#define TTL 1

struct node {
	int used, linked;
	uint64_t nlookup;
	char name[NAME_MAX + 1];
	uint32_t mode;
	unsigned char *data;
	size_t size, cap;
	struct timespec mtime;
};

struct lock {
	int used, flock;
	uint64_t node, owner, start, end;
	uint32_t type, pid;
};

struct waiter {
	int used;
	uint64_t unique, node;
	struct fuse_lk_in in;
};

static int fuse_fd;
static struct node nodes[NNODES];	/* nodes[FUSE_ROOT_ID] is the directory */
static struct lock locks[1024];
static struct waiter waiters[64];
static struct timespec mount_time;

static void reply(uint64_t unique, int err, const void *a, size_t alen,
		  const void *b, size_t blen)
{
	struct fuse_out_header h = {
		.len = sizeof h + (err ? 0 : alen + blen),
		.error = err,
		.unique = unique,
	};
	struct iovec iov[3] = {
		{ &h, sizeof h }, { (void *)a, alen }, { (void *)b, blen },
	};

	/* ENOENT: the request was interrupted and is gone. */
	if (writev(fuse_fd, iov, err ? 1 : 3) < 0 && errno != ENOENT)
		FAIL("reply to request %llu", (unsigned long long)unique);
}

static void reply_err(uint64_t unique, int err)
{
	reply(unique, -err, NULL, 0, NULL, 0);
}

static struct node *node_get(uint64_t id)
{
	if (id <= FUSE_ROOT_ID || id >= NNODES || !nodes[id].used)
		return NULL;
	return &nodes[id];
}

static struct node *node_find(const char *name)
{
	for (int i = FUSE_ROOT_ID + 1; i < NNODES; i++)
		if (nodes[i].used && nodes[i].linked && !strcmp(nodes[i].name, name))
			return &nodes[i];
	return NULL;
}

static void fill_attr(uint64_t id, struct fuse_attr *a)
{
	memset(a, 0, sizeof *a);
	a->ino = id;
	a->blksize = 4096;
	if (id == FUSE_ROOT_ID) {
		a->mode = S_IFDIR | 0755;
		a->nlink = 2;
		a->atime = a->mtime = a->ctime = mount_time.tv_sec;
		return;
	}
	struct node *n = &nodes[id];
	a->mode = n->mode;
	a->nlink = n->linked;
	a->size = n->size;
	a->blocks = (n->size + 511) / 512;
	a->atime = a->ctime = mount_time.tv_sec;
	a->mtime = n->mtime.tv_sec;
	a->mtimensec = n->mtime.tv_nsec;
}

static void fill_entry(uint64_t id, struct fuse_entry_out *e)
{
	memset(e, 0, sizeof *e);
	e->nodeid = id;
	e->generation = 1;
	e->entry_valid = e->attr_valid = TTL;
	fill_attr(id, &e->attr);
	nodes[id].nlookup++;
}

static void node_drop(struct node *n)
{
	if (n->nlookup || n->linked)
		return;
	free(n->data);
	memset(n, 0, sizeof *n);
}

static int node_resize(struct node *n, uint64_t size)
{
	if (size > MAXSIZE)
		return -EFBIG;
	if (size > n->cap) {
		size_t cap = n->cap ? n->cap : 4096;
		while (cap < size)
			cap *= 2;
		unsigned char *p = realloc(n->data, cap);
		if (!p)
			return -ENOMEM;
		memset(p + n->cap, 0, cap - n->cap);
		n->data = p;
		n->cap = cap;
	}
	if (size < n->size)
		memset(n->data + size, 0, n->size - size);
	n->size = size;
	clock_gettime(CLOCK_REALTIME, &n->mtime);
	return 0;
}

static void unlink_name(const char *name)
{
	struct node *n = node_find(name);

	if (n) {
		n->linked = 0;
		node_drop(n);
	}
}

/* ---- locks: POSIX byte ranges per owner, and flock per open file */

static int overlaps(const struct lock *l, uint64_t node, int flock,
		    uint64_t start, uint64_t end)
{
	return l->used && l->node == node && l->flock == flock &&
	       l->start <= end && start <= l->end;
}

static struct lock *lock_conflict(uint64_t node, const struct fuse_lk_in *in)
{
	int flock = !!(in->lk_flags & FUSE_LK_FLOCK);

	if (in->lk.type == F_UNLCK)
		return NULL;
	for (size_t i = 0; i < sizeof locks / sizeof *locks; i++) {
		struct lock *l = &locks[i];
		if (overlaps(l, node, flock, in->lk.start, in->lk.end) &&
		    l->owner != in->owner &&
		    (l->type == F_WRLCK || in->lk.type == F_WRLCK))
			return l;
	}
	return NULL;
}

static struct lock *lock_slot(void)
{
	for (size_t i = 0; i < sizeof locks / sizeof *locks; i++)
		if (!locks[i].used)
			return &locks[i];
	return NULL;
}

/* Set the owner's lock over the range: what it held there is replaced. */
static int lock_apply(uint64_t node, const struct fuse_lk_in *in)
{
	int flock = !!(in->lk_flags & FUSE_LK_FLOCK);
	uint64_t s = in->lk.start, e = in->lk.end;

	if (flock)
		s = 0, e = UINT64_MAX;
	/* Splitting a range needs at most two free slots. */
	struct lock *a = lock_slot();
	if (!a)
		return -ENOLCK;
	a->used = 1;
	struct lock *b = lock_slot();
	a->used = 0;
	if (!b)
		return -ENOLCK;
	for (size_t i = 0; i < sizeof locks / sizeof *locks; i++) {
		struct lock *l = &locks[i];
		if (!overlaps(l, node, flock, s, e) || l->owner != in->owner)
			continue;
		if (l->start < s && l->end > e) {
			*b = *l;
			b->start = e + 1;
			l->end = s - 1;
			b = NULL;
		} else if (l->start < s) {
			l->end = s - 1;
		} else if (l->end > e) {
			l->start = e + 1;
		} else {
			l->used = 0;
		}
	}
	if (in->lk.type != F_UNLCK) {
		a = lock_slot();
		*a = (struct lock){ 1, flock, node, in->owner, s, e,
				    in->lk.type, in->lk.pid };
	}
	return 0;
}

static void lock_drop_owner(uint64_t node, uint64_t owner, int flock)
{
	for (size_t i = 0; i < sizeof locks / sizeof *locks; i++)
		if (locks[i].used && locks[i].node == node &&
		    locks[i].owner == owner && locks[i].flock == flock)
			locks[i].used = 0;
}

/* Grant, first come first served, the waiting requests that now can be. */
static void lock_wake(void)
{
	for (int again = 1; again;) {
		again = 0;
		for (size_t i = 0; i < sizeof waiters / sizeof *waiters; i++) {
			struct waiter *w = &waiters[i];
			if (!w->used || lock_conflict(w->node, &w->in))
				continue;
			int err = lock_apply(w->node, &w->in);
			w->used = 0;
			atomic_fetch_sub(&st->waiting, 1);
			atomic_fetch_add(&st->lock_wakeups, 1);
			reply(w->unique, err, NULL, 0, NULL, 0);
			again = 1;
		}
	}
}

static void do_setlk(uint64_t unique, uint64_t node, const struct fuse_lk_in *in, int sleep)
{
	if (in->lk.type != F_RDLCK && in->lk.type != F_WRLCK && in->lk.type != F_UNLCK) {
		reply_err(unique, EINVAL);
		return;
	}
	if (in->lk_flags & FUSE_LK_FLOCK)
		atomic_fetch_add(&st->flock_ops, 1);
	if (!lock_conflict(node, in)) {
		reply(unique, lock_apply(node, in), NULL, 0, NULL, 0);
		lock_wake();
		return;
	}
	if (!sleep) {
		reply_err(unique, EAGAIN);
		return;
	}
	for (size_t i = 0; i < sizeof waiters / sizeof *waiters; i++) {
		if (!waiters[i].used) {
			waiters[i] = (struct waiter){ 1, unique, node, *in };
			atomic_fetch_add(&st->waiting, 1);
			atomic_fetch_add(&st->lock_waits, 1);
			return;
		}
	}
	reply_err(unique, ENOLCK);
}

static void do_getlk(uint64_t unique, uint64_t node, const struct fuse_lk_in *in)
{
	struct fuse_lk_out out = { .lk = { .type = F_UNLCK } };
	struct lock *l = lock_conflict(node, in);

	if (l)
		out.lk = (struct fuse_file_lock){ l->start, l->end, l->type, l->pid };
	reply(unique, 0, &out, sizeof out, NULL, 0);
}

static void do_interrupt(uint64_t unique)
{
	for (size_t i = 0; i < sizeof waiters / sizeof *waiters; i++) {
		struct waiter *w = &waiters[i];
		if (w->used && w->unique == unique) {
			w->used = 0;
			atomic_fetch_sub(&st->waiting, 1);
			atomic_fetch_add(&st->lock_interrupted, 1);
			reply_err(unique, EINTR);
		}
	}
	/* Any other request has been answered already. */
}

/* ---- requests */

static void do_init(uint64_t unique, const struct fuse_init_in *in)
{
	const uint32_t want = FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS |
			      FUSE_ASYNC_READ | FUSE_BIG_WRITES;
	struct fuse_init_out out = {
		.major = FUSE_KERNEL_VERSION,
		.minor = FUSE_KERNEL_MINOR_VERSION,
		.max_readahead = in->max_readahead,
		.flags = in->flags & want,
		.max_background = 16,
		.congestion_threshold = 12,
		.max_write = MAX_WRITE,
		.time_gran = 1,
	};

	if (in->major != FUSE_KERNEL_VERSION) {
		reply_err(unique, EPROTO);
		return;
	}
	if (in->minor < out.minor)
		out.minor = in->minor;
	atomic_store(&st->init_flags, out.flags);
	atomic_store(&st->minor, out.minor);
	reply(unique, 0, &out, sizeof out, NULL, 0);
}

static void do_readdir(uint64_t unique, const struct fuse_read_in *in)
{
	static char buf[64 << 10];
	size_t len = 0, max = in->size < sizeof buf ? in->size : sizeof buf;

	for (uint64_t i = in->offset; i < NNODES; i++) {
		const char *name;
		uint32_t type;
		uint64_t ino = i;

		if (i == 0) {
			name = ".";
			type = DT_DIR;
			ino = FUSE_ROOT_ID;
		} else if (i == FUSE_ROOT_ID) {
			name = "..";
			type = DT_DIR;
		} else if (nodes[i].used && nodes[i].linked) {
			name = nodes[i].name;
			type = DT_REG;
		} else {
			continue;
		}
		size_t nl = strlen(name), rec = FUSE_DIRENT_SIZE(&(struct fuse_dirent){ .namelen = nl });
		if (len + rec > max)
			break;
		struct fuse_dirent *d = (struct fuse_dirent *)(buf + len);
		memset(d, 0, rec);
		d->ino = ino;
		d->off = i + 1;
		d->namelen = nl;
		d->type = type;
		memcpy(d->name, name, nl);
		len += rec;
	}
	reply(unique, 0, buf, len, NULL, 0);
}

static void do_rename(uint64_t unique, uint64_t parent, uint64_t newdir,
		      uint32_t flags, const char *old, const char *new)
{
	struct node *n = node_find(old);

	if (parent != FUSE_ROOT_ID || newdir != FUSE_ROOT_ID || !n) {
		reply_err(unique, ENOENT);
		return;
	}
	if (flags & ~RENAME_NOREPLACE) {
		reply_err(unique, EINVAL);
		return;
	}
	if (strlen(new) > NAME_MAX) {
		reply_err(unique, ENAMETOOLONG);
		return;
	}
	struct node *t = node_find(new);
	if (t == n) {
		reply_err(unique, 0);
		return;
	}
	if (t && (flags & RENAME_NOREPLACE)) {
		reply_err(unique, EEXIST);
		return;
	}
	if (t)
		unlink_name(new);
	strcpy(n->name, new);
	reply_err(unique, 0);
}

/* The two NUL-terminated names after a request's fixed argument, both
 * inside the request: the second is returned in new. */
static int two_names(const struct fuse_in_header *h, size_t argsize, const char **new)
{
	const char *p = (const char *)(h + 1) + argsize, *end = (const char *)h + h->len;

	if (h->len < sizeof *h + argsize)
		return 0;
	const char *z = memchr(p, 0, end - p);
	if (!z || !memchr(z + 1, 0, end - z - 1))
		return 0;
	*new = z + 1;
	return 1;
}

static void handle(const struct fuse_in_header *h, const void *arg)
{
	uint64_t id = h->nodeid, unique = h->unique;
	struct node *n = node_get(id);
	struct fuse_attr_out ao;
	struct fuse_entry_out eo;
	struct fuse_open_out oo;

	if (h->opcode < NOPS)
		atomic_fetch_add(&st->ops[h->opcode], 1);
	switch (h->opcode) {
	case FUSE_INIT:
		do_init(unique, arg);
		return;
	case FUSE_DESTROY:
		reply_err(unique, 0);
		return;
	case FUSE_FORGET:
		if (n) {
			const struct fuse_forget_in *f = arg;
			n->nlookup -= f->nlookup < n->nlookup ? f->nlookup : n->nlookup;
			node_drop(n);
		}
		return;
	case FUSE_BATCH_FORGET: {
		const struct fuse_batch_forget_in *b = arg;
		const struct fuse_forget_one *one = (const void *)(b + 1);
		if (h->len < sizeof *h + sizeof *b ||
		    b->count > (h->len - sizeof *h - sizeof *b) / sizeof *one)
			return;	/* FORGET has no reply */
		for (uint32_t i = 0; i < b->count; i++) {
			struct node *m = node_get(one[i].nodeid);
			if (m) {
				m->nlookup -= one[i].nlookup < m->nlookup ? one[i].nlookup : m->nlookup;
				node_drop(m);
			}
		}
		return;
	}
	case FUSE_INTERRUPT:
		do_interrupt(((const struct fuse_interrupt_in *)arg)->unique);
		return;
	case FUSE_LOOKUP:
		if (id != FUSE_ROOT_ID || !(n = node_find(arg))) {
			reply_err(unique, ENOENT);
			return;
		}
		fill_entry(n - nodes, &eo);
		reply(unique, 0, &eo, sizeof eo, NULL, 0);
		return;
	case FUSE_GETATTR:
		if (id != FUSE_ROOT_ID && !n) {
			reply_err(unique, ENOENT);
			return;
		}
		memset(&ao, 0, sizeof ao);
		ao.attr_valid = TTL;
		fill_attr(id, &ao.attr);
		reply(unique, 0, &ao, sizeof ao, NULL, 0);
		return;
	case FUSE_SETATTR: {
		const struct fuse_setattr_in *in = arg;
		if (!n) {
			reply_err(unique, id == FUSE_ROOT_ID ? EPERM : ENOENT);
			return;
		}
		if (in->valid & FATTR_SIZE) {
			int err = node_resize(n, in->size);
			if (err) {
				reply_err(unique, -err);
				return;
			}
		}
		if (in->valid & FATTR_MODE)
			n->mode = S_IFREG | (in->mode & 07777);
		if (in->valid & FATTR_MTIME)
			n->mtime = (struct timespec){ in->mtime, in->mtimensec };
		memset(&ao, 0, sizeof ao);
		ao.attr_valid = TTL;
		fill_attr(id, &ao.attr);
		reply(unique, 0, &ao, sizeof ao, NULL, 0);
		return;
	}
	case FUSE_CREATE: {
		const struct fuse_create_in *in = arg;
		const char *name = (const char *)(in + 1);
		struct node *m = node_find(name);
		if (id != FUSE_ROOT_ID) {
			reply_err(unique, ENOENT);
			return;
		}
		if (m && (in->flags & O_EXCL)) {
			reply_err(unique, EEXIST);
			return;
		}
		if (strlen(name) > NAME_MAX) {
			reply_err(unique, ENAMETOOLONG);
			return;
		}
		for (int i = FUSE_ROOT_ID + 1; !m && i < NNODES; i++) {
			if (!nodes[i].used) {
				m = &nodes[i];
				*m = (struct node){ .used = 1, .linked = 1,
						    .mode = S_IFREG | (in->mode & 07777 & ~in->umask) };
				strcpy(m->name, name);
				clock_gettime(CLOCK_REALTIME, &m->mtime);
			}
		}
		if (!m) {
			reply_err(unique, ENOSPC);
			return;
		}
		if ((in->flags & O_TRUNC) && node_resize(m, 0)) {
			reply_err(unique, EIO);
			return;
		}
		fill_entry(m - nodes, &eo);
		oo = (struct fuse_open_out){ .fh = m - nodes, .open_flags = FOPEN_KEEP_CACHE };
		reply(unique, 0, &eo, sizeof eo, &oo, sizeof oo);
		return;
	}
	case FUSE_OPEN:
		if (!n) {
			reply_err(unique, ENOENT);
			return;
		}
		/* The page cache is the only writer: keep it across opens. */
		oo = (struct fuse_open_out){ .fh = id, .open_flags = FOPEN_KEEP_CACHE };
		reply(unique, 0, &oo, sizeof oo, NULL, 0);
		return;
	case FUSE_OPENDIR:
		oo = (struct fuse_open_out){ 0 };
		reply(unique, 0, &oo, sizeof oo, NULL, 0);
		return;
	case FUSE_READDIR:
		do_readdir(unique, arg);
		return;
	case FUSE_RELEASEDIR:
		reply_err(unique, 0);
		return;
	case FUSE_READ: {
		const struct fuse_read_in *in = arg;
		if (!n) {
			reply_err(unique, EBADF);
			return;
		}
		size_t len = in->offset >= n->size ? 0 : n->size - in->offset;
		if (len > in->size)
			len = in->size;
		reply(unique, 0, len ? n->data + in->offset : NULL, len, NULL, 0);
		return;
	}
	case FUSE_WRITE: {
		const struct fuse_write_in *in = arg;
		if (h->len < sizeof *h + sizeof *in ||
		    in->size > h->len - sizeof *h - sizeof *in) {
			reply_err(unique, EINVAL);
			return;
		}
		if (in->offset > MAXSIZE || in->size > MAXSIZE - in->offset) {
			reply_err(unique, EFBIG);
			return;
		}
		struct fuse_write_out out = { .size = in->size };
		if (!n) {
			reply_err(unique, EBADF);
			return;
		}
		if (in->write_flags & FUSE_WRITE_CACHE)
			atomic_fetch_add(&st->cache_writes, 1);
		if (in->offset + in->size > n->size) {
			int err = node_resize(n, in->offset + in->size);
			if (err) {
				reply_err(unique, -err);
				return;
			}
		}
		memcpy(n->data + in->offset, in + 1, in->size);
		clock_gettime(CLOCK_REALTIME, &n->mtime);
		reply(unique, 0, &out, sizeof out, NULL, 0);
		return;
	}
	case FUSE_FLUSH:
		/* The kernel leaves unlock on close to the flush. */
		if (n) {
			lock_drop_owner(id, ((const struct fuse_flush_in *)arg)->lock_owner, 0);
			lock_wake();
		}
		reply_err(unique, 0);
		return;
	case FUSE_RELEASE: {
		const struct fuse_release_in *in = arg;
		if (n && (in->release_flags & FUSE_RELEASE_FLOCK_UNLOCK)) {
			lock_drop_owner(id, in->lock_owner, 1);
			lock_wake();
		}
		reply_err(unique, 0);
		return;
	}
	case FUSE_FSYNC:
		if (!n) {
			reply_err(unique, EBADF);
			return;
		}
		if (((const struct fuse_fsync_in *)arg)->fsync_flags & 1)
			atomic_fetch_add(&st->fdatasyncs, 1);
		else
			atomic_fetch_add(&st->fsyncs, 1);
		atomic_store(&st->sync_node, id);
		atomic_store(&st->sync_size, n->size);
		atomic_store(&st->sync_sum, checksum(n->data, n->size));
		reply_err(unique, 0);
		return;
	case FUSE_UNLINK:
		if (id != FUSE_ROOT_ID || !node_find(arg)) {
			reply_err(unique, ENOENT);
			return;
		}
		unlink_name(arg);
		reply_err(unique, 0);
		return;
	case FUSE_RENAME: {
		const struct fuse_rename_in *in = arg;
		const char *new;
		if (!two_names(h, sizeof *in, &new)) {
			reply_err(unique, EINVAL);
			return;
		}
		do_rename(unique, id, in->newdir, 0, (const char *)(in + 1), new);
		return;
	}
	case FUSE_RENAME2: {
		const struct fuse_rename2_in *in = arg;
		const char *new;
		if (!two_names(h, sizeof *in, &new)) {
			reply_err(unique, EINVAL);
			return;
		}
		do_rename(unique, id, in->newdir, in->flags, (const char *)(in + 1), new);
		return;
	}
	case FUSE_GETLK:
		if (!n) {
			reply_err(unique, EBADF);
			return;
		}
		do_getlk(unique, id, arg);
		return;
	case FUSE_SETLK:
	case FUSE_SETLKW:
		if (!n) {
			reply_err(unique, EBADF);
			return;
		}
		do_setlk(unique, id, arg, h->opcode == FUSE_SETLKW);
		return;
	case FUSE_STATFS: {
		struct fuse_statfs_out out = { .st = {
			.blocks = MAXSIZE / 4096, .bfree = MAXSIZE / 4096,
			.bavail = MAXSIZE / 4096, .files = NNODES, .ffree = NNODES,
			.bsize = 4096, .namelen = NAME_MAX, .frsize = 4096 } };
		reply(unique, 0, &out, sizeof out, NULL, 0);
		return;
	}
	default:
		reply_err(unique, ENOSYS);
		return;
	}
}

/* One thread serves every request, so the tables need no locking;
 * F_SETLKW requests that must wait are answered later. */
static void *serve(void *arg)
{
	static unsigned char buf[MAX_WRITE + 64 * 1024];

	(void)arg;
	for (;;) {
		/* One byte stays free for the NUL below. */
		ssize_t n = read(fuse_fd, buf, sizeof buf - 1);
		if (n < 0) {
			if (errno == ENOENT || errno == EINTR || errno == EAGAIN)
				continue;
			if (errno == ENODEV)
				return NULL;	/* unmounted */
			FAIL("read /dev/fuse");
		}
		const struct fuse_in_header *h = (const void *)buf;
		if ((size_t)n < sizeof *h || h->len != (size_t)n)
			FAIL("short request: %zd bytes", n);
		buf[n] = 0;	/* names end in NUL; keep a stray one bounded */
		handle(h, h + 1);
	}
}

/* ---- test helpers */

static const char *mnt;

static const char *path(const char *name)
{
	static char buf[2][PATH_MAX];
	static int which;

	which ^= 1;
	snprintf(buf[which], sizeof buf[which], "%s/%s", mnt, name);
	return buf[which];
}

static int wait_child(pid_t pid)
{
	int status;

	SYS(waitpid(pid, &status, 0));
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static void expect_child(pid_t pid, const char *what)
{
	int rc = wait_child(pid);

	errno = 0;
	CHECK(rc == 0, "%s: child exited %d", what, rc);
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Wait (at most 10 s) until the server has this many F_SETLKW requests waiting. */
static void wait_waiting(int n)
{
	for (double end = now() + 10; atomic_load(&st->waiting) != n;) {
		errno = 0;
		CHECK(now() < end, "%d F_SETLKW waiting, not %d", atomic_load(&st->waiting), n);
		usleep(1000);
	}
}

static int setlk(int fd, int cmd, short type, off_t start, off_t len)
{
	struct flock fl = { .l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len };

	return fcntl(fd, cmd, &fl);
}

static struct flock getlk(int fd, short type, off_t start, off_t len)
{
	struct flock fl = { .l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len };

	SYS(fcntl(fd, F_GETLK, &fl));
	return fl;
}

/* A pipe each way between parent and child, to step them together.
 * Each side closes the other's ends, so a side that exits early is seen
 * as end of file instead of a wait forever. */
struct chan { int up[2], down[2]; };

static void chan_open(struct chan *c)
{
	SYS(pipe(c->up));
	SYS(pipe(c->down));
}

static void chan_side(struct chan *c, int child)
{
	if (child) {
		SYS(close(c->up[0]));
		SYS(close(c->down[1]));
	} else {
		SYS(close(c->up[1]));
		SYS(close(c->down[0]));
	}
}

static void chan_close(struct chan *c)
{
	SYS(close(c->up[0]));
	SYS(close(c->down[1]));
}

static void chan_send(int fd)
{
	char b = 1;

	CHECK(write(fd, &b, 1) == 1, "pipe write");
}

static void chan_recv(int fd)
{
	char b;

	CHECK(read(fd, &b, 1) == 1, "pipe read (the other side exited?)");
}

/* ---- MAP_SHARED coherence (the WAL index) */

#define SHM_SIZE (32 << 10)	/* SQLite maps the WAL index 32 KiB at a time */
#define ROUNDS 2000
#define RECORD 256

struct shm_head {
	/* Even rounds: 2 * round + 1 + who, stored through the mapping with
	 * release and loaded with acquire. */
	_Atomic uint32_t seq;
	/* Odd rounds: the same value, written with pwrite(); the pipe orders
	 * it before the other side reads it. */
	uint32_t pwrite_round;
};

static void fill_record(unsigned char *p, uint32_t round, int who)
{
	for (int i = 0; i < RECORD - 8; i++)
		p[i] = (unsigned char)(round * 31 + i * 7 + who);
	uint64_t sum = checksum(p, RECORD - 8);
	memcpy(p + RECORD - 8, &sum, 8);
}

static int record_ok(const unsigned char *p, uint32_t round, int who)
{
	unsigned char want[RECORD];

	fill_record(want, round, who);
	return !memcmp(p, want, RECORD);
}

/* Each round's record lives on its own page, away from the counter. */
static off_t record_off(uint32_t round, int who)
{
	return 4096 * (1 + round % 7) + who * RECORD + (round % 8) * 2 * RECORD;
}

static void wait_seq(struct shm_head *h, uint32_t seq)
{
	double end = now() + 10;

	while (atomic_load_explicit(&h->seq, memory_order_acquire) != seq) {
		errno = 0;
		CHECK(now() < end, "seq %u never arrived (at %u)", seq, atomic_load(&h->seq));
		sched_yield();
	}
}

/* Each round one side stores its record and the other checks it through
 * both its mapping and pread().  Even rounds store through the mapping,
 * odd rounds through pwrite(). */
static void shm_send(int fd, unsigned char *m, int out, uint32_t r, int who)
{
	struct shm_head *h = (struct shm_head *)m;
	unsigned char rec[RECORD];
	uint32_t tag = 2 * r + 1 + who;

	fill_record(rec, r, who);
	if (r & 1) {
		CHECK(pwrite(fd, rec, RECORD, record_off(r, who)) == RECORD, "pwrite record");
		CHECK(pwrite(fd, &tag, 4, offsetof(struct shm_head, pwrite_round)) == 4, "pwrite round");
		chan_send(out);
	} else {
		memcpy(m + record_off(r, who), rec, RECORD);
		atomic_store_explicit(&h->seq, tag, memory_order_release);
	}
}

static void shm_recv(int fd, unsigned char *m, int in, uint32_t r, int who)
{
	struct shm_head *h = (struct shm_head *)m;
	unsigned char rec[RECORD];
	uint32_t tag = 2 * r + 1 + who;

	if (r & 1) {
		chan_recv(in);
		uint32_t seen = *(volatile uint32_t *)&h->pwrite_round;
		errno = 0;
		CHECK(seen == tag, "round %u: pwrite() of %u seen as %u in the mapping", r, tag, seen);
	} else {
		wait_seq(h, tag);
	}
	errno = 0;
	CHECK(record_ok(m + record_off(r, who), r, who), "round %u: record of %d via mapping", r, who);
	CHECK(pread(fd, rec, RECORD, record_off(r, who)) == RECORD, "pread");
	errno = 0;
	CHECK(record_ok(rec, r, who), "round %u: record of %d via pread", r, who);
}

static void shm_child(struct chan *c)
{
	int fd = SYS(open(path("wal.db-shm"), O_RDWR));
	unsigned char *m = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	CHECK(m != MAP_FAILED, "child mmap");
	chan_side(c, 1);
	for (uint32_t r = 0; r < ROUNDS; r++) {
		shm_recv(fd, m, c->down[0], r, 0);
		shm_send(fd, m, c->up[1], r, 1);
		if (r % 250 == 249)
			SYS(msync(m, SHM_SIZE, MS_SYNC));
	}
	SYS(munmap(m, SHM_SIZE));
	SYS(close(fd));
	_exit(0);
}

static void test_mmap_shared(void)
{
	int fd = SYS(open(path("wal.db-shm"), O_RDWR | O_CREAT | O_TRUNC, 0644));
	struct stat sb;

	/* Grow the file a byte per page as SQLite does before mapping it. */
	for (off_t off = 4096 - 1; off < SHM_SIZE; off += 4096)
		CHECK(pwrite(fd, "", 1, off) == 1, "extend to %lld", (long long)off + 1);
	SYS(fstat(fd, &sb));
	errno = 0;
	CHECK(sb.st_size == SHM_SIZE, "size %lld", (long long)sb.st_size);
	unsigned char *m = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(m != MAP_FAILED, "mmap");

	unsigned long long cache_writes = atomic_load(&st->cache_writes);
	struct chan c;
	chan_open(&c);
	pid_t pid = SYS(fork());
	if (!pid)
		shm_child(&c);
	chan_side(&c, 0);
	for (uint32_t r = 0; r < ROUNDS; r++) {
		shm_send(fd, m, c.down[1], r, 0);
		shm_recv(fd, m, c.up[0], r, 1);
	}
	expect_child(pid, "mapping child");
	chan_close(&c);

	/* msync(MS_SYNC) writes the dirty pages back and syncs: the server
	 * holds exactly the bytes of the mapping. */
	memset(m + SHM_SIZE - 512, 0x5a, 512);
	SYS(msync(m, SHM_SIZE, MS_SYNC));
	errno = 0;
	CHECK(atomic_load(&st->cache_writes) > cache_writes, "no page writeback reached the server");
	CHECK(atomic_load(&st->sync_size) == SHM_SIZE, "server size %llu",
	      (unsigned long long)atomic_load(&st->sync_size));
	CHECK(atomic_load(&st->sync_sum) == checksum(m, SHM_SIZE), "server bytes differ from the mapping");

	/* A new descriptor reads the same bytes. */
	SYS(munmap(m, SHM_SIZE));
	SYS(close(fd));
	unsigned char *all = malloc(SHM_SIZE), *again = malloc(SHM_SIZE);
	CHECK(all && again, "malloc");
	fd = SYS(open(path("wal.db-shm"), O_RDONLY));
	CHECK(pread(fd, all, SHM_SIZE, 0) == SHM_SIZE, "pread all");
	m = mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	CHECK(m != MAP_FAILED, "mmap read-only");
	memcpy(again, m, SHM_SIZE);
	errno = 0;
	CHECK(!memcmp(all, again, SHM_SIZE), "read and mapping differ after reopen");
	CHECK(atomic_load(&st->sync_sum) == checksum(all, SHM_SIZE), "reopened bytes differ from the server's");
	SYS(munmap(m, SHM_SIZE));
	SYS(close(fd));
	free(all);
	free(again);
	printf("  mmap: %d rounds between two MAP_SHARED mappings\n", ROUNDS);
}

/* ---- fcntl byte range locks (SQLite's lock bytes) */

#define PENDING 1000	/* stand-ins for SQLite's PENDING, RESERVED and SHARED bytes */
#define RESERVED 1001
#define SHARED 1002
#define SHARED_LEN 510

static void test_lock_conflicts(int fd)
{
	struct chan c;

	struct flock fl = getlk(fd, F_WRLCK, 0, 0);
	errno = 0;
	CHECK(fl.l_type == F_UNLCK, "unlocked file reports lock type %d", fl.l_type);

	/* The parent takes RESERVED for writing and a SHARED range for reading. */
	SYS(setlk(fd, F_SETLK, F_WRLCK, RESERVED, 1));
	SYS(setlk(fd, F_SETLK, F_RDLCK, SHARED, SHARED_LEN));
	chan_open(&c);
	pid_t pid = SYS(fork());
	if (!pid) {
		chan_side(&c, 1);
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		struct flock g = getlk(cfd, F_WRLCK, RESERVED, 1);
		errno = 0;
		CHECK(g.l_type == F_WRLCK && g.l_start == RESERVED && g.l_len == 1 &&
		      g.l_pid == getppid(), "F_GETLK on RESERVED: type %d start %lld len %lld pid %d",
		      g.l_type, (long long)g.l_start, (long long)g.l_len, g.l_pid);
		CHECK(setlk(cfd, F_SETLK, F_RDLCK, RESERVED, 1) < 0 &&
		      (errno == EAGAIN || errno == EACCES), "read lock on a write-locked byte");
		/* Overlapping only at the range's end still conflicts. */
		CHECK(setlk(cfd, F_SETLK, F_WRLCK, RESERVED - 9, 10) < 0 &&
		      (errno == EAGAIN || errno == EACCES), "write lock overlapping RESERVED");
		/* Ranges next to it are free. */
		SYS(setlk(cfd, F_SETLK, F_WRLCK, PENDING, 1));
		SYS(setlk(cfd, F_SETLK, F_WRLCK, RESERVED + SHARED_LEN + 1, 0));
		/* Read locks share, write locks do not. */
		SYS(setlk(cfd, F_SETLK, F_RDLCK, SHARED + 5, 10));
		CHECK(setlk(cfd, F_SETLK, F_WRLCK, SHARED + SHARED_LEN - 1, 1) < 0 &&
		      (errno == EAGAIN || errno == EACCES), "write lock on a read-locked byte");
		g = getlk(cfd, F_WRLCK, SHARED, 1);
		errno = 0;
		CHECK(g.l_type == F_RDLCK && g.l_pid == getppid(), "F_GETLK on SHARED: type %d", g.l_type);
		chan_send(c.up[1]);
		chan_recv(c.down[0]);
		/* The parent unlocked the middle of its read lock: only the
		 * middle is free. */
		SYS(setlk(cfd, F_SETLK, F_WRLCK, SHARED + 100, 10));
		CHECK(setlk(cfd, F_SETLK, F_WRLCK, SHARED + 99, 1) < 0 &&
		      (errno == EAGAIN || errno == EACCES), "write lock below the unlocked part");
		CHECK(setlk(cfd, F_SETLK, F_WRLCK, SHARED + 110, 1) < 0 &&
		      (errno == EAGAIN || errno == EACCES), "write lock above the unlocked part");
		_exit(0);
	}
	chan_side(&c, 0);
	chan_recv(c.up[0]);
	/* And the child's locks hold against the parent. */
	struct flock g = getlk(fd, F_WRLCK, PENDING, 1);
	errno = 0;
	CHECK(g.l_type == F_WRLCK && g.l_pid == pid, "F_GETLK on PENDING: type %d pid %d", g.l_type, g.l_pid);
	CHECK(setlk(fd, F_SETLK, F_WRLCK, 1 << 20, 1) < 0 && (errno == EAGAIN || errno == EACCES),
	      "write lock in the child's range to end of file");
	SYS(setlk(fd, F_SETLK, F_UNLCK, SHARED + 100, 10));
	chan_send(c.down[1]);
	expect_child(pid, "lock conflicts");
	chan_close(&c);
	/* The child's locks went with it. */
	g = getlk(fd, F_WRLCK, 0, 0);
	errno = 0;
	CHECK(g.l_type == F_UNLCK, "locks left after the child exited: type %d pid %d", g.l_type, g.l_pid);
	SYS(setlk(fd, F_SETLK, F_UNLCK, 0, 0));
}

#define WORKERS 4
#define ITERS 200

/* Writers take PENDING with F_SETLKW, as SQLite's busy loop would with a
 * blocking lock, and increment a counter kept in the file. */
static void test_lock_exclusion(int fd)
{
	_Atomic int *inside = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(inside != MAP_FAILED, "mmap");
	unsigned long long waits = atomic_load(&st->lock_waits);
	pid_t pids[WORKERS];

	/* Every worker's first F_SETLKW waits on the parent's lock, so the
	 * server always has several waiters for one release. */
	SYS(setlk(fd, F_SETLK, F_WRLCK, PENDING, 1));

	for (int w = 0; w < WORKERS; w++) {
		pids[w] = SYS(fork());
		if (pids[w])
			continue;
		int wfd = SYS(open(path("lock.db"), O_RDWR));
		for (int i = 0; i < ITERS; i++) {
			/* Readers' ranges never conflict with each other. */
			SYS(setlk(wfd, F_SETLK, F_RDLCK, SHARED + w, 1));
			SYS(setlk(wfd, F_SETLKW, F_WRLCK, PENDING, 1));
			errno = 0;
			CHECK(atomic_fetch_add(inside, 1) == 0, "two holders of one write lock");
			uint32_t v;
			CHECK(pread(wfd, &v, 4, 8192) == 4, "pread counter");
			if (i % 4 == 0)
				sched_yield();
			v++;
			CHECK(pwrite(wfd, &v, 4, 8192) == 4, "pwrite counter");
			atomic_fetch_sub(inside, 1);
			SYS(setlk(wfd, F_SETLK, F_UNLCK, PENDING, 1));
			SYS(setlk(wfd, F_SETLK, F_UNLCK, SHARED + w, 1));
			if (i % 3 == 0)
				sched_yield();
		}
		_exit(0);
	}
	wait_waiting(WORKERS);
	SYS(setlk(fd, F_SETLK, F_UNLCK, PENDING, 1));
	for (int w = 0; w < WORKERS; w++)
		expect_child(pids[w], "lock worker");
	int rd = SYS(open(path("lock.db"), O_RDONLY));
	uint32_t v = 0;
	CHECK(pread(rd, &v, 4, 8192) == 4, "pread counter");
	SYS(close(rd));
	errno = 0;
	CHECK(v == WORKERS * ITERS, "counter %u, not %u", v, WORKERS * ITERS);
	CHECK(atomic_load(&st->waiting) == 0, "%d requests still waiting", atomic_load(&st->waiting));
	printf("  locks: %d workers x %d exclusive sections, %llu waited\n", WORKERS, ITERS,
	       atomic_load(&st->lock_waits) - waits);
	munmap((void *)inside, 4096);
}

/* F_UNLCK by a holder that stays alive wakes a waiter at once. */
static void test_lock_unlock_wakes(int fd)
{
	unsigned long long wakeups = atomic_load(&st->lock_wakeups);
	int status = 0;
	pid_t r = 0;

	SYS(setlk(fd, F_SETLK, F_WRLCK, PENDING, 1));
	pid_t pid = SYS(fork());
	if (!pid) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		SYS(setlk(cfd, F_SETLKW, F_RDLCK, PENDING, 1));
		_exit(0);
	}
	wait_waiting(1);
	SYS(setlk(fd, F_SETLK, F_UNLCK, PENDING, 1));
	for (double end = now() + 10; !r && now() < end; usleep(1000))
		r = SYS(waitpid(pid, &status, WNOHANG));
	errno = 0;
	CHECK(r == pid, "F_SETLKW still waiting after the holder unlocked");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status), "waiter ended with status %#x", status);
	CHECK(atomic_load(&st->lock_wakeups) > wakeups, "the waiter was not woken by the server");
}

/* A holder that exits without unlocking: closing its descriptor sends
 * FUSE_FLUSH with its lock owner, which releases the lock and wakes the
 * waiter. */
static void test_lock_holder_exit(void)
{
	struct chan c;
	unsigned long long flushes = nops(FUSE_FLUSH), wakeups = atomic_load(&st->lock_wakeups);

	chan_open(&c);
	pid_t holder = SYS(fork());
	if (!holder) {
		chan_side(&c, 1);
		int fd = SYS(open(path("lock.db"), O_RDWR));
		SYS(setlk(fd, F_SETLK, F_WRLCK, PENDING, 3));
		chan_send(c.up[1]);
		chan_recv(c.down[0]);
		_exit(3);
	}
	chan_side(&c, 0);
	chan_recv(c.up[0]);
	pid_t waiter = SYS(fork());
	if (!waiter) {
		int fd = SYS(open(path("lock.db"), O_RDWR));
		SYS(setlk(fd, F_SETLKW, F_WRLCK, RESERVED, 1));
		struct flock g = getlk(fd, F_WRLCK, PENDING, 3);
		errno = 0;
		CHECK(g.l_type == F_UNLCK, "holder's lock left: type %d", g.l_type);
		_exit(0);
	}
	wait_waiting(1);
	errno = 0;
	CHECK(waitpid(waiter, NULL, WNOHANG) == 0, "F_SETLKW returned while the lock was held");
	chan_send(c.down[1]);
	int rc = wait_child(holder);
	errno = 0;
	CHECK(rc == 3, "holder exited %d", rc);
	expect_child(waiter, "waiter after the holder exited");
	CHECK(nops(FUSE_FLUSH) > flushes, "no FUSE_FLUSH when the holder exited");
	CHECK(atomic_load(&st->lock_wakeups) > wakeups, "the waiter was not woken by the server");
	chan_close(&c);
}

/* POSIX drops a process's locks on a file when it closes any descriptor
 * of it, a rule SQLite has to live with: FUSE keeps it. */
static void test_lock_close_other_fd(void)
{
	int fd = SYS(open(path("lock.db"), O_RDWR));
	int other = SYS(open(path("lock.db"), O_RDONLY));
	pid_t pid;

	SYS(setlk(fd, F_SETLK, F_WRLCK, SHARED, SHARED_LEN));
	if (!(pid = SYS(fork()))) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		_exit(setlk(cfd, F_SETLK, F_RDLCK, SHARED, 1) < 0 &&
		      (errno == EAGAIN || errno == EACCES) ? 0 : 1);
	}
	expect_child(pid, "lock held before close");
	SYS(close(other));
	if (!(pid = SYS(fork()))) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		_exit(setlk(cfd, F_SETLK, F_WRLCK, SHARED, SHARED_LEN) == 0 ? 0 : 1);
	}
	expect_child(pid, "lock gone after closing another descriptor");
	SYS(close(fd));
}

static void on_signal(int sig)
{
	(void)sig;
}

/* A signal ends F_SETLKW with EINTR: the kernel sends FUSE_INTERRUPT and
 * the server answers the waiting request.  The signal is sent only once
 * the server holds the request, however slow the machine. */
static void test_lock_interrupt(int fd)
{
	unsigned long long interrupted = atomic_load(&st->lock_interrupted);

	SYS(setlk(fd, F_SETLK, F_WRLCK, PENDING, 1));
	pid_t pid = SYS(fork());
	if (!pid) {
		struct sigaction sa = { .sa_handler = on_signal };	/* no SA_RESTART */
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		SYS(sigaction(SIGUSR1, &sa, NULL));
		int r = setlk(cfd, F_SETLKW, F_WRLCK, PENDING, 1);
		CHECK(r < 0 && errno == EINTR, "F_SETLKW returned %d, not EINTR", r);
		/* The interrupted request holds nothing. */
		struct flock g = getlk(cfd, F_WRLCK, PENDING, 1);
		errno = 0;
		CHECK(g.l_type == F_WRLCK && g.l_pid == getppid(), "lock owner after EINTR: pid %d", g.l_pid);
		_exit(0);
	}
	wait_waiting(1);
	SYS(kill(pid, SIGUSR1));
	expect_child(pid, "interrupted F_SETLKW");
	SYS(setlk(fd, F_SETLK, F_UNLCK, PENDING, 1));
	errno = 0;
	CHECK(atomic_load(&st->lock_interrupted) == interrupted + 1, "server saw %llu interrupts",
	      atomic_load(&st->lock_interrupted) - interrupted);
	CHECK(atomic_load(&st->waiting) == 0, "%d requests still waiting", atomic_load(&st->waiting));
}

/* flock goes to the server too, apart from POSIX locks. */
static void test_flock(void)
{
	unsigned long long flock_ops = atomic_load(&st->flock_ops);
	int fd = SYS(open(path("lock.db"), O_RDWR));
	pid_t pid;

	SYS(flock(fd, LOCK_EX));
	if (!(pid = SYS(fork()))) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		CHECK(flock(cfd, LOCK_SH | LOCK_NB) < 0 && errno == EWOULDBLOCK, "flock against LOCK_EX");
		SYS(setlk(cfd, F_SETLK, F_WRLCK, 0, 0));
		_exit(0);
	}
	expect_child(pid, "flock held");
	SYS(flock(fd, LOCK_SH));
	if (!(pid = SYS(fork()))) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		SYS(flock(cfd, LOCK_SH | LOCK_NB));
		CHECK(flock(cfd, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK, "LOCK_EX against LOCK_SH");
		_exit(0);
	}
	expect_child(pid, "flock shared");
	/* Releasing the open file drops its flock; the request waits for it. */
	SYS(close(fd));
	if (!(pid = SYS(fork()))) {
		int cfd = SYS(open(path("lock.db"), O_RDWR));
		SYS(flock(cfd, LOCK_EX));
		_exit(0);
	}
	expect_child(pid, "flock after close");
	errno = 0;
	CHECK(atomic_load(&st->flock_ops) > flock_ops, "flock never reached the server");
}

static void test_locks(void)
{
	unsigned long long setlk_ops = nops(FUSE_SETLK), getlk_ops = nops(FUSE_GETLK);
	int fd = SYS(open(path("lock.db"), O_RDWR | O_CREAT | O_TRUNC, 0644));

	SYS(ftruncate(fd, 16384));
	test_lock_conflicts(fd);
	test_lock_exclusion(fd);
	test_lock_unlock_wakes(fd);
	test_lock_holder_exit();
	test_lock_close_other_fd();
	test_lock_interrupt(fd);
	SYS(close(fd));
	test_flock();
	errno = 0;
	CHECK(nops(FUSE_SETLK) > setlk_ops && nops(FUSE_GETLK) > getlk_ops,
	      "locks were not passed to the server");
	CHECK(nops(FUSE_SETLKW) > 0, "no F_SETLKW reached the server");
}

/* ---- WAL frames, checkpoint, truncation and atomic replacement */

#define PAGE 4096
#define FRAME_HDR 24
#define WAL_HDR 32
#define FRAMES 64
#define COMMIT_EVERY 8

static void page_fill(unsigned char *p, uint32_t pgno, uint32_t gen)
{
	for (int i = 0; i < PAGE; i++)
		p[i] = (unsigned char)(pgno * 13 + gen * 101 + i);
}

static void test_wal(void)
{
	static unsigned char page[PAGE], frame[FRAME_HDR + PAGE], buf[PAGE];
	int db = SYS(open(path("main.db"), O_RDWR | O_CREAT | O_TRUNC, 0644));
	int wal = SYS(open(path("main.db-wal"), O_RDWR | O_CREAT | O_TRUNC, 0644));
	unsigned char *mirror = calloc(1, WAL_HDR + FRAMES * sizeof frame);
	struct stat sb;

	CHECK(mirror, "calloc");
	/* The database starts with 16 pages of generation 0. */
	for (uint32_t pg = 0; pg < 16; pg++) {
		page_fill(page, pg, 0);
		CHECK(pwrite(db, page, PAGE, (off_t)pg * PAGE) == PAGE, "pwrite db page %u", pg);
	}
	unsigned long long fsyncs = atomic_load(&st->fsyncs);
	SYS(fsync(db));
	errno = 0;
	CHECK(atomic_load(&st->fsyncs) == fsyncs + 1, "fsync count %llu, not %llu",
	      atomic_load(&st->fsyncs), fsyncs + 1);

	memset(mirror, 0x37, WAL_HDR);
	CHECK(pwrite(wal, mirror, WAL_HDR, 0) == WAL_HDR, "pwrite WAL header");
	unsigned long long syncs = atomic_load(&st->fdatasyncs);
	for (uint32_t f = 0; f < FRAMES; f++) {
		uint32_t pgno = f % 16, gen = 1 + f / 16;
		off_t off = WAL_HDR + (off_t)f * sizeof frame;
		memset(frame, 0, FRAME_HDR);
		memcpy(frame, &pgno, 4);
		uint32_t commit = (f + 1) % COMMIT_EVERY == 0 ? f + 1 : 0;
		memcpy(frame + 4, &commit, 4);
		page_fill(frame + FRAME_HDR, pgno, gen);
		uint64_t sum = checksum(frame + FRAME_HDR, PAGE);
		memcpy(frame + 8, &sum, 8);
		CHECK(pwrite(wal, frame, sizeof frame, off) == (ssize_t)sizeof frame, "append frame %u", f);
		memcpy(mirror + off, frame, sizeof frame);
		if (!commit)
			continue;
		SYS(fdatasync(wal));
		syncs++;
		size_t len = off + sizeof frame;
		errno = 0;
		CHECK(atomic_load(&st->fdatasyncs) == syncs, "fdatasync count %llu, not %llu",
		      atomic_load(&st->fdatasyncs), syncs);
		CHECK(atomic_load(&st->sync_size) == len, "server WAL size %llu, not %zu",
		      (unsigned long long)atomic_load(&st->sync_size), len);
		CHECK(atomic_load(&st->sync_sum) == checksum(mirror, len), "server WAL bytes after frame %u", f);
	}
	/* A reader opening the WAL sees every frame. */
	int rd = SYS(open(path("main.db-wal"), O_RDONLY));
	for (uint32_t f = 0; f < FRAMES; f++) {
		off_t off = WAL_HDR + (off_t)f * sizeof frame;
		CHECK(pread(rd, frame, sizeof frame, off) == (ssize_t)sizeof frame, "read frame %u", f);
		uint64_t sum;
		memcpy(&sum, frame + 8, 8);
		errno = 0;
		CHECK(!memcmp(frame, mirror + off, sizeof frame) && sum == checksum(frame + FRAME_HDR, PAGE),
		      "frame %u read back differs", f);
	}
	SYS(close(rd));

	/* Checkpoint: the last frame of each page goes to the database. */
	for (uint32_t pg = 0; pg < 16; pg++) {
		off_t off = WAL_HDR + (off_t)(FRAMES - 16 + pg) * sizeof frame;
		CHECK(pread(wal, frame, sizeof frame, off) == (ssize_t)sizeof frame, "read frame for page %u", pg);
		CHECK(pwrite(db, frame + FRAME_HDR, PAGE, (off_t)pg * PAGE) == PAGE, "checkpoint page %u", pg);
	}
	SYS(fsync(db));
	errno = 0;
	CHECK(atomic_load(&st->fsyncs) == fsyncs + 2, "fsync count after checkpoint");
	/* The server holds the checkpointed pages, not only the page cache. */
	static unsigned char want[16 * PAGE];
	for (uint32_t pg = 0; pg < 16; pg++)
		page_fill(want + pg * PAGE, pg, FRAMES / 16);
	SYS(fstat(db, &sb));
	errno = 0;
	CHECK(atomic_load(&st->sync_node) == sb.st_ino, "last fsync was of node %llu, not %llu",
	      (unsigned long long)atomic_load(&st->sync_node), (unsigned long long)sb.st_ino);
	CHECK(atomic_load(&st->sync_size) == sizeof want, "server database size %llu after checkpoint",
	      (unsigned long long)atomic_load(&st->sync_size));
	CHECK(atomic_load(&st->sync_sum) == checksum(want, sizeof want),
	      "server database bytes differ after checkpoint");
	/* Then the WAL restarts from nothing. */
	unsigned long long setattrs = nops(FUSE_SETATTR);
	SYS(ftruncate(wal, 0));
	SYS(fsync(wal));
	errno = 0;
	CHECK(nops(FUSE_SETATTR) > setattrs, "ftruncate sent no FUSE_SETATTR");
	CHECK(atomic_load(&st->sync_size) == 0, "server WAL size %llu after truncation",
	      (unsigned long long)atomic_load(&st->sync_size));
	SYS(stat(path("main.db-wal"), &sb));
	errno = 0;
	CHECK(sb.st_size == 0, "WAL size %lld after truncation", (long long)sb.st_size);
	CHECK(pread(wal, buf, PAGE, 0) == 0, "WAL not empty after truncation");
	for (uint32_t pg = 0; pg < 16; pg++) {
		CHECK(pread(db, buf, PAGE, (off_t)pg * PAGE) == PAGE, "read page %u", pg);
		page_fill(page, pg, FRAMES / 16);
		errno = 0;
		CHECK(!memcmp(buf, page, PAGE), "page %u after checkpoint", pg);
	}

	/* Replace the database by rename, with the old one still open. */
	int tmp = SYS(open(path("main.db.tmp"), O_RDWR | O_CREAT | O_EXCL, 0644));
	errno = 0;
	CHECK(open(path("main.db.tmp"), O_RDWR | O_CREAT | O_EXCL, 0644) < 0 && errno == EEXIST,
	      "O_EXCL on an existing file");
	page_fill(page, 99, 99);
	CHECK(pwrite(tmp, page, PAGE, 0) == PAGE, "pwrite replacement");
	SYS(fsync(tmp));
	SYS(close(tmp));
	unsigned long long renames = nops(FUSE_RENAME), renames2 = nops(FUSE_RENAME2);
	errno = 0;
	CHECK(syscall(SYS_renameat2, AT_FDCWD, path("main.db.tmp"), AT_FDCWD, path("main.db"),
		      RENAME_NOREPLACE) < 0 && errno == EEXIST, "RENAME_NOREPLACE onto an existing file");
	SYS(syscall(SYS_renameat2, AT_FDCWD, path("main.db.tmp"), AT_FDCWD, path("main.db.new"),
		    RENAME_NOREPLACE));
	SYS(rename(path("main.db.new"), path("main.db")));
	errno = 0;
	CHECK(nops(FUSE_RENAME2) > renames2 && nops(FUSE_RENAME) > renames, "rename requests not seen");
	CHECK(stat(path("main.db.tmp"), &sb) < 0 && errno == ENOENT, "old name still there");
	CHECK(stat(path("main.db.new"), &sb) < 0 && errno == ENOENT, "intermediate name still there");
	int fresh = SYS(open(path("main.db"), O_RDONLY));
	SYS(fstat(fresh, &sb));
	errno = 0;
	CHECK(sb.st_size == PAGE, "replacement size %lld", (long long)sb.st_size);
	CHECK(pread(fresh, buf, PAGE, 0) == PAGE && !memcmp(buf, page, PAGE), "replacement contents");
	SYS(close(fresh));
	/* The descriptor opened before still has the old file. */
	SYS(fstat(db, &sb));
	errno = 0;
	CHECK(sb.st_size == 16 * PAGE && sb.st_nlink == 0, "replaced file: size %lld nlink %lu",
	      (long long)sb.st_size, (unsigned long)sb.st_nlink);
	CHECK(pread(db, buf, PAGE, 15 * PAGE) == PAGE, "read replaced file");
	page_fill(page, 15, FRAMES / 16);
	errno = 0;
	CHECK(!memcmp(buf, page, PAGE), "replaced file's contents");
	SYS(close(db));

	SYS(close(wal));
	SYS(unlink(path("main.db-wal")));
	errno = 0;
	CHECK(open(path("main.db-wal"), O_RDONLY) < 0 && errno == ENOENT, "unlinked WAL still opens");
	free(mirror);
	printf("  wal: %d frames, %d commits\n", FRAMES, FRAMES / COMMIT_EVERY);
}

static void run_tests(void)
{
	unsigned flags;
	double end = now() + 10;

	/* The first request waits for FUSE_INIT. */
	struct stat sb;
	SYS(stat(mnt, &sb));
	while (!(flags = atomic_load(&st->init_flags))) {
		errno = 0;
		CHECK(now() < end, "no FUSE_INIT");
		usleep(1000);
	}
	printf("  protocol 7.%u, flags %#x\n", atomic_load(&st->minor), flags);
	errno = 0;
	CHECK((flags & (FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS)) == (FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS),
	      "kernel does not pass locks to the server");
	test_mmap_shared();
	test_locks();
	test_wal();
	static const struct { unsigned op; const char *name; } used[] = {
		{ FUSE_LOOKUP, "LOOKUP" }, { FUSE_GETATTR, "GETATTR" }, { FUSE_SETATTR, "SETATTR" },
		{ FUSE_CREATE, "CREATE" }, { FUSE_OPEN, "OPEN" }, { FUSE_READ, "READ" },
		{ FUSE_WRITE, "WRITE" }, { FUSE_FLUSH, "FLUSH" }, { FUSE_FSYNC, "FSYNC" },
		{ FUSE_RELEASE, "RELEASE" }, { FUSE_UNLINK, "UNLINK" }, { FUSE_RENAME, "RENAME" },
		{ FUSE_RENAME2, "RENAME2" }, { FUSE_GETLK, "GETLK" }, { FUSE_SETLK, "SETLK" },
		{ FUSE_SETLKW, "SETLKW" }, { FUSE_INTERRUPT, "INTERRUPT" },
	};
	for (size_t i = 0; i < sizeof used / sizeof *used; i++) {
		errno = 0;
		CHECK(nops(used[i].op), "no FUSE_%s request", used[i].name);
	}
}

int main(int argc, char **argv)
{
	char opts[128];
	int made = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc != 2) {
		fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]);
		return 2;
	}
	mnt = argv[1];
	printf("FUSETEST: start\n");
	st = mmap(NULL, sizeof *st, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(st != MAP_FAILED, "mmap stats");
	clock_gettime(CLOCK_REALTIME, &mount_time);
	nodes[FUSE_ROOT_ID].used = 1;
	if (mkdir(mnt, 0755) == 0)
		made = 1;
	else
		CHECK(errno == EEXIST, "mkdir %s", mnt);
	fuse_fd = SYS(open("/dev/fuse", O_RDWR | O_CLOEXEC));
	snprintf(opts, sizeof opts, "fd=%d,rootmode=40000,user_id=%u,group_id=%u,allow_other,default_permissions",
		 fuse_fd, (unsigned)getuid(), (unsigned)getgid());
	SYS(mount("fusetest", mnt, "fuse", MS_NOSUID | MS_NODEV, opts));
	pthread_t server;
	errno = pthread_create(&server, NULL, serve, NULL);
	CHECK(!errno, "pthread_create");

	/* The tests run in a process of their own; it and its children must
	 * not keep the connection open, so a hang ends when this one exits. */
	pid_t pid = SYS(fork());
	if (!pid) {
		close(fuse_fd);
		run_tests();
		_exit(0);
	}
	int status;
	for (double end = now() + 120;; usleep(10000)) {
		pid_t r = SYS(waitpid(pid, &status, WNOHANG));
		if (r == pid)
			break;
		if (now() > end) {
			printf("FUSETEST: FAIL timeout\n");
			kill(pid, SIGKILL);
			umount2(mnt, MNT_DETACH);
			_exit(1);
		}
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		/* Exiting closes the connection, so nothing left waits on it. */
		printf("FUSETEST: FAIL (tests ended with status %#x)\n", status);
		umount2(mnt, MNT_DETACH);
		_exit(1);
	}
	SYS(umount2(mnt, 0));
	/* Unmounting ends the connection: the server's read gets ENODEV. */
	errno = pthread_join(server, NULL);
	CHECK(!errno, "pthread_join");
	close(fuse_fd);
	if (made)
		rmdir(mnt);
	printf("FUSETEST: PASS\n");
	return 0;
}
