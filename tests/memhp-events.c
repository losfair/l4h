/* SPDX-License-Identifier: GPL-2.0-only */
/* Run the driver's request, worker and IRQ code with a deterministic
 * host and workqueue. Queueing an already-pending work does not change its
 * delay; modifying it does, just as in Linux. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <l4h/abi.h>

typedef l4h_u32 u32;
typedef int irqreturn_t;
typedef struct { int v; } atomic_t;
#define IRQ_HANDLED 1
#define HZ 100
#define RETRY_BUSY HZ
#define RETRY_STUCK (10 * HZ)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) write_once(&(x), (v))
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))
#define wait_event(q, condition) do { if (!(condition)) complete_request(); assert(condition); } while (0)
#define pr_info_ratelimited(...) ((void)0)
#define for_each_set_bit(m, map, n) for ((m) = 0; (m) < (n); (m)++) if (test_bit((m), (map)))

struct work_struct { int unused; };
static struct work_struct memhp_work;
static struct l4h_mem_page memory;
static struct l4h_mem_page *page = &memory;
static unsigned int region_count = 4;
static u32 mem_seq, mem_target;
static unsigned long mem_kick;
static unsigned long added[1], pending[1];
static int mem_wq, memhp_mutex, memhp_wq;
static atomic_t plugged_blocks, ceiling_blocks;
static bool demand_mode;
static int queued_delay, requests, wakes;
static bool immediate_completion, target_during_completion, target_before_publish;

static irqreturn_t memhp_interrupt(int irq, void *data);
static long mem_call(unsigned long op, unsigned int m);
static void atomic_set(atomic_t *a, int v) { a->v = v; }
static void mutex_lock(int *m) { (void)m; }
static void mutex_unlock(int *m) { (void)m; }
static void wake_up(int *q) { (void)q; wakes++; }
static void mod_delayed_work(int q, struct work_struct *w, unsigned long delay)
{
	(void)q; (void)w;
	queued_delay = delay;
}
static bool queue_delayed_work(int q, struct work_struct *w, unsigned long delay)
{
	(void)q; (void)w;
	if (queued_delay >= 0)
		return false;
	queued_delay = delay;
	return true;
}
static bool test_bit(unsigned int m, const unsigned long *map) { return (*map >> m) & 1; }
static void __clear_bit(unsigned int m, unsigned long *map) { *map &= ~(1ul << m); }
static bool bitmap_empty(const unsigned long *map, unsigned int n) { (void)n; return !*map; }
static unsigned int bitmap_weight(const unsigned long *map, unsigned int n)
{
	(void)n;
	return __builtin_popcountl(*map);
}
static unsigned int find_first_zero_bit(const unsigned long *map, unsigned int n)
{
	unsigned int m;
	for (m = 0; m < n && test_bit(m, map); m++);
	return m;
}
static unsigned long reconcile_demand(unsigned int ceiling, unsigned int *np)
{
	(void)ceiling; (void)np;
	assert(false);
	return 0;
}
static int unplug_one(void) { return -EBUSY; }
static long plug_noreclaim(unsigned int m) { return mem_call(L4H_MEM_PLUG, m); }
static void write_once(u32 *p, u32 value)
{
	if (p == &mem_target && target_before_publish) {
		target_before_publish = false;
		page->target = 0;
		memhp_interrupt(0, NULL);
	}
	*p = value;
}
static void complete_request(void)
{
	page->result = -EBUSY;
	page->done_seq = page->req_seq;
	if (target_during_completion)
		page->target = 0;
	memhp_interrupt(0, NULL);
}
static void l4h_signal(unsigned long cap)
{
	(void)cap;
	requests++;
	if (immediate_completion)
		complete_request();
}

#include "memhp-driver.inc"

static void reset(unsigned int target)
{
	memset(&memory, 0, sizeof(memory));
	page->target = target;
	mem_target = mem_seq = 0;
	added[0] = pending[0] = 0;
	requests = wakes = 0;
	queued_delay = -1;
	immediate_completion = target_during_completion = target_before_publish = false;
}

int main(void)
{
	/* Responses both before and after entering wait_event must preserve
	 * the busy retry delay, including a duplicate/late completion IRQ. */
	for (int early = 0; early < 2; early++) {
		reset(1);
		immediate_completion = early;
		memhp_work_fn(&memhp_work);
		assert(requests == 1 && wakes == 1 && queued_delay == RETRY_BUSY);
		memhp_interrupt(0, NULL);
		assert(queued_delay == RETRY_BUSY);
	}
	/* A pending unplug uses the same delay even with the target met. */
	reset(0);
	pending[0] = 1;
	memhp_work_fn(&memhp_work);
	assert(requests == 1 && queued_delay == RETRY_BUSY && pending[0] == 1);
	/* Linux's longer retry after an unsuccessful offline also survives
	 * a late completion interrupt. */
	reset(0);
	added[0] = 1;
	memhp_work_fn(&memhp_work);
	memhp_interrupt(0, NULL);
	assert(requests == 0 && queued_delay == RETRY_STUCK);
	/* A new target supersedes a retry, including a coalesced completion. */
	page->target = 2;
	memhp_interrupt(0, NULL);
	assert(queued_delay == 0);
	reset(1);
	target_during_completion = true;
	memhp_work_fn(&memhp_work);
	assert(requests == 1 && queued_delay == 0);
	/* IRQ observed the old target before the worker published its target;
	 * the worker's final recheck must still reconcile the newer value. */
	reset(1);
	added[0] = 1;
	target_before_publish = true;
	memhp_work_fn(&memhp_work);
	assert(requests == 0 && queued_delay == 0);
	puts("MEMHP EVENTS: PASS (busy completions, retries, target races)");
}
