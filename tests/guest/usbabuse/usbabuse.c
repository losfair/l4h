// SPDX-License-Identifier: GPL-2.0
/*
 * A hostile driver for l4h-usbd (DESIGN.md §9.7): it writes the queue
 * area of the guest's first USB controller directly, instead of usb-l4h,
 * and checks that usbd refuses every malformed request and recovers from
 * garbage indices: segments outside the pool, across its end, in RAM or
 * overflowing; bad slots, endpoints, route strings and port features;
 * isoch packets outside the data; cancels of nothing; SQ heads far beyond
 * usbd's tail and CQ tails far beyond its head; floods past the CQ; and
 * records rewritten from another vCPU while usbd reads them.  The host
 * must stay up, and with an IOMMU log no fault.
 *
 * Loading it runs the test and prints "USBABUSE: PASS" (or FAIL); it then
 * refuses to stay loaded.
 */
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <l4h_sys.h>

struct q {
	unsigned int index;
	struct l4h_usb_info *info;
	struct l4h_usb_ctrl *ctrl;
	struct l4h_usb_ctl_req *csq;
	struct l4h_usb_xfer_req *xsq;
	struct l4h_usb_cqe *cq;
	unsigned long kick;
	u32 ch, xh, ct;
	u64 pool, pool_size, ram_base;
	int fails;
	/* Records and the last completion: too large for the stack. */
	struct l4h_usb_xfer_req rr;
	struct l4h_usb_ctl_req cc;
	struct l4h_usb_cqe last;
};

#define say(fmt, ...) pr_info("USBABUSE: " fmt "\n", ##__VA_ARGS__)
#define check(cond, fmt, ...) do { if (!(cond)) { say("FAIL: " fmt, ##__VA_ARGS__); q->fails++; } } while (0)

static void kick(struct q *q)
{
	smp_mb();
	if (READ_ONCE(q->info->usbd_waiting.v))
		l4h_signal(q->kick);
}

static u32 cq_avail(struct q *q)
{
	return READ_ONCE(q->info->cq_head.v) - q->ct;
}

/* Wait up to ms for n completions. */
static bool wait_cq(struct q *q, u32 n, int ms)
{
	while (cq_avail(q) < n && ms-- > 0) {
		kick(q);
		msleep(1);
	}
	return cq_avail(q) >= n;
}

/* Consume a completion (into q->last): its status. */
static int pop(struct q *q)
{
	rmb();
	memcpy(&q->last, &q->cq[q->ct % L4H_USB_CQ_SIZE], sizeof(q->last));
	q->ct++;
	WRITE_ONCE(q->ctrl->cq_tail.v, q->ct);
	kick(q);
	return q->last.status;
}

static void push_xfer(struct q *q, const struct l4h_usb_xfer_req *r)
{
	q->xsq[q->xh % L4H_USB_XFER_SQ_SIZE] = *r;
	smp_wmb();
	q->xh++;
	WRITE_ONCE(q->ctrl->xfer_sq_head.v, q->xh);
	kick(q);
}

static void push_ctl(struct q *q, const struct l4h_usb_ctl_req *r)
{
	q->csq[q->ch % L4H_USB_CTL_SQ_SIZE] = *r;
	smp_wmb();
	q->ch++;
	WRITE_ONCE(q->ctrl->ctl_sq_head.v, q->ch);
	kick(q);
}

/* One request's status, or 1 if it did not complete. */
static int xfer_status(struct q *q, const struct l4h_usb_xfer_req *r)
{
	push_xfer(q, r);
	if (!wait_cq(q, 1, 2000))
		return 1;
	return pop(q);
}

static int ctl_status(struct q *q, const struct l4h_usb_ctl_req *r, u32 *val)
{
	int st;

	push_ctl(q, r);
	if (!wait_cq(q, 1, 6000))
		return 1;
	st = pop(q);
	if (val)
		*val = q->last.val[0];
	return st;
}

/* A bulk transfer record, in q->rr. */
#define bulk(q, ...) (*bulk_ptr(q, __VA_ARGS__))
static struct l4h_usb_xfer_req *bulk_ptr(struct q *q, u16 slot, u8 dci, u64 gpa, u32 len)
{
	struct l4h_usb_xfer_req *r = &q->rr;

	memset(r, 0, sizeof(*r));
	r->tag = 1;
	r->slot = slot;
	r->dci = dci;
	r->type = L4H_USB_XFER_BULK;
	r->length = len;
	r->n_segs = 1;
	r->segs[0].gpa = gpa;
	r->segs[0].len = len;
	return r;
}

static int rewriter(void *data)
{
	struct q *q = data;
	unsigned int i = 0;

	/* Flip every record's first segment in and out of the pool. */
	while (!kthread_should_stop()) {
		struct l4h_usb_xfer_req *r = &q->xsq[i++ % L4H_USB_XFER_SQ_SIZE];

		WRITE_ONCE(r->segs[0].gpa, (i & 1) ? q->pool : 0);
		WRITE_ONCE(r->segs[0].len, (i & 2) ? 4096 : 0xffffffff);
		WRITE_ONCE(r->n_segs, (i & 4) ? 1 : 0xffff);
		WRITE_ONCE(r->length, (i & 8) ? 4096 : 0);
		WRITE_ONCE(r->dci, i);
		if ((i & 1023) == 0)
			cond_resched();
	}
	return 0;
}

#define r (q->rr)
#define c (q->cc)
static int run(struct q *q)
{
	u64 p = q->pool, end = q->pool + q->pool_size;
	u32 seq, slot = 0, n;
	struct task_struct *t;
	int i, st;

	if (READ_ONCE(q->info->magic) != L4H_USB_MAGIC) {
		say("FAIL: no usbd on device %u", q->index);
		return -ENODEV;
	}
	/* A fresh start: our indices from usbd's, then a reset. */
	q->ch = READ_ONCE(q->info->ctl_sq_tail.v);
	q->xh = READ_ONCE(q->info->xfer_sq_tail.v);
	q->ct = READ_ONCE(q->info->cq_head.v);
	WRITE_ONCE(q->ctrl->ctl_sq_head.v, q->ch);
	WRITE_ONCE(q->ctrl->xfer_sq_head.v, q->xh);
	WRITE_ONCE(q->ctrl->cq_tail.v, q->ct);
	WRITE_ONCE(q->ctrl->eq_tail.v, READ_ONCE(q->info->eq_head.v));
	seq = READ_ONCE(q->ctrl->reset_seq.v) + 1;
	WRITE_ONCE(q->ctrl->reset_seq.v, seq);
	kick(q);
	for (i = 0; i < 10000 && READ_ONCE(q->info->reset_done) != seq; i++)
		msleep(1);
	check(READ_ONCE(q->info->reset_done) == seq && READ_ONCE(q->info->state) == L4H_USB_READY, "reset");
	say("%u ports, %u slots, max transfer %u", q->info->max_ports, q->info->max_slots, q->info->max_transfer);

	/* Segments: outside the pool, across its end, in RAM, overflowing,
	 * empty; too many; lengths that disagree. */
	{
		u64 bad[][2] = {
			{ p - 1, 2 }, { end - 4095, 4096 }, { end, 1 }, { 0, 4096 }, { 0x100000, 4096 },
			{ ~0ull - 100, 4096 }, { p, 0 }, { p + (1ull << 63), 4096 },
		};

		for (i = 0; i < ARRAY_SIZE(bad); i++) {
			r = bulk(q, 1, 2, bad[i][0], bad[i][1]);
			st = xfer_status(q, &r);
			check(st == L4H_USB_ST_INVALID, "segment %llx+%llx: %d", bad[i][0], bad[i][1], st);
		}
	}
	r = bulk(q, 1, 2, p, 4096);
	r.n_segs = L4H_USB_MAX_SEGS + 1;
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "too many segments");
	r = bulk(q, 1, 2, p, 4096);
	r.length = 8192;
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "length beyond the segments");
	r = bulk(q, 1, 2, p, q->info->max_transfer + 4096);
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "beyond max_transfer");
	/* Slots and endpoints that do not exist. */
	r = bulk(q, 0, 2, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_NODEV, "slot 0");
	r = bulk(q, 999, 2, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_NODEV, "slot 999");
	r = bulk(q, 1, 40, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "DCI 40");
	r = bulk(q, 1, 1, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "bulk on ep0");
	r = bulk(q, 1, 2, p, 512);
	r.type = 9;
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "type 9");
	/* Isoch packets outside the data. */
	r = bulk(q, 1, 3, p, 3000);
	r.type = L4H_USB_XFER_ISOC;
	r.n_iso = 2;
	r.iso[0].offset = 0;
	r.iso[0].len = 1500;
	r.iso[1].offset = 1501;
	r.iso[1].len = 1500;
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "isoch packet past the data");
	r.n_iso = 49;
	check(xfer_status(q, &r) == L4H_USB_ST_INVALID, "49 isoch packets");

	/* Port and slot requests. */
	memset(&c, 0, sizeof(c));
	c.op = L4H_USB_OP_PORT_GET;
	c.port = 0;
	check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "port 0");
	c.port = 255;
	check(q->info->max_ports == 255 || ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "port 255");
	c.op = L4H_USB_OP_PORT_SET;
	c.port = 1;
	c.arg[0] = 99;
	check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "port feature 99");
	c.arg[0] = L4H_USB_PF_LINK_STATE;
	c.arg[1] = 7;
	check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "link state 7");
	c.op = 77;
	check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "op 77");
	c.op = L4H_USB_OP_ADDRESS;
	c.slot = 5;
	check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "address of a slot not enabled");
	c.op = L4H_USB_OP_URB_CANCEL;
	c.arg[0] = 0x12345;
	check(ctl_status(q, &c, NULL) == 0, "cancel of nothing");
	check(ctl_status(q, &c, NULL) == 0, "second cancel of nothing");
	memset(&c, 0, sizeof(c));
	c.op = L4H_USB_OP_SLOT_ENABLE;
	st = ctl_status(q, &c, &slot);
	check(st == 0 && slot >= 1 && slot <= q->info->max_slots, "slot enable: %d %u", st, slot);
	if (st == 0) {
		c.op = L4H_USB_OP_ADDRESS;
		c.slot = slot;
		c.port = 1;
		c.arg[0] = 0x10;	/* a port after the end of the route */
		c.arg[1] = L4H_USB_SPEED_HIGH;
		c.arg[5] = 64;
		check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "bad route string");
		c.arg[0] = 0;
		c.arg[2] = 63;	/* a TT hub slot not enabled */
		c.arg[3] = 1;
		check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "bad TT hub slot");
		c.arg[2] = 0;
		c.arg[5] = 65;
		check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "ep0 max packet 65");
		c.op = L4H_USB_OP_EP_CONFIG;
		c.n_eps = 31;
		check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "31 endpoints");
		c.n_eps = 1;
		c.eps[0].dci = 2;
		c.eps[0].type = L4H_USB_EP_BULK_OUT;
		c.eps[0].max_packet = 512;
		check(ctl_status(q, &c, NULL) == L4H_USB_ST_INVALID, "endpoints before an address");
		memset(&c, 0, sizeof(c));
		c.op = L4H_USB_OP_SLOT_DISABLE;
		c.slot = slot;
		check(ctl_status(q, &c, NULL) == 0, "slot disable");
	}

	/* An SQ head far beyond usbd's tail is ignored until it makes sense. */
	n = q->xh;
	WRITE_ONCE(q->ctrl->xfer_sq_head.v, n + 1000);
	kick(q);
	msleep(100);
	check(cq_avail(q) == 0, "a wild SQ head was served");
	check(READ_ONCE(q->info->xfer_sq_tail.v) == n, "a wild SQ head moved the tail");
	r = bulk(q, 0, 2, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_NODEV, "after a wild SQ head");
	/* A CQ tail far beyond usbd's head stalls only us. */
	WRITE_ONCE(q->ctrl->cq_tail.v, q->ct + 5000);
	push_xfer(q, &r);
	msleep(100);
	check(cq_avail(q) == 0, "served with a wild CQ tail");
	WRITE_ONCE(q->ctrl->cq_tail.v, q->ct);
	kick(q);
	check(wait_cq(q, 1, 2000) && pop(q) == L4H_USB_ST_NODEV, "after a wild CQ tail");

	/* Flood: three SQs' worth without consuming: usbd stops at the CQ's
	 * size, then serves the rest as we consume. */
	for (i = 0; i < 3 * L4H_USB_XFER_SQ_SIZE; i++) {
		while (q->xh - READ_ONCE(q->info->xfer_sq_tail.v) >= L4H_USB_XFER_SQ_SIZE && cq_avail(q) < L4H_USB_CQ_SIZE)
			msleep(1);
		if (q->xh - READ_ONCE(q->info->xfer_sq_tail.v) >= L4H_USB_XFER_SQ_SIZE)
			break;
		r = bulk(q, 0, 2, p, 512);
		r.tag = i;
		push_xfer(q, &r);
	}
	msleep(100);
	check(cq_avail(q) == L4H_USB_CQ_SIZE, "flood: %u completions, not the CQ's %u", cq_avail(q), L4H_USB_CQ_SIZE);
	n = 0;
	while (n < (u32)i && wait_cq(q, 1, 2000)) {
		pop(q);
		n++;
	}
	check(n == (u32)i, "flood: %u of %d completions", n, i);

	/* Records rewritten from another vCPU while usbd reads them. */
	t = kthread_create(rewriter, q, "usbabuse");
	if (!IS_ERR(t)) {
		kthread_bind(t, num_online_cpus() > 1 ? 1 : 0);
		wake_up_process(t);
		for (i = 0; i < 4000; i++) {
			r = bulk(q, 0, 2, p, 4096);
			push_xfer(q, &r);
			while (cq_avail(q))
				pop(q);
			if (q->xh - READ_ONCE(q->info->xfer_sq_tail.v) >= L4H_USB_XFER_SQ_SIZE)
				wait_cq(q, 1, 100);
		}
		kthread_stop(t);
		while (wait_cq(q, 1, 500))
			pop(q);
		check(READ_ONCE(q->info->xfer_sq_tail.v) == q->xh, "racing records: tail %u, head %u",
		      READ_ONCE(q->info->xfer_sq_tail.v), q->xh);
	}
	/* Still serving. */
	r = bulk(q, 0, 2, p, 512);
	check(xfer_status(q, &r) == L4H_USB_ST_NODEV, "after the races");
	check(READ_ONCE(q->info->state) == L4H_USB_READY, "state %u", READ_ONCE(q->info->state));
	say("%s (%d failures)", q->fails ? "FAIL" : "PASS", q->fails);
	return 0;
}
#undef r
#undef c

static int __init usbabuse_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	struct q *q;
	unsigned int i;

	for (i = 0; i < bi->nr_devices && i < L4H_MAX_DEVICES; i++)
		if (bi->devices[i].type == L4H_DEV_USB)
			break;
	if (i == bi->nr_devices || i == L4H_MAX_DEVICES) {
		say("FAIL: no USB controller");
		return -ENODEV;
	}
	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return -ENOMEM;
	q->index = i;
	q->info = (void *)bi->devices[i].page_va;
	q->ctrl = (void *)bi->devices[i].page_va + 4096;
	q->csq = (void *)bi->devices[i].page_va + L4H_USB_CTL_SQ_OFF;
	q->xsq = (void *)bi->devices[i].page_va + L4H_USB_XFER_SQ_OFF;
	q->cq = (void *)bi->devices[i].page_va + L4H_USB_CQ_OFF;
	q->kick = L4H_CPTR2(L4H_SLOT_DEV_CNODE, bi->devices[i].kick_slot);
	q->pool = bi->io_pool_gpa;
	q->pool_size = bi->io_pool_size;
	run(q);
	kfree(q);
	return -EAGAIN;
}
module_init(usbabuse_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hostile-guest test of l4h-usbd");
