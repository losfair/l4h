// SPDX-License-Identifier: GPL-2.0
/*
 * usb-l4h: the host controller driver of an xHCI controller that l4h-usbd
 * drives for this guest (L4H_DEV_USB, DESIGN.md §9.7).
 *
 * The guest never touches the controller.  The hc_driver operations
 * (slots, endpoints, root-hub ports) become records in the control SQ of
 * the queue area shared with usbd, and each URB one record in the
 * transfer SQ, naming its buffers as I/O pool segments.  Completions come
 * back in the CQ, matched by tag, and port changes and controller resets
 * in the EQ.  The controller's ports form two root hubs, as with xhci-hcd:
 * a USB 2 HCD and a shared USB 3 HCD.
 *
 * Buffers must lie in the I/O pool, the only memory usbd lets the
 * controller reach: both HCDs map URBs with virtio-l4h's DMA device, which
 * is bound to the pool, so URB buffers bounce through it.  The device
 * address of a mapping is its guest-physical address, which is what usbd
 * translates.
 *
 * Control operations sleep until their completion.  URBs may be submitted
 * and unlinked in atomic context: those the queues cannot take wait in
 * software lists, which the interrupt handler (or a short timer, since
 * usbd consuming an SQ raises no event) pushes on.
 */

#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/unaligned.h>
#include <linux/usb.h>
#include <linux/usb/ch11.h>
#include <linux/usb/hcd.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <asm/l4h_dma.h>
#include <irq_kern.h>
#include <l4h_sys.h>

#define UL4H_TAGS		L4H_USB_CQ_SIZE	/* transfers in flight */
#define UL4H_TAG_IDX(t)		((t) & (UL4H_TAGS - 1))
#define UL4H_CANCEL_TAG		BIT(31)		/* a URB_CANCEL: the transfer's tag */
/* Longer than usbd's own command and transfer timeouts (5 s). */
#define UL4H_CTL_TIMEOUT	(15 * HZ)
#define UL4H_RESET_TIMEOUT_MS	10000
#define UL4H_CANCEL_TRIES	8
#define UL4H_USB3_MAXPORTS	15		/* USB_SS_MAXPORTS */

/* PORTSC (xHCI 1.2 §5.4.8), as PORT_GET returns it. */
#define PORTSC_CCS		BIT(0)
#define PORTSC_PED		BIT(1)
#define PORTSC_OCA		BIT(3)
#define PORTSC_PR		BIT(4)
#define PORTSC_PLS_SHIFT	5
#define PORTSC_PLS		(0xfu << PORTSC_PLS_SHIFT)
#define PORTSC_PP		BIT(9)
#define PORTSC_SPEED(p)		(((p) >> 10) & 0xf)
#define PORTSC_CSC		BIT(17)
#define PORTSC_PEC		BIT(18)
#define PORTSC_WRC		BIT(19)
#define PORTSC_OCC		BIT(20)
#define PORTSC_PRC		BIT(21)
#define PORTSC_PLC		BIT(22)
#define PORTSC_CEC		BIT(23)
#define PORTSC_CAS		BIT(24)
#define PORTSC_DR		BIT(30)
#define PORTSC_CHANGES		(PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | \
				 PORTSC_PRC | PORTSC_PLC | PORTSC_CEC)

/* Port link states (PORTSC.PLS). */
#define PLS_U0			0
#define PLS_U2			2
#define PLS_U3			3
#define PLS_DISABLED		4
#define PLS_RXDETECT		5
#define PLS_INACTIVE		6
#define PLS_RECOVERY		8
#define PLS_COMPLIANCE		10
#define PLS_RESUME		15

#define PORTSC_PLS_GET(p)	(((p) & PORTSC_PLS) >> PORTSC_PLS_SHIFT)

/* A URB the driver owns: waiting to be written, or in flight. */
struct ul4h_urb {
	struct list_head node;		/* pending, cancels or a giveback list */
	struct urb *urb;
	struct usb_hcd *hcd;
	u32 tag;
	bool inflight;
	u8 cancel;			/* 0, UL4H_CANCEL_QUEUED or _SENT */
	u8 cancel_tries;
	int status;			/* for giveback */
};

#define UL4H_CANCEL_QUEUED	1
#define UL4H_CANCEL_SENT	2

/* A sleeping control request. */
struct ul4h_wait {
	struct list_head node;
	u32 tag;
	bool done;
	struct completion comp;
	s32 status;
	u32 val[2];
	u32 epoch;			/* info->hc_resets when it completed */
};

enum { UL4H_SLOT_ENABLED, UL4H_SLOT_DEFAULT, UL4H_SLOT_ADDRESSED };

/* A slot handle of usbd's, and the endpoint state xhci-hcd keeps in its
 * input context. */
struct ul4h_slot {
	struct usb_device *udev;	/* NULL: free, or lost in a reset */
	u32 epoch;
	u8 state;
	u16 ep0_mps;
	u32 active;			/* configured DCIs */
	u32 add, drop;			/* since the last check_bandwidth */
	u32 streams;			/* DCIs with streams */
	u8 interval[32];		/* xHCI interval of the active endpoints */
	struct l4h_usb_ep eps[32];	/* by DCI, for the next EP_CONFIG */
};

/* A root hub: its ports are the controller's ports of one protocol. */
struct ul4h_rh {
	struct usb_hcd *hcd;
	bool usb3;
	bool poll;			/* call usb_hcd_poll_rh_status() */
	unsigned int nports;
	u8 xport[USB_MAXCHILDREN];	/* hub port i+1 -> xHCI port */
	u32 chg[USB_MAXCHILDREN];	/* change bits read and not yet cleared */
	unsigned long event;		/* port i+1 had an event since its last read */
	unsigned long force_cc;		/* report C_CONNECTION: its device was lost */
	unsigned long suspended, c_suspend;
};

struct ul4h {
	spinlock_t lock;
	struct device *dev;
	unsigned int index;		/* boot info device index */
	struct l4h_usb_info *info;
	struct l4h_usb_ctrl *ctrl;
	struct l4h_usb_ctl_req *ctl_sq;
	struct l4h_usb_xfer_req *xfer_sq;
	struct l4h_usb_cqe *cq;
	struct l4h_usb_event *eq;
	unsigned long kick_cap;
	int irq;
	struct l4h_irq_route route;

	u32 features, max_transfer, max_streams;
	unsigned int max_slots, max_ports;

	/* Our indices; usbd's are on page 0. */
	u32 ctl_head, xfer_head, cq_tail, eq_tail, lost_seen;
	u32 ctl_seq, xfer_seq;
	bool need_kick, dead, removing, added;

	struct list_head waiters;	/* struct ul4h_wait */
	struct list_head pending;	/* URBs not yet written, in order */
	struct list_head cancels;	/* URB_CANCELs not yet written */
	struct ul4h_urb *inflight[UL4H_TAGS];
	DECLARE_BITMAP(tag_used, UL4H_TAGS);
	wait_queue_head_t wq;		/* control SQ room */
	struct timer_list retry;
	struct work_struct reset_work;

	struct ul4h_rh rh[2];		/* primary, shared */
	u8 port_rh[L4H_USB_MAX_PORTS + 1];	/* xHCI port -> rh index + 1 */
	u8 port_idx[L4H_USB_MAX_PORTS + 1];
	struct ul4h_slot *slots;	/* 1..max_slots */
};

static struct ul4h *hcd_to_ul4h(struct usb_hcd *hcd)
{
	return *(struct ul4h **)hcd->hcd_priv;
}

static struct ul4h_rh *ul4h_rh(struct ul4h *ul, struct usb_hcd *hcd)
{
	return ul->rh[1].hcd == hcd ? &ul->rh[1] : &ul->rh[0];
}

/* The slot of udev, if it still has one (lock held or not: a hint). */
static struct ul4h_slot *ul4h_slot_locked(struct ul4h *ul, struct usb_device *udev)
{
	unsigned int h = udev->slot_id;

	if (!h || h > ul->max_slots || ul->slots[h].udev != udev)
		return NULL;
	return &ul->slots[h];
}

static struct ul4h_slot *ul4h_slot(struct ul4h *ul, struct usb_device *udev)
{
	struct ul4h_slot *s;
	unsigned long flags;

	spin_lock_irqsave(&ul->lock, flags);
	s = ul4h_slot_locked(ul, udev);
	spin_unlock_irqrestore(&ul->lock, flags);
	return s;
}

static void ul4h_kick(struct ul4h *ul)
{
	/* The index writes before the usbd_waiting read (usbd: the reverse). */
	smp_mb();
	if (READ_ONCE(ul->info->usbd_waiting.v))
		l4h_signal(ul->kick_cap);
}

static void ul4h_unlock_kick(struct ul4h *ul, unsigned long flags)
{
	bool kick = ul->need_kick;

	ul->need_kick = false;
	spin_unlock_irqrestore(&ul->lock, flags);
	if (kick)
		ul4h_kick(ul);
}

static void ul4h_giveback(struct list_head *done)
{
	struct ul4h_urb *u, *n;

	list_for_each_entry_safe(u, n, done, node) {
		struct usb_hcd *hcd = u->hcd;
		struct urb *urb = u->urb;
		int status = u->status;

		urb->hcpriv = NULL;
		kfree(u);
		usb_hcd_giveback_urb(hcd, urb, status);
	}
}

/* Take a URB back from the driver (lock held); it is given back later. */
static void ul4h_finish(struct ul4h *ul, struct ul4h_urb *u, int status, struct list_head *done)
{
	if (u->inflight) {
		ul->inflight[UL4H_TAG_IDX(u->tag)] = NULL;
		clear_bit(UL4H_TAG_IDX(u->tag), ul->tag_used);
		u->inflight = false;
	}
	usb_hcd_unlink_urb_from_ep(u->hcd, u->urb);
	u->status = status;
	list_move_tail(&u->node, done);
}

static void ul4h_recover(struct ul4h *ul)
{
	if (!READ_ONCE(ul->dead) && !READ_ONCE(ul->removing))
		schedule_work(&ul->reset_work);
}

/* ---- control SQ */

static bool ul4h_ctl_room(struct ul4h *ul)
{
	return ul->ctl_head - READ_ONCE(ul->info->ctl_sq_tail.v) < L4H_USB_CTL_SQ_SIZE;
}

static struct l4h_usb_ctl_req *ul4h_ctl_next(struct ul4h *ul)
{
	return &ul->ctl_sq[ul->ctl_head % L4H_USB_CTL_SQ_SIZE];
}

static void ul4h_ctl_publish(struct ul4h *ul)
{
	ul->ctl_head++;
	/* The record before the head. */
	smp_store_release(&ul->ctrl->ctl_sq_head.v, ul->ctl_head);
	ul->need_kick = true;
}

/*
 * Send a control request and wait for its completion.  Returns its status
 * (a negative errno), with val[] and the reset epoch it completed in.
 */
static int ul4h_ctl(struct ul4h *ul, struct l4h_usb_ctl_req *req, u32 *val, u32 *epoch)
{
	unsigned long deadline = jiffies + UL4H_CTL_TIMEOUT;
	struct ul4h_wait w = { .done = false };
	unsigned long flags;
	long left;

	might_sleep();
	init_completion(&w.comp);
	for (;;) {
		spin_lock_irqsave(&ul->lock, flags);
		if (ul->dead) {
			spin_unlock_irqrestore(&ul->lock, flags);
			return -ESHUTDOWN;
		}
		if (ul4h_ctl_room(ul))
			break;
		spin_unlock_irqrestore(&ul->lock, flags);
		if (time_after(jiffies, deadline)) {
			dev_err(ul->dev, "control SQ stalled\n");
			ul4h_recover(ul);
			return -ETIMEDOUT;
		}
		/* usbd consuming the SQ raises no event: poll. */
		wait_event_timeout(ul->wq, ul4h_ctl_room(ul) || READ_ONCE(ul->dead), 1);
	}
	w.tag = ul->ctl_seq++ & ~UL4H_CANCEL_TAG;
	req->tag = w.tag;
	memcpy(ul4h_ctl_next(ul), req, sizeof(*req));
	ul4h_ctl_publish(ul);
	list_add_tail(&w.node, &ul->waiters);
	ul4h_unlock_kick(ul, flags);

	left = (long)(deadline - jiffies);
	wait_for_completion_timeout(&w.comp, max(left, 1L));

	spin_lock_irqsave(&ul->lock, flags);
	if (!w.done) {
		list_del(&w.node);
		spin_unlock_irqrestore(&ul->lock, flags);
		dev_err(ul->dev, "control request %u timed out\n", req->op);
		ul4h_recover(ul);
		return -ETIMEDOUT;
	}
	spin_unlock_irqrestore(&ul->lock, flags);
	if (val) {
		val[0] = w.val[0];
		val[1] = w.val[1];
	}
	if (epoch)
		*epoch = w.epoch;
	return w.status;
}

/* ---- transfer SQ */

static u8 ul4h_xfer_type(const struct usb_endpoint_descriptor *d)
{
	switch (usb_endpoint_type(d)) {
	case USB_ENDPOINT_XFER_CONTROL:
		return L4H_USB_XFER_CONTROL;
	case USB_ENDPOINT_XFER_ISOC:
		return L4H_USB_XFER_ISOC;
	case USB_ENDPOINT_XFER_BULK:
		return L4H_USB_XFER_BULK;
	default:
		return L4H_USB_XFER_INT;
	}
}

/* Device context index (xHCI §4.5.1): 2 * number + IN, 1 for ep0. */
static unsigned int ul4h_dci(const struct usb_endpoint_descriptor *d)
{
	unsigned int n = usb_endpoint_num(d);

	if (usb_endpoint_xfer_control(d))
		return 2 * n + 1;
	return 2 * n + (usb_endpoint_dir_in(d) ? 1 : 0);
}

/*
 * Write u's record (lock held).  -EBUSY: no room yet; another error:
 * fail the URB.
 */
static int ul4h_xfer_put(struct ul4h *ul, struct ul4h_urb *u)
{
	struct urb *urb = u->urb;
	struct l4h_usb_xfer_req *r;
	unsigned int idx, i, n = 0;
	u32 flags = 0, left;

	if (!ul4h_slot_locked(ul, urb->dev))
		return -ENODEV;
	if (ul->xfer_head - READ_ONCE(ul->info->xfer_sq_tail.v) >= L4H_USB_XFER_SQ_SIZE)
		return -EBUSY;
	idx = find_first_zero_bit(ul->tag_used, UL4H_TAGS);
	if (idx >= UL4H_TAGS)
		return -EBUSY;

	r = &ul->xfer_sq[ul->xfer_head % L4H_USB_XFER_SQ_SIZE];
	memset(r, 0, offsetof(struct l4h_usb_xfer_req, segs));
	u->tag = ((ul->xfer_seq++ << 8) | idx) & ~UL4H_CANCEL_TAG;
	r->tag = u->tag;
	r->slot = urb->dev->slot_id;
	r->dci = ul4h_dci(&urb->ep->desc);
	r->type = ul4h_xfer_type(&urb->ep->desc);
	if (usb_urb_dir_in(urb))
		flags |= L4H_USB_XF_IN;
	if (urb->transfer_flags & URB_ZERO_PACKET)
		flags |= L4H_USB_XF_ZERO_PACKET;
	if (urb->transfer_flags & URB_SHORT_NOT_OK)
		flags |= L4H_USB_XF_SHORT_NOT_OK;
	if (urb->transfer_flags & URB_ISO_ASAP)
		flags |= L4H_USB_XF_ISO_ASAP;
	r->flags = flags;
	r->stream = urb->stream_id;
	r->start_frame = urb->start_frame;
	r->length = urb->transfer_buffer_length;
	if (r->type == L4H_USB_XFER_CONTROL)
		memcpy(r->setup, urb->setup_packet, sizeof(r->setup));

	left = urb->transfer_buffer_length;
	if (urb->num_sgs) {
		struct scatterlist *sg;

		for_each_sg(urb->sg, sg, urb->num_mapped_sgs, i) {
			u32 len = min_t(u32, sg_dma_len(sg), left);

			if (!len)
				break;
			left -= len;
			/* swiotlb often bounces consecutive entries next to each
			 * other: one segment is fewer TRBs for usbd. */
			if (n && r->segs[n - 1].gpa + r->segs[n - 1].len == sg_dma_address(sg) &&
			    r->segs[n - 1].len <= U32_MAX - len) {
				r->segs[n - 1].len += len;
				continue;
			}
			r->segs[n].gpa = sg_dma_address(sg);
			r->segs[n].len = len;
			n++;
		}
	} else if (left) {
		r->segs[0].gpa = urb->transfer_dma;
		r->segs[0].len = left;
		n = 1;
		left = 0;
	}
	if (left)
		return -EINVAL;
	r->n_segs = n;
	if (r->type == L4H_USB_XFER_ISOC) {
		for (i = 0; i < urb->number_of_packets; i++) {
			r->iso[i].offset = urb->iso_frame_desc[i].offset;
			r->iso[i].len = urb->iso_frame_desc[i].length;
		}
		r->n_iso = urb->number_of_packets;
	}

	ul->inflight[idx] = u;
	set_bit(idx, ul->tag_used);
	u->inflight = true;
	ul->xfer_head++;
	smp_store_release(&ul->ctrl->xfer_sq_head.v, ul->xfer_head);
	ul->need_kick = true;
	return 0;
}

/* Write what waits in the software lists (lock held). */
static void ul4h_push(struct ul4h *ul, struct list_head *done)
{
	struct ul4h_urb *u, *n;
	int err;

	if (ul->dead)
		return;
	list_for_each_entry_safe(u, n, &ul->cancels, node) {
		struct l4h_usb_ctl_req *r;

		if (!ul4h_ctl_room(ul))
			break;
		r = ul4h_ctl_next(ul);
		memset(r, 0, offsetof(struct l4h_usb_ctl_req, eps));
		r->op = L4H_USB_OP_URB_CANCEL;
		r->tag = UL4H_CANCEL_TAG | u->tag;
		r->arg[0] = u->tag;
		ul4h_ctl_publish(ul);
		u->cancel = UL4H_CANCEL_SENT;
		list_del_init(&u->node);
	}
	list_for_each_entry_safe(u, n, &ul->pending, node) {
		err = ul4h_xfer_put(ul, u);
		if (err == -EBUSY)
			break;
		if (err)
			ul4h_finish(ul, u, err, done);
		else
			list_del_init(&u->node);
	}
	if ((!list_empty(&ul->pending) || !list_empty(&ul->cancels)) && !timer_pending(&ul->retry))
		mod_timer(&ul->retry, jiffies + 1);
}

static void ul4h_retry_fn(struct timer_list *t)
{
	struct ul4h *ul = timer_container_of(ul, t, retry);
	unsigned long flags;
	LIST_HEAD(done);

	spin_lock_irqsave(&ul->lock, flags);
	ul4h_push(ul, &done);
	ul4h_unlock_kick(ul, flags);
	ul4h_giveback(&done);
	wake_up(&ul->wq);
}

/* ---- completions and events */

static int ul4h_status(s32 st)
{
	return st > 0 || st < -MAX_ERRNO ? -EIO : st;
}

static void ul4h_xfer_done(struct ul4h *ul, const struct l4h_usb_cqe *c, struct list_head *done)
{
	u32 tag = READ_ONCE(c->tag);
	struct ul4h_urb *u = ul->inflight[UL4H_TAG_IDX(tag)];
	struct urb *urb;
	int status;

	if (!u || u->tag != tag) {
		dev_warn_ratelimited(ul->dev, "completion of unknown transfer %#x\n", tag);
		return;
	}
	urb = u->urb;
	status = ul4h_status(READ_ONCE(c->status));
	/* usbd reports short packets as errors only when asked to. */
	if (status == L4H_USB_ST_SHORT && !(urb->transfer_flags & URB_SHORT_NOT_OK))
		status = 0;
	urb->actual_length = min_t(u32, READ_ONCE(c->actual), urb->transfer_buffer_length);
	if (usb_pipeisoc(urb->pipe)) {
		unsigned int i, n = min_t(u32, READ_ONCE(c->n_iso), urb->number_of_packets);

		for (i = 0; i < n; i++) {
			struct usb_iso_packet_descriptor *d = &urb->iso_frame_desc[i];

			d->status = ul4h_status(READ_ONCE(c->iso[i].status));
			d->actual_length = min_t(u32, READ_ONCE(c->iso[i].actual), d->length);
		}
		urb->error_count = READ_ONCE(c->error_count);
		urb->start_frame = READ_ONCE(c->start_frame);
	}
	ul4h_finish(ul, u, status, done);
}

static void ul4h_ctl_done(struct ul4h *ul, const struct l4h_usb_cqe *c)
{
	u32 tag = READ_ONCE(c->tag);
	s32 status = ul4h_status(READ_ONCE(c->status));
	struct ul4h_wait *w;

	if (tag & UL4H_CANCEL_TAG) {
		struct ul4h_urb *u = ul->inflight[UL4H_TAG_IDX(tag)];

		/*
		 * The URB completes before its cancel does.  A cancel that
		 * failed while the URB is still in flight is tried again:
		 * without limit while usbd has yet to take the URB's record
		 * (AGAIN: it waits behind a full CQ), a few times otherwise.
		 */
		tag &= ~UL4H_CANCEL_TAG;
		if (u && u->tag == tag && u->cancel == UL4H_CANCEL_SENT && status &&
		    (status == L4H_USB_ST_AGAIN || u->cancel_tries++ < UL4H_CANCEL_TRIES)) {
			u->cancel = UL4H_CANCEL_QUEUED;
			list_add_tail(&u->node, &ul->cancels);
		}
		return;
	}
	list_for_each_entry(w, &ul->waiters, node) {
		if (w->tag != tag)
			continue;
		w->status = status;
		w->val[0] = READ_ONCE(c->val[0]);
		w->val[1] = READ_ONCE(c->val[1]);
		w->epoch = READ_ONCE(ul->info->hc_resets);
		w->done = true;
		list_del(&w->node);
		complete(&w->comp);
		return;
	}
}

static void ul4h_port_changed(struct ul4h *ul, unsigned int xport, u32 portsc)
{
	struct ul4h_rh *rh;
	unsigned int i;

	if (!xport || xport > ul->max_ports || !ul->port_rh[xport])
		return;
	rh = &ul->rh[ul->port_rh[xport] - 1];
	i = ul->port_idx[xport];
	rh->chg[i] |= portsc & PORTSC_CHANGES;
	rh->event |= BIT(i);
	rh->poll = true;
}

static void ul4h_all_ports_changed(struct ul4h *ul, bool lost)
{
	unsigned int r;

	for (r = 0; r < ARRAY_SIZE(ul->rh); r++) {
		struct ul4h_rh *rh = &ul->rh[r];
		unsigned long all = BIT(rh->nports) - 1;

		rh->event |= all;
		if (lost)
			rh->force_cc |= all;
		rh->poll = true;
	}
}

/*
 * The controller was reset: every slot from before is gone.  A slot whose
 * enable completed after this reset began has the current epoch.
 */
static void ul4h_slots_lost(struct ul4h *ul)
{
	u32 epoch = READ_ONCE(ul->info->hc_resets);
	unsigned int h;

	for (h = 1; h <= ul->max_slots; h++)
		if (ul->slots[h].udev && ul->slots[h].epoch != epoch)
			ul->slots[h].udev = NULL;
}

static void ul4h_poll_rhs(struct ul4h *ul)
{
	unsigned long flags;
	unsigned int r;

	for (r = 0; r < ARRAY_SIZE(ul->rh); r++) {
		struct usb_hcd *hcd = ul->rh[r].hcd;
		bool poll;

		spin_lock_irqsave(&ul->lock, flags);
		poll = ul->rh[r].poll;
		ul->rh[r].poll = false;
		spin_unlock_irqrestore(&ul->lock, flags);
		if (!poll || !hcd)
			continue;
		set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
		usb_hcd_resume_root_hub(hcd);
		usb_hcd_poll_rh_status(hcd);
	}
}

static void ul4h_die(struct ul4h *ul, const char *why)
{
	struct ul4h_urb *u, *n;
	struct ul4h_wait *w, *wn;
	unsigned long flags;
	LIST_HEAD(done);
	unsigned int i;

	spin_lock_irqsave(&ul->lock, flags);
	if (ul->dead) {
		spin_unlock_irqrestore(&ul->lock, flags);
		return;
	}
	ul->dead = true;
	/* Nothing will complete: give everything back here. */
	for (i = 0; i < UL4H_TAGS; i++)
		if (ul->inflight[i])
			ul4h_finish(ul, ul->inflight[i], -ESHUTDOWN, &done);
	list_for_each_entry_safe(u, n, &ul->pending, node)
		ul4h_finish(ul, u, -ESHUTDOWN, &done);
	list_for_each_entry_safe(w, wn, &ul->waiters, node) {
		w->status = -ESHUTDOWN;
		w->done = true;
		list_del(&w->node);
		complete(&w->comp);
	}
	spin_unlock_irqrestore(&ul->lock, flags);
	wake_up(&ul->wq);
	ul4h_giveback(&done);
	dev_err(ul->dev, "controller failed: %s\n", why);
	if (ul->added && !ul->removing)
		usb_hc_died(ul->rh[0].hcd);
}

/* Drain the CQ and the EQ (lock held).  Returns whether there was work. */
static bool ul4h_drain(struct ul4h *ul, struct list_head *done, bool *bad)
{
	struct l4h_usb_info *info = ul->info;
	bool work = false;
	u32 head, lost;

	head = smp_load_acquire(&info->cq_head.v);
	if (head - ul->cq_tail > L4H_USB_CQ_SIZE) {
		*bad = true;
		return false;
	}
	while (ul->cq_tail != head) {
		const struct l4h_usb_cqe *c = &ul->cq[ul->cq_tail % L4H_USB_CQ_SIZE];

		if (READ_ONCE(c->kind) == L4H_USB_CQ_XFER)
			ul4h_xfer_done(ul, c, done);
		else
			ul4h_ctl_done(ul, c);
		ul->cq_tail++;
		work = true;
	}
	if (work)
		smp_store_release(&ul->ctrl->cq_tail.v, ul->cq_tail);

	head = smp_load_acquire(&info->eq_head.v);
	if (head - ul->eq_tail > L4H_USB_EQ_SIZE) {
		*bad = true;
		return work;
	}
	if (ul->eq_tail != head) {
		while (ul->eq_tail != head) {
			const struct l4h_usb_event *e = &ul->eq[ul->eq_tail % L4H_USB_EQ_SIZE];

			switch (READ_ONCE(e->type)) {
			case L4H_USB_EV_PORT:
				ul4h_port_changed(ul, READ_ONCE(e->port), READ_ONCE(e->portsc));
				break;
			case L4H_USB_EV_HC_RESET:
				/*
				 * Its URBs come back with ST_SHUTDOWN.  Report a
				 * connect change on every port, so that the hub
				 * driver drops the devices it had and enumerates
				 * those still there.
				 */
				dev_warn(ul->dev, "controller reset by usbd\n");
				ul4h_slots_lost(ul);
				ul4h_all_ports_changed(ul, true);
				break;
			}
			ul->eq_tail++;
		}
		smp_store_release(&ul->ctrl->eq_tail.v, ul->eq_tail);
		work = true;
	}

	lost = READ_ONCE(info->lost_events.v);
	if (lost != ul->lost_seen) {
		ul->lost_seen = lost;
		ul4h_all_ports_changed(ul, false);
	}
	return work;
}

static irqreturn_t ul4h_interrupt(int irq, void *data)
{
	struct ul4h *ul = data;
	irqreturn_t ret = IRQ_NONE;
	unsigned long flags;
	bool bad = false;
	LIST_HEAD(done);

	spin_lock_irqsave(&ul->lock, flags);
	/* Look at the heads again after each round: nothing is missed. */
	while (!ul->dead && ul4h_drain(ul, &done, &bad)) {
		ul->need_kick = true;		/* CQ room for usbd */
		ret = IRQ_HANDLED;
	}
	ul4h_push(ul, &done);
	ul4h_unlock_kick(ul, flags);
	ul4h_giveback(&done);
	wake_up(&ul->wq);
	ul4h_poll_rhs(ul);
	if (READ_ONCE(ul->info->state) == L4H_USB_DEAD)
		ul4h_die(ul, "usbd reports it dead");
	else if (bad) {
		dev_err_ratelimited(ul->dev, "bad queue index from usbd\n");
		ul4h_recover(ul);
	}
	return ret;
}

static int ul4h_set_irq_cpu(void *data, unsigned int cpu)
{
	struct ul4h *ul = data;
	unsigned long mrs[3] = { ul->index, L4H_USB_DEVOP_IRQ_VCPU, cpu };

	return l4h_hypercall(L4H_HC_DEV_WRITE, mrs, 3, 1) ? -EINVAL : 0;
}

/* ---- reset */

/*
 * The reset handshake: usbd halts and resets the controller and completes
 * everything it had accepted with ST_SHUTDOWN, which the interrupt handler
 * consumes meanwhile.
 */
static int ul4h_reset_hc(struct ul4h *ul)
{
	struct l4h_usb_info *info = ul->info;
	u32 seq = READ_ONCE(ul->ctrl->reset_seq.v) + 1;
	unsigned int ms;

	WRITE_ONCE(ul->ctrl->reset_seq.v, seq);
	ul4h_kick(ul);
	for (ms = 0; ms < UL4H_RESET_TIMEOUT_MS; ms += 10) {
		u32 state = READ_ONCE(info->state);

		if (state == L4H_USB_DEAD)
			return -EIO;
		if (READ_ONCE(info->reset_done) == seq && state == L4H_USB_READY)
			return 0;
		msleep(10);
	}
	return -ETIMEDOUT;
}

static void ul4h_reset_work(struct work_struct *work)
{
	struct ul4h *ul = container_of(work, struct ul4h, reset_work);
	unsigned long flags;

	dev_warn(ul->dev, "resetting the controller\n");
	if (ul4h_reset_hc(ul)) {
		ul4h_die(ul, "reset failed");
		return;
	}
	spin_lock_irqsave(&ul->lock, flags);
	ul4h_slots_lost(ul);
	ul4h_all_ports_changed(ul, true);
	spin_unlock_irqrestore(&ul->lock, flags);
	ul4h_poll_rhs(ul);
}

/* ---- slots and endpoints */

static u32 ul4h_speed(struct usb_device *udev)
{
	switch (udev->speed) {
	case USB_SPEED_LOW:
		return L4H_USB_SPEED_LOW;
	case USB_SPEED_FULL:
		return L4H_USB_SPEED_FULL;
	case USB_SPEED_HIGH:
		return L4H_USB_SPEED_HIGH;
	case USB_SPEED_SUPER:
		return L4H_USB_SPEED_SUPER;
	case USB_SPEED_SUPER_PLUS:
		return L4H_USB_SPEED_SUPER_PLUS;
	default:
		return 0;
	}
}

static int ul4h_alloc_dev(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_SLOT_ENABLE };
	unsigned long flags;
	u32 val[2], epoch;
	int ret;

	ret = ul4h_ctl(ul, &req, val, &epoch);
	if (ret) {
		dev_dbg(ul->dev, "no slot: %d\n", ret);
		return 0;
	}
	if (!val[0] || val[0] > ul->max_slots) {
		dev_err(ul->dev, "usbd gave slot %u of %u\n", val[0], ul->max_slots);
		return 0;
	}
	spin_lock_irqsave(&ul->lock, flags);
	/* A previous owner of the handle lost it in a reset. */
	memset(&ul->slots[val[0]], 0, sizeof(ul->slots[0]));
	ul->slots[val[0]].udev = udev;
	ul->slots[val[0]].epoch = epoch;
	spin_unlock_irqrestore(&ul->lock, flags);
	udev->slot_id = val[0];
	return 1;
}

static void ul4h_disable_slot(struct ul4h *ul, struct usb_device *udev)
{
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_SLOT_DISABLE };
	struct ul4h_slot *s = ul4h_slot(ul, udev);
	unsigned long flags;

	if (!s)
		return;
	req.slot = udev->slot_id;
	ul4h_ctl(ul, &req, NULL, NULL);
	spin_lock_irqsave(&ul->lock, flags);
	if (s->udev == udev)
		s->udev = NULL;
	spin_unlock_irqrestore(&ul->lock, flags);
}

static void ul4h_free_dev(struct usb_hcd *hcd, struct usb_device *udev)
{
	ul4h_disable_slot(hcd_to_ul4h(hcd), udev);
}

static int ul4h_setup_dev(struct usb_hcd *hcd, struct usb_device *udev, bool bsr)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct ul4h_rh *rh = ul4h_rh(ul, hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_ADDRESS };
	struct usb_device *top;
	struct ul4h_slot *s;
	u32 val[2], mps;
	int ret;

	s = ul4h_slot(ul, udev);
	if (!s)
		return -EINVAL;
	/* enable_device on a slot already in the Default state. */
	if (bsr && s->state == UL4H_SLOT_DEFAULT)
		return 0;
	/* The root port above the device. */
	for (top = udev; top->parent && top->parent->parent; top = top->parent)
		;
	if (top->portnum < 1 || top->portnum > rh->nports)
		return -EINVAL;
	mps = usb_endpoint_maxp(&udev->ep0.desc);
	if (!mps)
		mps = udev->speed >= USB_SPEED_SUPER ? 512 : udev->speed == USB_SPEED_LOW ? 8 : 64;

	req.slot = udev->slot_id;
	req.port = rh->xport[top->portnum - 1];
	req.arg[0] = udev->route;
	req.arg[1] = ul4h_speed(udev);
	/* A LS/FS device behind a HS hub's transaction translator. */
	if (udev->tt && udev->tt->hub->parent) {
		req.arg[2] = udev->tt->hub->slot_id;
		req.arg[3] = udev->ttport;
		req.arg[4] = !!udev->tt->multi;
	}
	req.arg[5] = mps;
	req.arg[6] = bsr;
	ret = ul4h_ctl(ul, &req, val, NULL);
	if (ret == -EPROTO && !bsr) {
		/* As xhci-hcd: a fresh slot for the next attempt. */
		dev_warn(&udev->dev, "device not responding to setup address\n");
		ul4h_disable_slot(ul, udev);
		ul4h_alloc_dev(hcd, udev);
		return ret;
	}
	if (ret)
		return ret;
	s->state = bsr ? UL4H_SLOT_DEFAULT : UL4H_SLOT_ADDRESSED;
	s->ep0_mps = mps;
	if (!bsr)
		udev->devaddr = val[0];
	return 0;
}

static int ul4h_address_device(struct usb_hcd *hcd, struct usb_device *udev,
			       unsigned int timeout_ms)
{
	return ul4h_setup_dev(hcd, udev, false);
}

static int ul4h_enable_device(struct usb_hcd *hcd, struct usb_device *udev)
{
	return ul4h_setup_dev(hcd, udev, true);
}

static int ul4h_reset_device(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_DEV_RESET };
	struct ul4h_slot *s;
	int ret;

	if (!udev->parent)
		return 0;
	s = ul4h_slot(ul, udev);
	/* Lost in a controller reset: a new slot, as xhci-hcd does. */
	if (!s)
		return ul4h_alloc_dev(hcd, udev) ? 0 : -EINVAL;
	if (s->state == UL4H_SLOT_ENABLED)
		return 0;
	req.slot = udev->slot_id;
	ret = ul4h_ctl(ul, &req, NULL, NULL);
	if (ret)
		return ret;
	s->active = s->add = s->drop = s->streams = 0;
	s->state = UL4H_SLOT_DEFAULT;
	return 0;
}

/* Endpoint context fields, as xhci-mem.c computes them. */
static unsigned int ul4h_exponent_interval(struct usb_device *udev, struct usb_host_endpoint *ep)
{
	unsigned int interval = clamp_val(ep->desc.bInterval, 1, 16) - 1;

	/* Full-speed isoc intervals are in frames. */
	if (udev->speed == USB_SPEED_FULL)
		interval += 3;
	return interval;
}

static unsigned int ul4h_uframes_to_exponent(unsigned int uframes, unsigned int min,
					     unsigned int max)
{
	return clamp_val(fls(uframes) - 1, min, max);
}

static unsigned int ul4h_ep_interval(struct usb_device *udev, struct usb_host_endpoint *ep)
{
	const struct usb_endpoint_descriptor *d = &ep->desc;

	switch (udev->speed) {
	case USB_SPEED_HIGH:
		/* Max NAK rate */
		if (usb_endpoint_xfer_control(d) || usb_endpoint_xfer_bulk(d))
			return d->bInterval ? ul4h_uframes_to_exponent(d->bInterval, 0, 15) : 0;
		fallthrough;
	case USB_SPEED_SUPER_PLUS:
	case USB_SPEED_SUPER:
		if (usb_endpoint_xfer_int(d) || usb_endpoint_xfer_isoc(d))
			return ul4h_exponent_interval(udev, ep);
		return 0;
	case USB_SPEED_FULL:
		if (usb_endpoint_xfer_isoc(d))
			return ul4h_exponent_interval(udev, ep);
		fallthrough;
	case USB_SPEED_LOW:
		if (usb_endpoint_xfer_int(d) || usb_endpoint_xfer_isoc(d))
			return ul4h_uframes_to_exponent(d->bInterval * 8, 3, 10);
		return 0;
	default:
		return 0;
	}
}

/*
 * Mult: usbd does not say whether the controller has LEC (xHCI 1.1
 * Large ESIT Payload), so this is the value for one without it, which a
 * controller with LEC ignores.
 */
static unsigned int ul4h_ep_mult(struct usb_device *udev, struct usb_host_endpoint *ep)
{
	if (usb_endpoint_is_hs_isoc_double(udev, ep))
		return 1;
	if (udev->speed >= USB_SPEED_SUPER && usb_endpoint_xfer_isoc(&ep->desc))
		return ep->ss_ep_comp.bmAttributes & 0x3;
	return 0;
}

static unsigned int ul4h_ep_burst(struct usb_device *udev, struct usb_host_endpoint *ep)
{
	if (udev->speed >= USB_SPEED_SUPER)
		return ep->ss_ep_comp.bMaxBurst;
	if (udev->speed == USB_SPEED_HIGH &&
	    (usb_endpoint_xfer_isoc(&ep->desc) || usb_endpoint_xfer_int(&ep->desc))) {
		if (usb_endpoint_is_hs_isoc_double(udev, ep))
			return 2;
		return usb_endpoint_maxp_mult(&ep->desc) - 1;
	}
	return 0;
}

static u8 ul4h_ep_type(const struct usb_endpoint_descriptor *d)
{
	bool in = usb_endpoint_dir_in(d);

	switch (usb_endpoint_type(d)) {
	case USB_ENDPOINT_XFER_CONTROL:
		return L4H_USB_EP_CONTROL;
	case USB_ENDPOINT_XFER_BULK:
		return in ? L4H_USB_EP_BULK_IN : L4H_USB_EP_BULK_OUT;
	case USB_ENDPOINT_XFER_ISOC:
		return in ? L4H_USB_EP_ISOC_IN : L4H_USB_EP_ISOC_OUT;
	default:
		return in ? L4H_USB_EP_INT_IN : L4H_USB_EP_INT_OUT;
	}
}

static unsigned int ul4h_ep_maxp(struct usb_device *udev, struct usb_host_endpoint *ep)
{
	unsigned int mp;

	if (usb_endpoint_is_hs_isoc_double(udev, ep))
		mp = le16_to_cpu(ep->eusb2_isoc_ep_comp.wMaxPacketSize);
	else
		mp = usb_endpoint_maxp(&ep->desc);
	/* HS bulk max packet is 512, FS bulk 8, 16, 32 or 64. */
	if (usb_endpoint_xfer_bulk(&ep->desc)) {
		if (udev->speed == USB_SPEED_HIGH)
			mp = 512;
		else if (udev->speed == USB_SPEED_FULL)
			mp = clamp_val(rounddown_pow_of_two(max(mp, 1u)), 8, 64);
	}
	return mp;
}

static int ul4h_add_endpoint(struct usb_hcd *hcd, struct usb_device *udev,
			     struct usb_host_endpoint *ep)
{
	struct ul4h_slot *s;
	struct l4h_usb_ep *e;
	unsigned int dci, burst;
	u32 bit, esit;

	if (!udev->parent)
		return 0;
	s = ul4h_slot(hcd_to_ul4h(hcd), udev);
	if (!s)
		return -EINVAL;
	dci = ul4h_dci(&ep->desc);
	if (dci < 2)
		return 0;
	bit = BIT(dci);
	/* Changing an endpoint is a drop and an add. */
	if ((s->active & bit) && !(s->drop & bit))
		return -EINVAL;
	if (s->add & bit)
		return 0;

	e = &s->eps[dci];
	memset(e, 0, sizeof(*e));
	burst = ul4h_ep_burst(udev, ep);
	esit = usb_endpoint_max_periodic_payload(udev, ep);
	e->dci = dci;
	e->type = ul4h_ep_type(&ep->desc);
	e->interval = ul4h_ep_interval(udev, ep);
	e->burst_mult = (burst & 0xf) | (ul4h_ep_mult(udev, ep) << 4);
	e->max_packet = ul4h_ep_maxp(udev, ep);
	/* SSP isoc can exceed the 16 bits the record has. */
	e->max_esit = min_t(u32, esit, U16_MAX);
	s->add |= bit;
	ep->hcpriv = udev;
	return 0;
}

static int ul4h_drop_endpoint(struct usb_hcd *hcd, struct usb_device *udev,
			      struct usb_host_endpoint *ep)
{
	struct ul4h_slot *s;
	unsigned int dci;
	u32 bit;

	if (!udev->parent)
		return 0;
	s = ul4h_slot(hcd_to_ul4h(hcd), udev);
	if (!s)
		return -ENODEV;
	dci = ul4h_dci(&ep->desc);
	if (dci < 2)
		return 0;
	bit = BIT(dci);
	if (!(s->active & bit) || (s->drop & bit))
		return 0;
	s->drop |= bit;
	s->add &= ~bit;
	return 0;
}

static int ul4h_check_bandwidth(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_EP_CONFIG };
	struct ul4h_slot *s;
	unsigned int dci, n = 0;
	int ret;

	if (!udev->parent)
		return 0;
	s = ul4h_slot(ul, udev);
	if (!s)
		return -ENODEV;
	if (!s->add && !s->drop)
		return 0;
	req.slot = udev->slot_id;
	req.drop = s->drop;
	for (dci = 2; dci < 32; dci++)
		if (s->add & BIT(dci))
			req.eps[n++] = s->eps[dci];
	req.n_eps = n;
	ret = ul4h_ctl(ul, &req, NULL, NULL);
	if (ret)
		return ret;	/* reset_bandwidth follows */
	for (dci = 2; dci < 32; dci++)
		if (s->add & BIT(dci))
			s->interval[dci] = s->eps[dci].interval;
	s->active = (s->active & ~s->drop) | s->add;
	s->streams &= ~s->drop;
	s->add = s->drop = 0;
	return 0;
}

static void ul4h_reset_bandwidth(struct usb_hcd *hcd, struct usb_device *udev)
{
	struct ul4h_slot *s = ul4h_slot(hcd_to_ul4h(hcd), udev);

	if (s)
		s->add = s->drop = 0;
}

static void ul4h_endpoint_reset(struct usb_hcd *hcd, struct usb_host_endpoint *ep)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .slot = 0 };
	unsigned int dci = ul4h_dci(&ep->desc);
	struct usb_device *udev;
	struct ul4h_slot *s;

	/*
	 * ep0 of a FS device: usbcore guessed 64 bytes before it read the
	 * descriptor, as xhci_check_ep0_maxpacket() handles.
	 */
	if (dci == 1) {
		unsigned int mps;

		udev = container_of(ep, struct usb_device, ep0);
		if (udev->speed != USB_SPEED_FULL || !udev->slot_id)
			return;
		s = ul4h_slot(ul, udev);
		mps = usb_endpoint_maxp(&udev->ep0.desc);
		if (!s || mps == s->ep0_mps)
			return;
		switch (mps) {
		case 8: case 16: case 32: case 64: case 9:
			break;
		default:
			dev_dbg(&udev->dev, "incorrect max packet size %u for ep0\n", mps);
			return;
		}
		req.op = L4H_USB_OP_EP0_MPS;
		req.slot = udev->slot_id;
		req.arg[0] = mps;
		if (!ul4h_ctl(ul, &req, NULL, NULL))
			s->ep0_mps = mps;
		return;
	}

	/* Only bulk and interrupt endpoints have a data toggle. */
	udev = ep->hcpriv;
	if (!udev || usb_endpoint_xfer_control(&ep->desc) || usb_endpoint_xfer_isoc(&ep->desc))
		return;
	s = ul4h_slot(ul, udev);
	if (!s || !(s->active & BIT(dci)))
		return;
	req.op = L4H_USB_OP_EP_RESET;
	req.slot = udev->slot_id;
	req.arg[0] = dci;
	ul4h_ctl(ul, &req, NULL, NULL);
}

static int ul4h_alloc_streams(struct usb_hcd *hcd, struct usb_device *udev,
			      struct usb_host_endpoint **eps, unsigned int num_eps,
			      unsigned int num_streams, gfp_t mem_flags)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_STREAMS_ALLOC };
	unsigned int i, n;
	struct ul4h_slot *s;
	u32 mask = 0;
	int ret;

	if (!(ul->features & L4H_USB_F_STREAMS) || ul->max_streams < 4)
		return -ENOSYS;
	s = ul4h_slot(ul, udev);
	if (!eps || !s)
		return -EINVAL;
	/* Stream 0 is the controller's. */
	n = num_streams + 1;
	for (i = 0; i < num_eps; i++) {
		unsigned int max = usb_ss_max_streams(&eps[i]->ss_ep_comp);
		u32 bit = BIT(ul4h_dci(&eps[i]->desc));

		if (!max || !(s->active & bit) || ((s->streams | mask) & bit))
			return -EINVAL;
		mask |= bit;
		n = min(n, max + 1);
	}
	/* A power of two (the stream context array), never more than asked. */
	n = min(n, ul->max_streams);
	if (n <= 1)
		return -EINVAL;
	n = rounddown_pow_of_two(n);
	req.slot = udev->slot_id;
	req.drop = mask;
	req.arg[0] = n;
	ret = ul4h_ctl(ul, &req, NULL, NULL);
	if (ret)
		return ret;
	s->streams |= mask;
	return n - 1;
}

static int ul4h_free_streams(struct usb_hcd *hcd, struct usb_device *udev,
			     struct usb_host_endpoint **eps, unsigned int num_eps,
			     gfp_t mem_flags)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_STREAMS_FREE };
	struct ul4h_slot *s;
	unsigned int i;
	u32 mask = 0;
	int ret;

	s = ul4h_slot(ul, udev);
	if (!eps || !s)
		return -EINVAL;
	for (i = 0; i < num_eps; i++)
		mask |= BIT(ul4h_dci(&eps[i]->desc)) & s->streams;
	if (!mask)
		return -EINVAL;
	req.slot = udev->slot_id;
	req.drop = mask;
	ret = ul4h_ctl(ul, &req, NULL, NULL);
	if (ret)
		return ret;
	s->streams &= ~mask;
	return 0;
}

static int ul4h_update_hub_device(struct usb_hcd *hcd, struct usb_device *hdev,
				  struct usb_tt *tt, gfp_t mem_flags)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct l4h_usb_ctl_req req = { .op = L4H_USB_OP_HUB_CONFIG };
	unsigned int think = 0;

	if (!hdev->parent)
		return 0;
	if (!ul4h_slot(ul, hdev))
		return -EINVAL;
	/* TT think time in 666 ns FS bit-time units, for HS hubs only. */
	if (hdev->speed == USB_SPEED_HIGH && tt->think_time)
		think = tt->think_time / 666 - 1;
	req.slot = hdev->slot_id;
	req.arg[0] = hdev->maxchild;
	req.arg[1] = think;
	req.arg[2] = hdev->speed == USB_SPEED_HIGH && tt->multi;
	return ul4h_ctl(ul, &req, NULL, NULL);
}

/* ---- URBs */

static int ul4h_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	const struct usb_endpoint_descriptor *d = &urb->ep->desc;
	unsigned int dci = ul4h_dci(d);
	unsigned long flags;
	struct ul4h_slot *s;
	struct ul4h_urb *u;
	LIST_HEAD(done);
	int ret;

	if (urb->transfer_buffer_length > ul->max_transfer)
		return -EMSGSIZE;
	if (urb->num_sgs > L4H_USB_MAX_SEGS)
		return -EINVAL;
	if (usb_endpoint_xfer_isoc(d)) {
		if (!(ul->features & L4H_USB_F_ISOCH))
			return -ENOSYS;
		if (urb->number_of_packets > L4H_USB_MAX_ISO)
			return -EFBIG;
	}
	if (urb->stream_id && !(ul->features & L4H_USB_F_STREAMS))
		return -EINVAL;

	u = kzalloc(sizeof(*u), mem_flags);
	if (!u)
		return -ENOMEM;
	INIT_LIST_HEAD(&u->node);
	u->urb = urb;
	u->hcd = hcd;

	spin_lock_irqsave(&ul->lock, flags);
	s = ul4h_slot_locked(ul, urb->dev);
	ret = ul->dead ? -ESHUTDOWN : !s ? -ENODEV : 0;
	if (!ret)
		ret = usb_hcd_link_urb_to_ep(hcd, urb);
	if (ret) {
		spin_unlock_irqrestore(&ul->lock, flags);
		kfree(u);
		return ret;
	}
	urb->hcpriv = u;
	/* The interval the endpoint really has, as xhci-ring.c tells. */
	if ((usb_endpoint_xfer_int(d) || usb_endpoint_xfer_isoc(d)) && (s->active & BIT(dci))) {
		int interval = 1 << s->interval[dci];

		if (urb->dev->speed == USB_SPEED_LOW || urb->dev->speed == USB_SPEED_FULL)
			interval /= 8;
		urb->interval = interval;
	}
	/* Behind earlier ones of the same endpoint that wait. */
	list_add_tail(&u->node, &ul->pending);
	ul4h_push(ul, &done);
	ul4h_unlock_kick(ul, flags);
	ul4h_giveback(&done);
	return 0;
}

static int ul4h_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	unsigned long flags;
	struct ul4h_urb *u;
	LIST_HEAD(done);
	int ret;

	spin_lock_irqsave(&ul->lock, flags);
	ret = usb_hcd_check_unlink_urb(hcd, urb, status);
	u = urb->hcpriv;
	if (ret || !u) {
		spin_unlock_irqrestore(&ul->lock, flags);
		return ret;
	}
	if (!u->inflight) {
		ul4h_finish(ul, u, status, &done);
	} else if (!u->cancel) {
		/* usbd gives it back with ST_CANCELLED once it is safe. */
		u->cancel = UL4H_CANCEL_QUEUED;
		list_add_tail(&u->node, &ul->cancels);
		ul4h_push(ul, &done);
	}
	ul4h_unlock_kick(ul, flags);
	ul4h_giveback(&done);
	return 0;
}

static int ul4h_get_frame_number(struct usb_hcd *hcd)
{
	return READ_ONCE(hcd_to_ul4h(hcd)->info->mfindex) >> 3;
}

/* ---- root hubs */

static int ul4h_port_op(struct ul4h *ul, u32 op, unsigned int xport, u32 feature, u32 value,
			u32 *portsc)
{
	struct l4h_usb_ctl_req req = { .op = op, .port = xport };
	u32 val[2];
	int ret;

	req.arg[0] = feature;
	req.arg[1] = value;
	ret = ul4h_ctl(ul, &req, val, NULL);
	if (ret == L4H_USB_ST_INVALID)
		return -EPIPE;		/* as a hub stalls */
	if (!ret && portsc)
		*portsc = val[0];
	return ret;
}

static int ul4h_port_get(struct ul4h *ul, unsigned int xport, u32 *portsc)
{
	return ul4h_port_op(ul, L4H_USB_OP_PORT_GET, xport, 0, 0, portsc);
}

static int ul4h_port_set(struct ul4h *ul, unsigned int xport, u32 feature, u32 value)
{
	return ul4h_port_op(ul, L4H_USB_OP_PORT_SET, xport, feature, value, NULL);
}

static int ul4h_port_clear(struct ul4h *ul, unsigned int xport, u32 feature, u32 value)
{
	return ul4h_port_op(ul, L4H_USB_OP_PORT_CLEAR, xport, feature, value, NULL);
}

static void ul4h_hub_descriptor(struct ul4h *ul, struct ul4h_rh *rh,
				struct usb_hub_descriptor *desc)
{
	unsigned int i, ports = rh->nports;
	u32 removable = 0, portsc;

	/* DeviceRemovable: bit p for port p; PORTSC.DR is "not removable". */
	for (i = 0; i < ports; i++)
		if (!ul4h_port_get(ul, rh->xport[i], &portsc) && (portsc & PORTSC_DR))
			removable |= BIT(i + 1);

	memset(desc, 0, sizeof(*desc));
	desc->bNbrPorts = ports;
	/* Per-port power switching is the controller's (HCCPARAMS.PPC),
	 * which usbd does not report: say power is always on. */
	desc->wHubCharacteristics = cpu_to_le16(HUB_CHAR_NO_LPSM | HUB_CHAR_INDV_PORT_OCPM);
	if (rh->usb3) {
		desc->bDescriptorType = USB_DT_SS_HUB;
		desc->bDescLength = USB_DT_SS_HUB_SIZE;
		desc->bPwrOn2PwrGood = 50;
		desc->u.ss.DeviceRemovable = cpu_to_le16(removable);
	} else {
		unsigned int bytes = 1 + ports / 8;

		desc->bDescriptorType = USB_DT_HUB;
		desc->bDescLength = USB_DT_HUB_NONVAR_SIZE + 2 * bytes;
		desc->bPwrOn2PwrGood = 10;
		memset(desc->u.hs.DeviceRemovable, 0xff, sizeof(desc->u.hs.DeviceRemovable));
		memset(desc->u.hs.PortPwrCtrlMask, 0xff, sizeof(desc->u.hs.PortPwrCtrlMask));
		for (i = 0; i < bytes; i++)
			desc->u.hs.DeviceRemovable[i] = removable >> (8 * i);
	}
}

/* The root hub's BOS: a SuperSpeed capability, without LPM or LTM. */
static int ul4h_bos(char *buf, u16 wLength)
{
	struct usb_bos_descriptor *bos = (struct usb_bos_descriptor *)buf;
	struct usb_ss_cap_descriptor *ss = (struct usb_ss_cap_descriptor *)&buf[USB_DT_BOS_SIZE];
	unsigned int total = USB_DT_BOS_SIZE + USB_DT_USB_SS_CAP_SIZE;

	bos->bLength = USB_DT_BOS_SIZE;
	bos->bDescriptorType = USB_DT_BOS;
	bos->wTotalLength = cpu_to_le16(total);
	bos->bNumDeviceCaps = 1;
	if (wLength < total)
		return wLength;
	memset(ss, 0, sizeof(*ss));
	ss->bLength = USB_DT_USB_SS_CAP_SIZE;
	ss->bDescriptorType = USB_DT_DEVICE_CAPABILITY;
	ss->bDevCapabilityType = USB_SS_CAP_TYPE;
	ss->wSpeedSupported = cpu_to_le16(USB_5GBPS_OPERATION);
	ss->bFunctionalitySupport = USB_LOW_SPEED_OPERATION;
	return total;
}

/* Raw PORTSC to wPortStatus | wPortChange << 16, as xhci-hub.c does. */
static u32 ul4h_port_status(struct ul4h_rh *rh, unsigned int i, u32 portsc)
{
	u32 pls = PORTSC_PLS_GET(portsc), status = 0;

	if (portsc & PORTSC_CSC)
		status |= USB_PORT_STAT_C_CONNECTION << 16;
	if (portsc & PORTSC_PEC)
		status |= USB_PORT_STAT_C_ENABLE << 16;
	if (portsc & PORTSC_OCC)
		status |= USB_PORT_STAT_C_OVERCURRENT << 16;
	if (portsc & PORTSC_PRC)
		status |= USB_PORT_STAT_C_RESET << 16;
	if (portsc & PORTSC_CCS) {
		status |= USB_PORT_STAT_CONNECTION;
		if (!rh->usb3 && PORTSC_SPEED(portsc) == L4H_USB_SPEED_LOW)
			status |= USB_PORT_STAT_LOW_SPEED;
		if (!rh->usb3 && PORTSC_SPEED(portsc) == L4H_USB_SPEED_HIGH)
			status |= USB_PORT_STAT_HIGH_SPEED;
	}
	if (portsc & PORTSC_PED)
		status |= USB_PORT_STAT_ENABLE;
	if (portsc & PORTSC_OCA)
		status |= USB_PORT_STAT_OVERCURRENT;
	if (portsc & PORTSC_PR)
		status |= USB_PORT_STAT_RESET;

	if (rh->usb3) {
		/* Resume is the controller's business, not the hub driver's. */
		if ((portsc & PORTSC_PLC) && pls != PLS_RESUME)
			status |= USB_PORT_STAT_C_LINK_STATE << 16;
		if (portsc & PORTSC_WRC)
			status |= USB_PORT_STAT_C_BH_RESET << 16;
		if (portsc & PORTSC_CEC)
			status |= USB_PORT_STAT_C_CONFIG_ERROR << 16;
		if (portsc & PORTSC_PP)
			status |= USB_SS_PORT_STAT_POWER;
		if (pls != PLS_U3 && pls != PLS_RESUME && pls != PLS_RECOVERY)
			rh->suspended &= ~BIT(i);
		if (portsc & PORTSC_CAS) {
			/* Pretend compliance mode: the hub driver warm resets. */
			if (pls != PLS_COMPLIANCE && pls != PLS_INACTIVE)
				pls = PLS_COMPLIANCE;
			status |= USB_PORT_STAT_CONNECTION;
		} else if (pls == PLS_RESUME) {
			pls = PLS_U3;
		}
		status |= pls << PORTSC_PLS_SHIFT;
	} else {
		if (portsc & PORTSC_PP) {
			status |= USB_PORT_STAT_POWER;
			if (pls == PLS_U3 || pls == PLS_RESUME)
				status |= USB_PORT_STAT_SUSPEND;
			if (pls == PLS_U2)
				status |= USB_PORT_STAT_L1;
			if (pls == PLS_U0 && (rh->suspended & BIT(i))) {
				rh->suspended &= ~BIT(i);
				rh->c_suspend |= BIT(i);
			}
		}
		if (pls != PLS_U3 && pls != PLS_RESUME)
			rh->suspended &= ~BIT(i);
	}
	if (rh->c_suspend & BIT(i))
		status |= USB_PORT_STAT_C_SUSPEND << 16;
	if (rh->force_cc & BIT(i))
		status |= USB_PORT_STAT_C_CONNECTION << 16;
	return status;
}

static int ul4h_get_port_status(struct ul4h *ul, struct ul4h_rh *rh, unsigned int i, char *buf)
{
	unsigned int xport = rh->xport[i];
	u32 portsc, status;
	int ret;

	spin_lock_irq(&ul->lock);
	rh->event &= ~BIT(i);
	spin_unlock_irq(&ul->lock);
	ret = ul4h_port_get(ul, xport, &portsc);
	if (ret)
		return ret;
	/* A device resuming a USB 2 port: time the resume signalling. */
	if (!rh->usb3 && (portsc & PORTSC_PP) && (portsc & PORTSC_PED) &&
	    !(portsc & PORTSC_PR) && PORTSC_PLS_GET(portsc) == PLS_RESUME) {
		msleep(USB_RESUME_TIMEOUT);
		ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U0);
		if (!ret)
			ret = ul4h_port_get(ul, xport, &portsc);
		if (ret)
			return ret;
		spin_lock_irq(&ul->lock);
		rh->c_suspend |= BIT(i);
		spin_unlock_irq(&ul->lock);
	}
	spin_lock_irq(&ul->lock);
	rh->chg[i] = portsc & PORTSC_CHANGES;
	status = ul4h_port_status(rh, i, portsc);
	spin_unlock_irq(&ul->lock);
	put_unaligned_le32(status, buf);
	return 0;
}

static int ul4h_wait_pls(struct ul4h *ul, unsigned int xport, u32 pls, unsigned int ms)
{
	u32 portsc;
	int ret;

	for (;;) {
		ret = ul4h_port_get(ul, xport, &portsc);
		if (ret || PORTSC_PLS_GET(portsc) == pls)
			return ret;
		if (!ms)
			return 0;
		usleep_range(5000, 6000);
		ms -= min(ms, 5u);
	}
}

static int ul4h_set_port_feature(struct ul4h *ul, struct ul4h_rh *rh, unsigned int i,
				 u16 wValue, u16 wIndex)
{
	unsigned int xport = rh->xport[i];
	u32 portsc, pls, cur;
	int ret;

	switch (wValue) {
	case USB_PORT_FEAT_SUSPEND:
		if (rh->usb3)
			return -EPIPE;
		ret = ul4h_port_get(ul, xport, &portsc);
		if (ret)
			return ret;
		if (PORTSC_PLS_GET(portsc) != PLS_U0) {
			ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U0);
			if (ret)
				return ret;
			msleep(10);
			ret = ul4h_port_get(ul, xport, &portsc);
			if (ret)
				return ret;
		}
		if (!(portsc & PORTSC_PED) || (portsc & PORTSC_PR) ||
		    PORTSC_PLS_GET(portsc) >= PLS_U3)
			return -EPIPE;
		ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U3);
		if (ret)
			return ret;
		msleep(10);
		spin_lock_irq(&ul->lock);
		rh->suspended |= BIT(i);
		spin_unlock_irq(&ul->lock);
		return 0;
	case USB_PORT_FEAT_LINK_STATE:
		if (!rh->usb3)
			return -EPIPE;
		pls = (wIndex >> 8) & 0xff;
		if (pls == PLS_DISABLED) {
			/* Clear the change bits, for a new connect event. */
			ul4h_port_clear(ul, xport, L4H_USB_PF_CHANGE, PORTSC_CHANGES);
			return ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_DISABLED);
		}
		if (pls == PLS_RXDETECT)
			return ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_RXDETECT);
		ret = ul4h_port_get(ul, xport, &portsc);
		if (ret)
			return ret;
		if (!(portsc & PORTSC_PED))
			return -ENODEV;
		if (pls > PLS_U3)
			return -EPIPE;
		cur = PORTSC_PLS_GET(portsc);
		if (pls == PLS_U0) {
			if (cur == PLS_U0)
				return 0;
			if (cur <= PLS_U3) {
				ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U0);
				if (ret)
					return ret;
			}
			if (cur == PLS_U3 || cur == PLS_RESUME || cur == PLS_RECOVERY)
				return ul4h_wait_pls(ul, xport, PLS_U0, 500);
			return cur > PLS_U3 ? -EPIPE : 0;
		}
		if (pls == PLS_U3) {
			ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U3);
			if (!ret)
				ret = ul4h_wait_pls(ul, xport, PLS_U3, 100);
			if (ret)
				return ret;
			spin_lock_irq(&ul->lock);
			rh->suspended |= BIT(i);
			spin_unlock_irq(&ul->lock);
		}
		/* U1 and U2 are left to the controller. */
		return 0;
	case USB_PORT_FEAT_POWER:
		return ul4h_port_set(ul, xport, L4H_USB_PF_POWER, 0);
	case USB_PORT_FEAT_RESET:
		return ul4h_port_set(ul, xport, L4H_USB_PF_RESET, 0);
	case USB_PORT_FEAT_BH_PORT_RESET:
		if (!rh->usb3)
			return -EPIPE;
		return ul4h_port_set(ul, xport, L4H_USB_PF_WARM_RESET, 0);
	case USB_PORT_FEAT_REMOTE_WAKE_MASK:
		return ul4h_port_set(ul, xport, L4H_USB_PF_WAKE, (wIndex >> 8) & 0x7);
	case USB_PORT_FEAT_U1_TIMEOUT:
	case USB_PORT_FEAT_U2_TIMEOUT:
		/* No U1/U2 (LPM): nothing to time out. */
		return rh->usb3 ? 0 : -EPIPE;
	default:
		return -EPIPE;
	}
}

static int ul4h_clear_port_feature(struct ul4h *ul, struct ul4h_rh *rh, unsigned int i,
				   u16 wValue)
{
	unsigned int xport = rh->xport[i];
	u32 portsc, mask;
	int ret;

	switch (wValue) {
	case USB_PORT_FEAT_SUSPEND:
		ret = ul4h_port_get(ul, xport, &portsc);
		if (ret)
			return ret;
		if (portsc & PORTSC_PR)
			return -EPIPE;
		if (PORTSC_PLS_GET(portsc) == PLS_U3) {
			if (!(portsc & PORTSC_PED))
				return -EPIPE;
			ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_RESUME);
			if (ret)
				return ret;
			msleep(USB_RESUME_TIMEOUT);
			ret = ul4h_port_set(ul, xport, L4H_USB_PF_LINK_STATE, PLS_U0);
			if (ret)
				return ret;
		}
		spin_lock_irq(&ul->lock);
		rh->c_suspend |= BIT(i);
		rh->suspended &= ~BIT(i);
		spin_unlock_irq(&ul->lock);
		return 0;
	case USB_PORT_FEAT_C_SUSPEND:
		spin_lock_irq(&ul->lock);
		rh->c_suspend &= ~BIT(i);
		spin_unlock_irq(&ul->lock);
		mask = PORTSC_PLC;
		break;
	case USB_PORT_FEAT_C_PORT_LINK_STATE:
		mask = PORTSC_PLC;
		break;
	case USB_PORT_FEAT_C_RESET:
		mask = PORTSC_PRC;
		break;
	case USB_PORT_FEAT_C_BH_PORT_RESET:
		mask = PORTSC_WRC;
		break;
	case USB_PORT_FEAT_C_CONNECTION:
		spin_lock_irq(&ul->lock);
		rh->force_cc &= ~BIT(i);
		spin_unlock_irq(&ul->lock);
		mask = PORTSC_CSC;
		break;
	case USB_PORT_FEAT_C_OVER_CURRENT:
		mask = PORTSC_OCC;
		break;
	case USB_PORT_FEAT_C_ENABLE:
		mask = PORTSC_PEC;
		break;
	case USB_PORT_FEAT_C_PORT_CONFIG_ERROR:
		mask = PORTSC_CEC;
		break;
	case USB_PORT_FEAT_ENABLE:
		/* The hub driver may not disable SuperSpeed ports. */
		if (rh->usb3)
			return 0;
		return ul4h_port_clear(ul, xport, L4H_USB_PF_ENABLE, 0);
	case USB_PORT_FEAT_POWER:
		return ul4h_port_clear(ul, xport, L4H_USB_PF_POWER, 0);
	default:
		return -EPIPE;
	}
	ret = ul4h_port_clear(ul, xport, L4H_USB_PF_CHANGE, mask);
	if (!ret) {
		spin_lock_irq(&ul->lock);
		rh->chg[i] &= ~mask;
		spin_unlock_irq(&ul->lock);
	}
	return ret;
}

static int ul4h_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue, u16 wIndex,
			    char *buf, u16 wLength)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct ul4h_rh *rh = ul4h_rh(ul, hcd);
	unsigned int port1 = wIndex & 0xff;

	switch (typeReq) {
	case GetHubStatus:
		/* No power source; over-current is per port. */
		memset(buf, 0, 4);
		return 0;
	case GetHubDescriptor:
		if (rh->usb3 && (wLength < USB_DT_SS_HUB_SIZE || wValue != (USB_DT_SS_HUB << 8)))
			return -EPIPE;
		ul4h_hub_descriptor(ul, rh, (struct usb_hub_descriptor *)buf);
		return 0;
	case DeviceRequest | USB_REQ_GET_DESCRIPTOR:
		if ((wValue & 0xff00) != (USB_DT_BOS << 8) || !rh->usb3)
			return -EPIPE;
		return ul4h_bos(buf, wLength);
	case GetPortStatus:
		/* No USB 3.1 extended port status: this is a USB 3.0 hub. */
		if (!port1 || port1 > rh->nports || wValue)
			return -EPIPE;
		return ul4h_get_port_status(ul, rh, port1 - 1, buf);
	case SetPortFeature:
		if (!port1 || port1 > rh->nports)
			return -EPIPE;
		return ul4h_set_port_feature(ul, rh, port1 - 1, wValue, wIndex);
	case ClearPortFeature:
		if (!port1 || port1 > rh->nports)
			return -EPIPE;
		return ul4h_clear_port_feature(ul, rh, port1 - 1, wValue);
	default:
		return -EPIPE;
	}
}

/*
 * From the root hub's timer and usb_hcd_poll_rh_status(): only what the
 * EQ and the last port reads left, no request to usbd.
 */
static int ul4h_hub_status_data(struct usb_hcd *hcd, char *buf)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct ul4h_rh *rh = ul4h_rh(ul, hcd);
	unsigned int i, len = (rh->nports + 8) / 8;
	unsigned long flags, changed;

	memset(buf, 0, len);
	spin_lock_irqsave(&ul->lock, flags);
	changed = rh->event | rh->force_cc | rh->c_suspend;
	for (i = 0; i < rh->nports; i++)
		if (rh->chg[i])
			changed |= BIT(i);
	if (!changed)
		clear_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	spin_unlock_irqrestore(&ul->lock, flags);
	for (i = 0; i < rh->nports; i++)
		if (changed & BIT(i))
			buf[(i + 1) / 8] |= BIT((i + 1) % 8);
	return changed ? len : 0;
}

/* ---- HCDs */

static int ul4h_hcd_reset(struct usb_hcd *hcd)
{
	struct ul4h_rh *rh = ul4h_rh(hcd_to_ul4h(hcd), hcd);

	hcd->self.sg_tablesize = L4H_USB_MAX_SEGS;
	/*
	 * usbd lays out TDs as xhci-ring.c does, which handles segments of
	 * any length (UAS and usb-storage hand out such lists).
	 */
	hcd->self.no_sg_constraint = 1;
	/* The controller does not stop an endpoint on short packets. */
	hcd->self.no_stop_on_short = 1;
	if (!rh->usb3) {
		hcd->speed = HCD_USB2;
		hcd->self.root_hub->speed = USB_SPEED_HIGH;
		/* The USB 2 root hub has an integrated TT. */
		hcd->has_tt = 1;
	}
	return 0;
}

static int ul4h_hcd_start(struct usb_hcd *hcd)
{
	struct ul4h *ul = hcd_to_ul4h(hcd);
	struct ul4h_rh *rh = ul4h_rh(ul, hcd);

	hcd->uses_new_polling = 1;
	hcd->state = HC_STATE_RUNNING;
	/* Devices may have been connected before the root hub: look. */
	spin_lock_irq(&ul->lock);
	rh->event = BIT(rh->nports) - 1;
	spin_unlock_irq(&ul->lock);
	set_bit(HCD_FLAG_POLL_RH, &hcd->flags);
	return 0;
}

static void ul4h_hcd_stop(struct usb_hcd *hcd)
{
	/* The controller is reset in remove, after both HCDs are gone. */
}

static const struct hc_driver ul4h_hc_driver = {
	.description		= "usb-l4h",
	.product_desc		= "l4h xHCI Host Controller",
	.hcd_priv_size		= sizeof(struct ul4h *),
	.flags			= HCD_DMA | HCD_USB3 | HCD_SHARED | HCD_BH,
	.reset			= ul4h_hcd_reset,
	.start			= ul4h_hcd_start,
	.stop			= ul4h_hcd_stop,
	.get_frame_number	= ul4h_get_frame_number,
	.urb_enqueue		= ul4h_urb_enqueue,
	.urb_dequeue		= ul4h_urb_dequeue,
	.endpoint_reset		= ul4h_endpoint_reset,
	.hub_status_data	= ul4h_hub_status_data,
	.hub_control		= ul4h_hub_control,
	.alloc_dev		= ul4h_alloc_dev,
	.free_dev		= ul4h_free_dev,
	.alloc_streams		= ul4h_alloc_streams,
	.free_streams		= ul4h_free_streams,
	.add_endpoint		= ul4h_add_endpoint,
	.drop_endpoint		= ul4h_drop_endpoint,
	.check_bandwidth	= ul4h_check_bandwidth,
	.reset_bandwidth	= ul4h_reset_bandwidth,
	.address_device		= ul4h_address_device,
	.enable_device		= ul4h_enable_device,
	.update_hub_device	= ul4h_update_hub_device,
	.reset_device		= ul4h_reset_device,
};

/* Root hub ports from port_proto: the i-th port of a protocol is hub port i. */
static int ul4h_map_ports(struct ul4h *ul)
{
	const struct l4h_usb_info *info = ul->info;
	struct ul4h_rh *usb2, *usb3;
	unsigned int p, n2 = 0, n3 = 0;

	for (p = 1; p <= ul->max_ports; p++) {
		u8 proto = READ_ONCE(info->port_proto[p]);

		n2 += proto == 2;
		n3 += proto == 3;
	}
	if (n2 != READ_ONCE(info->usb2_ports) || n3 != READ_ONCE(info->usb3_ports))
		dev_warn(ul->dev, "port counts %u/%u, protocols say %u/%u\n",
			 READ_ONCE(info->usb2_ports), READ_ONCE(info->usb3_ports), n2, n3);
	if (!n2 && !n3)
		return -ENODEV;
	/* The primary HCD is USB 2 unless there are only USB 3 ports. */
	usb2 = n2 ? &ul->rh[0] : NULL;
	usb3 = n2 ? (n3 ? &ul->rh[1] : NULL) : &ul->rh[0];
	if (usb3)
		usb3->usb3 = true;
	for (p = 1; p <= ul->max_ports; p++) {
		u8 proto = READ_ONCE(info->port_proto[p]);
		struct ul4h_rh *rh = proto == 2 ? usb2 : proto == 3 ? usb3 : NULL;
		unsigned int max = proto == 3 ? UL4H_USB3_MAXPORTS : USB_MAXCHILDREN;

		if (!rh)
			continue;
		if (rh->nports >= max) {
			dev_warn(ul->dev, "port %u: more than %u USB %u ports\n", p, max, proto);
			continue;
		}
		ul->port_rh[p] = rh - ul->rh + 1;
		ul->port_idx[p] = rh->nports;
		rh->xport[rh->nports++] = p;
	}
	return 0;
}

static struct usb_hcd *ul4h_create_hcd(struct ul4h *ul, struct device *sysdev,
				       struct usb_hcd *primary)
{
	struct usb_hcd *hcd;

	hcd = __usb_create_hcd(&ul4h_hc_driver, sysdev, ul->dev, dev_name(ul->dev), primary);
	if (hcd)
		*(struct ul4h **)hcd->hcd_priv = ul;
	return hcd;
}

static void ul4h_teardown(struct ul4h *ul)
{
	WRITE_ONCE(ul->removing, true);
	cancel_work_sync(&ul->reset_work);
	/* Every pool buffer is the guest's again only after a reset. */
	if (!ul->dead && ul4h_reset_hc(ul))
		dev_warn(ul->dev, "reset at remove failed\n");
	free_irq(ul->irq, ul);
	irq_set_chip_data(ul->irq, NULL);
	timer_delete_sync(&ul->retry);
}

static int ul4h_probe(struct platform_device *pdev)
{
	const unsigned int *index = dev_get_platdata(&pdev->dev);
	struct device *dev = &pdev->dev;
	const struct l4h_dev_desc *desc;
	struct l4h_usb_info *info;
	struct device *sysdev;
	struct usb_hcd *hcd;
	struct ul4h *ul;
	unsigned int ms;
	void *area;
	int err;

	if (!index || *index >= L4H_MAX_DEVICES)
		return -ENODEV;
	desc = &l4h_bootinfo->devices[*index];
	sysdev = l4h_io_pool_dev();
	if (!sysdev) {
		dev_err(dev, "no I/O pool\n");
		return -ENODEV;
	}
	if (desc->page_size < L4H_USB_AREA_PAGES * PAGE_SIZE)
		return -EINVAL;
	area = (void *)(unsigned long)desc->page_va;
	info = area;
	/*
	 * Root asks usbd to attach without waiting for it, and the previous
	 * guest's removal may still be running: usbd writes the magic last.
	 */
	for (ms = 0; READ_ONCE(info->magic) != L4H_USB_MAGIC && ms < UL4H_RESET_TIMEOUT_MS; ms += 10)
		msleep(10);
	smp_rmb();	/* the fields usbd wrote before the magic */
	if (READ_ONCE(info->magic) != L4H_USB_MAGIC || READ_ONCE(info->version) != L4H_USB_VERSION) {
		dev_err(dev, "bad magic or version %u\n", READ_ONCE(info->version));
		return -ENODEV;
	}

	ul = devm_kzalloc(dev, sizeof(*ul), GFP_KERNEL);
	if (!ul)
		return -ENOMEM;
	spin_lock_init(&ul->lock);
	INIT_LIST_HEAD(&ul->waiters);
	INIT_LIST_HEAD(&ul->pending);
	INIT_LIST_HEAD(&ul->cancels);
	init_waitqueue_head(&ul->wq);
	timer_setup(&ul->retry, ul4h_retry_fn, 0);
	INIT_WORK(&ul->reset_work, ul4h_reset_work);
	ul->dev = dev;
	ul->index = *index;
	ul->info = info;
	ul->ctrl = area + PAGE_SIZE;
	ul->ctl_sq = area + L4H_USB_CTL_SQ_OFF;
	ul->xfer_sq = area + L4H_USB_XFER_SQ_OFF;
	ul->cq = area + L4H_USB_CQ_OFF;
	ul->eq = area + L4H_USB_EQ_OFF;
	ul->kick_cap = L4H_CPTR2(L4H_SLOT_DEV_CNODE, desc->kick_slot);
	ul->features = READ_ONCE(info->features);
	ul->max_transfer = READ_ONCE(info->max_transfer);
	ul->max_streams = READ_ONCE(info->max_streams);
	ul->max_slots = min_t(u32, READ_ONCE(info->max_slots), U8_MAX);
	ul->max_ports = min_t(u32, READ_ONCE(info->max_ports), L4H_USB_MAX_PORTS);
	ul->slots = devm_kcalloc(dev, ul->max_slots + 1, sizeof(*ul->slots), GFP_KERNEL);
	if (!ul->slots)
		return -ENOMEM;
	err = ul4h_map_ports(ul);
	if (err)
		return err;

	/*
	 * Start where usbd is: an earlier driver may have left records.  The
	 * reset below completes whatever it had accepted.
	 */
	ul->ctl_head = READ_ONCE(info->ctl_sq_tail.v);
	ul->xfer_head = READ_ONCE(info->xfer_sq_tail.v);
	ul->cq_tail = READ_ONCE(info->cq_head.v);
	ul->eq_tail = READ_ONCE(info->eq_head.v);
	ul->lost_seen = READ_ONCE(info->lost_events.v);
	WRITE_ONCE(ul->ctrl->ctl_sq_head.v, ul->ctl_head);
	WRITE_ONCE(ul->ctrl->xfer_sq_head.v, ul->xfer_head);
	WRITE_ONCE(ul->ctrl->cq_tail.v, ul->cq_tail);
	WRITE_ONCE(ul->ctrl->eq_tail.v, ul->eq_tail);

	ul->irq = l4h_event_irq(desc->event);
	if (ul->irq < 0)
		return ul->irq;
	ul->route.set_affinity = ul4h_set_irq_cpu;
	ul->route.data = ul;
	irq_set_chip_data(ul->irq, &ul->route);
	err = request_irq(ul->irq, ul4h_interrupt, 0, dev_name(dev), ul);
	if (err) {
		irq_set_chip_data(ul->irq, NULL);
		return err;
	}
	err = ul4h_reset_hc(ul);
	if (err) {
		dev_err(dev, "controller reset failed: %d\n", err);
		goto fail_irq;
	}

	err = -ENOMEM;
	hcd = ul4h_create_hcd(ul, sysdev, NULL);
	if (!hcd)
		goto fail_reset;
	ul->rh[0].hcd = hcd;
	err = usb_add_hcd(hcd, 0, 0);
	if (err)
		goto fail_put;
	ul->added = true;
	if (ul->rh[1].nports) {
		struct usb_hcd *shared = ul4h_create_hcd(ul, sysdev, hcd);

		err = -ENOMEM;
		if (!shared)
			goto fail_remove;
		if ((ul->features & L4H_USB_F_STREAMS) && ul->max_streams >= 4)
			shared->can_do_streams = 1;
		ul->rh[1].hcd = shared;
		err = usb_add_hcd(shared, 0, 0);
		if (err) {
			ul->rh[1].hcd = NULL;
			usb_put_hcd(shared);
			goto fail_remove;
		}
	} else if (ul->rh[0].usb3 && (ul->features & L4H_USB_F_STREAMS) && ul->max_streams >= 4) {
		hcd->can_do_streams = 1;
	}
	platform_set_drvdata(pdev, ul);
	dev_info(dev, "xHCI %x.%02x: %u USB 2 and %u USB 3 ports, %u slots, event %u\n",
		 READ_ONCE(info->hci_version) >> 8, READ_ONCE(info->hci_version) & 0xff,
		 ul->rh[0].usb3 ? 0 : ul->rh[0].nports,
		 ul->rh[0].usb3 ? ul->rh[0].nports : ul->rh[1].nports, ul->max_slots, desc->event);
	return 0;

fail_remove:
	usb_remove_hcd(hcd);
fail_put:
	ul->rh[0].hcd = NULL;
	usb_put_hcd(hcd);
fail_reset:
	ul4h_teardown(ul);
	return err;
fail_irq:
	WRITE_ONCE(ul->removing, true);
	cancel_work_sync(&ul->reset_work);
	free_irq(ul->irq, ul);
	irq_set_chip_data(ul->irq, NULL);
	timer_delete_sync(&ul->retry);
	return err;
}

static void ul4h_remove(struct platform_device *pdev)
{
	struct ul4h *ul = platform_get_drvdata(pdev);
	struct usb_hcd *primary = ul->rh[0].hcd, *shared = ul->rh[1].hcd;

	/* usbcore gives every URB back and frees every slot. */
	if (shared)
		usb_remove_hcd(shared);
	usb_remove_hcd(primary);
	ul4h_teardown(ul);
	ul->rh[1].hcd = NULL;
	ul->rh[0].hcd = NULL;
	if (shared)
		usb_put_hcd(shared);
	usb_put_hcd(primary);
}

static struct platform_driver ul4h_driver = {
	.probe = ul4h_probe,
	.remove = ul4h_remove,
	.driver = {
		.name = "usb-l4h",
	},
};

static struct platform_device *ul4h_pdevs[L4H_MAX_GUEST_USB];

static void ul4h_unregister_devices(void)
{
	unsigned int n;

	for (n = 0; n < ARRAY_SIZE(ul4h_pdevs); n++) {
		if (ul4h_pdevs[n])
			platform_device_unregister(ul4h_pdevs[n]);
		ul4h_pdevs[n] = NULL;
	}
}

static int __init ul4h_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	unsigned int i, n = 0;
	int err;

	err = platform_driver_register(&ul4h_driver);
	if (err)
		return err;
	for (i = 0; i < bi->nr_devices && i < L4H_MAX_DEVICES; i++) {
		struct platform_device *pdev;

		if (bi->devices[i].type != L4H_DEV_USB)
			continue;
		if (n == ARRAY_SIZE(ul4h_pdevs)) {
			pr_warn("usb-l4h: device %u: more than %u controllers\n", i, n);
			break;
		}
		pdev = platform_device_register_data(NULL, "usb-l4h", n, &i, sizeof(i));
		if (IS_ERR(pdev)) {
			pr_err("usb-l4h: device %u: %ld\n", i, PTR_ERR(pdev));
			continue;
		}
		ul4h_pdevs[n++] = pdev;
	}
	return 0;
}
module_init(ul4h_init);

static void __exit ul4h_exit(void)
{
	ul4h_unregister_devices();
	platform_driver_unregister(&ul4h_driver);
}
module_exit(ul4h_exit);

MODULE_DESCRIPTION("l4h xHCI host controller (l4h-usbd)");
MODULE_LICENSE("GPL");
