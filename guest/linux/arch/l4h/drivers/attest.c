// SPDX-License-Identifier: GPL-2.0
/*
 * Attestation by the l4h host (l4h-trustd, DESIGN.md §10.2), through the
 * attestation device (L4H_DEV_ATTEST, struct l4h_attest_page) on hosts
 * (flags work without a TPM):
 *
 * - configfs-tsm reports (/sys/kernel/config/tsm/report, provider "l4h"):
 *   inblob is the report data (up to 64 bytes, zero padded), outblob the
 *   report (COSE_Sign1), auxblob the host evidence (CBOR).
 * - /dev/l4h-attest: ioctl(L4H_ATTEST_IOC) makes any request,
 *   ActivateCredential included, for tools such as l4hctl.
 *
 * Requests are asynchronous: the caller sleeps until the host's answer
 * raises the device's event, and the vCPU runs other tasks meanwhile.
 */
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kobject.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/panic.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/tsm.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <asm/attest.h>
#include <irq_kern.h>
#include <l4h_sys.h>

struct l4h_attest_ioc {
	__u32 op;		/* L4H_ATTEST_* */
	__u32 blob_len;		/* ACTIVATE: credential blob bytes */
	__u32 secret_len;	/* ACTIVATE: encrypted secret bytes */
	__u32 out_len;		/* in: room at out; out: the result's length */
	__u64 data;		/* REPORT: 64 bytes; ACTIVATE: blob + secret; ACT/SEAL: blob_len bytes */
	__u64 out;
};

#define L4H_ATTEST_IOC _IOWR('L', 2, struct l4h_attest_ioc)
/* ActivateCredential creates the EK on first use: seconds on a slow TPM. */
#define ATTEST_TIMEOUT (150 * HZ)

static struct l4h_attest_page *page;
static unsigned long kick_cap;
static DECLARE_WAIT_QUEUE_HEAD(answered);
static DEFINE_MUTEX(attest_lock);
static u32 seq;
/* A request the host has not answered yet although its caller gave up: the
 * host still owns the page until done says so. */
static u32 outstanding;
static atomic_long_t pending = ATOMIC_LONG_INIT(0);
static bool ready, flags_supported = true;
static void taint_work(struct work_struct *work);
static DECLARE_WORK(taint_sender, taint_work);
static void no_reports(void);

/* add_taint() can run before probe, from an IRQ, or while reporting.
 * Never wait here. A report takes this pending word under attest_lock. */
void l4h_attest_taint(unsigned flag)
{
	if (flag >= BITS_PER_LONG)
		return;
	atomic_long_or(BIT(flag), &pending);
	if (smp_load_acquire(&ready))
		schedule_work(&taint_sender);
}

static bool attest_answered(u32 s)
{
	return READ_ONCE(page->done) == s || (READ_ONCE(page->state) & L4H_ATTEST_FAILED);
}

static irqreturn_t attest_interrupt(int irq, void *data)
{
	wake_up(&answered);
	return IRQ_HANDLED;
}

/*
 * Run request `op` with `in_len` bytes of `in` (`blob_len` of them the
 * credential blob) and collect its result, which may take several
 * replies.  Returns a kvmalloc'ed buffer in *out.
 */
static int attest_call_locked(u32 op, const u8 *in, size_t in_len, size_t blob_len, u8 **out, size_t *out_len)
{
	size_t total = 0, got = 0;
	u8 *buf = NULL;
	int ret = 0;

	if (in_len > L4H_ATTEST_PAGE_DATA)
		return -EINVAL;
	/* The host would write that answer over our request. */
	if (outstanding) {
		if (wait_event_killable(answered, attest_answered(outstanding))) {
			return -EINTR;
		}
		outstanding = 0;
	}
	do {
		/* 0 is "none" (outstanding, and the page's initial seq). */
		u32 s = ++seq ?: ++seq, n;
		long left;

		if (READ_ONCE(page->state) & L4H_ATTEST_FAILED) {
			ret = -EIO;
			break;
		}
		WRITE_ONCE(page->op, op);
		WRITE_ONCE(page->offset, got);
		WRITE_ONCE(page->in_len, in_len);
		WRITE_ONCE(page->blob_len, blob_len);
		if (in_len)
			memcpy(page->data, in, in_len);
		smp_wmb();
		WRITE_ONCE(page->seq, s);
		l4h_signal(kick_cap);
		left = wait_event_killable_timeout(answered, attest_answered(s), ATTEST_TIMEOUT);
		if (left <= 0) {
			outstanding = s;
			ret = left ? -EINTR : -ETIMEDOUT;
			break;
		}
		if (READ_ONCE(page->done) != s) {
			ret = -EIO;	/* the host failed */
			break;
		}
		smp_rmb();
		if (READ_ONCE(page->status)) {
			ret = READ_ONCE(page->status);
			break;
		}
		n = READ_ONCE(page->out_len);
		if (!buf) {
			total = READ_ONCE(page->total);
			buf = kvmalloc(max_t(size_t, total, 1), GFP_KERNEL);
			if (!buf) {
				ret = -ENOMEM;
				break;
			}
		}
		if (n > L4H_ATTEST_PAGE_DATA || READ_ONCE(page->total) != total || got + n > total ||
		    (!n && got < total)) {
			ret = -EIO;
			break;
		}
		memcpy(buf + got, page->data, n);
		got += n;
	} while (got < total);
	if (ret) {
		kvfree(buf);
		return ret;
	}
	*out = buf;
	*out_len = total;
	return 0;
}

/* attest_lock held. Put failed sends back: losing a taint on interruption
 * would allow a later report to claim a clean kernel. */
static int flush_taints(void)
{
	unsigned long mask;
	u8 bits[L4H_FLAG_BITS / 8] = {}, *out = NULL;
	size_t len;
	int ret;

	if (!flags_supported)
		return 0;
	mask = atomic_long_xchg(&pending, 0);
	if (!mask)
		return 0;
	put_unaligned_le64(mask, bits + L4H_FLAG_GUEST / 8);
	ret = attest_call_locked(L4H_ATTEST_ACT, bits, sizeof(bits), 0, &out, &len);
	kvfree(out);
	if (ret == -ENOSYS) {
		flags_supported = false;
		pr_warn_once("l4h-attest: host has no taint/seal operations\n");
		return 0;
	}
	if (ret)
		atomic_long_or(mask, &pending);
	return ret;
}

static void taint_work(struct work_struct *work)
{
	mutex_lock(&attest_lock);
	flush_taints();
	mutex_unlock(&attest_lock);
}

static int attest_call(u32 op, const u8 *in, size_t in_len, size_t blob_len, u8 **out, size_t *out_len)
{
	int ret;

	if (mutex_lock_killable(&attest_lock))
		return -EINTR;
	ret = flush_taints();
	if (!ret)
		ret = attest_call_locked(op, in, in_len, blob_len, out, out_len);
	mutex_unlock(&attest_lock);
	if (ret == -ENODEV && (READ_ONCE(page->state) & L4H_ATTEST_NO_REPORTS))
		no_reports();
	return ret;
}

static int attest_report(const u8 *data, size_t len, u8 **out, size_t *out_len)
{
	u8 d[L4H_ATTEST_DATA_SIZE] = {};

	memcpy(d, data, min_t(size_t, len, sizeof(d)));
	return attest_call(L4H_ATTEST_REPORT, d, sizeof(d), 0, out, out_len);
}

static int attest_evidence(u8 **out, size_t *out_len)
{
	return attest_call(L4H_ATTEST_EVIDENCE, NULL, 0, 0, out, out_len);
}

#if IS_ENABLED(CONFIG_TSM_REPORTS)
static int l4h_report_new(struct tsm_report *report, void *data)
{
	struct tsm_report_desc *desc = &report->desc;
	u8 *out, *aux;
	size_t len, aux_len;
	int ret;

	ret = attest_report(desc->inblob, desc->inblob_len, &out, &len);
	if (ret)
		return ret;
	ret = attest_evidence(&aux, &aux_len);
	if (ret) {
		kvfree(out);
		return ret;
	}
	report->outblob = out;
	report->outblob_len = len;
	report->auxblob = aux;
	report->auxblob_len = aux_len;
	return 0;
}

static bool l4h_report_attr_visible(int n)
{
	return n == TSM_REPORT_GENERATION || n == TSM_REPORT_PROVIDER;
}

static bool l4h_report_bin_attr_visible(int n)
{
	return n == TSM_REPORT_INBLOB || n == TSM_REPORT_OUTBLOB || n == TSM_REPORT_AUXBLOB;
}

static const struct tsm_report_ops l4h_tsm_ops = {
	.name = "l4h",
	.report_new = l4h_report_new,
	.report_attr_visible = l4h_report_attr_visible,
	.report_bin_attr_visible = l4h_report_bin_attr_visible,
};
#endif

/* Unregister outside attest_lock and the configfs callback: the latter
 * holds tsm's read lock. Registration is settled during probe. */
#if IS_ENABLED(CONFIG_TSM_REPORTS)
static bool tsm_registered;
#endif
static void unregister_tsm(struct work_struct *work)
{
#if IS_ENABLED(CONFIG_TSM_REPORTS)
	if (tsm_registered) {
		tsm_report_unregister(&l4h_tsm_ops);
		tsm_registered = false;
	}
#endif
}
static DECLARE_WORK(tsm_remover, unregister_tsm);
static void no_reports(void)
{
	schedule_work(&tsm_remover);
}

static ssize_t flags_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	u8 bits[L4H_FLAG_BITS / 8] = {}, *out;
	size_t len;
	unsigned int i, at = 0, offset = attr->attr.name[0] == 's' ? sizeof(bits) : 0;
	int ret = attest_call(L4H_ATTEST_ACT, bits, sizeof(bits), 0, &out, &len);

	if (ret)
		return ret;
	if (len != sizeof(struct l4h_attest_flags)) {
		kvfree(out);
		return -EIO;
	}
	for (i = 0; i < L4H_FLAG_BITS; i++)
		if (out[offset + i / 8] & BIT(i % 8))
			at += sysfs_emit_at(buf, at, "%s%u", at ? "," : "", i);
	at += sysfs_emit_at(buf, at, "\n");
	kvfree(out);
	return at;
}
static struct kobj_attribute taint_attr = __ATTR(taint, 0444, flags_show, NULL);
static struct kobj_attribute seal_attr = __ATTR(seal, 0444, flags_show, NULL);
static struct attribute *flags_attrs[] = { &taint_attr.attr, &seal_attr.attr, NULL };
static const struct attribute_group flags_group = { .name = "attest", .attrs = flags_attrs };

static long attest_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct l4h_attest_ioc c;
	u8 *in = NULL, *out = NULL;
	size_t in_len, len;
	long ret;

	if (cmd != L4H_ATTEST_IOC)
		return -ENOTTY;
	if (copy_from_user(&c, (void __user *)arg, sizeof(c)))
		return -EFAULT;
	switch (c.op) {
	case L4H_ATTEST_REPORT:
		in_len = L4H_ATTEST_DATA_SIZE;
		break;
	case L4H_ATTEST_ACTIVATE:
		in_len = (size_t)c.blob_len + c.secret_len;
		if (in_len > L4H_ATTEST_PAGE_DATA)
			return -EINVAL;
		break;
	case L4H_ATTEST_ACT:
		in_len = c.blob_len;
		if (c.secret_len || (in_len != L4H_FLAG_BITS / 8 && in_len != sizeof(struct l4h_attest_act)))
			return -EINVAL;
		break;
	case L4H_ATTEST_SEAL:
		in_len = c.blob_len;
		if (c.secret_len || in_len != L4H_FLAG_BITS / 8)
			return -EINVAL;
		break;
	case L4H_ATTEST_EVIDENCE:
		in_len = 0;
		break;
	default:
		return -EINVAL;
	}
	if (in_len) {
		in = memdup_user(u64_to_user_ptr(c.data), in_len);
		if (IS_ERR(in))
			return PTR_ERR(in);
	}
	/* Kernel events can only be recorded by the measured kernel. */
	if (c.op == L4H_ATTEST_ACT && memchr_inv(in, 0, L4H_FLAG_USER / 8)) {
		kfree(in);
		return -EPERM;
	}
	if (c.op == L4H_ATTEST_REPORT)
		ret = attest_report(in, in_len, &out, &len);
	else if (c.op == L4H_ATTEST_EVIDENCE)
		ret = attest_evidence(&out, &len);
	else
		ret = attest_call(c.op, in, in_len, c.blob_len, &out, &len);
	kfree(in);
	if (ret)
		return ret;
	if (len > c.out_len)
		ret = -ENOSPC;
	else if (copy_to_user(u64_to_user_ptr(c.out), out, len))
		ret = -EFAULT;
	c.out_len = len;
	if (ret != -EFAULT && copy_to_user((void __user *)arg, &c, sizeof(c)))
		ret = -EFAULT;
	kvfree(out);
	return ret;
}

static const struct file_operations attest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = attest_ioctl,
};

static struct miscdevice attest_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "l4h-attest",
	.fops = &attest_fops,
	.mode = 0600,
};

static int __init l4h_attest_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	unsigned int i;
	int irq, ret;
	struct kobject *kobj;
	u8 bits[L4H_FLAG_BITS / 8] = {}, *out = NULL;
	size_t len;

	for (i = 0; i < bi->nr_devices && i < L4H_MAX_DEVICES; i++) {
		if (bi->devices[i].type == L4H_DEV_ATTEST)
			break;
	}
	if (i == bi->nr_devices || i == L4H_MAX_DEVICES)
		return 0;
	page = (struct l4h_attest_page *)bi->devices[i].page_va;
	kick_cap = L4H_CPTR2(L4H_SLOT_DEV_CNODE, bi->devices[i].kick_slot);
	irq = l4h_event_irq(bi->devices[i].event);
	if (irq < 0)
		return irq;
	ret = request_irq(irq, attest_interrupt, 0, "l4h-attest", NULL);
	if (ret)
		return ret;
	seq = READ_ONCE(page->seq);
	/* Include taints from before the hook/driver was ready. The empty ACT
	 * also waits for TPM initialization, so NO_REPORTS is known at probe. */
	atomic_long_or(get_taint(), &pending);
	smp_store_release(&ready, true);
	ret = attest_call(L4H_ATTEST_ACT, bits, sizeof(bits), 0, &out, &len);
	kvfree(out);
	if (ret == -ENOSYS) {
		flags_supported = false;
		pr_warn_once("l4h-attest: host has no taint/seal operations\n");
	}
	ret = misc_register(&attest_dev);
	if (ret)
		return ret;
	kobj = kobject_create_and_add("l4h", kernel_kobj);
	if (kobj && sysfs_create_group(kobj, &flags_group))
		kobject_put(kobj);
#if IS_ENABLED(CONFIG_TSM_REPORTS)
	if (!(READ_ONCE(page->state) & (L4H_ATTEST_NO_REPORTS | L4H_ATTEST_FAILED))) {
		ret = tsm_report_register(&l4h_tsm_ops, NULL);
		if (ret)
			pr_warn("l4h-attest: no configfs-tsm reports: %d\n", ret);
		else
			tsm_registered = true;
	}
#endif
	pr_info("l4h-attest: %s\n", READ_ONCE(page->state) & L4H_ATTEST_NO_REPORTS ?
		"no TPM: flags only" : "host attestation available");
	return 0;
}
device_initcall(l4h_attest_init);
