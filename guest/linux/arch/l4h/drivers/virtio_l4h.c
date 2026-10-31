// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-l4h: virtio transport of the l4h guest.
 *
 * Devices are described in the l4h boot info.  Each has a shared device
 * page (struct l4h_virtio_regs, read directly), a kick notification and an
 * event line.  Register writes with side effects are committed with the
 * L4H_HC_DEV_WRITE hypercall to l4h-vmm.  No access traps.
 *
 * Devices never see guest RAM: every device is a child of one platform
 * device bound to the host's I/O pool (a restricted DMA pool, swiotlb), so
 * its rings come from the pool and its buffers bounce through it.  The
 * transport requires VIRTIO_F_ACCESS_PLATFORM, which makes virtio use the
 * DMA API, and l4h-vmm refuses drivers without it.
 */

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <uapi/linux/virtio_ids.h>
#include <irq_kern.h>
#include <l4h_sys.h>

struct virtio_l4h_device;
struct virtio_l4h_queue_irq {
	struct virtio_l4h_device *device;
	struct virtqueue *vq;
	unsigned int index;
	int irq;
	struct l4h_irq_route route;
	char name[32];
};

struct virtio_l4h_device {
	struct virtio_device vdev;
	unsigned int index;			/* boot info device index */
	struct l4h_virtio_regs *regs;
	void *config;
	unsigned long kick_cap;
	int irq;
	struct l4h_irq_route irq_route;
	struct virtio_l4h_queue_irq queue_irq[L4H_VIRTIO_QUEUE_IRQS];
};

#define to_vl4h(_vdev) container_of(_vdev, struct virtio_l4h_device, vdev)

/* The DMA device of every virtio-l4h device, bound to the I/O pool. */
static struct platform_device *vl4h_dma;

static unsigned long vl4h_op(struct virtio_l4h_device *d, unsigned long op, unsigned long a,
			     unsigned long b)
{
	unsigned long mrs[4] = { d->index, op, a, b };

	/* Make the register writes visible to the backend first. */
	smp_wmb();
	return l4h_hypercall(L4H_HC_DEV_WRITE, mrs, 4, 1);
}

static int vl4h_set_irq_cpu(void *data, unsigned int cpu)
{
	struct virtio_l4h_device *d = data;

	WRITE_ONCE(d->regs->irq_vcpu, cpu);
	return vl4h_op(d, L4H_VIRTIO_OP_IRQ_VCPU, 0, 0) ? -EINVAL : 0;
}

static int vl4h_set_queue_cpu(void *data, unsigned int cpu)
{
	struct virtio_l4h_queue_irq *q = data;
	struct virtio_l4h_device *d = q->device;

	WRITE_ONCE(d->regs->queue_irq_vcpu[q->index], cpu);
	return vl4h_op(d, L4H_VIRTIO_OP_IRQ_VCPU, q->index + 1, 0) ? -EINVAL : 0;
}

static irqreturn_t vl4h_queue_interrupt(int irq, void *data)
{
	struct virtio_l4h_queue_irq *q = data;

	return vring_interrupt(irq, q->vq);
}

static u64 vl4h_get_features(struct virtio_device *vdev)
{
	return READ_ONCE(to_vl4h(vdev)->regs->device_features);
}

static int vl4h_finalize_features(struct virtio_device *vdev)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	vring_transport_features(vdev);
	if (!__virtio_test_bit(vdev, VIRTIO_F_VERSION_1)) {
		dev_err(&vdev->dev, "virtio-l4h devices must offer VIRTIO_F_VERSION_1\n");
		return -EINVAL;
	}
	/* Device addresses must be I/O pool addresses: the DMA API. */
	if (!__virtio_test_bit(vdev, VIRTIO_F_ACCESS_PLATFORM)) {
		dev_err(&vdev->dev, "virtio-l4h devices must offer VIRTIO_F_ACCESS_PLATFORM\n");
		return -EINVAL;
	}
	WRITE_ONCE(d->regs->driver_features, vdev->features);
	vl4h_op(d, L4H_VIRTIO_OP_FEATURES, 0, 0);
	return 0;
}

static void vl4h_get(struct virtio_device *vdev, unsigned int offset, void *buf,
		     unsigned int len)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	if (offset + len > L4H_VIRTIO_CONFIG_SIZE)
		return;
	memcpy(buf, d->config + offset, len);
}

static void vl4h_set(struct virtio_device *vdev, unsigned int offset, const void *buf,
		     unsigned int len)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	if (offset + len > L4H_VIRTIO_CONFIG_SIZE)
		return;
	memcpy(d->config + offset, buf, len);
	vl4h_op(d, L4H_VIRTIO_OP_CONFIG, offset, len);
}

static u32 vl4h_generation(struct virtio_device *vdev)
{
	return READ_ONCE(to_vl4h(vdev)->regs->config_generation);
}

static u8 vl4h_get_status(struct virtio_device *vdev)
{
	return READ_ONCE(to_vl4h(vdev)->regs->status);
}

static void vl4h_set_status(struct virtio_device *vdev, u8 status)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	/* We should never be setting status to 0. */
	BUG_ON(status == 0);
	WRITE_ONCE(d->regs->status, status);
	vl4h_op(d, L4H_VIRTIO_OP_STATUS, 0, 0);
}

static void vl4h_reset(struct virtio_device *vdev)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	/* The backend completes the reset before the hypercall returns. */
	WRITE_ONCE(d->regs->status, 0);
	vl4h_op(d, L4H_VIRTIO_OP_STATUS, 0, 0);
}

static bool vl4h_notify(struct virtqueue *vq)
{
	struct virtio_l4h_device *d = to_vl4h(vq->vdev);

	/* Publish the ring update before setting the kick bit. */
	smp_mb();
	if (!(__atomic_fetch_or(&d->regs->kick, 1ull << vq->index, __ATOMIC_SEQ_CST) &
	      (1ull << vq->index)))
		l4h_signal(d->kick_cap);
	return true;
}

static irqreturn_t vl4h_interrupt(int irq, void *opaque)
{
	struct virtio_l4h_device *d = opaque;
	struct virtqueue *vq;
	unsigned int isr;
	irqreturn_t ret = IRQ_NONE;

	isr = __atomic_exchange_n(&d->regs->isr, 0, __ATOMIC_ACQ_REL);
	if (unlikely(isr & L4H_VIRTIO_ISR_CONFIG)) {
		virtio_config_changed(&d->vdev);
		ret = IRQ_HANDLED;
	}
	if (likely(isr & L4H_VIRTIO_ISR_VRING)) {
		virtio_device_for_each_vq(&d->vdev, vq)
			ret |= vring_interrupt(irq, vq);
	}
	return ret;
}

static void vl4h_del_vq(struct virtqueue *vq)
{
	struct virtio_l4h_device *d = to_vl4h(vq->vdev);
	struct l4h_virtq_regs *q = &d->regs->queues[vq->index];

	WRITE_ONCE(q->ready, 0);
	vl4h_op(d, L4H_VIRTIO_OP_QUEUE, vq->index, 0);
	if (vq->index < L4H_VIRTIO_QUEUE_IRQS) {
		struct virtio_l4h_queue_irq *irq = &d->queue_irq[vq->index];

		if (irq->irq >= 0) {
			irq_update_affinity_hint(irq->irq, NULL);
			free_irq(irq->irq, irq);
			irq_set_chip_data(irq->irq, NULL);
			irq->irq = -1;
			irq->vq = NULL;
		}
	}
	vring_del_virtqueue(vq);
}

static void vl4h_del_vqs(struct virtio_device *vdev)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);
	struct virtqueue *vq, *n;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list)
		vl4h_del_vq(vq);
	/* free_irq() warns about a hint left behind. */
	irq_update_affinity_hint(d->irq, NULL);
	free_irq(d->irq, d);
}

static void vl4h_synchronize_cbs(struct virtio_device *vdev)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);
	unsigned int q;

	synchronize_irq(d->irq);
	for (q = 0; q < L4H_VIRTIO_QUEUE_IRQS; q++)
		if (d->queue_irq[q].irq >= 0)
			synchronize_irq(d->queue_irq[q].irq);
}

static struct virtqueue *vl4h_setup_vq(struct virtio_device *vdev, unsigned int index,
				       void (*callback)(struct virtqueue *vq), const char *name,
				       bool ctx)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);
	struct l4h_virtq_regs *q;
	struct virtqueue *vq;
	unsigned int num, base;
	int err;

	if (!name)
		return NULL;
	if (index >= L4H_VIRTIO_MAX_QUEUES || index >= READ_ONCE(d->regs->num_queues))
		return ERR_PTR(-ENOENT);
	q = &d->regs->queues[index];
	if (READ_ONCE(q->ready))
		return ERR_PTR(-ENOENT);
	num = READ_ONCE(q->num_max);
	if (!num)
		return ERR_PTR(-ENOENT);

	vq = vring_create_virtqueue(index, num, PAGE_SIZE, vdev, true, true, ctx, vl4h_notify,
				    callback, name);
	if (!vq)
		return ERR_PTR(-ENOMEM);
	vq->num_max = num;

	WRITE_ONCE(q->num, virtqueue_get_vring_size(vq));
	WRITE_ONCE(q->desc, virtqueue_get_desc_addr(vq));
	WRITE_ONCE(q->driver, virtqueue_get_avail_addr(vq));
	WRITE_ONCE(q->device, virtqueue_get_used_addr(vq));
	WRITE_ONCE(q->ready, 1);
	if (vl4h_op(d, L4H_VIRTIO_OP_QUEUE, index, 0)) {
		/* The rings are not in the I/O pool, or the size is wrong. */
		dev_err(&vdev->dev, "queue %u refused by the host\n", index);
		WRITE_ONCE(q->ready, 0);
		vring_del_virtqueue(vq);
		return ERR_PTR(-EINVAL);
	}
	base = READ_ONCE(d->regs->queue_event_base);
	if (base && callback) {
		struct virtio_l4h_queue_irq *irq;
		unsigned int cpu;

		if (index >= L4H_VIRTIO_QUEUE_IRQS || base >= L4H_NR_EVENTS ||
		    index >= L4H_NR_EVENTS - base) {
			err = -EINVAL;
			goto fail;
		}
		irq = &d->queue_irq[index];
		irq->device = d;
		irq->vq = vq;
		irq->index = index;
		irq->irq = l4h_event_irq(base + index);
		if (irq->irq < 0) {
			err = irq->irq;
			goto fail;
		}
		irq->route.set_affinity = vl4h_set_queue_cpu;
		irq->route.data = irq;
		irq_set_chip_data(irq->irq, &irq->route);
		snprintf(irq->name, sizeof(irq->name), "%s-q%u", dev_name(&vdev->dev), index);
		err = request_irq(irq->irq, vl4h_queue_interrupt, 0, irq->name, irq);
		if (err) {
			irq_set_chip_data(irq->irq, NULL);
			irq->irq = -1;
			goto fail;
		}
		cpu = cpumask_nth(index % num_online_cpus(), cpu_online_mask);
		err = irq_set_affinity_and_hint(irq->irq, cpumask_of(cpu));
		if (err)
			goto fail;
	}
	return vq;
fail:
	vl4h_del_vq(vq);
	return ERR_PTR(err);
}

static int vl4h_find_vqs(struct virtio_device *vdev, unsigned int nvqs, struct virtqueue *vqs[],
			 struct virtqueue_info vqs_info[], struct irq_affinity *desc)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);
	int i, err, queue_idx = 0;

	err = request_irq(d->irq, vl4h_interrupt, IRQF_SHARED, dev_name(&vdev->dev), d);
	if (err)
		return err;

	for (i = 0; i < nvqs; ++i) {
		struct virtqueue_info *vqi = &vqs_info[i];

		if (!vqi->name) {
			vqs[i] = NULL;
			continue;
		}
		vqs[i] = vl4h_setup_vq(vdev, queue_idx++, vqi->callback, vqi->name, vqi->ctx);
		if (IS_ERR(vqs[i])) {
			vl4h_del_vqs(vdev);
			return PTR_ERR(vqs[i]);
		}
	}
	return 0;
}

static const char *vl4h_bus_name(struct virtio_device *vdev)
{
	return "l4h";
}

static int vl4h_vq_irq(struct virtio_l4h_device *d, unsigned int index)
{
	if (index < L4H_VIRTIO_QUEUE_IRQS && d->queue_irq[index].irq >= 0)
		return d->queue_irq[index].irq;
	return d->irq;
}

static int vl4h_set_vq_affinity(struct virtqueue *vq, const struct cpumask *mask)
{
	struct virtio_l4h_device *d = to_vl4h(vq->vdev);
	int irq = vl4h_vq_irq(d, vq->index);

	if (!mask)
		return irq_update_affinity_hint(irq, NULL);
	return irq_set_affinity_and_hint(irq, mask);
}

static const struct cpumask *vl4h_get_vq_affinity(struct virtio_device *vdev, int index)
{
	struct virtio_l4h_device *d = to_vl4h(vdev);

	if (index < 0)
		return NULL;
	return irq_get_affinity_mask(vl4h_vq_irq(d, index));
}

static const struct virtio_config_ops virtio_l4h_config_ops = {
	.get		= vl4h_get,
	.set		= vl4h_set,
	.generation	= vl4h_generation,
	.get_status	= vl4h_get_status,
	.set_status	= vl4h_set_status,
	.reset		= vl4h_reset,
	.find_vqs	= vl4h_find_vqs,
	.del_vqs	= vl4h_del_vqs,
	.get_features	= vl4h_get_features,
	.finalize_features = vl4h_finalize_features,
	.bus_name	= vl4h_bus_name,
	.set_vq_affinity = vl4h_set_vq_affinity,
	.get_vq_affinity = vl4h_get_vq_affinity,
	.synchronize_cbs = vl4h_synchronize_cbs,
};

static void vl4h_release_dev(struct device *dev)
{
	struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtio_l4h_device *d = to_vl4h(vdev);

	irq_set_chip_data(d->irq, NULL);
	kfree(d);
}

/* The parent of all virtio-l4h devices: their DMA goes through the pool. */
static int __init vl4h_dma_init(const struct l4h_bootinfo *bi)
{
	int err;

	if (!bi->io_pool_size) {
		pr_err("virtio-l4h: no I/O pool: no devices\n");
		return -ENODEV;
	}
	vl4h_dma = platform_device_register_simple("virtio-l4h", PLATFORM_DEVID_NONE, NULL, 0);
	if (IS_ERR(vl4h_dma))
		return PTR_ERR(vl4h_dma);
	err = dma_coerce_mask_and_coherent(&vl4h_dma->dev, DMA_BIT_MASK(64));
	if (!err)
		err = swiotlb_dev_init_pool(&vl4h_dma->dev, bi->io_pool_gpa, bi->io_pool_size);
	if (err) {
		pr_err("virtio-l4h: cannot use the I/O pool at %#llx: %d\n",
		       (unsigned long long)bi->io_pool_gpa, err);
		platform_device_unregister(vl4h_dma);
		vl4h_dma = NULL;
	}
	return err;
}

static int __init virtio_l4h_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	unsigned int i;

	if (vl4h_dma_init(bi))
		return 0;
	for (i = 0; i < bi->nr_devices && i < L4H_MAX_DEVICES; i++) {
		const struct l4h_dev_desc *desc = &bi->devices[i];
		struct virtio_l4h_device *d;
		int err, irq;

		if (desc->type != L4H_DEV_VIRTIO)
			continue;
		irq = l4h_event_irq(desc->event);
		if (irq < 0) {
			pr_err("virtio-l4h: device %u: bad event %u\n", i, desc->event);
			continue;
		}
		d = kzalloc(sizeof(*d), GFP_KERNEL);
		if (!d)
			return -ENOMEM;
		d->index = i;
		d->regs = (struct l4h_virtio_regs *)desc->page_va;
		d->config = (void *)desc->page_va + L4H_VIRTIO_CONFIG_OFF;
		d->kick_cap = L4H_CPTR2(L4H_SLOT_DEV_CNODE, desc->kick_slot);
		d->irq = irq;
		for (unsigned int q = 0; q < L4H_VIRTIO_QUEUE_IRQS; q++)
			d->queue_irq[q].irq = -1;
		if (READ_ONCE(d->regs->magic) != L4H_VIRTIO_MAGIC) {
			pr_err("virtio-l4h: device %u: bad magic\n", i);
			kfree(d);
			continue;
		}
		d->irq_route.set_affinity = vl4h_set_irq_cpu;
		d->irq_route.data = d;
		irq_set_chip_data(d->irq, &d->irq_route);
		d->vdev.id.device = READ_ONCE(d->regs->device_id);
		d->vdev.id.vendor = READ_ONCE(d->regs->vendor_id);
		d->vdev.config = &virtio_l4h_config_ops;
		d->vdev.dev.release = vl4h_release_dev;
		d->vdev.dev.parent = &vl4h_dma->dev;

		err = register_virtio_device(&d->vdev);
		if (err) {
			pr_err("virtio-l4h: device %u: register failed: %d\n", i, err);
			put_device(&d->vdev.dev);
			continue;
		}
		pr_info("virtio-l4h: device %u: virtio id %u, event %u\n", i, d->vdev.id.device,
			desc->event);
	}
	return 0;
}
device_initcall(virtio_l4h_init);
