// SPDX-License-Identifier: GPL-2.0
/*
 * The kernel's module tree (DESIGN.md §5.6): an EROFS image of its
 * /lib/modules, which the host maps read-only into every guest at
 * bootinfo.kmod_va.  It is the read-only block device /dev/l4hkmod, so
 *
 *	mount -t erofs -o ro /dev/l4hkmod /lib/modules
 *
 * gives /lib/modules/$(uname -r)/build the tree to build external modules
 * against. The default kernel builds all shipped drivers in.
 */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <l4h_sys.h>

static const u8 *image;
static u64 image_size;

static void kmod_submit_bio(struct bio *bio)
{
	u64 off = (u64)bio->bi_iter.bi_sector << SECTOR_SHIFT;
	struct bvec_iter iter;
	struct bio_vec bv;

	if (bio_op(bio) != REQ_OP_READ) {
		bio_io_error(bio);
		return;
	}
	bio_for_each_segment(bv, bio, iter) {
		if (off > image_size || bv.bv_len > image_size - off) {
			bio_io_error(bio);
			return;
		}
		memcpy_to_bvec(&bv, image + off);
		off += bv.bv_len;
	}
	bio_endio(bio);
}

static const struct block_device_operations kmod_fops = {
	.owner = THIS_MODULE,
	.submit_bio = kmod_submit_bio,
};

static int __init l4h_kmod_init(void)
{
	const struct l4h_bootinfo *bi = l4h_bootinfo;
	struct queue_limits lim = {
		.physical_block_size = PAGE_SIZE,
		.features = BLK_FEAT_SYNCHRONOUS | BLK_FEAT_NOWAIT,
	};
	struct gendisk *disk;
	int major, err;

	if (!bi->kmod_size)
		return 0;
	image = (const u8 *)(unsigned long)bi->kmod_va;
	image_size = bi->kmod_size;
	major = register_blkdev(0, "l4hkmod");
	if (major < 0)
		return major;
	disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_unregister;
	}
	disk->major = major;
	disk->first_minor = 0;
	disk->minors = 1;
	disk->fops = &kmod_fops;
	disk->flags |= GENHD_FL_NO_PART;
	strscpy(disk->disk_name, "l4hkmod");
	set_capacity(disk, image_size >> SECTOR_SHIFT);
	set_disk_ro(disk, true);
	err = add_disk(disk);
	if (err) {
		put_disk(disk);
		goto out_unregister;
	}
	pr_info("l4h-kmod: module tree, %llu KiB\n", image_size >> 10);
	return 0;

out_unregister:
	unregister_blkdev(major, "l4hkmod");
	return err;
}
device_initcall(l4h_kmod_init);
