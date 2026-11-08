/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __L4H_DMA_H
#define __L4H_DMA_H

struct device;

/* The DMA device bound to the host's I/O pool (virtio-l4h), or NULL. */
struct device *l4h_io_pool_dev(void);

#endif
