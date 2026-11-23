/* SPDX-License-Identifier: GPL-2.0 */
/* Kept for external modules; the contract lives with the host/guest ABI. */
#include <l4h/guest.h>

/* The provider's L4H_PROVIDER_* features (l4h/provider.h). */
unsigned long l4h_provider_features(void);
/* For user contexts a module makes itself (struct l4h_uctx): a badge no
 * Linux thread's has, and the empty CSpace to configure their TCBs with,
 * which leaves them no capability to invoke. */
unsigned long l4h_uctx_alloc_badge(void);
unsigned long l4h_empty_cnode_cptr(void);
