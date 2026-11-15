/* SPDX-License-Identifier: GPL-2.0-only */
/* The actual guest writer, with only its vCPU and notification mocked. */
#include <l4h/abi.h>

struct l4h_vcpu {
	struct l4h_event_page *evt;
	int in_console;
};
static struct l4h_vcpu vcpu;
struct l4h_provider_context {
	unsigned int console_seq;
};
static struct l4h_provider_context context;
static unsigned int kicks;
static struct l4h_vcpu *l4h_this_vcpu(void) { return &vcpu; }
static struct l4h_provider_context *l4h_provider_state(void) { return &context; }
static void seL4_Signal(unsigned long cap) { (void)cap; kicks++; }

#include "console-writer.inc"

void console_test_select(struct l4h_event_page *page) { vcpu.evt = page; }
unsigned int console_test_kicks(void) { return kicks; }
void console_test_reset(void) { kicks = context.console_seq = vcpu.in_console = 0; }
/* Model a reserved but unpublished ticket, and the u32 wrap boundary. */
void console_test_sequence(unsigned int seq) { context.console_seq = seq; }
