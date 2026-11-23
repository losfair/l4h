/* SPDX-License-Identifier: GPL-2.0 */
#define CTX_WORDS_ALL (sizeof(seL4_UserContext) / sizeof(seL4_Word))
#define CTX_WORDS_NOSEG CTX_WORDS_ALL
static void ctx_to_gp(const seL4_UserContext *c, unsigned long *gp, int nwords)
{
	gp[0] = c->x0;
	gp[1] = c->x1;
	gp[2] = c->x2;
	gp[3] = c->x3;
	gp[4] = c->x4;
	gp[5] = c->x5;
	gp[6] = c->x6;
	gp[7] = c->x7;
	gp[8] = c->x8;
	gp[9] = c->x9;
	gp[10] = c->x10;
	gp[11] = c->x11;
	gp[12] = c->x12;
	gp[13] = c->x13;
	gp[14] = c->x14;
	gp[15] = c->x15;
	gp[16] = c->x16;
	gp[17] = c->x17;
	gp[18] = c->x18;
	gp[19] = c->x19;
	gp[20] = c->x20;
	gp[21] = c->x21;
	gp[22] = c->x22;
	gp[23] = c->x23;
	gp[24] = c->x24;
	gp[25] = c->x25;
	gp[26] = c->x26;
	gp[27] = c->x27;
	gp[28] = c->x28;
	gp[29] = c->x29;
	gp[30] = c->x30;
	gp[31] = c->sp;
	gp[32] = c->pc;
	/* seL4 forces FIQ/SError masks internally; Linux exposes EL0 NZCV. */
	gp[33] = c->spsr & 0xf0000000UL;
	gp[HOST_TLS] = c->tpidr_el0;
}
static void gp_to_ctx(const unsigned long *gp, seL4_UserContext *c)
{
	c->x0 = gp[0];
	c->x1 = gp[1];
	c->x2 = gp[2];
	c->x3 = gp[3];
	c->x4 = gp[4];
	c->x5 = gp[5];
	c->x6 = gp[6];
	c->x7 = gp[7];
	c->x8 = gp[8];
	c->x9 = gp[9];
	c->x10 = gp[10];
	c->x11 = gp[11];
	c->x12 = gp[12];
	c->x13 = gp[13];
	c->x14 = gp[14];
	c->x15 = gp[15];
	c->x16 = gp[16];
	c->x17 = gp[17];
	c->x18 = gp[18];
	c->x19 = gp[19];
	c->x20 = gp[20];
	c->x21 = gp[21];
	c->x22 = gp[22];
	c->x23 = gp[23];
	c->x24 = gp[24];
	c->x25 = gp[25];
	c->x26 = gp[26];
	c->x27 = gp[27];
	c->x28 = gp[28];
	c->x29 = gp[29];
	c->x30 = gp[30];
	c->sp = gp[31];
	c->pc = gp[32];
	c->spsr = gp[33];
	c->tpidr_el0 = gp[HOST_TLS];
	c->tpidrro_el0 = 0;
}
/*
 * FL4 appends a trapping thread's x8-x30 and TPIDR_EL0 to its UnknownSyscall
 * message (FL4 #88), and a reply that long writes them back: a syscall then
 * needs neither TCB_ReadRegisters nor TCB_WriteRegisters, both of which run
 * under FL4's serial gate.  seL4 sends the standard 13 words.
 */
#define L4H_TRAP_X8	seL4_UnknownSyscall_Length	/* x8-x30, then TLS */
#define L4H_TRAP_TLS	(L4H_TRAP_X8 + 23)
#define L4H_TRAP_LENGTH	(L4H_TRAP_TLS + 1)

static void syscall_msg_to_gp(struct l4h_uctx *u, unsigned long *gp, seL4_Word length)
{
	/* ReadRegisters overwrites the fault IPC words. Save them first. */
	unsigned long nr = seL4_GetMR(seL4_UnknownSyscall_Syscall);
	unsigned long ip = seL4_GetMR(seL4_UnknownSyscall_FaultIP);

	if (length >= L4H_TRAP_LENGTH) {
		for (int i = 0; i < 8; i++)
			gp[i] = seL4_GetMR(seL4_UnknownSyscall_X0 + i);
		for (int i = 8; i <= 30; i++)
			gp[i] = seL4_GetMR(L4H_TRAP_X8 + i - 8);
		gp[31] = seL4_GetMR(seL4_UnknownSyscall_SP);
		gp[33] = seL4_GetMR(seL4_UnknownSyscall_SPSR) & 0xf0000000UL;
		gp[HOST_TLS] = seL4_GetMR(L4H_TRAP_TLS);
		/* Its reply can carry them too (gp_to_syscall_msg). */
		u->regs_dirty |= DIRTY_FULL_MSG;
	} else {
		/* x0-x7 only: x8-x30, PSTATE and TLS need a read. */
		u->regs_valid = 0;
		l4h_user_sync_regs(u, gp);
	}
	gp[HOST_ORIG_AX] = nr;
	gp[8] = nr;
	gp[HOST_IP] = ip + 4;
	gp[36] = gp[0]; /* original x0 for restarted syscalls */
}

/* The reply to a syscall stop that sets every register but TPIDRRO_EL0
 * (always 0 here), when the stop's message had them all (DIRTY_FULL_MSG). */
static int gp_to_syscall_msg(const struct l4h_uctx *u, const unsigned long *gp)
{
	if (!(u->regs_dirty & DIRTY_FULL_MSG))
		return 0;
	for (int i = 0; i < 8; i++)
		seL4_SetMR(seL4_UnknownSyscall_X0 + i, gp[i]);
	/* The thread restarts at FaultIP. */
	seL4_SetMR(seL4_UnknownSyscall_FaultIP, gp[HOST_IP]);
	seL4_SetMR(seL4_UnknownSyscall_SP, gp[31]);
	seL4_SetMR(seL4_UnknownSyscall_LR, gp[HOST_IP]);
	seL4_SetMR(seL4_UnknownSyscall_SPSR, gp[33]);
	seL4_SetMR(seL4_UnknownSyscall_Syscall, 0);
	for (int i = 8; i <= 30; i++)
		seL4_SetMR(L4H_TRAP_X8 + i - 8, gp[i]);
	seL4_SetMR(L4H_TRAP_TLS, gp[HOST_TLS]);
	return 1;
}
