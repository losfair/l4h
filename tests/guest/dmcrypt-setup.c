// SPDX-License-Identifier: GPL-2.0-only
// Minimal dm-crypt setup via DM ioctls (no dmsetup/cryptsetup in busybox).
// Usage: dmcrypt-setup DEV SECTORS HEXKEY128 [extra opt...]
// Creates dm device "bench" (/dev/dm-0) as aes-xts-plain64 with 4 KiB sectors, matching
// blkd's encrypted windows (tweak = 4 KiB unit number).
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static char buf[16384];
static struct dm_ioctl *hdr(const char *name) {
    memset(buf, 0, sizeof buf);
    struct dm_ioctl *io = (void *)buf;
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = 0;
    io->version[2] = 0;
    io->data_size = sizeof buf;
    io->data_start = sizeof *io;
    strcpy(io->name, name);
    return io;
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    int fd = open("/dev/mapper/control", O_RDWR);
    if (fd < 0) { perror("control"); return 1; }
    struct dm_ioctl *io = hdr("bench");
    if (ioctl(fd, DM_DEV_CREATE, io)) { perror("create"); return 1; }
    io = hdr("bench");
    io->target_count = 1;
    struct dm_target_spec *t = (void *)(buf + sizeof *io);
    t->sector_start = 0;
    t->length = strtoull(argv[2], 0, 0);
    strcpy(t->target_type, "crypt");
    char *p = (char *)(t + 1);
    int nopt = 1 + (argc - 4);
    int n = sprintf(p, "aes-xts-plain64 %s 0 %s 0 %d sector_size:4096", argv[3], argv[1], nopt);
    for (int i = 4; i < argc; i++) n += sprintf(p + n, " %s", argv[i]);
    t->next = (sizeof *t + n + 1 + 7) & ~7;
    if (ioctl(fd, DM_TABLE_LOAD, io)) { perror("load"); return 1; }
    io = hdr("bench");
    if (ioctl(fd, DM_DEV_SUSPEND, io)) { perror("resume"); return 1; }
    printf("dm-crypt: /dev/dm-%u opts=%d\n", (unsigned)(io->dev & 0xff), nopt);
    return 0;
}
