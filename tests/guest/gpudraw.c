/*
 * A guest of tests/run-gputest.sh: shows image 1 (gpu-pattern.h) on its
 * virtio-gpu, then on each line of console input the next step: "flip"
 * flips to image 2, "off" turns the display off.  Usage: gpudraw WxH,
 * the size the host gave the display, which must be the preferred mode.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <drm/drm.h>
#include <drm/drm_mode.h>
#include "gpu-pattern.h"

#define DIE(...) do { printf("GPUVM: FAIL "); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); exit(1); } while (0)

static uint32_t make_fb(int fd, uint32_t w, uint32_t h, unsigned int seed)
{
	struct drm_mode_create_dumb cd = { .width = w, .height = h, .bpp = 32 };
	struct drm_mode_fb_cmd fc = { .width = w, .height = h, .bpp = 32, .depth = 24 };
	struct drm_mode_map_dumb md = { 0 };
	uint32_t *p;

	if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd))
		DIE("CREATE_DUMB");
	fc.pitch = cd.pitch;
	fc.handle = md.handle = cd.handle;
	if (ioctl(fd, DRM_IOCTL_MODE_ADDFB, &fc) || ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md))
		DIE("ADDFB");
	p = mmap(NULL, cd.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, md.offset);
	if (p == MAP_FAILED)
		DIE("mmap");
	/* XRGB8888 */
	for (uint32_t y = 0; y < h; y++)
		for (uint32_t x = 0; x < w; x++)
			p[y * (cd.pitch / 4) + x] = gpu_pattern(x, y, seed);
	return fc.fb_id;
}

static void wait_line(const char *want)
{
	char line[64];

	while (fgets(line, sizeof(line), stdin))
		if (!strncmp(line, want, strlen(want)))
			return;
	DIE("console closed");
}

int main(int argc, char **argv)
{
	char name[32] = { 0 }, path[32];
	struct drm_version ver = { .name_len = sizeof(name) - 1, .name = name };
	struct drm_mode_card_res res = { 0 };
	uint32_t crtcs[4], conns[4], fbs[4], encs[4], w, h, fb1, fb2;
	struct drm_mode_get_connector conn = { 0 };
	struct drm_mode_modeinfo modes[64], *mode = NULL;
	struct drm_mode_crtc crtc = { 0 };
	struct drm_mode_crtc_page_flip pf = { 0 };
	struct drm_event_vblank ev;
	int fd = -1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2 || sscanf(argv[1], "%ux%u", &w, &h) != 2)
		DIE("usage: gpudraw WxH");
	for (int i = 0; i < 4 && fd < 0; i++) {
		snprintf(path, sizeof(path), "/dev/dri/card%d", i);
		fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd >= 0 && (ioctl(fd, DRM_IOCTL_VERSION, &ver) || strcmp(name, "virtio_gpu"))) {
			close(fd);
			fd = -1;
		}
	}
	if (fd < 0)
		DIE("no virtio_gpu card");
	if (ioctl(fd, DRM_IOCTL_SET_MASTER, 0) || ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res))
		DIE("GETRESOURCES");
	if (!res.count_crtcs || !res.count_connectors || res.count_crtcs > 4 || res.count_connectors > 4 ||
	    res.count_fbs > 4 || res.count_encoders > 4)
		DIE("%u CRTCs, %u connectors", res.count_crtcs, res.count_connectors);
	res.crtc_id_ptr = (uintptr_t)crtcs;
	res.connector_id_ptr = (uintptr_t)conns;
	res.fb_id_ptr = (uintptr_t)fbs;
	res.encoder_id_ptr = (uintptr_t)encs;
	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res))
		DIE("GETRESOURCES");
	conn.connector_id = conns[0];
	if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) || !conn.count_modes || conn.count_modes > 64)
		DIE("connector: %u modes", conn.count_modes);
	conn.modes_ptr = (uintptr_t)modes;
	conn.count_props = conn.count_encoders = 0;
	if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn))
		DIE("GETCONNECTOR");
	for (uint32_t i = 0; i < conn.count_modes; i++)
		if (modes[i].type & DRM_MODE_TYPE_PREFERRED)
			mode = &modes[i];
	if (!mode || mode->hdisplay != w || mode->vdisplay != h)
		DIE("preferred mode %ux%u, not %ux%u", mode ? mode->hdisplay : 0, mode ? mode->vdisplay : 0, w, h);

	fb1 = make_fb(fd, w, h, 1);
	fb2 = make_fb(fd, w, h, 2);
	crtc.crtc_id = crtcs[0];
	crtc.fb_id = fb1;
	crtc.set_connectors_ptr = (uintptr_t)&conn.connector_id;
	crtc.count_connectors = 1;
	crtc.mode = *mode;
	crtc.mode_valid = 1;
	if (ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &crtc))
		DIE("SETCRTC");
	printf("GPUVM: showing 1 %ux%u\n", w, h);

	wait_line("flip");
	pf.crtc_id = crtcs[0];
	pf.fb_id = fb2;
	pf.flags = DRM_MODE_PAGE_FLIP_EVENT;
	if (ioctl(fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) || read(fd, &ev, sizeof(ev)) != sizeof(ev) ||
	    ev.base.type != DRM_EVENT_FLIP_COMPLETE)
		DIE("PAGE_FLIP");
	printf("GPUVM: showing 2\n");

	wait_line("off");
	crtc = (struct drm_mode_crtc){ .crtc_id = crtcs[0] };
	if (ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &crtc))
		DIE("SETCRTC off");
	printf("GPUVM: off\n");
	for (;;)
		pause();
}
