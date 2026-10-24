/*
 * dom0 side of tests/run-gputest.sh: check that a screenshot (a binary
 * PPM from l4hctl screenshot) is image SEED (gpu-pattern.h) of WxH.
 * Usage: gpucheck FILE W H SEED
 */
#include <stdio.h>
#include <stdlib.h>
#include "gpu-pattern.h"

int main(int argc, char **argv)
{
	unsigned int w, h, max, seed, bad = 0;
	FILE *f;

	if (argc != 5 || !(f = fopen(argv[1], "rb"))) {
		printf("GPUCHECK: usage: gpucheck FILE W H SEED\n");
		return 2;
	}
	seed = atoi(argv[4]);
	if (fscanf(f, "P6 %u %u %u", &w, &h, &max) != 3 || fgetc(f) == EOF || max != 255) {
		printf("GPUCHECK: %s: not a binary PPM\n", argv[1]);
		return 1;
	}
	if (w != (unsigned)atoi(argv[2]) || h != (unsigned)atoi(argv[3])) {
		printf("GPUCHECK: %ux%u, expected %sx%s\n", w, h, argv[2], argv[3]);
		return 1;
	}
	for (unsigned int y = 0; y < h; y++)
		for (unsigned int x = 0; x < w; x++) {
			unsigned int c = gpu_pattern(x, y, seed);
			int r = fgetc(f), g = fgetc(f), b = fgetc(f);

			if (b == EOF) {
				printf("GPUCHECK: short image\n");
				return 1;
			}
			if ((unsigned)r != c >> 16 || (unsigned)g != (c >> 8 & 0xff) || (unsigned)b != (c & 0xff)) {
				if (!bad)
					printf("GPUCHECK: first difference at %u,%u: %02x%02x%02x, expected %06x\n",
					       x, y, r, g, b, c);
				bad++;
			}
		}
	printf("GPUCHECK: %u of %u pixels differ from image %u\n", bad, w * h, seed);
	return bad != 0;
}
