/* The images of tests/run-gputest.sh: pixel (x, y) of image `seed`, as
 * 0xRRGGBB. */
static inline unsigned int gpu_pattern(unsigned int x, unsigned int y, unsigned int seed)
{
	return ((x * 3 + seed * 50) & 0xff) << 16 | ((y * 5 + seed * 90) & 0xff) << 8 |
	       ((x ^ y ^ (seed * 77)) & 0xff);
}
