/* SPDX-License-Identifier: GPL-2.0 */
/* Bootstrap validation must work without any microkernel headers or calls. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <l4h/provider.h>

int main(int argc, char **argv)
{
	struct l4h_provider p = {
		.magic = L4H_PROVIDER_MAGIC, .version = L4H_PROVIDER_VERSION,
		.size = sizeof(p),
/* Fake code addresses exercise the validator without executing a provider. */
#define L4H_PROVIDER_OP(ret, name, args, call) \
	.name = (__typeof__(p.name))(L4H_PROVIDER_VA + sizeof(p)),
#define L4H_PROVIDER_NORETURN(name, args, call) L4H_PROVIDER_OP(void, name, args, call)
#include <l4h/provider-ops.h>
#undef L4H_PROVIDER_NORETURN
#undef L4H_PROVIDER_OP
	};
	l4h_u64 size = sizeof(p) + 4096;
	_Static_assert(sizeof(struct l4h_tls) == L4H_TLS_SIZE, "assembly TLS stride");
	_Static_assert(sizeof(struct l4h_tls_block) == 2 * L4H_TLS_SIZE, "assembly vCPU stride");
#ifdef __aarch64__
	_Static_assert(offsetof(struct l4h_tls, current) == 56, "arm64 current-task offset");
#else
	_Static_assert(offsetof(struct l4h_tls, current) == 24, "x86 current-task offset");
#endif
	assert(l4h_provider_valid(&p, size));
	assert(!l4h_provider_valid(&p, sizeof(p) - 1));
	assert(!l4h_provider_valid(&p, L4H_PROVIDER_MAX + 1));
	p.magic ^= 1;
	assert(!l4h_provider_valid(&p, size));
	p.magic ^= 1;
	p.version++;
	assert(!l4h_provider_valid(&p, size));
	p.version--;
	p.size = size + 1;
	assert(!l4h_provider_valid(&p, size));
	p.size = sizeof(p);
	p.l4h_page_map = 0;
	assert(!l4h_provider_valid(&p, size));
	p.l4h_page_map = (__typeof__(p.l4h_page_map))(L4H_PROVIDER_VA + sizeof(p) - 1);
	assert(!l4h_provider_valid(&p, size));
	p.l4h_page_map = (__typeof__(p.l4h_page_map))(L4H_PROVIDER_VA + size);
	assert(!l4h_provider_valid(&p, size));
	p.l4h_page_map = (__typeof__(p.l4h_page_map))(L4H_PROVIDER_VA + size - 1);
	assert(l4h_provider_valid(&p, size));
	for (int i = 1; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		assert(f && !fseek(f, 0, SEEK_END));
		long length = ftell(f);
		assert(length > 0 && (unsigned long)length <= L4H_PROVIDER_MAX);
		rewind(f);
		void *image = malloc(length);
		assert(image && fread(image, 1, length, f) == (unsigned long)length);
		assert(l4h_provider_valid(image, length));
		fclose(f);
		free(image);
	}
	puts("PROVIDER: bootstrap validation PASS");
}
