/* SPDX-License-Identifier: GPL-2.0-only */
/* The production wrapper against EFI service fixtures, including a GRUB
 * child that returns success and a child that returns an error. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../boot/grub-efi-wrapper.c"

__asm__(".pushsection .rodata\n"
        ".global _binary_grub_efi_start, _binary_grub_efi_end\n"
        "_binary_grub_efi_start: .byte 1,2,3,4\n"
        "_binary_grub_efi_end:\n.popsection\n");

static const uint8_t device_path[] = { 1, 1, 4, 0, 0x7f, 0xff, 4, 0 };
static const uint8_t file_path[] = { 4, 4, 8, 0, 'x', 0, 0, 0, 0x7f, 0xff, 4, 0 };
static uint8_t path[16];
static struct loaded_image parent;
static unsigned allocations, frees, loads, starts, unloads;
static status_t load_status, start_status, protocol_status, allocation_status;

static status_t EFIAPI protocol(void *handle, const struct guid *guid, void **out)
{
    if (protocol_status) return protocol_status;
    if (handle == (void *)1) {
        assert(!memcmp(guid, &loaded_image_guid, sizeof(*guid)));
        *out = &parent;
    } else {
        assert(handle == (void *)2);
        assert(!memcmp(guid, &device_path_guid, sizeof(*guid)));
        *out = (void *)device_path;
    }
    return 0;
}

static status_t EFIAPI allocate(unsigned type, size_t len, void **out)
{
    assert(type == 2 && len == sizeof(path));
    allocations++;
    if (allocation_status) return allocation_status;
    *out = path;
    return 0;
}

static status_t EFIAPI release(void *buffer)
{
    assert(buffer == path && allocations == 1 && frees == 0);
    frees++;
    return 0;
}

static status_t EFIAPI load(uint8_t policy, void *image, void *full_path,
                           const void *payload, size_t size, void **child)
{
    assert(policy == 0 && image == (void *)1);
    assert(payload == _binary_grub_efi_start && size == 4);
    if (parent.device && parent.file_path) {
        assert(full_path == path);
        assert(!memcmp(path, device_path, 4));
        assert(!memcmp(path + 4, file_path, sizeof(file_path)));
    } else {
        assert(full_path == NULL);
    }
    loads++;
    *child = load_status == EFI_LOAD_ERROR ? NULL : (void *)3;
    return load_status;
}

static status_t EFIAPI start(void *child, size_t *exit_size, void **exit_data)
{
    assert(child == (void *)3 && exit_size == NULL && exit_data == NULL);
    assert(frees == allocations);
    starts++;
    return start_status;
}

static status_t EFIAPI unload(void *child)
{
    assert(child == (void *)3 && frees == allocations);
    unloads++;
    return 0;
}

int main(void)
{
    struct boot_services bs = { .allocate_pool = allocate, .free_pool = release,
        .handle_protocol = protocol, .load_image = load, .start_image = start, .unload_image = unload };
    struct system_table st = { .boot_services = &bs };
    for (unsigned mode = 0; mode < 7; mode++) {
        allocations = frees = loads = starts = unloads = 0;
        load_status = mode == 2 ? EFI_LOAD_ERROR : mode == 6 ? (UINT64_C(1) << 63) | 26 : 0;
        start_status = mode == 1 ? EFI_LOAD_ERROR : 0;
        protocol_status = mode == 4 ? EFI_LOAD_ERROR : 0;
        allocation_status = mode == 5 ? EFI_LOAD_ERROR : 0;
        parent = (struct loaded_image){ .device = (void *)2, .file_path = file_path };
        if (mode == 3) parent.file_path = NULL;
        assert(efi_main((void *)1, &st) == EFI_LOAD_ERROR);
        assert(starts == (mode < 2 || mode == 3));
        // EFI_SUCCESS from an application means firmware unloaded it.
        // A failed StartImage or policy-rejected LoadImage needs cleanup.
        assert(unloads == (mode == 1 || mode == 6));
        assert(frees == (mode != 3 && mode != 4 && mode != 5));
    }
    assert(path_size(device_path) == sizeof(device_path));
    const uint8_t bad[] = { 1, 1, 0, 0 };
    assert(path_size(bad) == 0);
    puts("EFI WRAPPER: PASS (status, device path, allocation and image cleanup)");
}
