/* SPDX-License-Identifier: GPL-2.0-only */
/* GRUB 2.12's exit ignores arguments and returns EFI_SUCCESS. Load the
 * standalone GRUB as a child image: L4H boot never returns, so any return
 * to this wrapper is a failed boot attempt. Return EFI_LOAD_ERROR after
 * GRUB has completed its normal cleanup and its image has been unloaded.
 *
 * Only the fixed UEFI x64 ABI fields used here are declared, avoiding a
 * dependency on a particular EFI SDK or distribution's GRUB headers.
 */
#include <stddef.h>
#include <stdint.h>

#define EFIAPI __attribute__((ms_abi))
#define EFI_LOAD_ERROR ((UINT64_C(1) << 63) | 1)
typedef uint64_t status_t;
struct guid { uint32_t a; uint16_t b, c; uint8_t d[8]; };
struct boot_services {
    uint8_t before_allocate_pool[64];
    status_t (EFIAPI *allocate_pool)(unsigned, size_t, void **);
    status_t (EFIAPI *free_pool)(void *);
    uint8_t before_handle_protocol[72];
    status_t (EFIAPI *handle_protocol)(void *, const struct guid *, void **);
    uint8_t before_load_image[40];
    status_t (EFIAPI *load_image)(uint8_t, void *, void *, const void *, size_t, void **);
    status_t (EFIAPI *start_image)(void *, size_t *, void **);
    void *exit;
    status_t (EFIAPI *unload_image)(void *);
};
struct system_table {
    uint8_t before_boot_services[96];
    struct boot_services *boot_services;
};
struct loaded_image {
    uint32_t revision;
    void *parent, *system_table, *device;
    const uint8_t *file_path;
};
_Static_assert(sizeof(void *) == 8, "x86_64-efi only");
_Static_assert(offsetof(struct boot_services, allocate_pool) == 64, "EFI AllocatePool");
_Static_assert(offsetof(struct boot_services, handle_protocol) == 152, "EFI HandleProtocol");
_Static_assert(offsetof(struct boot_services, load_image) == 200, "EFI LoadImage");
_Static_assert(offsetof(struct boot_services, start_image) == 208, "EFI StartImage");
_Static_assert(offsetof(struct boot_services, unload_image) == 224, "EFI UnloadImage");
_Static_assert(offsetof(struct system_table, boot_services) == 96, "EFI BootServices");
_Static_assert(offsetof(struct loaded_image, device) == 24, "EFI LoadedImage device");
_Static_assert(offsetof(struct loaded_image, file_path) == 32, "EFI LoadedImage path");

static const struct guid loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2, {0x8e, 0x3f, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} };
static const struct guid device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2, {0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} };
extern const uint8_t _binary_grub_efi_start[], _binary_grub_efi_end[];
/* Ensure the PE has a relocation directory, even with position-independent
 * code, so firmware can load it away from its preferred image base. */
static const void *const relocation __attribute__((used)) = _binary_grub_efi_start;

static size_t path_size(const uint8_t *path)
{
    for (size_t at = 0; at <= 65536 - 4;) {
        size_t len = path[at + 2] | (size_t)path[at + 3] << 8;
        if (len < 4 || len > 65536 - at) return 0;
        if (path[at] == 0x7f && path[at + 1] == 0xff) return len == 4 ? at + len : 0;
        at += len;
    }
    return 0;
}

status_t EFIAPI efi_main(void *image, struct system_table *st)
{
    struct boot_services *bs = st->boot_services;
    struct loaded_image *parent;
    void *path = NULL;
    if (bs->handle_protocol(image, &loaded_image_guid, (void **)&parent)) return EFI_LOAD_ERROR;
    if (parent->device && parent->file_path) {
        const uint8_t *device;
        if (bs->handle_protocol(parent->device, &device_path_guid, (void **)&device)) return EFI_LOAD_ERROR;
        size_t prefix = path_size(device), file = path_size(parent->file_path);
        if (!prefix || !file) return EFI_LOAD_ERROR;
        size_t size = prefix - 4 + file;
        if (bs->allocate_pool(2, size, &path)) return EFI_LOAD_ERROR; /* EfiLoaderData */
        for (size_t i = 0; i < prefix - 4; i++) ((uint8_t *)path)[i] = device[i];
        for (size_t i = 0; i < file; i++) ((uint8_t *)path)[prefix - 4 + i] = parent->file_path[i];
    }
    void *child = NULL;
    status_t status = bs->load_image(0, image, path, _binary_grub_efi_start,
                                    (size_t)((uintptr_t)_binary_grub_efi_end - (uintptr_t)_binary_grub_efi_start), &child);
    if (path) bs->free_pool(path);
    if (!status) status = bs->start_image(child, NULL, NULL);
    /* Exit automatically unloads applications. Also release an image
     * rejected by policy after loading, or unable to start. */
    if (status && child) bs->unload_image(child);
    return EFI_LOAD_ERROR;
}
