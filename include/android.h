/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GUMMIBOOT_ANDROID_H

#include <openssl/x509.h>

#include "efi.h"
#include "efilib.h"
#ifdef HAL_AUTODETECT
#include "blobstore.h"
#endif
#include "targets.h"
#include "android_vb2.h"

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024


struct boot_img_hdr
{
    unsigned char magic[BOOT_MAGIC_SIZE];

    unsigned kernel_size;  /* size in bytes */
    unsigned kernel_addr;  /* physical load addr */

    unsigned ramdisk_size; /* size in bytes */
    unsigned ramdisk_addr; /* physical load addr */

    unsigned second_size;  /* size in bytes */
    unsigned second_addr;  /* physical load addr */

    unsigned tags_addr;    /* physical addr for kernel tags */
    unsigned page_size;    /* flash page size we assume */
    unsigned header_version;

    /* operating system version and security patch level; for
     * version "A.B.C" and patch level "Y-M-D":
     * ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
     * lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M)
     * os_version = ver << 11 | lvl */
    unsigned os_version;
    unsigned char name[BOOT_NAME_SIZE]; /* asciiz product name */

    unsigned char cmdline[BOOT_ARGS_SIZE];

    unsigned id[8]; /* timestamp / checksum / sha1 / etc */

    /* Supplemental command line data; kept here to maintain
     * binary compatibility with older versions of mkbootimg */
    unsigned char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];

    uint32_t recovery_acpio_size;   /* size of recovery acpio image */
    uint64_t recovery_acpio_offset; /* offset in boot image */
    uint32_t header_size;   /* size of boot image header in bytes */

    uint32_t acpi_size;   /* size of acpi image */
    uint64_t acpi_addr;   /* physical load addr */
} __attribute__((packed)) ;

/*
** +-----------------+
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages
** +-----------------+
** | ramdisk         | m pages
** +-----------------+
** | second stage    | o pages
** +-----------------+
** | recovery acpio  | p pages
** +-----------------+
** | acpi            | q pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
** p = (recovery_acpio_size + page_size - 1) / page_size
** q = (acpi_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/


#define VENDOR_BOOT_MAGIC "VNDRBOOT"
#define VENDOR_BOOT_MAGIC_SIZE 8
#define VENDOR_BOOT_ARGS_SIZE 2048
#define VENDOR_BOOT_NAME_SIZE 16

#define BOOT_IMG_HEADER_SIZE_V3 4096
#define BOOT_HEADER_V3          3

/* When the boot image header has a version of 3, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 *
 * Note that in version 3 of the boot image header, page size is fixed at 4096 bytes.
 *
 * The structure of the vendor boot image (introduced with version 3 and
 * required to be present when a v3 boot image is used) is as follows:
 *
 * +---------------------+
 * | vendor boot header  | o pages
 * +---------------------+
 * | vendor ramdisk      | p pages
 * +---------------------+
 * | dtb                 | q pages
 * +---------------------+

 * o = (2112 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, vendor ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisk at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. set up registers for kernel entry as required by your architecture
 * 6. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 */
struct boot_img_hdr_v3 {
    // Must be BOOT_MAGIC.
    uint8_t magic[BOOT_MAGIC_SIZE];

    uint32_t kernel_size; /* size in bytes */
    uint32_t ramdisk_size; /* size in bytes */

    // Operating system version and security patch level.
    // For version "A.B.C" and patch level "Y-M-D":
    //   (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
    //   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
    uint32_t os_version;

#if __cplusplus
    void SetOsVersion(unsigned major, unsigned minor, unsigned patch) {
        os_version &= ((1 << 11) - 1);
        os_version |= (((major & 0x7f) << 25) | ((minor & 0x7f) << 18) | ((patch & 0x7f) << 11));
    }

    void SetOsPatchLevel(unsigned year, unsigned month) {
        os_version &= ~((1 << 11) - 1);
        os_version |= (((year - 2000) & 0x7f) << 4) | ((month & 0xf) << 0);
    }
#endif

    uint32_t header_size;

    uint32_t reserved[4];

    // Version of the boot image header.
    uint32_t header_version;

    uint8_t cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

struct vendor_boot_img_hdr_v3 {
    // Must be VENDOR_BOOT_MAGIC.
    uint8_t magic[VENDOR_BOOT_MAGIC_SIZE];

    // Version of the vendor boot image header.
    uint32_t header_version;

    uint32_t page_size; /* flash page size we assume */

    uint32_t kernel_addr; /* physical load addr */
    uint32_t ramdisk_addr; /* physical load addr */

    uint32_t vendor_ramdisk_size; /* size in bytes */

    uint8_t cmdline[VENDOR_BOOT_ARGS_SIZE];

    uint32_t tags_addr; /* physical addr for kernel tags (if required) */
    uint8_t name[VENDOR_BOOT_NAME_SIZE]; /* asciiz product name */

    uint32_t header_size;

    uint32_t dtb_size; /* size in bytes for DTB image */
    uint64_t dtb_addr; /* physical load address for DTB image */
} __attribute__((packed));

#define VENDOR_RAMDISK_TYPE_NONE 0
#define VENDOR_RAMDISK_TYPE_PLATFORM 1
#define VENDOR_RAMDISK_TYPE_RECOVERY 2
#define VENDOR_RAMDISK_TYPE_DLKM 3
#define VENDOR_RAMDISK_NAME_SIZE 32
#define VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE 16

#define BOOT_IMG_HEADER_SIZE_V4 4096
#define BOOT_HEADER_V4          4

/* When the boot image header has a version of 4, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 * | boot signature      | g pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 * g = (signature_size + 4096 - 1) / 4096
 *
 * Note that in version 4 of the boot image header, page size is fixed at 4096
 * bytes.
 *
 * The structure of the vendor boot image version 4, which is required to be
 * present when a version 4 boot image is used, is as follows:
 *
 * +------------------------+
 * | vendor boot header     | o pages
 * +------------------------+
 * | vendor ramdisk section | p pages
 * +------------------------+
 * | dtb                    | q pages
 * +------------------------+
 * | vendor ramdisk table   | r pages
 * +------------------------+
 * | bootconfig             | s pages
 * +------------------------+
 *
 * o = (2128 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
 * s = (vendor_bootconfig_size + page_size - 1) / page_size
 *
 * Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
 * be included in the vendor boot image. The bootloader can select a subset of
 * ramdisks to load at runtime. To help the bootloader select the ramdisks, each
 * ramdisk is tagged with a type tag and a set of hardware identifiers
 * describing the board, soc or platform that this ramdisk is intended for.
 *
 * The vendor ramdisk section is consist of multiple ramdisk images concatenated
 * one after another, and vendor_ramdisk_size is the size of the section, which
 * is the total size of all the ramdisks included in the vendor boot image.
 *
 * The vendor ramdisk table holds the size, offset, type, name and hardware
 * identifiers of each ramdisk. The type field denotes the type of its content.
 * The vendor ramdisk names are unique. The hardware identifiers are specified
 * in the board_id field in each table entry. The board_id field is consist of a
 * vector of unsigned integer words, and the encoding scheme is defined by the
 * hardware vendor.
 *
 * For the different type of ramdisks, there are:
 *    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
 *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific bits, so
 *      the bootloader should always load these into memory.
 *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisks contain recovery resources, so
 *      the bootloader should load these when booting into recovery.
 *    - VENDOR_RAMDISK_TYPE_DLKM ramdisks contain dynamic loadable kernel
 *      modules.
 *
 * Version 4 of the vendor boot image also adds a bootconfig section to the end
 * of the image. This section contains Boot Configuration parameters known at
 * build time. The bootloader is responsible for placing this section directly
 * after the generic ramdisk, followed by the bootconfig trailer, before
 * entering the kernel.
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisks at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. load the bootconfig immediately following the generic ramdisk. Add
 *    additional bootconfig parameters followed by the bootconfig trailer.
 * 6. set up registers for kernel entry as required by your architecture
 * 7. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 */
struct boot_img_hdr_v4 {
    // Must be BOOT_MAGIC.
    uint8_t magic[BOOT_MAGIC_SIZE];

    uint32_t kernel_size; /* size in bytes */
    uint32_t ramdisk_size; /* size in bytes */

    // Operating system version and security patch level.
    // For version "A.B.C" and patch level "Y-M-D":
    //   (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
    //   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
    uint32_t os_version;

#if __cplusplus
    void SetOsVersion(unsigned major, unsigned minor, unsigned patch) {
        os_version &= ((1 << 11) - 1);
        os_version |= (((major & 0x7f) << 25) | ((minor & 0x7f) << 18) | ((patch & 0x7f) << 11));
    }

    void SetOsPatchLevel(unsigned year, unsigned month) {
        os_version &= ~((1 << 11) - 1);
        os_version |= (((year - 2000) & 0x7f) << 4) | ((month & 0xf) << 0);
    }
#endif

    uint32_t header_size;

    uint32_t reserved[4];

    // Version of the boot image header.
    uint32_t header_version;

    uint8_t cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];


    uint32_t signature_size; /* size in bytes */
} __attribute__((packed));

struct vendor_boot_img_hdr_v4 {
    // Must be VENDOR_BOOT_MAGIC.
    uint8_t magic[VENDOR_BOOT_MAGIC_SIZE];

    // Version of the vendor boot image header.
    uint32_t header_version;

    uint32_t page_size; /* flash page size we assume */

    uint32_t kernel_addr; /* physical load addr */
    uint32_t ramdisk_addr; /* physical load addr */

    uint32_t vendor_ramdisk_size; /* size in bytes */

    uint8_t cmdline[VENDOR_BOOT_ARGS_SIZE];

    uint32_t tags_addr; /* physical addr for kernel tags (if required) */
    uint8_t name[VENDOR_BOOT_NAME_SIZE]; /* asciiz product name */

    uint32_t header_size;

    uint32_t dtb_size; /* size in bytes for DTB image */
    uint64_t dtb_addr; /* physical load address for DTB image */

    uint32_t vendor_ramdisk_table_size; /* size in bytes for the vendor ramdisk table */
    uint32_t vendor_ramdisk_table_entry_num; /* number of entries in the vendor ramdisk table */
    uint32_t vendor_ramdisk_table_entry_size; /* size in bytes for a vendor ramdisk table entry */
    uint32_t bootconfig_size; /* size in bytes for the bootconfig section */
} __attribute__((packed));

struct vendor_ramdisk_table_entry_v4 {
    uint32_t ramdisk_size; /* size in bytes for the ramdisk image */
    uint32_t ramdisk_offset; /* offset to the ramdisk image in vendor ramdisk section */
    uint32_t ramdisk_type; /* type of the ramdisk */
    uint8_t ramdisk_name[VENDOR_RAMDISK_NAME_SIZE]; /* asciiz ramdisk name */

    // Hardware identifiers describing the board, soc or platform which this
    // ramdisk is intended to be loaded on.
    uint32_t board_id[VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];
} __attribute__((packed));

/* Bootloader Message (2-KiB)
 *
 * This structure describes the content of a block in flash
 * that is used for recovery and the bootloader to talk to
 * each other.
 *
 * The command field is updated by linux when it wants to
 * reboot into recovery or to update radio or bootloader firmware.
 * It is also updated by the bootloader when firmware update
 * is complete (to boot into recovery for any final cleanup)
 *
 * The status field is written by the bootloader after the
 * completion of an "update-radio" or "update-hboot" command.
 *
 * The recovery field is only written by linux and used
 * for the system to send a message to recovery or the
 * other way around.
 *
 * The stage field is written by packages which restart themselves
 * multiple times, so that the UI can reflect which invocation of the
 * package it is.  If the value is of the format "#/#" (eg, "1/3"),
 * the UI will add a simple indicator of that status.
 *
 * We used to have slot_suffix field for A/B boot control metadata in
 * this struct, which gets unintentionally cleared by recovery or
 * uncrypt. Move it into struct bootloader_message_ab to avoid the
 * issue.
 */
struct bootloader_message {
    char command[32];
    char status[32];
    char recovery[768];

    // The 'recovery' field used to be 1024 bytes.  It has only ever
    // been used to store the recovery command line, so 768 bytes
    // should be plenty.  We carve off the last 256 bytes to store the
    // stage string (for multistage packages), abl boot info (for ivi abl
    // platform usage) and possible future expansion.
    char stage[32];
    char abl[32];

    // The 'reserved' field used to be 192 bytes when it was initially
    // carved off from the 1024-byte recovery field. Bump it up to
    // 1152-byte so that the entire bootloader_message struct rounds up
    // to 2048-byte.
    char reserved[1152];
};

/*
 * We must be cautious when changing the bootloader_message struct size,
 * because A/B-specific fields may end up with different offsets.
 */
#if (__STDC_VERSION__ >= 201112L) || defined(__cplusplus)
_Static_assert(sizeof(struct bootloader_message) == 2048,
              "struct bootloader_message size changes, which may break A/B devices");
#endif

/*
 * The A/B-specific bootloader message structure (4-KiB).
 *
 * We separate A/B boot control metadata from the regular bootloader
 * message struct and keep it here. Everything that's A/B-specific
 * stays after struct bootloader_message, which should be managed by
 * the A/B-bootloader or boot control HAL.
 *
 * The slot_suffix field is used for A/B implementations where the
 * bootloader does not set the androidboot.ro.boot.slot_suffix kernel
 * commandline parameter. This is used by fs_mgr to mount /system and
 * other partitions with the slotselect flag set in fstab. A/B
 * implementations are free to use all 32 bytes and may store private
 * data past the first NUL-byte in this field. It is encouraged, but
 * not mandatory, to use 'struct bootloader_control' described below.
 */
struct bootloader_message_ab {
    struct bootloader_message message;
    char slot_suffix[32];

    // Round up the entire struct to 4096-byte.
    char reserved[2016];
};

/*
 * Be cautious about the struct size change, in case we put anything post
 * bootloader_message_ab struct (b/29159185).
 */
#if (__STDC_VERSION__ >= 201112L) || defined(__cplusplus)
_Static_assert(sizeof(struct bootloader_message_ab) == 4096,
              "struct bootloader_message_ab size changes");
#endif

#if (__STDC_VERSION__ >= 201112L || defined(__cplusplus))
_Static_assert(sizeof(struct bootloader_control) ==
               sizeof(((struct bootloader_message_ab *)0)->slot_suffix),
               "struct bootloader_control has wrong size");
#endif

/* Functions to load an Android boot image.
 * You can do this from a file, a partition GUID, or
 * from a RAM buffer */
EFI_STATUS android_image_start_buffer(
                IN EFI_HANDLE parent_image,
                IN VOID *bootimage,
                IN VOID *vendorbootimage,
                IN enum boot_target boot_target,
                IN UINT8 boot_state,
                IN EFI_GUID *swap,
                IN VBDATA *vb_data,
                IN const CHAR8 *abl_cmd_line);

EFI_STATUS setup_acpi_table(VOID *bootimage, enum boot_target target);

EFI_STATUS android_image_load_partition(
                IN const CHAR16 *label,
                OUT VOID **bootimage_p);

EFI_STATUS android_image_load_file(
                IN EFI_HANDLE device,
                IN CHAR16 *loader,
                IN BOOLEAN delete,
                OUT VOID **bootimage_p);

EFI_STATUS read_bcb(
                IN const CHAR16 *label,
                OUT struct bootloader_message *bcb);

EFI_STATUS write_bcb(
                IN const CHAR16 *label,
                IN struct bootloader_message *bcb);

/* Perform a security  RAM wipe */
EFI_STATUS android_clear_memory(void);

/* True if the current Android configuration use slot and does not
 * have a recovery partition.  When true, it means that the current
 * Android configuration requires to boot using the system partiton as
 * root filesystem.  It also means that the Recovery mode is provided
 * by the boot partition ramdisk.
 */
BOOLEAN recovery_in_boot_partition(void);

/* Sanity check the data and return a pointer to the header.
 * Return NULL if the sanity check fails */
struct boot_img_hdr *get_bootimage_header(VOID *bootimage_blob);

/* Return the size of a boot image, DOES NOT include any signature
 * block */
UINTN bootimage_size(struct boot_img_hdr *aosp_header);

/* Return the blob_size aligned on hdr->page_size.  */
UINT32 pagealign(struct boot_img_hdr *hdr, UINT32 blob_size);

#ifdef HAL_AUTODETECT
/* Get a particular blob type out of a boot image's blobstore, stored in
 * the 'second stage' area.
 *
 * Return values:
 * EFI_SUCCESS - Completed successfully. Do not free the blob pointer or
 * modify its contents
 * EFI_UNSUPPORTED - This boot image does not contain a blobstore
 * EFI_INVALID_PARAMETER - Boot image corrupted, or 2ndstage data isn't a
 * blobstore
 * EFI_NOT_FOUND - Specified type not found
 * EFI_OUT_OF_RESOURCES - Out of memory */
EFI_STATUS get_bootimage_blob(VOID *bootimage, enum blobtype btype, VOID **blob,
                              UINT32 *blobsize);
#endif

/* Get a pointer and size to the 2ndstage area of a boot image */
EFI_STATUS get_bootimage_2nd(VOID *bootimage, VOID **second, UINT32 *size);

EFI_STATUS prepend_command_line(CHAR16 **cmdline, CHAR16 *fmt, ...);

EFI_STATUS prepend_slot_command_line(CHAR16 **cmdline16,
                                     enum boot_target boot_target,
                                     VBDATA *vb_data);

UINTN get_vb_cmdlen(VBDATA *vb_data);

char *get_vb_cmdline(VBDATA *vb_data);
#endif

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */
