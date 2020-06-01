/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <uefi_utils.h>
#include <openssl/crypto.h>

#include "vars.h"
#include "lib.h"
#include "timer.h"
#include "security.h"
#include "android.h"
#include "options.h"
#include "power.h"
#include "trusty_interface.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"
#include "libtipc.h"
#include "rpmb_storage.h"
#include "security_efi.h"

#ifndef SIZE_2MB
#define SIZE_2MB                 0x200000U
#endif

#ifndef BASE_4GB
#define BASE_4GB                 0x100000000ULL
#endif

/* Trusty OS (TOS) definitions */
#define TOS_HEADER_MAGIC         0x6d6d76656967616d
#define TOS_HIGH_ADDR            0x3fffffff   /* Less than 1 GB */
#define TOS_STARTUP_VERSION_V2   0x02
#define TOS_STARTUP_VERSION_V3   0x03
#define SIPI_AP_HIGH_ADDR        0x100000  /* Less than 1MB */
#define SIPI_AP_MEMORY_LENGTH    0x1000  /* 4KB in length */
#define VMM_MEM_SIZE             0x01000000
#define TRUSTY_MEM_SIZE          0x01400000
#define TRUSTY_KEYBOX_KEY_SIZE   32
 /*
 * this is the startup structure containes the informations for ikgt and trusty
 * boot requirement(memory base/size, num_seed, seedlist, serials etc.)
 * and shared between ikgt and bootloader.
 */
struct tos_startup_info_v2 {
        /* version of TOS startup info structure, currently set it as 1 */
        UINT32 version;
        /* Size of this structure for mismatching check */
        UINT32 size;
        /* UEFI memory map address */
        UINT64 efi_memmap;
        /* UEFI memory map size */
        UINT32 efi_memmap_size;
        /* Reserved for AP's wake-up */
        UINT32 sipi_ap_wkup_addr;
        UINT64 trusty_mem_base;
        UINT64 vmm_mem_base;
        UINT32 trusty_mem_size;
        UINT32 vmm_mem_size;
        /*
        rpmb keys, Currently HMAC-SHA256 is used in RPMB spec and 256-bit (32byte) is enough.
        Hence only lower 32 bytes will be used for now for each entry. But keep higher 32 bytes
        for future extension. Note that, RPMB keys are already tied to storage device serial number.
        If there are multiple RPMB partitions, then we will get multiple available RPMB keys.
        And if rpmb_key[n][64] == 0, then the n-th RPMB key is unavailable (Either because of no such
        RPMB partition, or because OSloader doesn't want to share the n-th RPMB key with Trusty)
        */
        UINT8 rpmb_key[RPMB_MAX_PARTITION_NUMBER][RPMB_MAX_KEY_SIZE];
        /* Seed */
        UINT32 num_seeds;
        seed_info_t seed_list[BOOTLOADER_SEED_MAX_ENTRIES];
        /* Concatenation of mmc product name with a string representation of PSN */
        UINT8 serial[MMC_PROD_NAME_WITH_PSN_LEN];
} __attribute__((packed)) ;


struct tos_startup_info_v3 {
        /* version of TOS startup info structure, currently set it as 1 */
        UINT32 version;
        /* Size of this structure for mismatching check */
        UINT32 size;
        /* UEFI memory map address */
        UINT64 efi_memmap;
        /* UEFI memory map size */
        UINT32 efi_memmap_size;
        /* Reserved for AP's wake-up */
        UINT32 sipi_ap_wkup_addr;
        UINT64 trusty_mem_base;
        UINT64 vmm_mem_base;
        UINT32 trusty_mem_size;
        UINT32 vmm_mem_size;
        /*
        rpmb keys, Currently HMAC-SHA256 is used in RPMB spec and 256-bit (32byte) is enough.
        Hence only lower 32 bytes will be used for now for each entry. But keep higher 32 bytes
        for future extension. Note that, RPMB keys are already tied to storage device serial number.
        If there are multiple RPMB partitions, then we will get multiple available RPMB keys.
        And if rpmb_key[n][64] == 0, then the n-th RPMB key is unavailable (Either because of no such
        RPMB partition, or because OSloader doesn't want to share the n-th RPMB key with Trusty)
        */
        UINT8 rpmb_key[RPMB_MAX_PARTITION_NUMBER][RPMB_MAX_KEY_SIZE];
        /* Seed */
        UINT32 num_seeds;
        seed_info_t seed_list[BOOTLOADER_SEED_MAX_ENTRIES];
        /* Concatenation of mmc product name with a string representation of PSN */
        UINT8 serial[MMC_PROD_NAME_WITH_PSN_LEN];
        UINT8 attkb_key[TRUSTY_KEYBOX_KEY_SIZE];
        UINT64 efi_system_table;
} __attribute__((packed)) ;
/*
* this is the private image headrer of TOS image, which is packed at the begining of the
* image and shared between bootloader and ikgt, every boottime the bootloader
* is responsible to parse it and verify it.
* note: make sure the header address is 8-byte aligned
*/
struct tos_image_header {
        /* a 64bit magic value */
        UINT64 magic;
        /* version of the TOS header */
        UINT32 version;
        /* size of this structure */
        UINT32 size;
        /* TOS image version */
        UINT32 tos_version;
        /* entry offset */
        UINT32 entry_offset;
        /* Bootloader allocates a memory region with this specified size, and copies TOS image to
        *  this allocated space
        */
        UINT32 tos_ldr_size;
        UINT8 startup_struct_version;
        UINT8 reserved[3];
} __attribute__((packed)) ;

/* Get the TOS image header from the bootimage
 * Parameters:
 * bootimage - the address of android boot image that contains the tos image
 * Return values:
 * Returns the tos image header address or NULL
 */
static struct tos_image_header *get_tosimage_header(IN VOID *bootimage)
{
        struct boot_img_hdr *aosp_header;
        struct tos_image_header *tos_header;

        aosp_header = (struct boot_img_hdr *)bootimage;
        tos_header = (struct tos_image_header *)((UINT8 *)bootimage + aosp_header->page_size);
        if (tos_header->magic == TOS_HEADER_MAGIC)
                return tos_header;

        return NULL;
}

/* Get the VMM  base address and size */
static EFI_STATUS get_address_size_vmm(OUT UINT64 *vmm_mem_base, OUT UINT32 *vmm_size )
{
        EFI_STATUS ret;
        /* Need to rework the code for these values should be read from B-UINT regsiter */
        if (!vmm_mem_base || !vmm_size)
                return EFI_INVALID_PARAMETER;

        *vmm_mem_base = BASE_4GB; //allocate vmm's mem under 4G
        *vmm_size = VMM_MEM_SIZE;

        ret = allocate_pages(AllocateMaxAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(VMM_MEM_SIZE + SIZE_2MB), //allocate additional 2MB for alignment
                             vmm_mem_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for VMM base addess failed");
                return EFI_OUT_OF_RESOURCES;
        }

	*vmm_mem_base = ALIGN(*vmm_mem_base, SIZE_2MB);

        return EFI_SUCCESS;
}

/* Get the TRUSTY  base address and size */
static EFI_STATUS get_address_size_trusty(OUT UINT64 *trusty_mem_base, OUT UINT32 *trusty_size )
{
        EFI_STATUS ret;

        /* Need to rework the code for these values should be read from B-UINT regsiter */
        if (!trusty_mem_base || !trusty_size)
                return EFI_INVALID_PARAMETER;

        *trusty_mem_base = BASE_4GB; //allocate trusty's mem under 4G
        *trusty_size = TRUSTY_MEM_SIZE;

        ret = allocate_pages(AllocateMaxAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE + SIZE_2MB), //allocate additional 2MB for alignment
                             trusty_mem_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for Trusty base addess failed");
                return EFI_OUT_OF_RESOURCES;
        }

	*trusty_mem_base = ALIGN(*trusty_mem_base, SIZE_2MB);

        return EFI_SUCCESS;
}

/*
 * 1. Boot loader gets the tos image header address from kernel slot in
 *    android boot image (aosp_header + page_size)
 * 2. Boot loader should copy the to-be-loaded image to the
 *    address of ldr_mem_base, and then call into
 *    the entry of entry[32/64]_offset+ldr_mem_base.
 */
static EFI_STATUS start_tos_image(IN VOID *bootimage)
{
        EFI_STATUS ret;
        UINTN map_key, desc_size;
        UINT32 desc_ver, load_size, tos_ret;
        UINTN nr_entries;
        EFI_PHYSICAL_ADDRESS load_base = 0;
        EFI_PHYSICAL_ADDRESS startup_info_phy_addr = 0;
        EFI_PHYSICAL_ADDRESS sipi_ap_addr = 0;
        struct tos_startup_info_v2 *startup_info_v2 = NULL;
        struct tos_startup_info_v3 *startup_info_v3 = NULL;
        UINT8 *memory_map = NULL;
        UINT32 (*call_entry)(struct tos_startup_info_v2*);
        struct tos_image_header *tos_header;
        struct boot_img_hdr *boot_image_header;
        UINT64 temp_trusty_base_address, temp_vmm_base_address;
        UINT32 temp_trusty_address_size, temp_vmm_address_size;

        /* Find tos header in memory */
        debug(L"Reading TOS image header");
        if (!bootimage)
                return EFI_INVALID_PARAMETER;

        tos_header = get_tosimage_header(bootimage);
        if (!tos_header) {
                error(L"This partition does not contain a TOS image");
                return EFI_INVALID_PARAMETER;
        }

        boot_image_header = (struct boot_img_hdr *)bootimage;

        if (tos_header->size != sizeof(struct tos_image_header)){
                error(L"TOS header size mismatches in tos header");
                return EFI_INVALID_PARAMETER;
        }

        load_size = tos_header->tos_ldr_size;

        /* Allocate SIPI region */
        sipi_ap_addr = SIPI_AP_HIGH_ADDR;
        ret = allocate_pages(AllocateMaxAddress,
                             EfiRuntimeServicesData,
                             EFI_SIZE_TO_PAGES(SIPI_AP_MEMORY_LENGTH),
                             &sipi_ap_addr);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for TOS startup structure failed");
                goto cleanup;
        }

        /* Allocate loadtime at specified addresses */
        ret = allocate_pages(AllocateAnyPages,
                             EfiLoaderData,
                             EFI_SIZE_TO_PAGES(load_size),
                             &load_base);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for loadtime memory failed");
                goto cleanup;
        }

        /* Allocate space for startup structure */
        startup_info_phy_addr = TOS_HIGH_ADDR;
        ret = allocate_pages(AllocateMaxAddress,
                             EfiLoaderData,
                             (tos_header->startup_struct_version == TOS_STARTUP_VERSION_V3) ?
                             EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info_v3)):
                             EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info_v2)),
                             &startup_info_phy_addr);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Alloc memory for TOS startup structure failed");
                goto cleanup;
        }
        startup_info_v2 = (struct tos_startup_info_v2 *)(UINTN)startup_info_phy_addr;
        memset(startup_info_v2, 0, sizeof(*startup_info_v2));

        debug(L"TOS Loadtime memory address = 0x%x", load_base);

        /* Relocate to Loadtime region for TOS header + TOS */
        ret = memcpy_s((VOID *)(UINTN)load_base, load_size, (VOID *)tos_header,
                       boot_image_header->kernel_size);
        if (EFI_ERROR(ret)) {
                goto cleanup;
        }

        /* Get EFI memory map */
        memory_map = (CHAR8 *)LibMemoryMap(&nr_entries, &map_key, &desc_size, &desc_ver);
        if (!memory_map) {
                error(L"Get EFI memory map failed");
                goto cleanup;
        }

        /* Initialize startup struct */
        if (tos_header->startup_struct_version == TOS_STARTUP_VERSION_V3) {
               startup_info_v2->version = TOS_STARTUP_VERSION_V3;
               startup_info_v2->size = sizeof(struct tos_startup_info_v3);
        } else {
               startup_info_v2->version = TOS_STARTUP_VERSION_V2;
               startup_info_v2->size = sizeof(struct tos_startup_info_v2);
        }

        startup_info_v2->efi_memmap = (UINT64)(UINTN)memory_map;
        startup_info_v2->efi_memmap_size = desc_size * nr_entries;
        startup_info_v2->sipi_ap_wkup_addr = (UINT32)sipi_ap_addr;

        ret = get_seeds(&startup_info_v2->num_seeds, (VOID*)startup_info_v2->seed_list);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get trusty seed failed");
                goto cleanup;
        }

#ifdef RPMB_STORAGE
        ret = get_rpmb_keys(RPMB_MAX_PARTITION_NUMBER, startup_info_v2->rpmb_key);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get rpmb key list failed");
                goto cleanup;
        }
#endif

        ret = get_address_size_vmm(&temp_vmm_base_address, &temp_vmm_address_size);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get VMM address failed");
                goto cleanup;
        }
        startup_info_v2->vmm_mem_base = temp_vmm_base_address;
        startup_info_v2->vmm_mem_size = temp_vmm_address_size;
        ret = get_address_size_trusty(&temp_trusty_base_address, &temp_trusty_address_size);
        if (EFI_ERROR(ret)){
                efi_perror(ret, L"Get Trusty address failed");
                goto cleanup;
        }
        startup_info_v2->trusty_mem_base = temp_trusty_base_address;
        startup_info_v2->trusty_mem_size = temp_trusty_address_size;

        if (tos_header->startup_struct_version  == TOS_STARTUP_VERSION_V3) {
                startup_info_v3 = (struct tos_startup_info_v3 *)(UINTN)startup_info_phy_addr;
                startup_info_v3->efi_system_table = (UINT64)ST;
                memset(startup_info_v3->attkb_key, 0, sizeof(startup_info_v3->attkb_key));
                get_attkb_key(startup_info_v3->attkb_key);
        }
        /* Call TOS entry point */
        call_entry = (UINT32(*)(struct tos_startup_info_v2*))(
                        (UINTN)load_base + tos_header->entry_offset);
        debug(L"Call TOS loader entry_addr = 0x%x", call_entry);
        tos_ret = call_entry(startup_info_v2);
        if (tos_ret) {
                efi_perror(tos_ret, L"Load and start Trusty OS failed");
                ret = EFI_INVALID_PARAMETER;
                goto cleanup;
        }
        debug(L"TOS launch succeeded!");

cleanup:
        OPENSSL_cleanse(startup_info_v2->seed_list, sizeof(startup_info_v2->seed_list));
        OPENSSL_cleanse(startup_info_v2->rpmb_key, sizeof(startup_info_v2->rpmb_key));
        stop_bls_proto();
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Error has occurred!");
        }
        /* Free all the memory we allocated in this function */
        if (load_base)
                free_pages(load_base, EFI_SIZE_TO_PAGES(load_size));
        if (startup_info_phy_addr)
                free_pages(startup_info_phy_addr,
                (tos_header->startup_struct_version == TOS_STARTUP_VERSION_V3) ?
                EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info_v3)):
                EFI_SIZE_TO_PAGES(sizeof(struct tos_startup_info_v2)));
        if (memory_map)
                FreePool(memory_map);
        return ret;
}

EFI_STATUS set_trusty_param(__attribute__((unused))  IN VOID *param_data)
{
        return EFI_UNSUPPORTED;
}

EFI_STATUS start_trusty(VOID *tosimage)
{
        EFI_STATUS ret;
        if (!tosimage)
                return EFI_INVALID_PARAMETER;

        ret = start_tos_image(tosimage);
        stop_bls_proto();
        if (EFI_ERROR(ret)) {
            efi_perror(ret, L"Failed to launch tos image");
            return ret;
        }
        set_boottime_stamp(TM_LAUNCH_TRUSTY_DONE);
        // set up ql-ipc connection
//        trusty_ipc_init();
//        trusty_ipc_shutdown();

        return EFI_SUCCESS;
}
