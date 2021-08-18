/*
 * Copyright (c) 2017, Intel Corporation
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
#include <libtipc.h>
#include <hecisupport.h>
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
#include "libelfloader.h"
#include <uefi_utils.h>

#define TRUSTY_MEM_SIZE        0x1200000
#define BARRIER_MEM_SIZE       0x100000
#define TRUSTY_MEM_ALIGNED     (2*1024*1024)
#define TRUSTY_MEM_MIN_ADDRESS 0x04000000
#define TRUSTY_MEM_MAX_ADDRESS 0xFFFFFFFF
#define TRUSTY_BOOT_PARAM_VERSION 1

typedef struct trusty_boot_param {
	/* Size of this structure */
	uint32_t size_of_this_struct;
	uint32_t version;
	UINT64 trusty_mem_base;
        UINT32 trusty_mem_size;
} __attribute__((packed)) trusty_boot_param_t;

/* This is structure to proivde required data to Trusty when calling Trusty entry.
 * It is required to send the public key used to verify the android boot image,
 * the state of the device, the EFI memory map which is contained in the platform
 * info structure and the return address
 */
typedef struct tos_startup_params {
	/* Size of this structure */
	uint32_t size_of_this_struct;
	uint32_t version;

	/* Memory layout:
	 * barrier memory (1M bytes)
	 * TEE memory  (16M bytes)
	 * barrier memory (1M bytes)
	 */
	/* Start address of Tee memory,under 4G */
	uint32_t runtime_addr;

	/* Entry address of trusty */
	uint32_t entry_point;

	/* 16M */
	uint32_t runtime_size;
	/* 1MB */
	uint32_t barrier_size;
} __attribute__((packed)) trusty_startup_params_t;

/* Make sure the header address is 8-byte aligned */
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
        /* Trusty IMR base + seed_msg_dst_offset */
        UINT32 seed_msg_dst_offset;
};

static EFI_STATUS init_trusty_startup_params(trusty_startup_params_t *param, UINTN base,
	UINTN size, trusty_boot_param_t *boot_param)
{
	UINT64 entry_addr = 0;

	if (!param || !boot_param)
		return EFI_INVALID_PARAMETER;

	if (!relocate_elf_image(base, size, boot_param->trusty_mem_base + 0x1000 + BARRIER_MEM_SIZE,
				((boot_param->trusty_mem_size - 2*BARRIER_MEM_SIZE) << 10) - 0x1000, &entry_addr)) {
		error(L"relocate tos image failed");
		return EFI_INVALID_PARAMETER;
	}

	memset_s(param, sizeof(trusty_startup_params_t), 0, sizeof(trusty_startup_params_t));
	param->size_of_this_struct = sizeof(trusty_startup_params_t);
	param->runtime_addr = boot_param->trusty_mem_base + BARRIER_MEM_SIZE;
	param->entry_point = entry_addr;
	param->runtime_size = TRUSTY_MEM_SIZE - 2*BARRIER_MEM_SIZE;
	param->barrier_size = BARRIER_MEM_SIZE;
	param->version = TRUSTY_BOOT_PARAM_VERSION;

	return EFI_SUCCESS;
}

#define TRUSTY_VMCALL_SMC 0x74727500
static EFI_STATUS launch_trusty_os(trusty_startup_params_t *param)
{
	if (!param)
		return EFI_INVALID_PARAMETER;

	asm volatile(
		"vmcall; \n"
		: : "a"(TRUSTY_VMCALL_SMC), "D"((UINTN)param));

	return EFI_SUCCESS;
}

EFI_STATUS set_trusty_param(__attribute__((unused)) IN VOID *param_data)
{
	return EFI_UNSUPPORTED;
}

static EFI_STATUS search_usable_memory(OUT EFI_PHYSICAL_ADDRESS *lp_mem,
	IN UINT32 alloc_size, IN UINT32 align_size,
	IN EFI_PHYSICAL_ADDRESS min_addr,
	IN EFI_PHYSICAL_ADDRESS max_addr)
{
	EFI_MEMORY_DESCRIPTOR entries[64];
	EFI_MEMORY_DESCRIPTOR *cur;
	EFI_PHYSICAL_ADDRESS  start, end;
	EFI_STATUS ret;
	UINTN nr_entries;
	UINTN entry_sz;
	UINTN key;
	UINTN i;
	UINT32 descr_ver;

	if (lp_mem == NULL)
		return EFI_NOT_FOUND;

	nr_entries = sizeof(entries);
	ret = uefi_call_wrapper(BS->GetMemoryMap, 5, &nr_entries,
				(EFI_MEMORY_DESCRIPTOR *)entries,
				&key, &entry_sz, &descr_ver);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get the current memory map");
		return ret;
	}
	nr_entries /= entry_sz;
	sort_memory_map(entries, nr_entries, entry_sz);

	*lp_mem = 0;
	for (i = 0; i < nr_entries; i++) {
		cur = (EFI_MEMORY_DESCRIPTOR *)(entries + i);
		if (cur->Type != EfiConventionalMemory)
			continue;

		end = cur->PhysicalStart +
			cur->NumberOfPages * EFI_PAGE_SIZE;
		start = ALIGN(cur->PhysicalStart, align_size);

		if (min_addr != 0 && max_addr > min_addr)
		{
			if (start + alloc_size + align_size > max_addr)
				continue;
			if (end < min_addr + alloc_size + align_size)
				continue;

			if (start < min_addr)
				start = min_addr;

			if (end > max_addr)
				end = max_addr;
		}

		if (end - start < alloc_size + align_size)
			continue;

		*lp_mem = end - alloc_size;
		*lp_mem = ALIGN_DOWN(*lp_mem, align_size);
		break;
	}

	return *lp_mem ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}


EFI_STATUS start_trusty(VOID *tosimage)
{
	EFI_STATUS ret;
	const struct boot_img_hdr *header;
	UINTN load_base;
	trusty_startup_params_t trusty_startup_params;
	trusty_boot_param_t trusty_boot_params;
	EFI_PHYSICAL_ADDRESS Memory;

	if (!tosimage)
		return EFI_INVALID_PARAMETER;

	header = (const struct boot_img_hdr *)tosimage;
	load_base = (UINTN)(tosimage + header->page_size);

	ret = search_usable_memory(&Memory, TRUSTY_MEM_SIZE, TRUSTY_MEM_ALIGNED,
				TRUSTY_MEM_MIN_ADDRESS, TRUSTY_MEM_MAX_ADDRESS);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to allocate trusty pages");
		goto fail;
	}

	ret = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress,
				EfiRuntimeServicesData,  EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE), &Memory);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to allocate trusty pages");
		goto fail;
	}

	trusty_boot_params.trusty_mem_base = Memory;
	trusty_boot_params.trusty_mem_size = TRUSTY_MEM_SIZE;

	ret = init_trusty_startup_params(&trusty_startup_params, load_base, header->kernel_size, &trusty_boot_params);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init trusty startup params");
		goto fail;
	}

	ret = launch_trusty_os(&trusty_startup_params);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to launch trusty os");
		goto fail;
	}
	set_boottime_stamp(TM_LAUNCH_TRUSTY_DONE);
	trusty_ipc_init();
	trusty_ipc_shutdown();

	/* Since abl 1925_GP21, ABL will always send EOP before exit ABL */
	return ret;

fail:
	uefi_call_wrapper(BS->FreePages, 2, Memory, EFI_SIZE_TO_PAGES(TRUSTY_MEM_SIZE));

	return ret;
}
