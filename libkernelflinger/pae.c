/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
 *          Ioacara, Marius ValentinX <marius.valentinx.ioacara@intel.com>
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

#include <lib.h>
#include <uefi_utils.h>

#include "pae.h"

/*
 * This module uses the Physical Address Extension hardware support to
 * provide access to more than 4G memory regions from a 32 bits
 * address space.
 *
 * It sets up the page table hierarchy as follow:
 *
 *   linear address:
 *   |31                                                            0|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   \___/\________________/\________________________________________/
 *   2 |           | 9                         | 21
 *     |           |                           |
 *     |           |                           +---------+
 *     |           +--------------+                      |
 *     |                          |                      |   +-------+
 *     |  +----------------+      |   +---------------+  |   |   .   |
 *     |  | dir. pointer   |      |   |               |  |   |   .   |
 *     |  |  entry         |      |   |       .       |  |   |   .   |
 *     |  +----------------+      |   |       .       |  |   |       |
 *     |  | dir. pointer   |      |   |       .       |  |   |       |
 *     |  |  entry         |      |   |               |  |   +-------+
 *     |  +----------------+      |   +---------------+  +-->+-------+
 *     +->| dir. pointer   |      |   | 64 bits Page  |      |       |
 *        |  entry         |----+ |   | Descriptor    |--+   |       |
 *        +----------------+    | |   | entry         |  |   |       |
 *        | dir. pointer   |    | +-->+---------------+  |   |       |
 *        |  entry         |    |     |               |  |   |       |
 *  +---->+----------------+    |     |               |  |   |       |
 *  |                           |     |       .       |  |   |   .   |
 *  |                           |     |       .       |  |   |   .   |
 *  |                           |     |       .       |  |   |   .   |
 *  |                           |     |               |  |   |       |
 *  |   +-------------+         +---->+---------------+  |   |       |
 *  +---|    CR3      |                page directory    |   |       |
 *      +-------------+                                  |   |       |
 *                                                       |   |       |
 *                                                       +-->+-------+
 *                                                         2M memory page
 *
 * This module looks up for an unused memory region in the 32 bits
 * address space and map this region to more than 4G memory region.
 */

#define PAE_SUPPORT	(1 << 6)
#define UINT32_MAX	((UINT32)-1)
#define PAGE_BITS	(21) 			/* Number of bits of a page */
#define PAGE_SIZE	(1 << PAGE_BITS)
#define PAGE_ATTRIBUTES	(1 << 7 | 1 << 1 | 1)	/* 2MB page - read/write - present */
#define DIR_BITS	(32 - PAGE_BITS)
#define DIR_ATTRIBUTES	(1)			/* Directory is present */
#define MAX_MEMMAP_SZ	(128 * PAGE_SIZE)
#define MIN_MEMMAP_SZ	(32 * PAGE_SIZE)

static struct memmap_context {
	BOOLEAN initialized;

	/* 32 bits address space region used to map the DST memory
	 * region. */
	struct {
		UINT32 start;
		UINT32 end;
	} src;

	struct {
		EFI_PHYSICAL_ADDRESS start;
		EFI_PHYSICAL_ADDRESS end;
	} dst;

	UINT32 size;
} ctx;

/* Page table hierarchy. */
static volatile EFI_PHYSICAL_ADDRESS directory[1 << DIR_BITS]
	__attribute__((aligned(PAGE_SIZE)));
static volatile EFI_PHYSICAL_ADDRESS dir_ptr[1 << 2]
	__attribute__((aligned(0x20)));

static EFI_STATUS find_usable_memory_region(CHAR8 *entries, UINTN nr_entries,
					  UINTN entry_sz)
{
	EFI_MEMORY_DESCRIPTOR *cur;
	EFI_PHYSICAL_ADDRESS cur_end, start, end;
	UINT64 size;
	UINT32 type;
	UINTN i;

	ctx.src.start = 0;
	ctx.src.end = 0;
	for (i = 0; i < nr_entries; i++) {
		cur = (EFI_MEMORY_DESCRIPTOR *)(entries + entry_sz * i);
		if (cur->PhysicalStart > UINT32_MAX)
			continue;

		type = cur->Type;
		if (type != EfiLoaderCode && type != EfiBootServicesData
			&& type != EfiBootServicesCode && type != EfiLoaderData
			&& type != EfiConventionalMemory)
				continue;

		cur_end = cur->PhysicalStart +
			cur->NumberOfPages * EFI_PAGE_SIZE;
		end = ALIGN_DOWN(cur_end, PAGE_SIZE);
		start = ALIGN(cur->PhysicalStart, PAGE_SIZE);

		if (start >= end)
			continue;

		if (end - start < MIN_MEMMAP_SZ)
			continue;

		if (start < ctx.src.start)
			continue;

		size = min(end - start, (UINT64)MAX_MEMMAP_SZ);

		ctx.src.start = end - size;
		ctx.src.end = end;
		ctx.size = size;
	}

	return ctx.src.start ? EFI_SUCCESS : EFI_NOT_FOUND;
}

static void init_directory(void)
{
	EFI_PHYSICAL_ADDRESS cur;
	UINTN i, dir_size;

	dir_size = ARRAY_SIZE(directory) / ARRAY_SIZE(dir_ptr);
	for (i = 0; i < ARRAY_SIZE(dir_ptr); i++)
		dir_ptr[i] = (UINT32)&directory[i * dir_size] | DIR_ATTRIBUTES;

	for (i = 0, cur = 0; i < ARRAY_SIZE(directory); i++, cur += PAGE_SIZE)
		directory[i] = cur | PAGE_ATTRIBUTES;
}

static BOOLEAN has_above_4G_memory_region(CHAR8 *entries, UINTN nr_entries,
					  UINTN entry_sz)
{
	EFI_MEMORY_DESCRIPTOR *cur;
	EFI_PHYSICAL_ADDRESS end;
	UINTN i;

	for (i = 0; i < nr_entries; i++) {
		cur = (EFI_MEMORY_DESCRIPTOR *)(entries + entry_sz * i);
		end = cur->PhysicalStart + cur->NumberOfPages * EFI_PAGE_SIZE;
		if (end > UINT32_MAX)
			return TRUE;
	}

	return FALSE;
}

EFI_STATUS pae_init(CHAR8 *entries, UINTN nr_entries, UINTN entry_sz)
{
	EFI_STATUS ret;
	UINT32 reg[4];

	if (ctx.initialized)
		return EFI_ALREADY_STARTED;

	if (!has_above_4G_memory_region(entries, nr_entries, entry_sz))
		return EFI_SUCCESS;

	cpuid(1, reg);
	if (!(reg[3] & PAE_SUPPORT))
		return EFI_UNSUPPORTED;

	ret = find_usable_memory_region(entries, nr_entries, entry_sz);
	if (EFI_ERROR(ret))
		return ret;

	init_directory();

	/* Set bit 5 in CR4 to enable PAE. */
	asm volatile("movl %cr4, %eax\n"
		     "bts $5, %eax\n"
		     "movl %eax, %cr4\n");
	/* Load page directory pointers into CR3. */
	asm volatile("movl %%eax, %%cr3" :: "a" (&dir_ptr));
	/* Activate paging. */
	asm volatile("movl %cr0, %eax\n"
		     "orl $0x80000000, %eax\n"
		     "movl %eax, %cr0\n");

	ctx.initialized = TRUE;

	return EFI_SUCCESS;
}

static EFI_STATUS memmap(EFI_PHYSICAL_ADDRESS addr)
{
	UINT32 src;

	if (!ctx.initialized)
		return EFI_NOT_READY;

	addr &= ~(PAGE_SIZE - 1);
	ctx.dst.start = addr;
	for (src = ctx.src.start; src < ctx.src.end; src += PAGE_SIZE) {
		directory[src >> PAGE_BITS] = addr | PAGE_ATTRIBUTES;
		addr += PAGE_SIZE;
	}
	ctx.dst.end = addr;

	/* Reload page directory. */
	asm volatile("movl %%eax, %%cr3" :: "a" (&dir_ptr));

	return EFI_SUCCESS;
}

EFI_STATUS pae_map(EFI_PHYSICAL_ADDRESS addr, unsigned char **to, UINT64 *len)
{
	EFI_STATUS ret;

	if (addr <= UINT32_MAX) {
		*to = (unsigned char *)(UINT32)addr;
		if (*len > UINT32_MAX)
			*len = UINT32_MAX;
		if (addr > UINT32_MAX - *len)
			*len = UINT32_MAX - addr;

		if (addr + *len <= ctx.dst.start || addr >= ctx.dst.end)
			return EFI_SUCCESS;
	}

	ret = memmap(addr);
	if (EFI_ERROR(ret))
		return ret;

	*to = (unsigned char *)(UINT32)ctx.src.start + (addr - ctx.dst.start);
	*len = min(*len, ctx.size - (addr - ctx.dst.start));

	return EFI_SUCCESS;
}

EFI_STATUS pae_exit(void)
{
	if (!ctx.initialized)
		return EFI_SUCCESS;

	/* Disable paging. */
	asm volatile ("movl %cr0, %eax\n"
		      "andl $0x7fffffff, %eax\n"
		      "movl %eax, %cr0\n");
	/* Disable PAE. */
	asm volatile("movl %cr4, %eax\n"
		     "andl $0xffffffdf, %eax\n"
		     "movl %eax, %cr4\n");

	memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));

	return EFI_SUCCESS;
}
