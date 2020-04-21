/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
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

#ifndef _GPT_H_
#define _GPT_H_

#include <efi.h>
#include <efigpt.h>
#include "gpt_bin.h"
#include "storage.h"

#define MBR_CODE_SIZE	440
#define GPT_NAME_LEN	36

struct gpt_header {
	char signature[8];
	UINT32 revision;
	UINT32 size;
	UINT32 header_crc32;
	UINT32 reserved_zero;
	UINT64 my_lba;
	UINT64 alternate_lba;
	UINT64 first_usable_lba;
	UINT64 last_usable_lba;
	EFI_GUID disk_uuid;
	UINT64 entries_lba;
	UINT32 number_of_entries;
	UINT32 size_of_entry;
	UINT32 entries_crc32;
	/* Remainder of sector is reserved and should be 0 */
} __attribute__((packed));

struct gpt_partition {
	EFI_GUID type;
	EFI_GUID unique;
	UINT64 starting_lba;
	UINT64 ending_lba;
	union {
		struct {
			UINT16 reserved[3];
			UINT16 gpt_att;
		} __attribute__((packed)) fields;
		UINT64 whole;
	} attrs;
	UINT16 name[GPT_NAME_LEN]; /* UTF-16 encoded partition name */
	/* Remainder of entry is reserved and should be 0 */
} __attribute__((packed));

#define GPT_ENTRIES	128
#define GPT_ENTRY_SIZE	128
#define GPT_HEADER_SIZE (is_cur_storage_ufs()? 4096:512)

struct gpt_partition_interface {
	struct gpt_partition part;
	EFI_BLOCK_IO *bio;
	EFI_DISK_IO *dio;
	EFI_HANDLE handle;
};

EFI_STATUS gpt_get_partition_by_label(const CHAR16 *label, struct gpt_partition_interface *gpart, logical_unit_t log_unit);
EFI_STATUS gpt_list_partition(struct gpt_partition_interface **gpartlist, UINTN *part_count, logical_unit_t log_unit);
EFI_STATUS gpt_create(struct gpt_header *gh, UINTN gh_size,
		      UINT64 start_lba, UINTN part_count, struct gpt_bin_part *gbp, logical_unit_t log_unit);
void gpt_free_cache(void);
EFI_STATUS gpt_refresh(void);
EFI_STATUS gpt_get_root_disk(struct gpt_partition_interface *gpart, logical_unit_t log_unit);
EFI_STATUS gpt_get_partition_uuid(const CHAR16 *label, EFI_GUID *uuid, logical_unit_t log_unit);
EFI_STATUS gpt_get_partition_type(const CHAR16 *label, EFI_GUID *type, logical_unit_t log_unit);
EFI_STATUS gpt_swap_partition(const CHAR16 *label1, const CHAR16 *label2, logical_unit_t log_unit);
EFI_STATUS gpt_sync(void);
EFI_STATUS gpt_get_partition_handle(const CHAR16 *label, logical_unit_t log_unit, EFI_HANDLE *handle);
EFI_STATUS gpt_get_header(struct gpt_header **header, UINTN *size, logical_unit_t log_unit);
EFI_STATUS gpt_get_partitions(struct gpt_partition **partitions, UINTN *size, logical_unit_t log_unit);

#endif	/* _GPT_H_ */
