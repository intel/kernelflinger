/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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
 */

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <stdio.h>
#include <transport.h>
#include <version.h>

#include "lib.h"
#include "uefi_utils.h"
#include "protocol.h"
#include "flash.h"
#include "gpt.h"
#include "sparse.h"
#include "sparse_format.h"
#include "fastboot.h"
#include "fastboot_oem.h"
#include "text_parser.h"
#include "android.h"
#include "slot.h"
#include "security.h"
#include "security_interface.h"
#include "security_efi.h"
#ifdef USE_UI
#include "installer_ui.h"
#include "ui.h"
#endif
#ifdef USE_TPM
#include "tpm2_security.h"
#endif

static BOOLEAN last_cmd_succeeded;
static fastboot_handle fastboot_flash_cmd;
static fastboot_handle fastboot_erase_cmd;
static EFI_FILE_IO_INTERFACE *file_io_interface;
static data_callback_t fastboot_rx_cb, fastboot_tx_cb;
static BOOLEAN need_tx_cb;
static char *fastboot_cmd_buf;
static UINTN fastboot_cmd_buf_len;
static char command_buffer[256]; /* Large enough to fit long filename
				    on flash command.  */
static struct download_buffer *dl;

#define inst_perror(ret, x, ...) do { \
	fastboot_fail(x ": %r", ##__VA_ARGS__, ret); \
} while (0)

#define MAX_LABEL_LEN 64

static void flush_tx_buffer(void)
{
	while (need_tx_cb) {
		need_tx_cb = FALSE;
		fastboot_tx_cb(NULL, 0);
	}
}

static void do_erase(INTN argc, CHAR8 **argv)
{
	fastboot_erase_cmd(argc, argv);
	flush_tx_buffer();
}

static EFI_STATUS find_partition(CHAR8 *target)
{
	EFI_STATUS ret;
	CHAR16 *target16;
	struct gpt_partition_interface gparti;

	target16 = stra_to_str(target);
	if (!target16) {
		fastboot_fail("Failed to convert target to CHAR16");
		return EFI_OUT_OF_RESOURCES;
	}

	ret = gpt_get_partition_by_label(target16, &gparti, LOGICAL_UNIT_USER);
	FreePool(target16);

	return ret;
}

static CHAR8 *get_target(CHAR8 *target)
{
	EFI_STATUS ret;
	CHAR16 *target16;
	const CHAR16 *label16;
	static CHAR8 label[MAX_LABEL_LEN];
	CHAR8 *ret_target = NULL;

	ret = find_partition(target);
	if (!EFI_ERROR(ret))
		return target;
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND)
		return NULL;

	target16 = stra_to_str(target);
	if (!target16)
		return NULL;

	label16 = slot_label(target16);
	if (!label16) {
		ret_target = target;
		goto out;
	}

	if (StrLen(label16) + 1 > sizeof(label)) {
		fastboot_fail("Label name is too long");
		goto out;
	}

	ret = str_to_stra(label, label16, sizeof(label));
	if (!EFI_ERROR(ret))
		ret_target = label;

out:
	if (target16)
		FreePool(target16);

	return ret_target;
}

static void installer_erase(INTN argc, CHAR8 **argv)
{
	if (argc != 2) {
		fastboot_fail("Erase command requires exactly 2 arguments");
		return;
	}

	argv[1] = get_target(argv[1]);
	if (!argv[1])
		return;

	do_erase(argc, argv);
}

static void installer_flash_buffer(void *data, unsigned size,
				   INTN argc, CHAR8 **argv)
{
	void *data_save = dl->data;

	dl->data = data;
	dl->size = size;

	fastboot_flash_cmd(argc, argv);
	flush_tx_buffer();

	dl->data = data_save;
	dl->size = 0;
}

static EFI_STATUS read_file(EFI_FILE *file, UINTN size, void *data)
{
	EFI_STATUS ret;
	UINTN nsize = size;

	ret = uefi_call_wrapper(file->Read, 3, file, &nsize, data);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to read file");
		return ret;
	}
	if (size != nsize) {
		fastboot_fail("Failed to read %d bytes (only %d read)",
		    		  size, nsize);
		return EFI_INVALID_PARAMETER;
	}

	return ret;
}

typedef struct flash_buffer {
	struct sparse_header sph;
	struct chunk_header skip_ckh;
	union {
		struct chunk_header ckh;
		char data[1];
	} d;
	char ckh_data[1];
} __attribute__((__packed__)) flash_buffer_t;

/*when flash big chunks and in two image should add read_flags*/
static EFI_STATUS installer_flash_big_chunk_multiple(EFI_FILE **file, UINTN *read_flags,
	UINTN file_size, UINTN *remaining_data, flash_buffer_t *fb, UINTN argc, CHAR8 **argv)
{
	EFI_STATUS ret = EFI_INVALID_PARAMETER;
	UINTN payload_size, read_size, already_read, ckh_blks, data_size;
	const UINTN MAX_DATA_SIZE = dl->max_size - offsetof(flash_buffer_t, ckh_data);
	const UINTN MAX_BLKS = MAX_DATA_SIZE / fb->sph.blk_sz;
	const UINTN HEADER_SIZE = offsetof(flash_buffer_t, d);
	struct chunk_header *ckh;
	void *read_ptr;

	ckh = &fb->d.ckh;
	payload_size = ckh->total_sz - sizeof(*ckh);
	fb->sph.total_chunks = 2; /* skip and data chunks. */

	for (ckh_blks = ckh->chunk_sz; ckh_blks; ckh_blks -= ckh->chunk_sz) {
		ckh->chunk_sz = min(MAX_BLKS, ckh_blks);
		data_size = ckh->chunk_sz * fb->sph.blk_sz;
		ckh->total_sz = sizeof(*ckh) + data_size;
		fb->sph.total_blks = fb->skip_ckh.chunk_sz + ckh->chunk_sz;
		installer_flash_buffer(fb, ckh->total_sz + HEADER_SIZE, argc, argv);
		if (!last_cmd_succeeded)
			return EFI_INVALID_PARAMETER;

		payload_size -= data_size;
		if (!payload_size)
			break;

		/* Move the incomplete data from the end to the
		   beginning of the buffer. */
		read_ptr = fb->ckh_data;
		read_size = min(payload_size, MAX_DATA_SIZE);
		if (data_size < MAX_DATA_SIZE) {
			already_read = MAX_DATA_SIZE - data_size;
			ret = memcpy_s(read_ptr, MAX_DATA_SIZE, fb->d.data + ckh->total_sz, already_read);
			if (EFI_ERROR(ret))
				return ret;
			read_size -= already_read;
			read_ptr += already_read;
			if (read_size > file_size) {
				ret = read_file(file[*read_flags], file_size, read_ptr);
				if (EFI_ERROR(ret))
					return ret;
				read_size -= file_size;
				read_ptr += file_size;
				*remaining_data -= file_size;
				(*read_flags)++;
				}
		}
		ret = read_file(file[*read_flags], read_size, read_ptr);
		if (EFI_ERROR(ret))
			return ret;
		*remaining_data -= read_size;

		fb->skip_ckh.chunk_sz += ckh->chunk_sz;
	}

	if (payload_size)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}

/* This function splits a chunk too large to fit into a
   dl->max_size buffer into smaller chunks and flash them. */
static EFI_STATUS installer_flash_big_chunk(EFI_FILE *file, UINTN *remaining_data,
					    flash_buffer_t *fb, UINTN argc, CHAR8 **argv)
{
	EFI_STATUS ret = EFI_INVALID_PARAMETER;
	UINTN payload_size, read_size, already_read, ckh_blks, data_size;
	const UINTN MAX_DATA_SIZE = dl->max_size - offsetof(flash_buffer_t, ckh_data);
	const UINTN MAX_BLKS = MAX_DATA_SIZE / fb->sph.blk_sz;
	const UINTN HEADER_SIZE = offsetof(flash_buffer_t, d);
	struct chunk_header *ckh;
	void *read_ptr;

	ckh = &fb->d.ckh;
	payload_size = ckh->total_sz - sizeof(*ckh);
	fb->sph.total_chunks = 2; /* skip and data chunks. */

	for (ckh_blks = ckh->chunk_sz; ckh_blks; ckh_blks -= ckh->chunk_sz) {
		ckh->chunk_sz = min(MAX_BLKS, ckh_blks);
		data_size = ckh->chunk_sz * fb->sph.blk_sz;
		ckh->total_sz = sizeof(*ckh) + data_size;
		fb->sph.total_blks = fb->skip_ckh.chunk_sz + ckh->chunk_sz;

		installer_flash_buffer(fb, ckh->total_sz + HEADER_SIZE, argc, argv);
		if (!last_cmd_succeeded)
			return EFI_INVALID_PARAMETER;

		payload_size -= data_size;
		if (!payload_size)
			break;

		/* Move the incomplete data from the end to the
		   beginning of the buffer. */
		read_ptr = fb->ckh_data;
		read_size = min(payload_size, MAX_DATA_SIZE);
		if (data_size < MAX_DATA_SIZE) {
			already_read = MAX_DATA_SIZE - data_size;
			ret = memcpy_s(read_ptr, MAX_DATA_SIZE, fb->d.data + ckh->total_sz, already_read);
			if (EFI_ERROR(ret))
				return ret;
			read_size -= already_read;
			read_ptr += already_read;
		}

		ret = read_file(file, read_size, read_ptr);
		if (EFI_ERROR(ret))
			return ret;
		*remaining_data -= read_size;

		fb->skip_ckh.chunk_sz += ckh->chunk_sz;
	}

	if (payload_size)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}
/*this function splits a huge sparse file and put together the two image*/
static void installer_split_and_joint_flash(CHAR16 **filename,
						UINTN *size, UINTN num, UINTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	flash_buffer_t *fb;
	UINTN  read_flags = 0;
	struct sparse_header sph;
	struct chunk_header *ckh;
	UINTN read_size, flash_size, already_read = 0, remaining_data = 0;
	void *read_ptr;
	INTN nb_chunks;
	EFI_FILE *file[num];
	UINT32 blk_count;

	memset_s(file, sizeof(file), 0, sizeof(file));
	const UINTN HEADER_SIZE = offsetof(flash_buffer_t, d);
	const UINTN MAX_DATA_SIZE = dl->max_size - HEADER_SIZE;
	for (UINTN i = 0; i < num; i++) {
		remaining_data = remaining_data + size[i];
		ret = uefi_open_file(file_io_interface, filename[i], &file[i]);
		if (EFI_ERROR(ret)) {
			inst_perror(ret, "Failed to open %s file", filename[i]);
			return;
		}
	}

	ret = read_file(file[0], sizeof(sph), &sph);
	if (EFI_ERROR(ret))
		return;
	remaining_data -= sizeof(sph);
	size[read_flags] -=  sizeof(sph);
	if (!is_sparse_image((void *) &sph, sizeof(sph))) {
		fastboot_fail("sparse file expected");
		return;
	}
	fb = dl->data;
	ret = memcpy_s(&fb->sph, sizeof(fb->sph), &sph, sizeof(sph));
	if (EFI_ERROR(ret))
		return;
	/* Sparse skip chunk. */
	fb->skip_ckh.chunk_type = CHUNK_TYPE_DONT_CARE;
	fb->skip_ckh.total_sz = sizeof(fb->skip_ckh);
	nb_chunks = sph.total_chunks;
	read_size = MAX_DATA_SIZE;
	read_ptr = fb->d.data;
	blk_count = 0;
	while (nb_chunks > 0 && remaining_data > 0) {
		fb->sph.total_chunks = 1;
		fb->sph.total_blks = fb->skip_ckh.chunk_sz = blk_count;
		if (remaining_data < read_size)
			read_size = remaining_data;
		/* Read a new piece of the input sparse file. */
		ret = read_file(file[read_flags], read_size, read_ptr);
		if (EFI_ERROR(ret))
			goto exit;
		remaining_data -= read_size;
		size[read_flags] -= read_size;
		/* Process the loaded chunks to build the new header
		   and the skip chunk. */
		flash_size = HEADER_SIZE;
		ckh = &fb->d.ckh;
		while ((void *)ckh + sizeof(*ckh) <= read_ptr + read_size &&
				(void *)ckh + ckh->total_sz <= read_ptr + read_size) {
			if (nb_chunks == 0)
				goto exit;
			flash_size += ckh->total_sz;
			fb->sph.total_blks += ckh->chunk_sz;
			blk_count += ckh->chunk_sz;
			fb->sph.total_chunks++;
			nb_chunks--;
			ckh = (void *)ckh + ckh->total_sz;
		}
		/* chunk is too big to fit in the download buffer. */
		if (flash_size == HEADER_SIZE) {
			if (ckh->chunk_type != CHUNK_TYPE_RAW ||
					remaining_data < ckh->total_sz - MAX_DATA_SIZE) {
				fastboot_fail("Corrupted sparse file");
				goto exit;
			}

			blk_count += ckh->chunk_sz;
			nb_chunks--;

			ret = installer_flash_big_chunk_multiple(file, &read_flags,
						size[read_flags], &remaining_data, fb, argc, argv);
			if (EFI_ERROR(ret))
				goto exit;

			read_size = MAX_DATA_SIZE;
			read_ptr = fb->d.data;
			continue;
		}

		installer_flash_buffer(dl->data, flash_size, argc, argv);
		if (!last_cmd_succeeded)
			goto exit;
		/* Move the incomplete chunk from the end to the
		   beginning of the buffer. */

		if (dl->data + flash_size < read_ptr + read_size) {
			already_read = read_ptr + read_size - (void *)ckh;
			ret = memcpy_s(fb->d.data, MAX_DATA_SIZE, ckh, already_read);
			if (EFI_ERROR(ret))
				goto exit;
			read_size = MAX_DATA_SIZE - already_read;
			read_ptr = fb->d.data + already_read;

		} else {
			read_size = MAX_DATA_SIZE;
			read_ptr = fb->d.data;
		}
		if ((read_size > size[read_flags]) && (read_flags != (num - 1))) {
			ret = read_file(file[read_flags], size[read_flags], read_ptr);
			if (EFI_ERROR(ret))
				goto exit;
			ret = memcpy_s(fb->d.data+already_read, MAX_DATA_SIZE, read_ptr, size[read_flags]);
			if (EFI_ERROR(ret))
				goto exit;
			read_size = read_size - size[read_flags];
			remaining_data  -= size[read_flags];
			read_ptr = fb->d.data+already_read+size[read_flags];
			read_flags++;
			}
	}
exit:
	for (UINTN i = 0; i < num; i++)
		uefi_call_wrapper(file[i]->Close, 1, file[i]);
}
/* This function splits a huge sparse file into smaller ones and flash
   them. */
static void installer_split_and_flash(CHAR16 *filename, UINTN size,
				      UINTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	flash_buffer_t *fb;
	struct sparse_header sph;
	struct chunk_header *ckh;
	UINTN read_size, flash_size, already_read, remaining_data = size;
	void *read_ptr;
	INTN nb_chunks;
	EFI_FILE *file;
	UINT32 blk_count;
	const UINTN HEADER_SIZE = offsetof(flash_buffer_t, d);
	const UINTN MAX_DATA_SIZE = dl->max_size - HEADER_SIZE;

	ret = uefi_open_file(file_io_interface, filename, &file);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to open %s file", filename);
		return;
	}

	ret = read_file(file, sizeof(sph), &sph);
	if (EFI_ERROR(ret))
		return;
	remaining_data -= sizeof(sph);

	if (!is_sparse_image((void *) &sph, sizeof(sph))) {
		fastboot_fail("sparse file expected");
		return;
	}

	fb = dl->data;

	/* New sparse header. */
	ret = memcpy_s(&fb->sph, sizeof(fb->sph), &sph, sizeof(sph));
	if (EFI_ERROR(ret))
		return;

	/* Sparse skip chunk. */
	fb->skip_ckh.chunk_type = CHUNK_TYPE_DONT_CARE;
	fb->skip_ckh.total_sz = sizeof(fb->skip_ckh);

	nb_chunks = sph.total_chunks;
	read_size = MAX_DATA_SIZE;
	read_ptr = fb->d.data;
	blk_count = 0;

	while (nb_chunks > 0 && remaining_data > 0) {
		fb->sph.total_chunks = 1;
		fb->sph.total_blks = fb->skip_ckh.chunk_sz = blk_count;

		if (remaining_data < read_size)
			read_size = remaining_data;

		/* Read a new piece of the input sparse file. */
		ret = read_file(file, read_size, read_ptr);
		if (EFI_ERROR(ret))
			goto exit;
		remaining_data -= read_size;

		/* Process the loaded chunks to build the new header
		   and the skip chunk. */
		flash_size = HEADER_SIZE;
		ckh = &fb->d.ckh;
		while ((void *)ckh + sizeof(*ckh) <= read_ptr + read_size &&
				(void *)ckh + ckh->total_sz <= read_ptr + read_size) {
			if (nb_chunks == 0) {
				fastboot_fail("Corrupted sparse file: too many chunks");
				goto exit;
			}
			flash_size += ckh->total_sz;
			fb->sph.total_blks += ckh->chunk_sz;
			blk_count += ckh->chunk_sz;
			fb->sph.total_chunks++;
			nb_chunks--;
			ckh = (void *)ckh + ckh->total_sz;
		}

		/* chunk is too big to fit in the download buffer. */
		if (flash_size == HEADER_SIZE) {
			if (ckh->chunk_type != CHUNK_TYPE_RAW ||
					remaining_data < ckh->total_sz - MAX_DATA_SIZE) {
				fastboot_fail("Corrupted sparse file");
				goto exit;
			}

			blk_count += ckh->chunk_sz;
			nb_chunks--;

			ret = installer_flash_big_chunk(file, &remaining_data,
					fb, argc, argv);
			if (EFI_ERROR(ret))
				goto exit;

			read_size = MAX_DATA_SIZE;
			read_ptr = fb->d.data;
			continue;
		}

		installer_flash_buffer(dl->data, flash_size, argc, argv);
		if (!last_cmd_succeeded)
			goto exit;

		/* Move the incomplete chunk from the end to the
		   beginning of the buffer. */
		if (dl->data + flash_size < read_ptr + read_size) {
			already_read = read_ptr + read_size - (void *)ckh;
			ret = memcpy_s(fb->d.data, MAX_DATA_SIZE, ckh, already_read);
			if (EFI_ERROR(ret))
				goto exit;
			read_size = MAX_DATA_SIZE - already_read;
			read_ptr = fb->d.data + already_read;
		} else {
			read_size = MAX_DATA_SIZE;
			read_ptr = fb->d.data;
		}
	}

exit:
	uefi_call_wrapper(file->Close, 1, file);
}

static void installer_flash_cmd(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *filename;
	INTN num = argc - 2;
	CHAR16 *numname[num];
	void *data;
	UINTN size;
	UINTN numsize[num];
	if (argc < 3) {
		fastboot_fail("Flash command requires exactly more then 3 arguments");
		return;
	}

	for (int i = 0; i <  num; i++)
		numname[i] = NULL;

	if (argc > 3) {
		argc = 2;
		for (int i = 0; i <  num; i++) {
			numname[i] = stra_to_str(argv[i+2]);
			if (!numname[i]) {
				fastboot_fail("Failed to convert CHAR8 numname to CHAR16");
				return;
			}
			ret = uefi_get_file_size(file_io_interface, numname[i], &numsize[i]);
			if (EFI_ERROR(ret)) {
				inst_perror(ret, "Failed to get %s file size", numname[i]);
				goto exit;
			}
		}
		if (get_current_state() == LOCKED) {
			error(L"Installer: Flash %a is prohibited in %a state.", argv[1],
					get_current_state_string());
			fastboot_fail("Installer: Prohibited command in %a state.",
					get_current_state_string());
			return;
		}
		argv[1] = get_target(argv[1]);
		if (!argv[1])
			goto exit;

		ret = find_partition(argv[1]);
		switch (ret) {
		case EFI_SUCCESS:
			do_erase(argc, argv);
			if (!last_cmd_succeeded)
				goto exit;
			break;
		case EFI_NOT_FOUND:
			break;
		default:
			inst_perror(ret, "Failed to get partition information");
			goto exit;
		}

		installer_split_and_joint_flash(numname, numsize, num, argc, argv);
	} else {
		/* The fastboot flash command does not want the file parameter. */
		argc--;

		filename = stra_to_str(argv[2]);
		if (!filename) {
			fastboot_fail("Failed to convert CHAR8 filename to CHAR16");
			return;
		}
		if (get_current_state() == LOCKED) {
			error(L"Installer: Flash %a is prohibited in %a state.", argv[1],
				get_current_state_string());
			fastboot_fail("Installer: Prohibited command in %a state.",
				get_current_state_string());
			return;
		}
		ret = uefi_get_file_size(file_io_interface, filename, &size);
		if (EFI_ERROR(ret)) {
			inst_perror(ret, "Failed to get %s file size", filename);
			goto exit;
		}

		argv[1] = get_target(argv[1]);
		if (!argv[1])
			goto exit;

		ret = find_partition(argv[1]);
		switch (ret) {
		case EFI_SUCCESS:
			do_erase(argc, argv);
			if (!last_cmd_succeeded)
				goto exit;
			break;
		case EFI_NOT_FOUND:
			break;
		default:
			inst_perror(ret, "Failed to get partition information");
			goto exit;
		}

		if (size > dl->max_size) {
			installer_split_and_flash(filename, size, argc, argv);
			goto exit;
		}

		ret = uefi_read_file(file_io_interface, filename, &data, &size);
		if (EFI_ERROR(ret)) {
			inst_perror(ret, "Unable to read file %s", filename);
			goto exit;
		}

		installer_flash_buffer(data, size, argc, argv);
		FreePool(data);
	}
exit:
	if (num == 1) {
		FreePool(filename);
	} else {
		for (INTN i = 0; i < num; i++)
			if (numname[i])
				FreePool(numname[i]);
	}
}

#define SIZE_OF_FILENAME (label_length + 5)

static CHAR16 *get_format_image_filename(CHAR8 *label)
{
	EFI_STATUS ret;
	CHAR8 *filename;
	CHAR16 *filename16;
	UINTN label_length;

	if (!strcmp(label, (CHAR8 *)"data"))
		label = (CHAR8 *)"userdata";

	label_length = strlena(label);
	filename = AllocateZeroPool(SIZE_OF_FILENAME);
	if (!filename) {
		fastboot_fail("Unable to allocate CHAR8 filename buffer");
		return NULL;
	}
	ret = memcpy_s(filename, SIZE_OF_FILENAME, label, label_length);
	if (EFI_ERROR(ret)) {
		filename16 = NULL;
		goto out;
	}
	ret = memcpy_s(filename + label_length, SIZE_OF_FILENAME - label_length, ".img", 4);
	if (EFI_ERROR(ret)) {
		filename16 = NULL;
		goto out;
	}
	filename16 = stra_to_str(filename);
	if (!filename16)
		fastboot_fail("Unable to allocate CHAR16 filename buffer");

out:
	FreePool(filename);
	return filename16;
}

/* Simulate the fastboot host format command:
   1. get a filesystem image from a file;
   2. erase the partition;
   3. flash the filesystem image; */
static void installer_format(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	void *data = NULL;
	UINTN size;
	CHAR16 *filename;

	if (argc != 2 && argc != 3) {
		fastboot_fail("Format command requires 2 or 3 arguments");
		return;
	}

	filename = get_format_image_filename(argv[argc - 1]);
	if (!filename)
		return;

	ret = uefi_read_file(file_io_interface, filename, &data, &size);
	if (ret == EFI_NOT_FOUND && !StrCmp(L"userdata.img", filename)) {
		fastboot_info("userdata.img is missing, cannot format %a", argv[1]);
		fastboot_info("Android fs_mgr will manage this");
	} else if (EFI_ERROR(ret)) {
		inst_perror(ret, "Unable to read file %s", filename);
		goto free_filename;
	}

	argv[1] = get_target(argv[argc - 1]);
	if (!argv[1])
		goto free_data;

	argc = 2;
	do_erase(argc, argv);
	if (!last_cmd_succeeded)
		goto free_data;

	if (data)
		installer_flash_buffer(data, size, argc, argv);

free_data:
	FreePool(data);
free_filename:
	FreePool(filename);
}

static void installer_boot(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	VOID *bootimage;
	UINTN size;
	CHAR16 *filename;

	if (argc != 2) {
		fastboot_fail("boot command takes one parameter");
		return;
	}

	filename = stra_to_str((CHAR8 *)argv[1]);
	if (!filename) {
		fastboot_fail("Failed to convert filename to CHAR16");
		return;
	}

	ret = uefi_read_file(file_io_interface, filename, &bootimage, &size);
	FreePool(filename);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to read %a file", argv[1]);
		return;
	}

	ret = android_image_start_buffer(g_parent_image, bootimage, NULL,
					NORMAL_BOOT, BOOT_STATE_ORANGE, NULL,
					NULL, NULL);
	if (EFI_ERROR(ret))
		inst_perror(ret, "Failed to start %s image", filename);
	else
		fastboot_okay("");
}

static struct command {
	BOOLEAN optional;
	char *cmd;
} *commands;
static UINTN command_nb;
static UINTN current_command;

static void free_commands(void)
{
	UINTN i;

	if (!commands)
		return;

	for (i = 0; i < command_nb; i++)
		if (commands[i].cmd)
			FreePool(commands[i].cmd);

	FreePool(commands);
	commands = NULL;
	command_nb = 0;
	current_command = 0;
}

static EFI_STATUS create_new_command(struct command *command, char *str)
{
	char *cmd = str;

	command->optional = FALSE;

	if (*str == '[') {
		str++;
		cmd = (char *)strchr((CHAR8 *)str, ']');
		if (!cmd)
			return EFI_INVALID_PARAMETER;
		*cmd++ = '\0';

		while (*str) {
			switch (*str++) {
			case 'o':
				command->optional = TRUE;
				break;
			default:
				return EFI_INVALID_PARAMETER;
			}
		}

		while (*cmd && isspace(*cmd))
			cmd++;
		if (!*cmd)
			return EFI_INVALID_PARAMETER;
	}

	command->cmd = strdup(cmd);
	if (!command->cmd)
		return EFI_OUT_OF_RESOURCES;

	return EFI_SUCCESS;
}

#define SIZE_OF_NEW_COMMANDS ((command_nb + 1) * sizeof(*new_commands))

static EFI_STATUS store_command(char *command, VOID *context _unused)
{
	EFI_STATUS ret;
	struct command *new_commands;

	new_commands = AllocatePool(SIZE_OF_NEW_COMMANDS);
	if (!new_commands) {
		free_commands();
		return EFI_OUT_OF_RESOURCES;
	}

	ret = memcpy_s(new_commands, SIZE_OF_NEW_COMMANDS, commands, command_nb * sizeof(*commands));
	if (EFI_ERROR(ret)) {
		free_commands();
		return ret;
	}
	ret = create_new_command(&new_commands[command_nb], command);
	if (EFI_ERROR(ret)) {
		free_commands();
		return ret;
	}
	if (commands)
		FreePool(commands);
	commands = new_commands;
	command_nb++;

	return EFI_SUCCESS;
}

static char *next_command()
{
	if (command_nb == current_command) {
		free_commands();
		return NULL;
	}

	return commands[current_command++].cmd;
}

static void batch(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	void *data;
	UINTN size;
	CHAR16 *filename;

	if (argc != 2) {
		fastboot_fail("Batch command takes one parameter");
		return;
	}

	filename = stra_to_str(argv[1]);
	if (!filename) {
		fastboot_fail("Failed to convert CHAR8 filename to CHAR16");
		return;
	}

	ret = uefi_read_file(file_io_interface, filename, &data, &size);
	if (EFI_ERROR(ret)) {
		inst_perror(ret, "Failed to read %s file", filename);
		FreePool(filename);
		return;
	}
	FreePool(filename);

	ret = parse_text_buffer(data, size, store_command, NULL);
	FreePool(data);
	if (EFI_ERROR(ret))
		inst_perror(ret, "Failed to parse batch file");
	else
		fastboot_okay("");
}

static CHAR8 *build_default_options()
{
	EFI_STATUS ret;
	static CHAR8 options[64];
	const char cmd_prefix[] = "--batch installer";
	const char file_suffix[] = ".cmd";
	char *str;

	if (*options)
		return options;

	ret = memcpy_s(options, sizeof(options), cmd_prefix, sizeof(cmd_prefix) - 1);
	if (EFI_ERROR(ret))
		return NULL;
	str = (char *)options + strlen(options);

#ifdef HAL_AUTODETECT
	char *device = get_property_device();
	if (device) {
		*str++ = '_';
		while (*device)
			*str++ = *device++;
	}
#endif

	ret = memcpy_s(str, sizeof(file_suffix) - 1, file_suffix, sizeof(file_suffix) - 1);
	if (EFI_ERROR(ret))
		return NULL;

	return options;
}

static void usage(__attribute__((__unused__)) INTN argc,
		__attribute__((__unused__)) CHAR8 **argv)
{
	Print(L"Usage: installer [OPTIONS | COMMANDS]\n");
	Print(L"  installer is an EFI application acting like the fastboot command.\n\n");
	Print(L" COMMANDS               fastboot commands (cf. the fastboot manual page)\n");
	Print(L" -i                     include the device which is loaded from, must be the first option\n");
	Print(L" --help, -h             print this help and exit\n");
	Print(L" --version, -v          print Installer version and exit\n");
	Print(L" --batch, -b FILE       run all the fastboot commands of FILE\n");
	Print(L"If no option is provided, the installer assumes '%a'\n", build_default_options());
	Print(L"Note: 'update', 'flash-raw' and 'flashall' commands are NOT supported\n");

	fastboot_okay("");
}

static void version(__attribute__((__unused__)) INTN argc,
		__attribute__((__unused__)) CHAR8 **argv)
{
	Print(L"%s\n", KERNELFLINGER_VERSION);

	fastboot_okay("");
}

static void unsupported_cmd(__attribute__((__unused__)) INTN argc,
		CHAR8 **argv)
{
	fastboot_fail("installer does not the support the '%a' command", argv[0]);
}

static struct replacements {
	struct fastboot_cmd cmd;
	fastboot_handle *save_handle;
	const char *equ_name;
} REPLACEMENTS[] = {
	/* Fastboot replacements. */
	{ .cmd = { .name = "flash", .handle = installer_flash_cmd },
	  .save_handle = &fastboot_flash_cmd },
	{ .cmd = { .name = "erase", .handle = installer_erase },
	  .save_handle = &fastboot_erase_cmd },
	{ .cmd = { .name = "format", .handle = installer_format	} },
	{ .cmd = { .name = "boot", .handle = installer_boot } },
	/* Equivalent commands. */
	{ .cmd = { .name = "--set-active" }, .equ_name = "set_active" },
	/* Unsupported commands. */
	{ .cmd = { "update",	LOCKED, unsupported_cmd	    } },
	{ .cmd = { "flashall",	LOCKED, unsupported_cmd	    } },
	{ .cmd = { "devices",	LOCKED, unsupported_cmd	    } },
	{ .cmd = { "download",	LOCKED, unsupported_cmd	    } },
	/* Installer specific commands. */
	{ .cmd = { "--help",	LOCKED,	usage		    } },
	{ .cmd = { "-h",	LOCKED,	usage		    } },
	{ .cmd = { "--version",	LOCKED,	version		    } },
	{ .cmd = { "-v",	LOCKED,	version		    } },
	{ .cmd = { "--batch",	LOCKED,	batch		    } },
	{ .cmd = { "-b",	LOCKED,	batch		    } }
};

static EFI_STATUS installer_replace_functions(void)
{
	EFI_STATUS ret;
	struct fastboot_cmd *cmd;
	UINTN i;

	for (i = 0; i < ARRAY_SIZE(REPLACEMENTS); i++) {
		cmd = fastboot_get_root_cmd(REPLACEMENTS[i].cmd.name);

		if (cmd && REPLACEMENTS[i].save_handle)
			*(REPLACEMENTS[i].save_handle) = cmd->handle;

		if (cmd && REPLACEMENTS[i].cmd.handle)
			cmd->handle = REPLACEMENTS[i].cmd.handle;

		if (!cmd && REPLACEMENTS[i].cmd.handle) {
			ret = fastboot_register(&REPLACEMENTS[i].cmd);
			if (EFI_ERROR(ret))
				return ret;
			continue;
		}

		if (REPLACEMENTS[i].equ_name) {
			cmd = fastboot_get_root_cmd(REPLACEMENTS[i].equ_name);
			if (!cmd)
				return EFI_INVALID_PARAMETER;

			REPLACEMENTS[i].cmd.min_state = cmd->min_state;
			REPLACEMENTS[i].cmd.handle = cmd->handle;
			ret = fastboot_register(&REPLACEMENTS[i].cmd);
			if (EFI_ERROR(ret))
				return ret;
		}
	}

	return EFI_SUCCESS;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS ret;
	EFI_LOADED_IMAGE *loaded_img = NULL;
	CHAR8 *options, *buf;
	UINTN i;
	void *bootimage;
	void *efiimage;
	UINTN imagesize;
	enum boot_target target;
	BOOLEAN include_self = FALSE;

	InitializeLib(image, _table);
	g_parent_image = image;

	ret = handle_protocol(image, &LoadedImageProtocol, (void **)&loaded_img);
	if (ret != EFI_SUCCESS) {
		efi_perror(ret, L"LoadedImageProtocol error");
		return ret;
	}

	/* Initialize File IO interface. */
	ret = uefi_call_wrapper(BS->HandleProtocol, 3, loaded_img->DeviceHandle,
			&FileSystemProtocol, (void *)&file_io_interface);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get FileSystemProtocol");
		return ret;
	}

	/* Prepare parameters. */
	UINTN size = StrLen(loaded_img->LoadOptions) + 1;
	buf = options = AllocatePool(size);
	if (!options) {
		error(L"Unable to allocate buffer for parameters");
		return EFI_OUT_OF_RESOURCES;
	}
	str_to_stra(options, loaded_img->LoadOptions, size);
	/* Snip control and space characters. */
	for (i = size - 1; options[i] <= ' '; i--)
		options[i] = '\0';
	/* Drop the first parameter.  */
	options = strchr(options, ' ');
	if (options)
		skip_whitespace((char **)&options);

	/* Check options before build and run commands */
	if (options) {
		if (!strncmp(options, "-i", 2)) {
			include_self = TRUE;
			options += 2;
			skip_whitespace((char **)&options);
		}
	}

	if (!options || *options == '\0')
		options = build_default_options();
	store_command((char *)options, NULL);

	/* Set do not install to the device which is loaded from */
	if (!include_self)
		set_exclude_device(loaded_img->DeviceHandle);

#ifdef USE_TPM
	if (!is_live_boot()) {
		ret = tpm2_init();
		if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
			efi_perror(ret, L"Failed to init TPM, exit");
			goto exit;
		}
	}
#endif

	ret = set_device_security_info(NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init security info, exit");
		goto exit;
	}

	/* Initialize slot management. */
	ret = slot_init();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Slot management initialization failed");
		goto exit;
	}

	new_install_device = TRUE;

#ifdef USE_UI
	ret = ux_prompt_user_confirm();
	if (ret != EFI_SUCCESS)
		goto exit;
#endif

	/* Run the fastboot library. */
	ret = fastboot_start(&bootimage, &efiimage, &imagesize, &target);
	if (EFI_ERROR(ret))
		goto exit;

	if (target != UNKNOWN_TARGET)
		reboot_to_target(target, EfiResetCold);

exit:
	FreePool(buf);
	if (EFI_ERROR(ret))
		return ret;
	return last_cmd_succeeded ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/* Installer transport abstraction. */
EFI_STATUS installer_transport_start(start_callback_t start_cb,
				     data_callback_t rx_cb,
				     data_callback_t tx_cb)
{
	EFI_STATUS ret;
	ret = fastboot_set_command_buffer(command_buffer,
					  sizeof(command_buffer));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to set fastboot command buffer");
		return ret;
	}

	fastboot_tx_cb = tx_cb;
	fastboot_rx_cb = rx_cb;
	start_cb();

	if (!fastboot_cmd_buf)
		return EFI_INVALID_PARAMETER;

	dl = fastboot_download_buffer();
	if (!dl || !dl->data || !dl->max_size)
		return EFI_NOT_READY;

	return EFI_SUCCESS;
}

EFI_STATUS installer_transport_stop(void)
{
	return EFI_SUCCESS;
}

EFI_STATUS installer_transport_run(void)
{
	static BOOLEAN initialized = FALSE;
	EFI_STATUS ret;
	char *cmd;
	UINTN cmd_len;

	if (!initialized) {
		ret = installer_replace_functions();
		if (EFI_ERROR(ret))
			return ret;
		if (!fastboot_flash_cmd) {
			fastboot_fail("Failed to get the flash handle");
			return ret;
		}
		initialized = TRUE;
	}

	if (current_command > 0) {
		flush_tx_buffer();
		if (last_cmd_succeeded)
			Print(L"Command successfully executed\n");
		else {
			if (!commands[current_command - 1].optional)
				goto stop;
			Print(L"Command failed but is optional\n");
		}
	}

	cmd = next_command();
	if (!cmd)
		goto stop;

	cmd_len = strlena((CHAR8 *)cmd);
	if (cmd_len > fastboot_cmd_buf_len) {
		inst_perror(EFI_BUFFER_TOO_SMALL,
			    "command too long for fastboot command buffer");
		goto stop;
	}

	ret = memcpy_s(fastboot_cmd_buf, fastboot_cmd_buf_len, cmd, cmd_len);
	if (EFI_ERROR(ret))
		goto stop;

	Print(L"Starting command: '%a'\n", cmd);
	fastboot_rx_cb(fastboot_cmd_buf, cmd_len);

	return EFI_SUCCESS;

stop:
	fastboot_stop(NULL, NULL, 0, EXIT_SHELL);
	return EFI_SUCCESS;
}

EFI_STATUS installer_transport_read(void *buf, UINT32 size)
{
	fastboot_cmd_buf = buf;
	fastboot_cmd_buf_len = size;

	return EFI_SUCCESS;
}

EFI_STATUS installer_transport_write(void *buf, UINT32 size)
{
#define PREFIX_LEN 4

	if (size < PREFIX_LEN)
		return EFI_SUCCESS;

	if (!memcmp((CHAR8 *)"INFO", buf, PREFIX_LEN)) {
		Print(L"(bootloader) %a\n", buf + PREFIX_LEN);
		need_tx_cb = TRUE;
	} if (!memcmp((CHAR8 *)"OKAY", buf, PREFIX_LEN)) {
		if (((char *)buf)[PREFIX_LEN] != '\0')
			Print(L"%a\n", buf + PREFIX_LEN);
		last_cmd_succeeded = TRUE;
		fastboot_tx_cb(NULL, 0);
	} else if (!memcmp((CHAR8 *)"FAIL", buf, PREFIX_LEN)) {
		error(L"%a", buf + PREFIX_LEN);
		last_cmd_succeeded = FALSE;
		fastboot_tx_cb(NULL, 0);
	}

	return EFI_SUCCESS;
}

static transport_t INSTALLER_TRANSPORT[] = {
	{
		.name = "Installer for fastboot",
		.start = installer_transport_start,
		.stop = installer_transport_stop,
		.run = installer_transport_run,
		.read = installer_transport_read,
		.write = installer_transport_write
	}
};

EFI_STATUS fastboot_transport_register(void)
{
	return transport_register(INSTALLER_TRANSPORT,
				  ARRAY_SIZE(INSTALLER_TRANSPORT));
}

void fastboot_transport_unregister(void)
{
	transport_unregister();
}

/* UI wrapper functions. */
void fastboot_ui_destroy(void)
{
}

void fastboot_ui_refresh(void)
{
}

EFI_STATUS fastboot_ui_init(void)
{
	return EFI_SUCCESS;
}

enum boot_target fastboot_ui_event_handler()
{
	return UNKNOWN_TARGET;
}

/* Installer does not support UI.  It is intended to be used in
   factory or for engineering purpose only.  */
BOOLEAN fastboot_ui_confirm_for_state(__attribute__((__unused__)) enum device_state target)
{
	return TRUE;
}
