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

#include <efi.h>
#include <efilib.h>
#include <lib.h>
#include <fastboot.h>
#include <android.h>
#include <slot.h>
#include "fastboot.h"
#include "uefi_utils.h"
#include "gpt.h"
#include "gpt_bin.h"
#include "flash.h"
#include "storage.h"
#include "sparse.h"
#include "oemvars.h"
#include "vars.h"
#include "bootloader.h"
#include "authenticated_action.h"
#if defined(IOC_USE_SLCAN) || defined(IOC_USE_CBC)
#include "ioc_uart_protocol.h"
#endif
#ifdef FASTBOOT_KEYBOX_PROVISION
#include "aes_gcm.h"
#include "keybox_provision.h"
#endif
static struct gpt_partition_interface gparti;
static UINT64 cur_offset;
static BOOLEAN userdata_erased = FALSE;
BOOLEAN new_install_device = FALSE;

#define part_start (gparti.part.starting_lba * gparti.bio->Media->BlockSize)
#define part_end ((gparti.part.ending_lba + 1) * gparti.bio->Media->BlockSize)

#define is_inside_partition(off, sz) \
		(off >= part_start && off + sz <= part_end)

EFI_STATUS flash_skip(UINT64 size)
{
	if (!is_inside_partition(cur_offset, size)) {
		error(L"Attempt to skip outside of partition [%ld %ld] [%ld %ld]",
				part_start, part_end, cur_offset, cur_offset + size);
		return EFI_INVALID_PARAMETER;
	}
	cur_offset += size;
	return EFI_SUCCESS;
}

EFI_STATUS flash_write(VOID *data, UINTN size)
{
	EFI_STATUS ret;

	if (!gparti.bio)
		return EFI_INVALID_PARAMETER;

	if (!is_inside_partition(cur_offset, size)) {
		error(L"Attempt to write outside of partition [%ld %ld] [%ld %ld]",
				part_start, part_end, cur_offset, cur_offset + size);
		return EFI_INVALID_PARAMETER;
	}
	ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5, gparti.dio, gparti.bio->Media->MediaId, cur_offset, size, data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write bytes");
		return ret;
	}

	cur_offset += size;
	return EFI_SUCCESS;
}

EFI_STATUS flash_fill(UINT32 pattern, UINTN size)
{
	EFI_STATUS ret;
	UINT32 *aligned_buf;
	VOID *buf;
	UINTN i, buf_size, write_size;

	if (!gparti.bio || !size || size % gparti.bio->Media->BlockSize)
		return EFI_INVALID_PARAMETER;

	buf_size = min(gparti.bio->Media->BlockSize * N_BLOCK, size);
	ret = alloc_aligned(&buf, (VOID **)&aligned_buf, buf_size, gparti.bio->Media->IoAlign);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Unable to allocate the pattern buf");
		return ret;
	}

	for (i = 0; i < buf_size / sizeof(*aligned_buf); i++)
		aligned_buf[i] = pattern;

	for (; size; size -= write_size) {
		write_size = min(size, buf_size);
		ret = flash_write(aligned_buf, write_size);
		if (EFI_ERROR(ret))
			goto out;
	}

out:
	FreePool(buf);
	return ret;
}

static EFI_STATUS flash_into_esp(VOID *data, UINTN size, CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io;

	ret = get_esp_fs(&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition ESP");
		return ret;
	}
	return uefi_write_file_with_dir(io, label, data, size);
}

#define MBR_LB_SIZE (is_cur_storage_ufs()? 4096:512)

static EFI_STATUS get_full_gpt_header(VOID **data_p, UINTN *size_p)
{
	VOID *data = *data_p;
	UINTN size = *size_p;
	struct gpt_header *gh;

	if (size < MBR_LB_SIZE)
		return EFI_NOT_FOUND;

	gh = data + MBR_LB_SIZE;
	size -= MBR_SIZE;

	if (size < (GPT_HEADER_SIZE + (GPT_ENTRIES * GPT_ENTRY_SIZE)) ||
	    CompareMem(gh->signature, EFI_PTAB_HEADER_ID, sizeof(gh->signature)))
		return EFI_NOT_FOUND;

	*data_p = gh;
	*size_p = (GPT_HEADER_SIZE + (GPT_ENTRIES * GPT_ENTRY_SIZE));
	return EFI_SUCCESS;
}

/* _flash_gpt supports two gpt binary format:
 * - The bpttool gpt binary : MBR + GPT Header + GPT entries
 * - The GPT binary format generated by the gpt_ini2bin.py script.
 */
static EFI_STATUS _flash_gpt(VOID *data, UINTN size, logical_unit_t log_unit)
{
	EFI_STATUS ret;
	struct gpt_bin_header *gb_hdr;
	struct gpt_bin_part *gb_part;

	ret = get_full_gpt_header(&data, &size);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND)
		return ret;
	if (!EFI_ERROR(ret))
		return gpt_create((struct gpt_header *)data, size, 0, 0, NULL, log_unit);

 	gb_hdr = data;
 	gb_part = (struct gpt_bin_part *)&gb_hdr[1];
	if (size >= sizeof(*gb_hdr) &&
	    gb_hdr->magic == GPT_BIN_MAGIC &&
	    size == sizeof(*gb_hdr) + (gb_hdr->npart * sizeof(*gb_part)))
		return gpt_create(NULL, 0, gb_hdr->start_lba, gb_hdr->npart,
				  gb_part, log_unit);

	error(L"Unsupport gpt binary format");
	return EFI_INVALID_PARAMETER;
}

static EFI_STATUS flash_gpt(VOID *data, UINTN size)
{
	EFI_STATUS ret;

	ret = _flash_gpt(data, size, LOGICAL_UNIT_USER);
	return EFI_ERROR(ret) ? ret : EFI_SUCCESS | REFRESH_PARTITION_VAR;
}

static EFI_STATUS flash_gpt_gpp1(VOID *data, UINTN size)
{
	return _flash_gpt(data, size, LOGICAL_UNIT_FACTORY);
}

#ifndef USER
static EFI_STATUS flash_efirun(VOID *data, UINTN size)
{
	return fastboot_stop(NULL, data, size, UNKNOWN_TARGET);
}

static EFI_STATUS flash_mbr(VOID *data, UINTN size)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;

	if (size > MBR_CODE_SIZE)
		return EFI_INVALID_PARAMETER;

	ret = gpt_get_root_disk(&gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get disk information");
		return ret;
	}

	ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId, 0, size, data);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to flash MBR");

	return ret;
}
#endif

static EFI_STATUS flash_sfu(VOID *data, UINTN size)
{
	return flash_into_esp(data, size, L"BIOSUPDATE.fv");
}

static EFI_STATUS flash_ifwi(VOID *data, UINTN size)
{
	return flash_into_esp(data, size, L"ifwi.bin");
}

#if defined(IOC_USE_SLCAN) || defined(IOC_USE_CBC)
static EFI_STATUS flash_ioc(VOID *data, UINTN size)
{
	EFI_STATUS ret;
	EFI_GUID guid = EFI_IOC_UART_PROTOCOL_GUID;
	IOC_UART_PROTOCOL *iocprotocal;

	ret = LibLocateProtocol(&guid, (void **)&iocprotocal);
	if (EFI_ERROR(ret)) {
		debug(L"IOC UART Protocol is not supported");
		return EFI_UNSUPPORTED;
	}

	if (!EFI_ERROR(ret)) {
		ret = uefi_call_wrapper(iocprotocal->flash_ioc_firmware, 3, iocprotocal, data, size);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to flash ioc firmware");
			return ret;
		}
	}

	return EFI_SUCCESS;
}
#endif

static EFI_STATUS flash_new_bootimage(VOID *kernel, UINTN kernel_size,
				      VOID *ramdisk, UINTN ramdisk_size)
{
	struct boot_img_hdr *bootimage, *new_bootimage;
	VOID *new_cur, *cur;
	UINTN new_size, partlen, page_size;
	EFI_STATUS ret;

	ret = gpt_get_partition_by_label(slot_label(BOOT_LABEL), &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		error(L"Unable to get information on the boot partition");
		return ret;
	}
	partlen = (gparti.part.ending_lba + 1 - gparti.part.starting_lba)
		* gparti.bio->Media->BlockSize;

	bootimage = AllocatePool(sizeof(*bootimage));
	if (!bootimage) {
		error(L"Unable to allocate bootimage buffer");
		return EFI_OUT_OF_RESOURCES;
	}

	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId,
				gparti.part.starting_lba * gparti.bio->Media->BlockSize,
				sizeof(*bootimage), bootimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load the current bootimage");
		goto out;
	}

	if (memcmp(bootimage->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
		error(L"boot partition does not contain a valid bootimage");
		ret = EFI_UNSUPPORTED;
		goto out;
	}

	if (bootimage_size(bootimage) > partlen) {
		error(L"Invalid boot image size");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	bootimage = ReallocatePool(bootimage, sizeof(*bootimage),
				   bootimage_size(bootimage));
	if (!bootimage) {
		error(L"Unable to increase the bootimage buffer size");
		return EFI_OUT_OF_RESOURCES;
	}

	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId,
				gparti.part.starting_lba * gparti.bio->Media->BlockSize,
				bootimage_size(bootimage), bootimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to load the current bootimage");
		goto out;
	}

	page_size = bootimage->page_size;
	if (!kernel) {
		kernel = (VOID *)bootimage + page_size;
		kernel_size = bootimage->kernel_size;
	}
	if (!ramdisk) {
		ramdisk = (VOID *)bootimage + page_size +
			pagealign(bootimage, bootimage->kernel_size);
		ramdisk_size = bootimage->ramdisk_size;
	}

	new_size = bootimage_size(bootimage)
		- pagealign(bootimage, bootimage->kernel_size)
		+ pagealign(bootimage, kernel_size)
		- pagealign(bootimage, bootimage->ramdisk_size)
		+ pagealign(bootimage, ramdisk_size);
	if (new_size > partlen) {
		error(L"Kernel image is too large to fit in the boot partition");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	new_bootimage = AllocateZeroPool(new_size);
	if (!new_bootimage) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	/* Create the new bootimage. */
	ret = memcpy_s((VOID *)new_bootimage, new_size, bootimage, sizeof(*bootimage));
	if (EFI_ERROR(ret))
		goto out1;

	cur = (VOID *)bootimage + page_size;
	new_cur = (VOID *)new_bootimage + page_size;

	new_bootimage->kernel_size = kernel_size;
	ret = memcpy_s(new_cur, new_size - page_size, kernel, kernel_size);
	if (EFI_ERROR(ret))
		goto out1;

	cur += pagealign(bootimage, bootimage->kernel_size);
	new_cur += pagealign(new_bootimage, kernel_size);

	new_bootimage->ramdisk_size = ramdisk_size;
	ret = memcpy_s(new_cur, new_size - page_size - pagealign(new_bootimage, kernel_size),
				   ramdisk, ramdisk_size);
	if (EFI_ERROR(ret))
		goto out1;

	cur += pagealign(bootimage, bootimage->ramdisk_size);
	new_cur += pagealign(new_bootimage, ramdisk_size);

	ret = memcpy_s(new_cur,
				   new_size - page_size - pagealign(new_bootimage, kernel_size) - pagealign(new_bootimage, ramdisk_size),
				   cur, bootimage->second_size);
	if (EFI_ERROR(ret))
		goto out1;


	if (bootimage->header_version >= 1) {
		ret = memcpy_s(new_bootimage + new_bootimage->recovery_acpio_offset,
					   new_bootimage->recovery_acpio_size,
					   bootimage + bootimage->recovery_acpio_offset,
					   bootimage->recovery_acpio_size);
		if (EFI_ERROR(ret))
			goto out1;
	}

	if (bootimage->header_version == 2) {
		ret = memcpy_s(new_bootimage + new_bootimage->acpi_addr,
					   new_bootimage->acpi_size,
					   bootimage + bootimage->acpi_addr,
					   bootimage->acpi_size);
		if (EFI_ERROR(ret))
			goto out1;
	}

	/* Flash new the bootimage. */
	cur_offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;
	ret = flash_write(new_bootimage, new_size);

out1:
	FreePool(new_bootimage);

out:
	FreePool(bootimage);
	return ret;
}

static EFI_STATUS flash_kernel(VOID *data, UINTN size)
{
	return flash_new_bootimage(data, size, NULL, 0);
}

static EFI_STATUS flash_ramdisk(VOID *data, UINTN size)
{
	return flash_new_bootimage(NULL, 0, data, size);
}

static CHAR16 *DM_VERITY_PARTITIONS[] =
	{ SYSTEM_LABEL, VENDOR_LABEL, OEM_LABEL };

EFI_STATUS flash_partition(VOID *data, UINTN size, CHAR16 *label)
{
	EFI_STATUS ret;
	UINTN i;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	cur_offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;

	if (is_sparse_image(data, size))
		ret = flash_sparse(data, size);
	else
		ret = flash_write(data, size);

	if (EFI_ERROR(ret))
		return ret;

	if (!CompareGuid(&gparti.part.type, &EfiPartTypeSystemPartitionGuid)) {
		ret = gpt_refresh();
		if (EFI_ERROR(ret))
			return ret;
	}

	for (i = 0; i < ARRAY_SIZE(DM_VERITY_PARTITIONS); i++)
		if (!StrCmp(DM_VERITY_PARTITIONS[i], label))
			return slot_set_verity_corrupted(FALSE);

	return EFI_SUCCESS;
}

static struct label_exception {
	CHAR16 *name;
	EFI_STATUS (*flash_func)(VOID *data, UINTN size);
} LABEL_EXCEPTIONS[] = {
	{ L"gpt", flash_gpt },
	{ L"gpt-gpp1", flash_gpt_gpp1 },
#ifndef USER
	{ L"efirun", flash_efirun },
	{ L"mbr", flash_mbr },
#endif
	{ L"sfu", flash_sfu },
	{ L"ifwi", flash_ifwi },
	{ L"oemvars", flash_oemvars },
	{ L"kernel", flash_kernel },
	{ L"ramdisk", flash_ramdisk },
	{ ESP_LABEL, flash_esp },
#ifndef USE_SBL
	{ BOOTLOADER_LABEL, flash_bootloader },
	{ BOOTLOADER_A_LABEL, flash_bootloader_a },
	{ BOOTLOADER_B_LABEL, flash_bootloader_b },
#endif
#if defined(IOC_USE_SLCAN) || defined(IOC_USE_CBC)
	{ L"ioc", flash_ioc },
#endif
#ifdef FASTBOOT_KEYBOX_PROVISION
	{ L"keybox", flash_keybox }
#endif
};

EFI_STATUS flash(VOID *data, UINTN size, CHAR16 *label)
{
	UINTN i;

#ifndef USER
	/* special case for writing inside esp partition */
	CHAR16 esp[] = L"/ESP/";
	if (!StrnCmp(esp, label, StrLen(esp)))
		return flash_into_esp(data, size, &label[ARRAY_SIZE(esp) - 1]);
#endif
	/* special cases */
	for (i = 0; i < ARRAY_SIZE(LABEL_EXCEPTIONS); i++)
		if (!StrCmp(LABEL_EXCEPTIONS[i].name, label))
			return LABEL_EXCEPTIONS[i].flash_func(data, size);

	return flash_partition(data, size, label);
}

EFI_STATUS flash_file(EFI_HANDLE image, CHAR16 *filename, CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io = NULL;
	VOID *buffer = NULL;
	UINTN size = 0;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, image, &FileSystemProtocol, (void *)&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get FileSystemProtocol");
		goto out;
	}

	ret = uefi_read_file(io, filename, &buffer, &size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read file %s", filename);
		goto out;
	}

	ret = flash(buffer, size, label);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to flash file %s on partition %s", filename, label);
		goto free_buffer;
	}

free_buffer:
	FreePool(buffer);
out:
	return ret;

}

#define FS_MGR_SIZE 4096
static EFI_STATUS erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end)
{
	EFI_STATUS ret;
	EFI_LBA min_end;

	ret = storage_erase_blocks(handle, bio, start, end);
	if (ret == EFI_SUCCESS) {
		/* If the Android fs_mgr fails mounting a partition,
		   it tries to detect if the partition has been wiped
		   out to determine if it has to format it.  fs_mgr
		   considers that the partition has been wiped out if
		   the first 4096 bytes are filled up with all 0 or
		   all 1.  storage_erase_blocks() uses hardware
		   support to erase the blocks which does not guarantee
		   that content will be all 0 or all 1.  It also can
		   be indeterminate data. */
		min_end = start + (FS_MGR_SIZE / bio->Media->BlockSize) + 1;
		return fill_zero(bio, start, min(min_end, end));
	}

	debug(L"Fallbacking to filling with zeros");
	return fill_zero(bio, start, end);
}

static EFI_STATUS fast_erase_part(const CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_LBA start, end, min_end;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	start = gparti.part.starting_lba;
	end = gparti.part.ending_lba;
	min_end = start + (FS_MGR_SIZE / gparti.bio->Media->BlockSize) + 1;

	ret = fill_zero(gparti.bio, start, min(min_end, end));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to erase partition %s", label);
		return ret;
	}

	if (!CompareGuid(&gparti.part.type, &EfiPartTypeSystemPartitionGuid))
		return gpt_refresh();

	return EFI_SUCCESS;
}

EFI_STATUS erase_by_label(CHAR16 *label)
{
	EFI_STATUS ret;

	/* userdata/data partition only need to be erased once during each boot */
	if (!StrCmp(label, L"userdata") || !StrCmp(label, L"data")) {
		if (userdata_erased) {
			debug(L"userdata/data partition had already been erased. skip.");
			return EFI_SUCCESS;
		}

		if (new_install_device) {
			debug(L"New install devcie, fast erase userdata/data partition");
			return fast_erase_part(label);
		} else {
#ifndef USER
			debug(L"fast erase userdata/data partition for userdebug build");
			return fast_erase_part(label);
#endif
		}
	}

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}
	ret = erase_blocks(gparti.handle, gparti.bio, gparti.part.starting_lba, gparti.part.ending_lba);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to erase partition %s", label);
		return ret;
	}
	if (!CompareGuid(&gparti.part.type, &EfiPartTypeSystemPartitionGuid))
		return gpt_refresh();

	if (!StrCmp(label, L"userdata") || !StrCmp(label, L"data"))
		userdata_erased = TRUE;

	return EFI_SUCCESS;
}

EFI_STATUS garbage_disk(void)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	VOID *chunk;
	VOID *aligned_chunk;
	UINTN size;

	ret = gpt_get_root_disk(&gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get disk information");
		return ret;
	}

	size = gparti.bio->Media->BlockSize * N_BLOCK;
	ret = alloc_aligned(&chunk, &aligned_chunk, size, gparti.bio->Media->IoAlign);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Unable to allocate the garbage chunk");
		return ret;
	}

	ret = generate_random_numbers(aligned_chunk, size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		FreePool(chunk);
		return ret;
	}

	ret = fill_with(gparti.bio, gparti.part.starting_lba,
			gparti.part.ending_lba, aligned_chunk, N_BLOCK);

	FreePool(chunk);
	return gpt_refresh();
}
