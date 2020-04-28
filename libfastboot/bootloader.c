/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include "flash.h"
#include "gpt.h"
#include "bootmgr.h"
#include "bootloader.h"
#include "text_parser.h"
#include "uefi_utils.h"
#include "slot.h"

#define ESP_TMP_PART		ESP_LABEL L"2"
#define BOOTLOADER_TMP_PART	BOOTLOADER_LABEL L"2"
#define MANIFEST_PATH		L"\\manifest.txt"

#if __LP64__
#define DEFAULT_UEFI_LOAD_PATH	L"\\EFI\\BOOT\\bootx64.efi"
#else
#define DEFAULT_UEFI_LOAD_PATH	L"\\EFI\\BOOT\\bootia32.efi"
#endif
#define KFLD_UEFI_LOAD_PATH 	L"\\EFI\\INTEL\\KF4UEFI.EFI"

static const load_option_t DEFAULT_LOAD_OPTIONS[] = {
	{ L"Android-IA", DEFAULT_UEFI_LOAD_PATH, NULL }
};

static load_option_t *load_options;
static UINTN load_option_nb;

static void free_load_options()
{
	UINTN i;

	if (!load_options || load_options == DEFAULT_LOAD_OPTIONS)
		return;

	for (i = 0; i < load_option_nb; i++) {
		if (load_options[i].description)
			FreePool(load_options[i].description);
		if (load_options[i].path)
			FreePool(load_options[i].path);
		if (load_options[i].opt_params)
			FreePool(load_options[i].opt_params);
	}

	FreePool(load_options);
	load_options = NULL;
	load_option_nb = 0;
}

static EFI_STATUS add_load_option(CHAR8 *description, CHAR8 *path, CHAR8 *opt_params)
{
	EFI_STATUS ret;
	load_option_t *new_load_options;
	load_option_t *current;

	new_load_options = AllocatePool((load_option_nb + 1) * sizeof(*load_options));
	if (!new_load_options) {
		free_load_options();
		return EFI_OUT_OF_RESOURCES;
	}
	if (load_option_nb != 0) {
		ret = memcpy_s(new_load_options, sizeof(*new_load_options), load_options,
					   load_option_nb * sizeof(*load_options));
		if (EFI_ERROR(ret)) {
			free_load_options();
			return ret;
		}
	}
	FreePool(load_options);
	load_options = new_load_options;
	current = &load_options[load_option_nb];
	load_option_nb++;

	current->path = NULL;
	current->opt_params = NULL;

	current->description = stra_to_str(description);
	if (!current->description) {
		free_load_options();
		return EFI_OUT_OF_RESOURCES;
	}

	current->path = stra_to_str(path);
	if (!current->path) {
		free_load_options();
		return EFI_OUT_OF_RESOURCES;
	}

	if (opt_params) {
		current->opt_params = stra_to_str(opt_params);
		if (!current->opt_params) {
			free_load_options();
			return EFI_OUT_OF_RESOURCES;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS parse_line(char *line, VOID *context _unused)
{
	CHAR8 *description = (CHAR8 *)line;
	CHAR8 *path;
	CHAR8 *opt_params;

	path = strchr((CHAR8 *)line, '=');
	if (!path)
		return EFI_INVALID_PARAMETER;

	*path++ = '\0';
	if (!*path || !*description)
		return EFI_INVALID_PARAMETER;

	opt_params = strchr(path, ';');
	if (opt_params)
		*opt_params++ = '\0';

	return add_load_option(description, path, opt_params);
}

static EFI_STATUS read_load_options(EFI_HANDLE handle)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *file_io_interface;
	VOID *data;
	UINTN size;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, handle,
				&FileSystemProtocol, (void *)&file_io_interface);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get FileSystemProtocol");
		return ret;
	}

	ret = uefi_read_file(file_io_interface, MANIFEST_PATH, &data, &size);
	if (ret == EFI_NOT_FOUND) {
		debug(L"'%s' file not found, using default load options",
		      MANIFEST_PATH);
		load_options = (load_option_t *)DEFAULT_LOAD_OPTIONS;
		load_option_nb = ARRAY_SIZE(DEFAULT_LOAD_OPTIONS);
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(ret))
		return ret;

	ret = parse_text_buffer(data, size, parse_line, NULL);
	FreePool(data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to parse '%s' file", MANIFEST_PATH);
		return ret;
	}

	if (load_option_nb == 0) {
		error(L"Did not find any load option in '%s' file", MANIFEST_PATH);
		return EFI_INVALID_PARAMETER;
	}

	return EFI_SUCCESS;
}

/* we perform a "safe flash procedure" for EFI System partition:
 * 1. write data to the BOOTLOADER_TMP_PART partition
 * 2. perform sanity check on BOOTLOADER_TMP_PART partition files
 * 3. swap BOOTLOADER_PART and BOOTLOADER_TMP_PART partition
 * 4. erase BOOTLOADER_TMP_PART partition
 * 5. install the load options into the Boot Manager
 */
static EFI_STATUS flash_efi_partition(CHAR16 *label, CHAR16 *tmp_part,
		CHAR16 *uefi_load_path, BOOLEAN is_load_options, VOID *data, UINTN size)
{
	EFI_STATUS ret, erase_ret;
	EFI_HANDLE handle;
	UINTN i;

	ret = flash_partition(data, size, tmp_part);
	if (EFI_ERROR(ret))
		return ret;

	ret = gpt_refresh();
	if (EFI_ERROR(ret))
		return ret;

	ret = gpt_get_partition_handle(tmp_part,
				       LOGICAL_UNIT_USER, &handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get handle for '%s' partition",
			   tmp_part);
		ret = EFI_NOT_FOUND;
		goto exit;
	}

	ret = verify_image(handle, uefi_load_path);
	if (EFI_ERROR(ret))
		goto exit;

	if (is_load_options) {
		ret = read_load_options(handle);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to get load options");
			goto exit;
		}

		for (i = 0; i < load_option_nb; i++) {
			ret = verify_image(handle, load_options->path);
			if (EFI_ERROR(ret))
				goto exit;
		}
	}

	ret = gpt_swap_partition(tmp_part, label, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to swap partitions");

	if (is_load_options) {
		ret = bootmgr_register_entries(label, load_options, load_option_nb);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to install the load options");
	}
exit:
	/* Microsoft allows to use the FAT32 filesystem for the ESP
	   partition only and in the context of a UEFI device.  We
	   have to get rid of this potential second FAT32
	   partition.  */
	erase_ret = erase_by_label(tmp_part);
	if (EFI_ERROR(erase_ret))
		efi_perror(erase_ret, L"Failed to erase '%s' partition", tmp_part);

	free_load_options();

	return EFI_ERROR(ret) ? ret : erase_ret;
}

/* For non UEFI platform, perform "default flash procedure".
 * For UEFI platform, perform a "safe flash procedure"
 * if bootloader2 partition exists;  otherwise, return EFI_UNSUPPORTED.
 */
static EFI_STATUS flash_bootloader_verify(CHAR16 *label, VOID *data, UINTN size)
{
	EFI_GUID type;
	EFI_STATUS ret;

	if (!is_UEFI())
		return flash_partition(data, size, label);

	ret = gpt_get_partition_type(BOOTLOADER_TMP_PART, &type, LOGICAL_UNIT_USER);
	/* bootlader2 partition does not exist. */
	if (EFI_ERROR(ret))
		return EFI_UNSUPPORTED;

	return flash_efi_partition(label, BOOTLOADER_TMP_PART,
				KFLD_UEFI_LOAD_PATH, FALSE, data, size);
}

/* we perform a "safe flash procedure" for esp partition.
 */
EFI_STATUS flash_esp(VOID *data, UINTN size)
{
	return flash_efi_partition(ESP_LABEL, ESP_TMP_PART,
				DEFAULT_UEFI_LOAD_PATH, TRUE, data, size);
}

EFI_STATUS flash_bootloader_a(VOID *data, UINTN size)
{
	return flash_bootloader_verify(BOOTLOADER_A_LABEL, data, size);
}

EFI_STATUS flash_bootloader_b(VOID *data, UINTN size)
{
	return flash_bootloader_verify(BOOTLOADER_B_LABEL, data, size);
}

/* when flashing efi bootloader or bootloader_a/bootloader_b,
 * it need safe flashing.
 * If the bootloader partition is the EFI System partition, we perform
 * a "safe flash procedure".
 */
EFI_STATUS flash_bootloader(VOID *data, UINTN size)
{
	EFI_STATUS ret;
	EFI_GUID type;
	CHAR16 *label;

	label = (CHAR16 *)slot_label(BOOTLOADER_LABEL);

	if (!label) {
		error(L"invalid bootloader label");
		return EFI_INVALID_PARAMETER;
	}

	if (StrCmp(label, BOOTLOADER_LABEL)) {
		debug(L"bootloader slot ab is enable.");
		return flash_bootloader_verify(label, data, size);
	}

	ret = gpt_get_partition_type(label, &type, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return ret;

	/* Not the EFI System Partition. */
	if (memcmp(&type, &EfiPartTypeSystemPartitionGuid, sizeof(type)))
		return flash_partition(data, size, label);

	return flash_efi_partition(BOOTLOADER_LABEL, BOOTLOADER_TMP_PART,
				DEFAULT_UEFI_LOAD_PATH, TRUE, data, size);
}
