/*
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Author: Zhou, Jianfeng <jianfeng.zhou@intel.com>
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

#include "log.h"
#include "protocol.h"
#include "uefi_utils.h"

#define SYSTEMD_BOOT_FILE L"loaderx64.efi"

EFI_STATUS load_and_start_efi(EFI_HANDLE image_handle, CHAR16 *efi_file)
{
	EFI_GUID gEfiLoadedImageProtocolGuid = LOADED_IMAGE_PROTOCOL;
	EFI_STATUS Status = EFI_SUCCESS;
	EFI_HANDLE efi_handle = NULL;
	EFI_DEVICE_PATH *device_path;
	EFI_LOADED_IMAGE *image_info;
	EFI_LOADED_IMAGE *g_loaded_image = NULL;
	UINTN exit_data_size = 0;

	uefi_call_wrapper(BS->HandleProtocol, 3, image_handle, &LoadedImageProtocol, (void **)&g_loaded_image);
	device_path = FileDevicePath(g_loaded_image->DeviceHandle, efi_file);
	Status = BS->LoadImage(
			FALSE,
			image_handle,
			device_path,
			(VOID *) NULL,
			0,
			&efi_handle);
	if (Status != EFI_SUCCESS && Status != EFI_SECURITY_VIOLATION) {
		efi_perror(Status, L"Could not load the image '%s'", efi_file);
		return Status;
	}

	debug(L"Load '%s' success", efi_file);
	Status = BS->OpenProtocol(
			efi_handle,
			&gEfiLoadedImageProtocolGuid,
			(VOID **) &image_info,
			image_handle,
			(VOID *) NULL,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL
			);
	if (!EFI_ERROR(Status))
		debug(L"ImageSize = %d", image_info->ImageSize);

	Status = BS->StartImage(efi_handle, &exit_data_size, (CHAR16 **) NULL);
	if (Status != EFI_SUCCESS) {
		efi_perror(Status, L"Could not start image");
		efi_perror(Status, L"Exit data size: %d", exit_data_size);
	}

	return Status;
}

CHAR16 *get_base_path(EFI_HANDLE image_handle)
{
	EFI_STATUS ret;
	EFI_LOADED_IMAGE *g_loaded_image = NULL;
	CHAR16 *self_path = NULL;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle, &LoadedImageProtocol, (void **)&g_loaded_image);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"OpenProtocol LoadedImageProtocol failed");
		return NULL;
	}

	self_path = ((FILEPATH_DEVICE_PATH *)(g_loaded_image->FilePath))->PathName;
	return self_path;
}

CHAR16 *absolute_path(EFI_HANDLE image_handle, CHAR16 *file)
{
	CHAR16 *base_path = NULL;
	CHAR16 *abs_path = NULL;
	UINTN len;

	if (file[0] == L'\\')
		return StrDuplicate(file);

	base_path = get_base_path(image_handle);
	if (base_path == NULL)
		return NULL;

	len = StrLen(base_path) + StrLen(file) + 2;
	abs_path = (CHAR16 *)AllocatePool(len * sizeof(CHAR16));
	if (abs_path == NULL)
		return NULL;

	StrCpy(abs_path, base_path);
	StrCat(abs_path, L"\\");
	StrCat(abs_path, file);

	return abs_path;
}

EFI_STATUS start_systemd_boot(EFI_HANDLE image_handle)
{
	EFI_STATUS ret;
	CHAR16 *boot_path = NULL;

	boot_path = absolute_path(image_handle, SYSTEMD_BOOT_FILE);
	if (boot_path == NULL)
		return EFI_NOT_STARTED;

	debug(L"load and start '%s'...", boot_path);
	ret = load_and_start_efi(image_handle, boot_path);
	FreePool(boot_path);
	return ret;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS ret;

	InitializeLib(image, _table);

	ret = start_systemd_boot(image);
	return ret;
}

