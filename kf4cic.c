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
#include "vbmeta_ias.h"
#include "lib.h"
#include "ux.h"

#ifdef RPMB_STORAGE
#include "rpmb.h"
#include "rpmb_storage.h"
#endif

#include "security.h"
#include "security_interface.h"

#ifdef USE_TRUSTY
#include "trusty_interface.h"
#endif

#ifdef USE_TPM
#include "tpm2_security.h"
#endif

#define SYSTEMD_BOOT_FILE L"loaderx64.efi"
#define TOS_IMAGE_FILE    L"tos.img"
#define VBMETA_IAS_FILE   L"vbmeta.ias"
#define ESP_PARTITION     L"EFI"

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
		error(L"Could not load the image '%s'", efi_file);
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
		error(L"Could not start image");
		error(L"Exit data size: %d", exit_data_size);
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
		error(L"OpenProtocol LoadedImageProtocol failed");
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

	len = StrLen(base_path);
	if (len > 4) {
		if (StrcaseCmp(base_path + len - 4, L".EFI") == 0) {
			UINTN i = len - 4;

			while (i > 0 && base_path[i] != L'\\')
				i--;

			base_path[i] = 0;
		}
	}

	len = StrLen(base_path);
	if (len == 0)
		return StrDuplicate(file);

	len = StrLen(base_path) + StrLen(file) + 2;
	abs_path = (CHAR16 *)AllocatePool(len * sizeof(CHAR16));
	if (abs_path == NULL)
		return NULL;

	StrCpy(abs_path, base_path);
	StrCat(abs_path, L"\\");
	StrCat(abs_path, file);

	return abs_path;
}

static VOID show_disable_secure_boot_warnning()
{
	enum boot_target bt = NORMAL_BOOT;

#ifdef USE_UI
	bt = ux_prompt_user(SECURE_BOOT_CODE, FALSE, BOOT_STATE_YELLOW, NULL, 0);
#else
	debug(L"Secure boot is disabled");
#endif
	if (bt != NORMAL_BOOT)
		halt_system();
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

#ifdef USE_TRUSTY
EFI_STATUS load_file(EFI_HANDLE image_handle, CHAR16 *file, OUT VOID **image)
{
	EFI_STATUS ret;
	UINTN size = 0;
	EFI_FILE_IO_INTERFACE *io;
	EFI_LOADED_IMAGE *g_loaded_image = NULL;
	CHAR16 *abs_path;

	uefi_call_wrapper(BS->HandleProtocol, 3, image_handle, &LoadedImageProtocol, (void **)&g_loaded_image);
	ret = handle_protocol(g_loaded_image->DeviceHandle, &FileSystemProtocol, (void **)&io);
	if (EFI_ERROR(ret))
		return ret;

	abs_path = absolute_path(image_handle, file);
	if (abs_path == NULL)
		return EFI_NOT_FOUND;

	ret = uefi_read_file(io, abs_path, image, &size);
	FreePool(abs_path);
	if (EFI_ERROR(ret)) {
		error(L"read file failed: %s", file);
		return ret;
	}

	debug(L"file size of '%s' = %d\n", file, size);
	return ret;
}

EFI_STATUS load_and_start_tos(EFI_HANDLE image)
{
	EFI_STATUS ret;
	VOID *tosimage = NULL;

	ret = load_file(image, TOS_IMAGE_FILE, &tosimage);
	if (EFI_ERROR(ret))
		return ret;

	ret = start_trusty(tosimage);
	debug(L"start_trusty return: %r(%x)\n", ret, ret);
	return ret;
}
#endif

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS ret;
	BOOLEAN    verify_pass = FALSE;
	CHAR16     *vbmeta_path = NULL;
#ifdef RPMB_STORAGE
	UINT32 boot_state;
#endif

	InitializeLib(image, _table);

	vbmeta_path = absolute_path(image, VBMETA_IAS_FILE);
	// if secureboot is disabled, return always successful and verify_pass always true
	ret = verify_vbmeta_ias(ESP_PARTITION, vbmeta_path, &verify_pass);
	if (vbmeta_path != NULL)
		FreePool(vbmeta_path);
	if (EFI_ERROR(ret) || !verify_pass)
		return ret;

#ifdef USE_TPM
	if (is_platform_secure_boot_enabled()) {
		ret = tpm2_init();
		if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
			error(L"Failed to init TPM");
			return ret;
		}
	}
#endif

#ifdef RPMB_STORAGE
	ret = set_device_security_info(NULL);
	if (EFI_ERROR(ret))
		error(L"Failed to init security info");

	if (is_platform_secure_boot_enabled())
		boot_state = BOOT_STATE_GREEN;
	else {
		boot_state = BOOT_STATE_YELLOW;
		show_disable_secure_boot_warnning();
	}
	init_rot_data(boot_state);

	debug(L"teedata region init...\n");
	ret = rpmb_storage_init();
	if (EFI_ERROR(ret))
		error(L"Failed to init teedata region");

	debug(L"teedata region init ret = %X\n", ret);

	ret = rpmb_key_init();
	if (EFI_ERROR(ret))
		error(L"teedata region init failure for osloader.\n");
#endif

#ifdef USE_TRUSTY
	debug(L"TRUSTY enabled...\n");
	ret = load_and_start_tos(image);
	if (EFI_ERROR(ret))
		return ret;
#endif

#ifdef USE_TPM
	// Make sure the TPM2 is ended
	tpm2_end();
#endif

	ret = start_systemd_boot(image);
	return ret;
}

