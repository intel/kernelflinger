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
#include "lib.h"
#include "ux.h"

#include "security.h"
#include "security_interface.h"

#ifdef USE_TRUSTY
#include "trusty_interface.h"
#include "trusty_common.h"
#endif

#ifdef USE_TPM
#include "tpm2_security.h"
#endif

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
	EFI_STATUS ret;

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

	ret = strcpy16_s(abs_path, len, base_path);
	if (EFI_ERROR(ret))
		return NULL;
	ret = strcat16_s(abs_path, len, L"\\");
	if (EFI_ERROR(ret))
		return NULL;
	ret = strcat16_s(abs_path, len, file);
	if (EFI_ERROR(ret))
		return NULL;

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
static EFI_STATUS load_and_start_tos(void)
{
	EFI_STATUS ret;
	VOID *tosimage = NULL;

	debug(L"loading trusty");
	ret = load_tos_image(&tosimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Load tos image failed");
		return ret;
	}

	debug(L"start trusty");
	ret = start_trusty(tosimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Unable to start trusty;");
		return ret;
	}

	return ret;
}

static EFI_STATUS update_rollback_indexes()
{
	EFI_STATUS ret;
	AvbOps *ops;
	AvbSlotVerifyResult verify_result;
	AvbSlotVerifyData *slot_data = NULL;
	UINT8 boot_state = BOOT_STATE_GREEN;
	const char *requested_partitions[] = {"tos", NULL};

	ops = avb_init();
	if (!ops) {
		error(L"Failed to init avb");
		return EFI_OUT_OF_RESOURCES;
	}

	verify_result = avb_slot_verify(ops,
					requested_partitions,
					"",
					AVB_SLOT_VERIFY_FLAGS_NONE,
					AVB_HASHTREE_ERROR_MODE_RESTART,
					&slot_data);
	ret = get_avb_result(slot_data,
				FALSE,
				verify_result,
				&boot_state);
	if (EFI_ERROR(ret)) {
		error(L"Failed to get avb result for tos");
		return ret;
	}

	avb_update_stored_rollback_indexes_for_slot(ops, slot_data);

	return ret;
}
#endif

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
	EFI_STATUS ret;
	UINT32 boot_state;

	InitializeLib(image, _table);

	/* Set device state as locked due to there is no fastboot
	 * implement in CIC host oS side to support whole devcie lock/unlock */
	if (device_is_unlocked()) {
		ret = set_current_state(LOCKED);
		if (EFI_ERROR(ret)) {
			error(L"Failed to set device state");
			return ret;
		}
	}

	if (is_platform_secure_boot_enabled())
		boot_state = BOOT_STATE_GREEN;
	else {
		boot_state = BOOT_STATE_YELLOW;
		show_disable_secure_boot_warnning();
	}

#ifdef USE_TPM
	if (is_platform_secure_boot_enabled()) {
		ret = tpm2_init();
		if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
			error(L"Failed to init TPM");
			return ret;
		}
	}
#endif

	ret = set_device_security_info(NULL);
	if (EFI_ERROR(ret)) {
		error(L"Failed to init security info");
		return ret;
	}

	init_rot_data(boot_state);
        init_attestation_ids();

#ifdef USE_TRUSTY
	debug(L"TRUSTY enabled...\n");
	ret = load_and_start_tos();
	if (EFI_ERROR(ret))
		return ret;

	if (boot_state == BOOT_STATE_GREEN) {
		ret = update_rollback_indexes();
		if (EFI_ERROR(ret)) {
			error(L"Failed to update rollback indexes.\n");
			return ret;
		}
	}
#endif

#ifdef USE_TPM
	// Make sure the TPM2 is ended
	tpm2_end();
#endif

	ret = start_systemd_boot(image);
	return ret;
}

