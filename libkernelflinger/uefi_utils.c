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
#include <gpt.h>
#include "protocol.h"
#include "uefi_utils.h"
#include "options.h"

/* GUID for ESP partition on gmin */
const EFI_GUID esp_ptn_guid = { 0x2568845d, 0x2332, 0x4675,
		{0xbc, 0x39, 0x8f, 0xa5, 0xa4, 0x74, 0x8d, 0x15}};

EFI_STATUS get_esp_fs(EFI_FILE_IO_INTERFACE **esp_fs)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_GUID SimpleFileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_HANDLE esp_handle = NULL;
	EFI_FILE_IO_INTERFACE *esp;

	ret = gpt_get_partition_handle(BOOTLOADER_LABEL, LOGICAL_UNIT_USER,
				       &esp_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get ESP partition");
		return ret;
	}

	ret = handle_protocol(esp_handle, &SimpleFileSystemProtocol,
			      (void **)&esp);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"HandleProtocol for ESP partition failed");
		return ret;
	}
	*esp_fs = esp;

	return ret;
}

EFI_STATUS uefi_open_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, EFI_FILE **file)
{
	EFI_STATUS ret;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, file);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper((*file)->Open, 5, *file, file, filename, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

#define FILENAME_MAX_LENGTH 200

EFI_STATUS uefi_get_file_size(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE_INFO *info;
	UINTN info_size;
	EFI_FILE *file;

	ret = uefi_open_file(io, filename, &file);
	if (EFI_ERROR(ret))
		goto out;

	info_size = SIZE_OF_EFI_FILE_INFO + FILENAME_MAX_LENGTH;

	info = AllocatePool(info_size);
	if (!info) {
		ret = EFI_OUT_OF_RESOURCES;
		goto close;
	}

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &info_size, info);
	if (EFI_ERROR(ret))
		goto free_info;

	*size = info->FileSize;

free_info:
	FreePool(info);
close:
	uefi_call_wrapper(file->Close, 1, file);
out:
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to read file %s", filename);
	return ret;
}

EFI_STATUS uefi_read_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void **data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE_INFO *info;
	UINTN info_size;
	EFI_FILE *file;

	ret = uefi_open_file(io, filename, &file);
	if (EFI_ERROR(ret))
		goto out;

	info_size = SIZE_OF_EFI_FILE_INFO + FILENAME_MAX_LENGTH;

	info = AllocatePool(info_size);
	if (!info) {
		ret = EFI_OUT_OF_RESOURCES;
		goto close;
	}

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &info_size, info);
	if (EFI_ERROR(ret))
		goto free_info;

	*size = info->FileSize;
	*data = AllocatePool(*size);

retry:
	ret = uefi_call_wrapper(file->Read, 3, file, size, *data);
	if (ret == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(*size);
		goto retry;
	}

	if (EFI_ERROR(ret))
		FreePool(*data);

free_info:
	FreePool(info);
close:
	uefi_call_wrapper(file->Close, 1, file);
out:
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to read file %s", filename);
	return ret;
}

EFI_STATUS uefi_write_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN *size)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to write file %s", filename);
	return ret;
}

EFI_STATUS uefi_create_dir(EFI_FILE *parent, EFI_FILE **dir, CHAR16 *dirname)
{
	return uefi_call_wrapper(parent->Open, 5, parent, dir, dirname,
				 EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
				 EFI_FILE_DIRECTORY);
}

#define MAX_SUBDIR 10
EFI_STATUS uefi_write_file_with_dir(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN size)
{
	EFI_STATUS ret;
	EFI_FILE *dirs[MAX_SUBDIR];
	EFI_FILE *file;
	CHAR16 *start;
	CHAR16 *end;
	INTN subdir = 0;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &dirs[0]);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open root directory");
		return ret;
	}
	start = filename;
	for (end = filename; *end; end++) {
		if (*end != '/')
			continue;
		if (start == end) {
			start++;
			continue;
		}

		*end = 0;
		debug(L"create directory %s", start);
		ret = uefi_create_dir(dirs[subdir], &dirs[subdir + 1], start);
		*end = '/';
		if (EFI_ERROR(ret))
			goto out;
		subdir++;
		if (subdir >= MAX_SUBDIR - 1) {
			error(L"too many subdirectories, limit is %d", MAX_SUBDIR);
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}
		start = end + 1;
	}
	debug(L"write file %s", start);
	ret = uefi_call_wrapper(dirs[subdir]->Open, 5, dirs[subdir], &file, start, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Write, 3, file, &size, data);
	uefi_call_wrapper(file->Close, 1, file);

out:
	for (; subdir >= 0; subdir--)
		uefi_call_wrapper(dirs[subdir]->Close, 1, dirs[subdir]);

	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to write file %s", filename);
	return ret;
}

EFI_STATUS uefi_delete_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file, *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, filename,
				EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(file->Delete, 1, file);

out:
	if (EFI_ERROR(ret) || ret == EFI_WARN_DELETE_FAILURE)
		efi_perror(ret, L"Failed to delete file %s", filename);

	return ret;
}

BOOLEAN uefi_exist_file(EFI_FILE *parent, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *file;

	ret = uefi_call_wrapper(parent->Open, 5, parent, &file, filename,
				EFI_FILE_MODE_READ, 0);
	if (!EFI_ERROR(ret))
		uefi_call_wrapper(file->Close, 1, file);
	else if (ret != EFI_NOT_FOUND) // IO error
		efi_perror(ret, L"Failed to found file %s", filename);

	return ret == EFI_SUCCESS;
}

BOOLEAN uefi_exist_file_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename)
{
	EFI_STATUS ret;
	EFI_FILE *root;
	BOOLEAN ret2;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open volume %s", filename);
		return FALSE;
	}

	ret2 = uefi_exist_file(root, filename);
	uefi_call_wrapper(root->Close, 1, root);

	return ret2;
}

EFI_STATUS uefi_create_directory(EFI_FILE *parent, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *dir;

	ret = uefi_create_dir(parent, &dir, dirname);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create directory %s", dirname);
	} else {
		uefi_call_wrapper(dir->Close, 1, dir);
	}

	return ret;
}

EFI_STATUS uefi_create_directory_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *dirname)
{
	EFI_STATUS ret;
	EFI_FILE *root;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open volume %s", dirname);
		return ret;
	}

	return uefi_create_directory(root, dirname);
}


EFI_STATUS uefi_rename_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *oldname, CHAR16 *newname)
{
	EFI_STATUS ret;
	EFI_FILE *file = NULL, *root = NULL;
	EFI_FILE_INFO *info = NULL;
	UINTN info_size;

	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &root);
	if (EFI_ERROR(ret))
		goto out;

	ret = uefi_call_wrapper(root->Open, 5, root, &file, oldname,
				EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(ret)) {
		goto out;
	}

	info_size = SIZE_OF_EFI_FILE_INFO + FILENAME_MAX_LENGTH;
	info = AllocatePool(info_size);
	if (!info) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &info_size, info);
	if (EFI_ERROR(ret))
		goto out;

	// Set the new file name
	ret = strncpy16_s(info->FileName, FILENAME_MAX_LENGTH / sizeof(CHAR16), newname, FILENAME_MAX_LENGTH / sizeof(CHAR16));
	if (EFI_ERROR(ret))
		goto out;
	info->Size = SIZE_OF_EFI_FILE_INFO + StrLen(info->FileName) * 2 + 2;

	ret = uefi_call_wrapper(file->SetInfo, 4, file, &GenericFileInfo, info->Size, info);

out:
	if (info != NULL)
		FreePool(info);
	if (file != NULL)
		uefi_call_wrapper(file->Close, 1, file);
	if (root != NULL)
		uefi_call_wrapper(root->Close, 1, root);

	return ret;
}


EFI_STATUS verify_image(EFI_HANDLE handle, CHAR16 *path)
{
	EFI_STATUS ret, unload_ret = EFI_SUCCESS;
	EFI_DEVICE_PATH *edp;
	EFI_HANDLE image;

	edp = FileDevicePath(handle, path);
	if (!edp) {
		error(L"Couldn't generate a path for '%s'", path);
		return EFI_INVALID_PARAMETER;
	}

	ret = uefi_call_wrapper(BS->LoadImage, 6, FALSE, g_parent_image,
				edp, NULL, 0, &image);
	FreePool(edp);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to load '%s'", path);
	if (!EFI_ERROR(ret) || ret == EFI_SECURITY_VIOLATION) {
		unload_ret = uefi_call_wrapper(BS->UnloadImage, 1, image);
		if (EFI_ERROR(unload_ret))
			efi_perror(unload_ret, L"Failed to unload image");
	}

	return EFI_ERROR(ret) ? ret : unload_ret;
}

EFI_STATUS uefi_bios_update_capsule(EFI_HANDLE root_dir, CHAR16 *name)
{
	UINTN len = 0;
	UINT64 max = 0;
	EFI_CAPSULE_HEADER *capHeader = NULL;
	EFI_CAPSULE_HEADER **capHeaderArray = NULL;
	EFI_CAPSULE_BLOCK_DESCRIPTOR *scatterList = NULL;
	CHAR8 *content = NULL;
	EFI_RESET_TYPE resetType;
	EFI_STATUS ret;

	if (!root_dir)
		return EFI_INVALID_PARAMETER;

	ret = file_read(root_dir, name, &content, &len);
	if (EFI_ERROR(ret)) {
		if (ret == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		efi_perror(ret, L"Failed to read file %s", name);
		return ret;
	}
	debug(L"Trying to load capsule: %s", name);

	if (len <= 0) {
		error(L"Couldn't load capsule data from disk");
		ret = EFI_LOAD_ERROR;
		goto out;
	}
	/* Some capsules might invoke reset during UpdateCapsule
	 * so delete the file now
	 */
	ret = file_delete(root_dir, name);
	if (ret != EFI_SUCCESS) {
		efi_perror(ret, L"Couldn't delete %s", name);
		goto out;
	}

	capHeader = (EFI_CAPSULE_HEADER *) content;
	capHeaderArray = AllocatePool(2 * sizeof(EFI_CAPSULE_HEADER *));
	if (!capHeaderArray) {
		error(L"Can allocate pool for capsule header");
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}
	capHeaderArray[0] = capHeader;
	capHeaderArray[1] = NULL;
	debug(L"Querying capsule capabilities");
	ret = uefi_call_wrapper(RT->QueryCapsuleCapabilities, 4,
		capHeaderArray, 1,  &max, &resetType);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"QueryCapsuleCapabilities failed");
		goto out;
	}
	if (len > max) {
		error(L"Bad buffer size of QueryCapsuleCapabilities");
		ret = EFI_BAD_BUFFER_SIZE;
		goto out;
	}
	scatterList = AllocatePool(2*sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR));
	if (!scatterList) {
		error(L"Can allocate pool for capsule block");
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}
	memset((CHAR8 *)scatterList, 0x0,
			2 * sizeof(EFI_CAPSULE_BLOCK_DESCRIPTOR));
	scatterList->Length = len;
	scatterList->Union.DataBlock = (EFI_PHYSICAL_ADDRESS) (UINTN) capHeader;

	debug(L"Calling RT->UpdateCapsule");
	ret = uefi_call_wrapper(RT->UpdateCapsule, 3, capHeaderArray, 1,
		(EFI_PHYSICAL_ADDRESS) (UINTN) scatterList);
	if (ret != EFI_SUCCESS) {
		efi_perror(ret, L"UpdateCapsule failed");
		goto out;
	}

	debug(L"I am about to reset the system after BIOS capsules");

	uefi_call_wrapper(RT->ResetSystem, 4, resetType, EFI_SUCCESS, 0, NULL);

out:
	if (content != NULL)
		FreePool(content);
	if (capHeaderArray != NULL)
		FreePool(capHeaderArray);
	if (scatterList != NULL)
		FreePool(scatterList);

	return ret;
}

/* Chainload another EFI application on the ESP with the specified path,
 * optionally deleting the file before entering
 */
EFI_STATUS uefi_enter_binary(EFI_HANDLE part_handle, CHAR16 *path,
		BOOLEAN delete, UINT32 load_options_size, VOID *load_options)
{
	EFI_DEVICE_PATH *edp;
	EFI_STATUS ret;
	EFI_HANDLE image;
	EFI_LOADED_IMAGE *loaded_image;

	if (!part_handle)
		return EFI_INVALID_PARAMETER;

	edp = FileDevicePath(part_handle, path);
	if (!edp) {
		error(L"Couldn't generate a path");
		return EFI_INVALID_PARAMETER;
	}

	ret = uefi_call_wrapper(BS->LoadImage, 6, FALSE, g_parent_image,
			edp, NULL, 0, &image);
	FreePool(edp);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"BS->LoadImage '%s'", path);
		return ret;
	}
	if (delete) {
		ret = file_delete(part_handle, path);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Couldn't delete %s", path);
	}
	if (load_options_size > 0) {
		// Set the command line option
		ret = uefi_call_wrapper(BS->OpenProtocol, 6, image,
				&LoadedImageProtocol, (VOID **)&loaded_image,
				image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"OpenProtocol: LoadedImageProtocol");
			goto out;
		}
		if (loaded_image == NULL) {
			error(L"LoadedImageProtocol, but return image is NULL");
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}
		loaded_image->LoadOptionsSize = load_options_size;
		loaded_image->LoadOptions = load_options;
	}
	ret = uefi_call_wrapper(BS->StartImage, 3, image, NULL, NULL);

out:
	uefi_call_wrapper(BS->UnloadImage, 1, image);

	return ret;
}

EFI_STATUS uefi_check_upgrade(EFI_LOADED_IMAGE *loaded_image,
		CHAR16 *partition, CHAR16 *upgrade_file,
		CHAR16 *self_path1, CHAR16 *bak_path1, CHAR16 *self_path2, CHAR16 *bak_path2)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io = NULL;
	EFI_GUID SimpleFileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_HANDLE part_handle = NULL;
	CHAR16 *self_path = NULL;
	UINTN self_path_len;
	CHAR16 efi_full_path[512];
	CHAR16 *bak_path = NULL;
	UINTN argc;
	CHAR16 **argv;
	CHAR16 *options;

	if (loaded_image == NULL
			|| loaded_image->FilePath == NULL
			|| loaded_image->FilePath->Type != MEDIA_DEVICE_PATH
			|| loaded_image->FilePath->SubType != MEDIA_FILEPATH_DP) {
		// maybe loaded by the "fastboot boot" command, or the BIOS not support
		debug(L"Loaded image or FilePath is NULL");
		return EFI_INVALID_PARAMETER;
	}

	self_path = ((FILEPATH_DEVICE_PATH *)(loaded_image->FilePath))->PathName;
	ret = get_argv(loaded_image, &argc, &argv, &options);
	if (EFI_ERROR(ret))
		goto out;
	if (argc > 0 && argv[0][0] != L'-') {
		// If load from EFI shell, then the loaded_image->FilePath is the working directory of shell,
		// and argv[0] is the efi application path.
		// If load from BIOS boot manager, or other EFI application, then the loaded_image->FilePath
		// is the full path of efi application path.
		self_path_len = StrLen(self_path);
		if (self_path_len > 0) {
			// Build the full path of efi application path.
			if (self_path[self_path_len - 1] == L'\\') {
				// Loaded from EFI shell root directory, ended with '\'.
				SPrint(efi_full_path, sizeof(efi_full_path), L"%s%s", self_path, argv[0]);
				self_path = efi_full_path;
			} else if (self_path_len <= 4 || StrcaseCmp(self_path + self_path_len - 4, L".EFI")) {
				// Loaded from EFI shell and not root directory, need add '\'.
				SPrint(efi_full_path, sizeof(efi_full_path), L"%s\\%s", self_path, argv[0]);
				self_path = efi_full_path;
			}
		} else
			self_path = argv[0];
	}
	FreePool(argv);
	FreePool(options);
	debug(L"EFI path: %s", self_path);

	if (!StrcaseCmp(self_path, self_path1))
		bak_path = bak_path1;
	else if (!StrcaseCmp(self_path, self_path2))
		bak_path = bak_path2;
	else {
		debug(L"Unsupported running path for check upgrade");
		goto out;
	}

	ret = gpt_get_partition_handle(partition, LOGICAL_UNIT_USER, &part_handle);
	if (EFI_ERROR(ret)) {
		if (ret != EFI_NOT_FOUND)
			efi_perror(ret, L"Failed to find partition %s", partition);
		goto out;
	}

	ret = handle_protocol(part_handle, &SimpleFileSystemProtocol, (void **)&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"HandleProtocol for FAT in partition %s failed", partition);
		goto out;
	}

	if (!uefi_exist_file_root(io, upgrade_file)) {
		debug(L"Upgrade file %s is not exist", upgrade_file);
		goto out;
	}
	debug(L"Upgrade file %s is exist", upgrade_file);

	ret = verify_image(part_handle, upgrade_file);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Verify upgrade image failed");
		uefi_delete_file(io, upgrade_file);
		goto out;
	}
	debug(L"Success to verify the upgrade image");

	// Verify it again
	if (!uefi_exist_file_root(io, self_path)) {
		error(L"Can't find file %s", self_path);
		ret = EFI_NOT_FOUND;
		goto out;
	}

	if (uefi_exist_file_root(io, bak_path)) {
		ret = uefi_delete_file(io, bak_path);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to delete %s", bak_path);
			goto out;
		}
		debug(L"Success to delete old %s", bak_path);
	}
	ret = uefi_rename_file(io, self_path, bak_path);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to rename the %s to %s", self_path, bak_path);
		goto out;
	}
	debug(L"Success rename file %s to %s", self_path, bak_path);
	ret = uefi_rename_file(io, upgrade_file, self_path);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to rename the upgrade file %s to %s", upgrade_file, self_path);
		goto out;
	}
	debug(L"Success rename the upgrade file %s to %s", upgrade_file, self_path);

	error(L"I am about to load the new boot loader after upgrade it");
	if (loaded_image != NULL)
		uefi_enter_binary(part_handle, self_path, FALSE, loaded_image->LoadOptionsSize, loaded_image->LoadOptions);
	reboot(NULL, EfiResetCold);

out:
	return ret;
}
