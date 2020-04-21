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

#ifndef __UEFI_UTILS_H__
#define __UEFI_UTILS_H__

#include <efi.h>
#include <efilib.h>

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1)/(y))
#define ALIGN(x, y) ((y) * DIV_ROUND_UP((x), (y)))
#define ALIGN_DOWN(x, y) ((y) * ((x) / (y)))

EFI_STATUS get_esp_fs(EFI_FILE_IO_INTERFACE **esp_fs);
EFI_STATUS uefi_open_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, EFI_FILE **file);
EFI_STATUS uefi_get_file_size(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, UINTN *size);
EFI_STATUS uefi_read_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void **data, UINTN *size);
EFI_STATUS uefi_write_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN *size);
EFI_STATUS uefi_write_file_with_dir(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename, void *data, UINTN size);
EFI_STATUS uefi_create_dir(EFI_FILE *parent, EFI_FILE **dir, CHAR16 *dirname);
EFI_STATUS uefi_delete_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename);
EFI_STATUS find_device_partition(const EFI_GUID *guid, EFI_HANDLE **handles, UINTN *no_handles);
BOOLEAN uefi_exist_file_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *filename);
EFI_STATUS uefi_create_directory(EFI_FILE *parent, CHAR16 *dirname);
EFI_STATUS uefi_create_directory_root(EFI_FILE_IO_INTERFACE *io, CHAR16 *dirname);
EFI_STATUS uefi_rename_file(EFI_FILE_IO_INTERFACE *io, CHAR16 *oldname, CHAR16 *newname);
EFI_STATUS verify_image(EFI_HANDLE handle, CHAR16 *path);
EFI_STATUS uefi_bios_update_capsule(EFI_HANDLE root_dir, CHAR16 *name);
EFI_STATUS uefi_enter_binary(EFI_HANDLE part_handle, CHAR16 *path,
		BOOLEAN delete, UINT32 load_options_size, VOID *load_options);
EFI_STATUS uefi_check_upgrade(EFI_LOADED_IMAGE *loaded_image,
		CHAR16 *partition, CHAR16 *upgrade_file,
		CHAR16 *self_path1, CHAR16 *bak_path1, CHAR16 *self_path2, CHAR16 *bak_path2);

#endif /* __UEFI_UTILS_H__ */
