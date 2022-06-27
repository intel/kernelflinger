/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
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
#include <log.h>
#include <lib.h>
#include "storage.h"
#include "gpt.h"
#include "pci.h"
#include "protocol/EraseBlock.h"
#include "timer.h"

static struct storage *cur_storage;
static PCI_DEVICE_PATH boot_device = { .Function = -1, .Device = -1 };
static SCSI_DEVICE_PATH boot_device_scsi = { .Pun = -1, .Lun = -1 };
static enum storage_type boot_device_type;
static BOOLEAN initialized = FALSE;
static EFI_DEVICE_PATH *exclude_device = NULL;

// The EFI_HANDLE of boot device.
// It maybe a handle to a partition of the kernelflinger loaded.
static EFI_HANDLE boot_device_handle;

static BOOLEAN is_boot_device(EFI_DEVICE_PATH *p)
{
	PCI_DEVICE_PATH *pci;

	if (boot_device.Header.Type == 0 && boot_device_scsi.Header.Type == 0)
		return FALSE;

	pci = get_pci_device_path(p);
	if (pci == NULL) {
		SCSI_DEVICE_PATH *scsi =  get_scsi_device_path(p);

		if (scsi == NULL)
			return 0;

		return scsi->Pun == boot_device_scsi.Pun && scsi->Lun == boot_device_scsi.Lun;
	}

	return pci && pci->Function == boot_device.Function
		&& pci->Device == boot_device.Device;
}

extern struct storage STORAGE(STORAGE_EMMC);
extern struct storage STORAGE(STORAGE_UFS);
extern struct storage STORAGE(STORAGE_SDCARD);
extern struct storage STORAGE(STORAGE_SATA);
extern struct storage STORAGE(STORAGE_NVME);
extern struct storage STORAGE(STORAGE_ISCSI);
extern struct storage STORAGE(STORAGE_VIRTUAL);
#ifdef USB_STORAGE
extern struct storage STORAGE(STORAGE_USB);
#endif
extern struct storage STORAGE(STORAGE_GENERAL_BLOCK);


static EFI_STATUS identify_storage(EFI_DEVICE_PATH *device_path,
				   enum storage_type filter,
				   struct storage **storage,
				   enum storage_type *type)
{
	enum storage_type st;
	static struct storage *supported_storage[STORAGE_ALL] = {
		&STORAGE(STORAGE_EMMC)
		, &STORAGE(STORAGE_UFS)
		, &STORAGE(STORAGE_SDCARD)
		, &STORAGE(STORAGE_SATA)
		, &STORAGE(STORAGE_NVME)
		, &STORAGE(STORAGE_VIRTUAL)
		, &STORAGE(STORAGE_ISCSI)
#ifdef USB_STORAGE
		, &STORAGE(STORAGE_USB)
#endif
		, &STORAGE(STORAGE_GENERAL_BLOCK)
	};

	for (st = STORAGE_EMMC; st < STORAGE_ALL; st++) {
		if ((filter == st || filter == STORAGE_ALL) &&
		    supported_storage[st] && supported_storage[st]->probe(device_path)) {
			debug(L"%s storage identified", supported_storage[st]->name);
			*storage = supported_storage[st];
			*type = st;
			return EFI_SUCCESS;
		}
	}

	return EFI_UNSUPPORTED;
}

BOOLEAN is_same_device(EFI_DEVICE_PATH *p, EFI_DEVICE_PATH *e)
{
	if (!p)
		return FALSE;
	if (!e)
		return FALSE;

	while (!IsDevicePathEndType(p)) {
		if (DevicePathType(p) == MEDIA_DEVICE_PATH) {
			p = NextDevicePathNode(p);
			continue;
		}
		while (!IsDevicePathEndType(e)) {
			if (DevicePathType(e) == MEDIA_DEVICE_PATH) {
				e = NextDevicePathNode(e);
				continue;
			}
			break;
		}
		if (IsDevicePathEndType(e))
			return FALSE;

		if (DevicePathNodeLength(p) != DevicePathNodeLength(e))
			return FALSE;
		if (memcmp(p, e, DevicePathNodeLength(p)))
			return FALSE;
		e = NextDevicePathNode(e);
		p = NextDevicePathNode(p);
	}
	while (!IsDevicePathEndType(e)) {
		if (DevicePathType(e) != MEDIA_DEVICE_PATH)
			return FALSE;
		e = NextDevicePathNode(e);
	}

	return TRUE;
}

EFI_STATUS identify_scsi_boot_device(enum storage_type filter)
{
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path;
	SCSI_DEVICE_PATH *scsi = NULL;
	struct storage *storage;
	enum storage_type type;
	EFI_HANDLE new_boot_device_handle = NULL;
	SCSI_DEVICE_PATH new_boot_device = { .Pun = -1, .Lun = -1 };
	enum storage_type new_boot_device_type;
	struct storage *new_storage;

	new_storage = NULL;
	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	new_boot_device.Header.Type = 0;
	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (!device_path)
			continue;

		scsi = get_scsi_device_path(device_path);
		if (!scsi)
			continue;

		if (is_same_device(device_path, exclude_device))
			continue;

		if (new_boot_device.Pun == scsi->Pun &&
				new_boot_device.Lun == scsi->Lun &&
				new_boot_device.Header.Type == scsi->Header.Type &&
				new_boot_device.Header.SubType == scsi->Header.SubType)
			continue;

		ret = identify_storage(device_path, filter, &storage, &type);
		if (EFI_ERROR(ret))
			continue;

		if (!new_boot_device.Header.Type || new_boot_device_type >= type) {
				ret = memcpy_s(&new_boot_device, sizeof(new_boot_device), scsi,
							   sizeof(new_boot_device));
				if (EFI_ERROR(ret)) {
						FreePool(handles);
						return ret;
				}
				new_boot_device_type = type;
				new_storage = storage;
				new_boot_device_handle = handles[i];
			continue;
		}

		if (new_boot_device_type == type &&
				type != STORAGE_GENERAL_BLOCK &&
				filter > type) {
			error(L"Multiple identifcal storage found! Can't make a decision");
			new_storage = NULL;
			new_boot_device.Header.Type = 0;
			FreePool(handles);
			return EFI_UNSUPPORTED;
		}
	}

	FreePool(handles);

	if (!new_storage) {
		error(L"No SCSI storage found for type %d", filter);
		return EFI_UNSUPPORTED;
	}
	cur_storage = new_storage;
	boot_device_type = new_boot_device_type;
	boot_device_handle = new_boot_device_handle;
	boot_device_scsi = new_boot_device;

	debug(L"%s storage selected", cur_storage->name);
	return EFI_SUCCESS;
}


EFI_STATUS identify_boot_device(enum storage_type filter)
{
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path;
	PCI_DEVICE_PATH *pci = NULL;
	struct storage *storage;
	enum storage_type type;
	EFI_HANDLE new_boot_device_handle = NULL;
	PCI_DEVICE_PATH new_boot_device = { .Function = -1, .Device = -1 };
	enum storage_type new_boot_device_type;
	struct storage *new_storage;

	new_storage = NULL;
	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	new_boot_device.Header.Type = 0;
	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (!device_path)
			continue;

		pci = get_pci_device_path(device_path);
		if (!pci)
			continue;

		if (is_same_device(device_path, exclude_device))
			continue;

		if (new_boot_device.Function == pci->Function &&
				new_boot_device.Device == pci->Device &&
				new_boot_device.Header.Type == pci->Header.Type &&
				new_boot_device.Header.SubType == pci->Header.SubType)
			continue;

		ret = identify_storage(device_path, filter, &storage, &type);
		if (EFI_ERROR(ret))
			continue;

		if (!new_boot_device.Header.Type || new_boot_device_type >= type) {
				ret = memcpy_s(&new_boot_device, sizeof(new_boot_device), pci,
							   sizeof(new_boot_device));
				if (EFI_ERROR(ret)) {
						FreePool(handles);
						return ret;
				}
				new_boot_device_type = type;
				new_storage = storage;
				new_boot_device_handle = handles[i];
			continue;
		}

		if (new_boot_device_type == type &&
				type != STORAGE_GENERAL_BLOCK &&
				filter > type) {
			error(L"Multiple identifcal storage found! Can't make a decision");
			new_storage = NULL;
			new_boot_device.Header.Type = 0;
			FreePool(handles);
			return EFI_UNSUPPORTED;
		}
	}

	FreePool(handles);

	if (!new_storage) {
		return identify_scsi_boot_device(filter);
	}
	cur_storage = new_storage;
	boot_device_type = new_boot_device_type;
	boot_device_handle = new_boot_device_handle;
	ret = memcpy_s(&boot_device, sizeof(boot_device), &new_boot_device, sizeof(new_boot_device));
	if (EFI_ERROR(ret))
		return ret;

	debug(L"%s storage selected", cur_storage->name);
	return EFI_SUCCESS;
}

static BOOLEAN valid_storage(void)
{
	if (!initialized) {
		initialized = TRUE;
		return !EFI_ERROR(identify_boot_device(STORAGE_ALL));
	}

	return (boot_device.Header.Type || boot_device_scsi.Header.Type) && cur_storage;
}

static EFI_STATUS media_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end)
{
	EFI_DEVICE_PATH *dev_path;
	EFI_GUID guid = EFI_ERASE_BLOCK_PROTOCOL_GUID;
	EFI_ERASE_BLOCK_PROTOCOL *erase_blockp;
	UINTN size, erase_granularity;
	EFI_STATUS ret;
	EFI_HANDLE storage_handle = NULL;
	EFI_LBA left;

	dev_path = DevicePathFromHandle(handle);
	if (!dev_path) {
		error(L"Failed to get device path");
		return EFI_DEVICE_ERROR;
	}

	ret = uefi_call_wrapper(BS->LocateDevicePath, 3,
			&guid, &dev_path, &storage_handle);
	if (EFI_ERROR(ret))
		return EFI_UNSUPPORTED;

	ret = uefi_call_wrapper(BS->HandleProtocol, 3,
			storage_handle, &guid, (void **)&erase_blockp);
	if (EFI_ERROR(ret))
		return EFI_UNSUPPORTED;

	erase_granularity = erase_blockp->EraseLengthGranularity;

	/* check if space to be erased is lesser than group size
	 * in such a case we cannot afford a group erase.
	 */
	if ((end - start + 1) < erase_granularity) {
		ret = fill_zero(bio, start, end);
		if (EFI_ERROR(ret))
			error(L"Failed to fill with zeros");

		return ret;
	}

	left = start % erase_granularity;
	if (left) {
		ret = fill_zero(bio, start, start + erase_granularity - left - 1);
		if (EFI_ERROR(ret)) {
			error(L"Failed to fill with zeros");
			return ret;
		}
		start += erase_granularity - left;
	}

	left = (end + 1) % erase_granularity;
	if (left) {
		ret = fill_zero(bio, end + 1 - left, end);
		if (EFI_ERROR(ret)) {
			error(L"Failed to fill with zeros");
			return ret;
		}
		end -= left;
	}

	size = (end - start + 1) * bio->Media->BlockSize;
	ret = uefi_call_wrapper(erase_blockp->EraseBlocks, 5, erase_blockp, bio->Media->MediaId,
			start, NULL, size);
	if (EFI_ERROR(ret))
		error(L"EFI_ERASE_BLOCK_PROTOCOL failed to erase block");

	return ret;
}

EFI_STATUS storage_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	if (!valid_storage())
		return EFI_UNSUPPORTED;

	if (!is_boot_device(p))
		return EFI_UNSUPPORTED;

	return cur_storage->check_logical_unit(p, log_unit);
}

EFI_STATUS storage_erase_blocks(EFI_HANDLE handle, EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end)
{
	EFI_STATUS ret;

	if (!valid_storage())
		return EFI_UNSUPPORTED;

	/* check if underlying BIOS supports ERASE_BLOCK_PROTOCOL
	 * If so use ERASE_BLOCK_PROTOCOL to erase blocks.
	 */
	ret = media_erase_blocks(handle, bio, start, end);
	if (ret == EFI_SUCCESS || ret != EFI_UNSUPPORTED)
		return ret;

	debug(L"ERASE_BLOCK_PROTOCOL not supported");
	return cur_storage->erase_blocks(handle, bio, start, end);
}

EFI_STATUS fill_with(EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end,
			    VOID *pattern, UINTN pattern_blocks)
{
	EFI_LBA lba;
	UINT64 size;
	uint32_t total, print_sec, print_prev;
	EFI_STATUS ret;

	debug(L"Fill lba %d -> %d", start, end);
	if (end <= start)
		return EFI_INVALID_PARAMETER;

	total = end - start +1;
	info_n(L"Erasing ");
	print_sec = boottime_in_msec() / 1000;
	print_prev = 0;
	for (lba = start; lba <= end; lba += pattern_blocks) {
		if (lba + pattern_blocks > end + 1)
			size = end - lba + 1;
		else
			size = pattern_blocks;

		ret = uefi_call_wrapper(bio->WriteBlocks, 5, bio, bio->Media->MediaId, lba,
				bio->Media->BlockSize * size, pattern);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to erase block %ld", lba);
			return ret;
		}

		print_progress(lba + size - start, total, boottime_in_msec() / 1000, &print_sec, &print_prev);
	}
	print_progress(total, total, boottime_in_msec() / 1000, &print_sec, &print_prev);
	info_n(L"\n");

	return EFI_SUCCESS;
}

EFI_STATUS fill_zero(EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end)
{
	EFI_STATUS ret;
	VOID *emptyblock;
	VOID *aligned_emptyblock;

	ret = alloc_aligned(&emptyblock, &aligned_emptyblock,
			    bio->Media->BlockSize * N_BLOCK,
			    bio->Media->IoAlign);
	if (EFI_ERROR(ret))
		return ret;

	ret = fill_with(bio, start, end, aligned_emptyblock, N_BLOCK);

	FreePool(emptyblock);

	return ret;
}

EFI_STATUS storage_set_boot_device(EFI_HANDLE device)
{
	EFI_DEVICE_PATH *device_path  = DevicePathFromHandle(device);
	EFI_STATUS ret;
	PCI_DEVICE_PATH *pci;
	CHAR16 *dps;

	if (!device_path) {
		error(L"Failed to get device path from boot handle");
		return EFI_UNSUPPORTED;
	}

	ret = identify_storage(device_path, STORAGE_ALL, &cur_storage, &boot_device_type);
	if (EFI_ERROR(ret)) {
		error(L"Boot device unsupported");
		return ret;
	}

	pci = get_pci_device_path(device_path);
	if (!pci) {
		SCSI_DEVICE_PATH *scsi = get_scsi_device_path(device_path);
		if (scsi == NULL) {
			error(L"Only PCI/SCSI boot device is supported");
			return EFI_UNSUPPORTED;
		}

		error(L"Setting boot device to: SCSI");
		initialized = TRUE;
		boot_device_scsi = *scsi;
		boot_device_handle = device;
		return EFI_SUCCESS;
	}

	dps = DevicePathToStr((EFI_DEVICE_PATH *)pci);
	debug(L"Setting PCI boot device to: %s", dps);
	FreePool(dps);

	initialized = TRUE;
	ret = memcpy_s(&boot_device, sizeof(boot_device), pci, sizeof(boot_device));
	if (EFI_ERROR(ret))
		return ret;
	boot_device_handle = device;
	return EFI_SUCCESS;
}

EFI_HANDLE get_boot_device_handle(void)
{
	return boot_device_handle;
}

const char *get_boot_device_var(void)
{
	static char boot_device_var[64]; // MAX_VARIABLE_LENGTH
	PCI_DEVICE_PATH *pci;
	CHAR16 *dps;
	EFI_DEVICE_PATH *device_path = DevicePathFromHandle(boot_device_handle);

	if (!device_path) {
		error(L"Failed to get device path from boot handle");
		return NULL;
	}

	pci = get_pci_device_path(device_path);
	if (!pci) {
		error(L"Boot device is not PCI, unsupported");
		return NULL;
	}

	dps = DevicePathToStr((EFI_DEVICE_PATH *)pci);
	debug(L"The boot device is %s", dps);
	efi_snprintf((CHAR8 *)boot_device_var, sizeof(boot_device_var), (CHAR8 *)"%s", dps);
	FreePool(dps);

	return boot_device_var;
}

PCI_DEVICE_PATH *get_boot_device(void)
{
	EFI_STATUS ret;

	if (!initialized) {
		ret = identify_boot_device(STORAGE_ALL);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to get boot device");
		else
			initialized = TRUE;
	}

	if (boot_device_scsi.Header.Type)
		return (PCI_DEVICE_PATH *)&boot_device_scsi;
	return boot_device.Header.Type == 0 ? NULL : &boot_device;
}


EFI_STATUS get_boot_device_type(enum storage_type *type)
{
	PCI_DEVICE_PATH *boot_device;

	if (!type)
		return EFI_INVALID_PARAMETER;

	boot_device = get_boot_device();

	if (boot_device) {
		*type = boot_device_type;
		return EFI_SUCCESS;
	}
	return EFI_DEVICE_ERROR;
}

BOOLEAN is_cur_storage_ufs(void)
{
	if (cur_storage == &STORAGE(STORAGE_UFS))
		return TRUE;
	else
		return FALSE;
}

EFI_STATUS set_logical_unit(UINT64 user_lun, UINT64 factory_lun)
{
	if (cur_storage && cur_storage->set_logical_unit)
		return cur_storage->set_logical_unit(user_lun, factory_lun);
	return EFI_UNSUPPORTED;
}

EFI_STATUS get_logical_block_size(UINTN *logical_blk_size)
{
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;

	ret = gpt_get_root_disk(&gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get disk information");
		return ret;
	}

	*logical_blk_size = gparti.bio->Media->BlockSize;

	return EFI_SUCCESS;
}

EFI_STATUS storage_get_erase_block_size(UINTN *erase_blk_size)
{
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;
	struct gpt_partition_interface gparti;

	if (cur_storage->get_erase_block_size) {
		ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol, &BlockIoProtocol, NULL, &nb_handle, &handles);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to locate Block IO Protocol");
			return ret;
		}

		for (i = 0; i < nb_handle; i++) {
			device_path = DevicePathFromHandle(handles[i]);
			if (is_boot_device(device_path))
				break;
		}

		if (i == nb_handle)
			goto notfound;

		return cur_storage->get_erase_block_size(handles[i], erase_blk_size);
	}

notfound:
	ret = gpt_get_root_disk(&gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get disk information");
		return ret;
	}

	*erase_blk_size = gparti.bio->Media->BlockSize;

	return EFI_SUCCESS;
}

BOOLEAN is_live_boot(void)
{
#ifdef LIVE_BOOT
	return cur_storage == &STORAGE(STORAGE_USB);
#else
	return FALSE;
#endif
}

BOOLEAN is_boot_device_virtual(void)
{
	return cur_storage == &STORAGE(STORAGE_VIRTUAL);
}

#define PRINT_INTERVAL (3)
void print_progress(EFI_LBA done, EFI_LBA total, uint32_t sec, uint32_t *print_sec, uint32_t *prev)
{
	UINT64 progress = 0;
	CHAR8 buf[128];
	CHAR8 *pos = buf;
	CHAR16 *temp;
	uint32_t print_prev = *prev;

	progress = done * 50 / total;
	if (sec - *print_sec > PRINT_INTERVAL || progress == 50) {
		for (; print_prev <= progress; print_prev++) {
			if (print_prev % 5 == 0)
				pos += strlen(itoa(print_prev * 2, pos, 10));
			else
				*pos++ = '.';
		}
		*pos = '\0';
		temp = stra_to_str(buf);
		if (temp) {
			info_n(L"%s", temp);
			FreePool(temp);
		}
		pos = buf;
		*print_sec = sec;
		*prev = print_prev;
	}
}

void set_exclude_device(EFI_HANDLE device)
{
	CHAR16 *dps;

	if (device == NULL) {
		exclude_device = NULL;
		return;
	}

	exclude_device = DevicePathFromHandle(device);
	if (exclude_device == NULL)
		return;

	dps = DevicePathToStr(exclude_device);
	warning(L"Exclude device from installation: %s", dps);
	FreePool(dps);
}

EFI_DEVICE_PATH *get_exclude_device(void)
{
	return exclude_device;
}

