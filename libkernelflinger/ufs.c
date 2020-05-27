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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#include <lib.h>
#include "storage.h"
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"

/* Latest gnu-efi still does not define 'MSG_UFS_DP', Add this
 * macro definition here for adapt to UFS storage detect in
 * BIOS (which build under EDK2).
 */
#ifndef MSG_UFS_DP
#define MSG_UFS_DP	0x19
#endif

static EFI_DEVICE_PATH *get_ufs_device_path(EFI_DEVICE_PATH *p)
{
	for (; !IsDevicePathEndType(p); p = NextDevicePathNode(p))
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
		    && DevicePathSubType(p) == MSG_UFS_DP)
			return p;
	return NULL;
}

static EFI_STATUS ufs_erase_blocks(EFI_HANDLE handle, __attribute__((unused)) EFI_BLOCK_IO *bio, EFI_LBA start, EFI_LBA end)
{
	EFI_STATUS ret;
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET scsi_req;
	struct unmap_parameter unmap;
	struct command_descriptor_block_unmap cdb;
	EFI_HANDLE scsi_handle;
	EFI_DEVICE_PATH *dp = DevicePathFromHandle(handle);
	EFI_DEVICE_PATH *scsi_dp = dp;
	UINT8 target_bytes[TARGET_MAX_BYTES];
	UINT8 *target = target_bytes;
	UINT64 lun;

	if (!dp) {
		error(L"Failed to get device path from handle");
		return EFI_INVALID_PARAMETER;
	}
	ret = uefi_call_wrapper(BS->LocateDevicePath, 3, &ScsiPassThruProtocolGuid,
				&scsi_dp, &scsi_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to locate SCSI root device");
		return ret;
	}

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, scsi_handle,
				&ScsiPassThruProtocolGuid, (void *)&scsi);
	if (EFI_ERROR(ret)) {
		error(L"failed to get scsi protocol");
		return ret;
	}

	scsi_dp = get_ufs_device_path(dp);
	if (!scsi_dp) {
		error(L"Failed to get SCSI device path");
		return EFI_NOT_FOUND;
	}

	ret = uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, scsi_dp, (UINT8 **)&target, &lun);
	if (EFI_ERROR(ret)) {
		error(L"Failed to get LUN of current device");
		return ret;
	}

	ZeroMem(&scsi_req, sizeof(scsi_req));
	ZeroMem(&unmap, sizeof(unmap));
	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_UNMAP;
	cdb.param_length = htobe16(sizeof(unmap));

	unmap.data_length = htobe16(sizeof(unmap) - sizeof(unmap.data_length));
	unmap.block_desc_length = htobe16(sizeof(unmap.block_desc));
	unmap.block_desc.lba = htobe64(start);
	unmap.block_desc.count = htobe32(end - start + 1);

	scsi_req.Timeout = BLOCK_TIMEOUT * (end - start + 1);
	scsi_req.OutDataBuffer = &unmap;
	scsi_req.Cdb = &cdb;
	scsi_req.OutTransferLength = sizeof(unmap);
	scsi_req.CdbLength = sizeof(cdb);
	scsi_req.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_WRITE;

	ret = uefi_call_wrapper(scsi->PassThru, 5, scsi, target, lun, &scsi_req, NULL);
	return ret;
}


static UINT64 lun_factory = UFS_DEFAULT_FACTORY_LUN;
static UINT64 lun_user = UFS_DEFAULT_USER_LUN;
#define LUN_UNKNOWN ((UINT64)-1)

static UINT64 log_unit_to_ufs_lun(logical_unit_t log_unit)
{
	switch(log_unit) {
	case LOGICAL_UNIT_USER:
		return lun_user;
	case LOGICAL_UNIT_FACTORY:
		return lun_factory;
	default:
		error(L"Unknown logical partition %d", log_unit);
		return LUN_UNKNOWN;
	}
}

static EFI_STATUS ufs_check_logical_unit(EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_STATUS ret;
	UINT8 target_bytes[TARGET_MAX_BYTES];
	UINT8 *target = target_bytes;
	UINT64 target_lun;
	UINT64 lun;
	EFI_HANDLE scsi_handle;

	lun = log_unit_to_ufs_lun(log_unit);
	if (lun == LUN_UNKNOWN)
		return EFI_NOT_FOUND;

	ret = uefi_call_wrapper(BS->LocateDevicePath, 3, &ScsiPassThruProtocolGuid,
				&p, &scsi_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to locate SCSI root device");
		return ret;
	}

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, scsi_handle,
				&ScsiPassThruProtocolGuid, (void *)&scsi);
	if (EFI_ERROR(ret)) {
		error(L"failed to get scsi protocol");
		return ret;
	}

	p = get_ufs_device_path(p);
	if (!p)
		return EFI_NOT_FOUND;

	ret = uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, p, (UINT8 **)&target, &target_lun);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to get LUN for device");

	/* First byte is used to identify well known logical units like Boot.
	 * Here we only want normal logical units so first byte must be 0
	 * Second byte contains the LUN number.
	 */
	if ((target_lun & 0xFF) != 0)
		return EFI_NOT_FOUND;
	target_lun = (target_lun >> 8) & 0xFF;

	return target_lun == lun ? EFI_SUCCESS : EFI_NOT_FOUND;
}

static EFI_STATUS ufs_detect_user_unit(EFI_DEVICE_PATH *p)
{
	EFI_GUID ScsiPassThruProtocolGuid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *scsi;
	EFI_STATUS ret;
	UINT8 target_bytes[TARGET_MAX_BYTES];
	UINT8 *target = target_bytes;
	UINT64 boot_lun;

	EFI_HANDLE scsi_handle;

	ret = uefi_call_wrapper(BS->LocateDevicePath, 3, &ScsiPassThruProtocolGuid,
				&p, &scsi_handle);
	if (EFI_ERROR(ret)) {
		error(L"Failed to locate SCSI root device");
		return ret;
	}

	ret = uefi_call_wrapper(BS->HandleProtocol, 3, scsi_handle,
				&ScsiPassThruProtocolGuid, (void *)&scsi);
	if (EFI_ERROR(ret)) {
		error(L"failed to get scsi protocol");
		return ret;
	}

	p = get_ufs_device_path(p);
	if (!p)
		return EFI_NOT_FOUND;

	ret = uefi_call_wrapper(scsi->GetTargetLun, 4, scsi, p, (UINT8 **)&target,
				&boot_lun);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to get LUN for device");

	/* First byte is used to identify well known logical units like Boot.
	 * Here we only want normal logical units so first byte must be 0
	 * Second byte contains the LUN number.
	 */
	if ((boot_lun & 0xFF) != 0)
		return EFI_NOT_FOUND;
	lun_user = (boot_lun >> 8) & 0xFF;

	return EFI_SUCCESS;


}

static BOOLEAN is_ufs(EFI_DEVICE_PATH *p)
{
	BOOLEAN ret = FALSE;
	if (get_ufs_device_path(p) != NULL) {
		ufs_detect_user_unit(p);
		ret = TRUE;
	}
	return ret;
}

/*for Installer.efi, can't get LUN of user from boot image, must input from outside
 *if UFS layout is not default
 */
static EFI_STATUS ufs_set_log_unit_lun(UINT64 new_lun_user, UINT64 new_lun_factory)
{
	if ((new_lun_user > UFS_MAX_LUN) || (new_lun_factory > UFS_MAX_LUN))
		return EFI_INVALID_PARAMETER;
	lun_user = new_lun_user;
	lun_factory = new_lun_factory;
	return EFI_SUCCESS;
}

struct storage STORAGE(STORAGE_UFS) = {
	.erase_blocks = ufs_erase_blocks,
	.check_logical_unit = ufs_check_logical_unit,
	.set_logical_unit = ufs_set_log_unit_lun,
	.probe = is_ufs,
	.name = L"UFS"
};
