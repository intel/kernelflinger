/*
 * Copyright (c) 2017, Intel Corporation
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

#include "protocol/NvmExpressHci.h"
#include "protocol/DevicePath.h"
#include "protocol/NvmExpressPassthru.h"

#define EFI_TIMER_PERIOD_SECONDS(Seconds)     ((UINT64)(Seconds) * 10000000)
#define NVME_GENERIC_TIMEOUT                  (EFI_TIMER_PERIOD_SECONDS(5))
#define NVME_MAX_WRITE_ZEROS_BLOCKS           0x10000

#define NVME_CTRL_ONCS_WRITE_ZEROES           (1 << 3)

#define NVME_RW_FUA               (1 << 14)
#define NVME_CMD_WRITE_ZEROS      0x08
#define NVME_CONTROLLER_ID        0

#define MSG_NVME_NAMESPACE_DP     0x17

#define ATTR_UNUSED __attribute__((unused))

typedef struct {
	EFI_DEVICE_PATH_PROTOCOL        Header;
	UINT32                          NamespaceId;
	UINT64                          NamespaceUuid;
} NVME_NAMESPACE_DEVICE_PATH;


EFI_STATUS get_nvme_passthru(EFI_DEVICE_PATH *FilePath, VOID **Interface)
{
	EFI_GUID gEfiNvmExpressPassThruProtocolGuid = EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID;
	EFI_STATUS              Status;
	EFI_HANDLE              Device;

	Status = uefi_call_wrapper(BS->LocateDevicePath, 3, &gEfiNvmExpressPassThruProtocolGuid, &FilePath, &Device);
	if (!EFI_ERROR(Status)) {
		Status = uefi_call_wrapper(BS->HandleProtocol, 3, Device, &gEfiNvmExpressPassThruProtocolGuid, Interface);
		debug(L"Locate NvmExpressPassThru: ret=%d", Status);
	}

	if (EFI_ERROR(Status))
		*Interface = NULL;

	return Status;
}

static NVME_NAMESPACE_DEVICE_PATH *get_nvme_device_path(EFI_DEVICE_PATH *p)
{
	for (; !IsDevicePathEndType(p); p = NextDevicePathNode(p)) {
		if (DevicePathType(p) == MESSAGING_DEVICE_PATH
		   && DevicePathSubType(p) == MSG_NVME_NAMESPACE_DP)
			return (NVME_NAMESPACE_DEVICE_PATH *)p;
	}

	return NULL;
}

static BOOLEAN is_nvme_supported_write_zeros(EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassthru)
{
	NVME_ADMIN_CONTROLLER_DATA CtrlData;

	EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET CommandPacket;
	EFI_NVM_EXPRESS_COMMAND                  Command;
	EFI_NVM_EXPRESS_COMPLETION               Completion;
	EFI_STATUS                               Status;

	ZeroMem(&CommandPacket, sizeof(EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET));
	ZeroMem(&Command, sizeof(EFI_NVM_EXPRESS_COMMAND));
	ZeroMem(&Completion, sizeof(EFI_NVM_EXPRESS_COMPLETION));

	Command.Cdw0.Opcode = NVME_ADMIN_IDENTIFY_CMD;

	/* According to Nvm Express 1.1 spec Figure 38, When not used, the field shall be cleared to 0h.
	 * For the Identify command, the Namespace Identifier is only used for the Namespace data structure.
	 */
	Command.Nsid        = 0;

	CommandPacket.NvmeCmd        = &Command;
	CommandPacket.NvmeCompletion = &Completion;
	CommandPacket.TransferBuffer = (VOID *) &CtrlData;
	CommandPacket.TransferLength = sizeof(NVME_ADMIN_CONTROLLER_DATA);
	CommandPacket.CommandTimeout = NVME_GENERIC_TIMEOUT;
	CommandPacket.QueueType      = NVME_ADMIN_QUEUE;

	/* Set bit 0 (Cns bit) to 1 to identify a controller */
	Command.Cdw10                = 1;
	Command.Flags                = CDW10_VALID;

	Status = NvmePassthru->PassThru(NvmePassthru, NVME_CONTROLLER_ID, &CommandPacket, NULL);
	if (EFI_ERROR(Status))
		return FALSE;

	if (CtrlData.Oncs & NVME_CTRL_ONCS_WRITE_ZEROES)
		return TRUE;

	return FALSE;
}

EFI_STATUS nvme_erase_blocks_impl(
	EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassthru,
	UINT32 NamespaceId,
	UINT64 Lba,
	UINT32 Blocks
)
{
	EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET CommandPacket;
	EFI_NVM_EXPRESS_COMMAND                  Command;
	EFI_NVM_EXPRESS_COMPLETION               Completion;
	EFI_STATUS                               Status;

	ZeroMem(&CommandPacket, sizeof(EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET));
	ZeroMem(&Command, sizeof(EFI_NVM_EXPRESS_COMMAND));
	ZeroMem(&Completion, sizeof(EFI_NVM_EXPRESS_COMPLETION));

	CommandPacket.NvmeCmd        = &Command;
	CommandPacket.NvmeCompletion = &Completion;

	CommandPacket.NvmeCmd->Cdw0.Opcode = NVME_CMD_WRITE_ZEROS;
	CommandPacket.NvmeCmd->Nsid  = NamespaceId;

	CommandPacket.TransferBuffer = (VOID *)NULL;
	CommandPacket.TransferLength = 0;

	CommandPacket.CommandTimeout = NVME_GENERIC_TIMEOUT;
	CommandPacket.QueueType      = NVME_IO_QUEUE;

	CommandPacket.NvmeCmd->Cdw10 = (UINT32)Lba;
	CommandPacket.NvmeCmd->Cdw11 = (UINT32)(Lba >> 32);

	/* Set Force Unit Access bit (bit 30) to use write-through behaviour */
	CommandPacket.NvmeCmd->Cdw12 = ((Blocks - 1) & 0xFFFF) | (NVME_RW_FUA << 16);

	CommandPacket.MetadataBuffer = NULL;
	CommandPacket.MetadataLength = 0;

	CommandPacket.NvmeCmd->Flags = CDW10_VALID | CDW11_VALID | CDW12_VALID;

	Status = NvmePassthru->PassThru(NvmePassthru, NamespaceId, &CommandPacket, NULL);
	if (EFI_ERROR(Status))
		debug(L"NvmePassthru(NVME_CMD_WRITE_ZEROS) failed, ret = %d", Status);

	return Status;
}

static EFI_STATUS nvme_erase_blocks(
	EFI_HANDLE handle,
	ATTR_UNUSED EFI_BLOCK_IO *bio,
	EFI_LBA start,
	EFI_LBA end
)
{
	EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassthru;
	NVME_NAMESPACE_DEVICE_PATH *nvme_dp;
	EFI_DEVICE_PATH *dp;
	EFI_STATUS ret;
	UINT32 NamespaceId = 0;
	UINT32 num;
	EFI_LBA blk;

	/* No UEFI platform can support NVME_CMD_WRITE_ZERROS correctly to erase blocks,
	 * what's worse, this command can cause some platform crash. It's better to shift
	 * this work to the following fill_zero
	 */
	if (is_UEFI())
		return EFI_SUCCESS;

	debug(L"nvme_erase_blocks: 0x%X blocks", end - start + 1);
	dp = DevicePathFromHandle(handle);
	if (!dp) {
		error(L"Failed to get device path from handle");
		return EFI_INVALID_PARAMETER;
	}

	ret = get_nvme_passthru(dp, (VOID **) &NvmePassthru);
	if (EFI_ERROR(ret))
		return ret;

	if (!is_nvme_supported_write_zeros(NvmePassthru))
		return EFI_UNSUPPORTED;

	nvme_dp = get_nvme_device_path(dp);
	ret = NvmePassthru->GetNamespace(NvmePassthru, (EFI_DEVICE_PATH_PROTOCOL *)nvme_dp, &NamespaceId);
	debug(L"GetNamespace() ret=%d, NamespaceId=%d", ret, NamespaceId);

	for (blk = start;  blk < end; ) {
		if (end - blk >= NVME_MAX_WRITE_ZEROS_BLOCKS)
			num = NVME_MAX_WRITE_ZEROS_BLOCKS;
		else
			num = end - blk;

		ret = nvme_erase_blocks_impl(NvmePassthru, NamespaceId, blk, num);
		if (EFI_ERROR(ret))
			return EFI_UNSUPPORTED;

		blk += num;
	}

	return ret;
}

static EFI_STATUS nvme_check_logical_unit(ATTR_UNUSED EFI_DEVICE_PATH *p, logical_unit_t log_unit)
{
	return log_unit == LOGICAL_UNIT_USER ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static BOOLEAN is_nvme(EFI_DEVICE_PATH *p)
{
	return get_nvme_device_path(p) != NULL;
}

struct storage STORAGE(STORAGE_NVME) = {
	.erase_blocks = nvme_erase_blocks,
	.check_logical_unit = nvme_check_logical_unit,
	.probe = is_nvme,
	.name = L"NVME"
};


