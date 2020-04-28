/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: kwen <kui.wen@intel.com>
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

#include "protocol/Mmc.h"
#include "protocol/SdHostIo.h"
#include "rpmb.h"
#include "gpt.h"
#include "rpmb_storage_common.h"
#include "rpmb_ufs.h"
#include "rpmb_emmc.h"
#include "rpmb_virtual.h"
#include "rpmb_nvme.h"
#include "storage.h"

#define MAGIC_KEY_OFFSET		0
#define MAGIC_KEY_DATA			"key_sim"
#define MAGIC_KEY_SIZE			7
#define WRITE_COUNTER_SIZE		4

/* here 1024 means 1024 blocks, so 1024 blocks * 256 B = 256KB */
#define RPMB_ADDR_BOUNDARY_NATIVE_H  1024
#define RPMB_ADDR_BOUNDARY_NATIVE_L   0
#define RPMB_ADDR_BOUNDARY_VIRTUAL_H  256
#define RPMB_ADDR_BOUNDARY_VIRTUAL_L  128
static BOOLEAN g_initialized = FALSE;
static rpmb_ops_func_t *storage_rpmb_ops;

static BOOLEAN check_bootloader_rpmb_address(UINT16 blk_addr)
{
	if (is_boot_device_virtual())  {
		if (blk_addr >= RPMB_ADDR_BOUNDARY_VIRTUAL_H || blk_addr<RPMB_ADDR_BOUNDARY_VIRTUAL_L)
			return FALSE;
	}
	else {
		if (blk_addr >= RPMB_ADDR_BOUNDARY_NATIVE_H || blk_addr<RPMB_ADDR_BOUNDARY_NATIVE_L)
			return FALSE;
	}
	return TRUE;
}

static EFI_STATUS rpmb_simulate_read_write_teedata_partition(
		BOOLEAN bread, UINT32 offset, UINT32 len, void *data)
{
	UINT64 partlen;
	UINT64 partoffset;
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;

	if (!data)
		return EFI_INVALID_PARAMETER;

	ret = gpt_get_partition_by_label(L"teedata", &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		error(L"teedata partition not found");
		return ret;
	}

	partlen = (gparti.part.ending_lba + 1 - gparti.part.starting_lba) * gparti.bio->Media->BlockSize;
	partoffset = gparti.part.starting_lba * gparti.bio->Media->BlockSize;

	if (len + offset > partlen) {
		debug(L"attempt to read/write outside of partition %s, (len %lld offset %lld partition len %lld)",
				gparti.part.name, len, offset, partlen);
		return EFI_END_OF_MEDIA;
	}
	if (bread) {
		ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5,
				gparti.dio, gparti.bio->Media->MediaId, partoffset + offset, len, data);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"read partition %s failed", gparti.part.name);
	} else {
		ret = uefi_call_wrapper(gparti.dio->WriteDisk, 5,
				gparti.dio, gparti.bio->Media->MediaId, partoffset + offset, len, data);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"write partition %s failed", gparti.part.name);
	}

	return ret;
}

EFI_STATUS simulate_get_rpmb_counter(UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	unsigned char data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE];
	unsigned char counter_data[WRITE_COUNTER_SIZE];

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, MAGIC_KEY_OFFSET,
			MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE, data);
	if (EFI_ERROR(ret)) {
		error(L"read data from emulation rpmb parition failed");
		return ret;
	}

	if (memcmp(data, MAGIC_KEY_DATA, MAGIC_KEY_SIZE)) {
		*result = RPMB_RES_NO_AUTH_KEY_PROGRAM;
		return EFI_ABORTED;
	}
	if (memcmp(&data[MAGIC_KEY_SIZE], key, RPMB_KEY_SIZE)) {
		*result = RPMB_RES_AUTH_FAILURE;
		return EFI_ABORTED;
	}
	ret = memcpy_s(counter_data, sizeof(counter_data), &data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE],
				   WRITE_COUNTER_SIZE);
	if (EFI_ERROR(ret))
		return ret;

	*write_counter = ((UINT32)counter_data[0]) << 24;
	*write_counter |= ((UINT32)counter_data[1]) << 16;
	*write_counter |= ((UINT32)counter_data[2]) << 8;
	*write_counter |= ((UINT32)counter_data[3]);

	return ret;
}

EFI_STATUS simulate_program_rpmb_key(const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	unsigned char data[MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE];
	unsigned char magic[MAGIC_KEY_SIZE];

	if (!key || !result)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, MAGIC_KEY_OFFSET,
			MAGIC_KEY_SIZE, magic);
	if (EFI_ERROR(ret)) {
		error(L"read key from emulation rpmb parition failed");
		return ret;
	}

	memset(data, 0, sizeof(data));
	if (memcmp(magic, MAGIC_KEY_DATA, MAGIC_KEY_SIZE)) {
		debug(L"rpmb key not provisioned");
		ret = memcpy_s(data, sizeof(data), MAGIC_KEY_DATA, MAGIC_KEY_SIZE);
		if (EFI_ERROR(ret))
			return ret;
		ret = memcpy_s(&data[MAGIC_KEY_SIZE], sizeof(data), key, RPMB_KEY_SIZE);
		if (EFI_ERROR(ret))
			return ret;

		ret = rpmb_simulate_read_write_teedata_partition(FALSE, MAGIC_KEY_OFFSET,
				MAGIC_KEY_SIZE + RPMB_KEY_SIZE + WRITE_COUNTER_SIZE, data);
		if (EFI_ERROR(ret)) {
			error(L"write key magic, key and counter to emulation rpmb parition failed");
			return ret;
		}
	} else {
		debug(L"rpmb key already provisioned");
		*result = RPMB_RES_GENERAL_FAILURE;
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS simulate_read_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size)
{
	EFI_STATUS ret;

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(TRUE, offset,
			size, buffer);
	if (EFI_ERROR(ret))
		error(L"read data from emulation parition failed");

	return ret;
}

EFI_STATUS simulate_write_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size)
{
	EFI_STATUS ret;

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	ret = rpmb_simulate_read_write_teedata_partition(FALSE, offset,
			size, buffer);
	if (EFI_ERROR(ret))
		error(L"write data to emulation parition failed");

	return ret;
}

EFI_STATUS rpmb_init(EFI_HANDLE disk_handle)
{
	g_initialized = TRUE;
	void *rpmb_dev;
	enum storage_type type;
	EFI_STATUS ret;

	ret = get_boot_device_type(&type);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get storage type ");
		return ret;
	}

	switch (type) {
	case STORAGE_UFS:
		storage_rpmb_ops = get_ufs_storage_rpmb_ops();
		if (!storage_rpmb_ops) {
			error(L"failed to get ufs rpmb operation instance");
			return EFI_NOT_FOUND;
		}

		if ((storage_rpmb_ops->get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init ufs rpmb pass through success");
			return EFI_SUCCESS;
		}
		error(L"init ufs rpmb using pass through failed");
		break;
	case STORAGE_EMMC:
		storage_rpmb_ops = get_emmc_storage_rpmb_ops(disk_handle);
		if (!storage_rpmb_ops) {
			error(L"failed to get emmc rpmb operation instance");
			return EFI_NOT_FOUND;
		}
		if ((storage_rpmb_ops->get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init emmc rpmb success");
			return EFI_SUCCESS;
		}
		error(L"init emmc rpmb protocol failed");
		break;
	case STORAGE_VIRTUAL:
		storage_rpmb_ops = get_virtual_storage_rpmb_ops();
		if (!storage_rpmb_ops) {
			error(L"failed to get virtual rpmb operation instance");
			return EFI_NOT_FOUND;
		}
		if ((storage_rpmb_ops->get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init virtual media rpmb using pass through success");
			return EFI_SUCCESS;
		}
		error(L"init virtual media rpmb using pass through failed");
		break;
#ifdef NVME_RPMB
	case STORAGE_NVME:
		storage_rpmb_ops = get_nvme_storage_rpmb_ops();
		if (!storage_rpmb_ops) {
			error(L"failed to get nvme rpmb operation instance");
			return EFI_NOT_FOUND;
		}
		if ((storage_rpmb_ops->get_storage_protocol)((void **)(&rpmb_dev), disk_handle) == EFI_SUCCESS) {
			debug(L"init nvme rpmb success");
			return EFI_SUCCESS;
		}
		error(L"init nvme rpmb failed");
		break;
#endif
	default:
		error(L"boot device not supported");
		return EFI_NOT_FOUND;

	}

	return EFI_NOT_FOUND;
}

EFI_STATUS get_storage_protocol(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	if (!g_initialized)
		rpmb_init(disk_handle);

	return storage_rpmb_ops->get_storage_protocol(rpmb_dev, disk_handle);
}

EFI_STATUS program_rpmb_key(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	return storage_rpmb_ops->program_rpmb_key(rpmb_dev, key, result);
}

EFI_STATUS get_storage_partition_num(void *rpmb_dev, UINT8 *current_part)
{
	return storage_rpmb_ops->get_storage_partition_num(rpmb_dev, current_part);
}

EFI_STATUS storage_partition_switch(void *rpmb_dev, UINT8 part)
{
	return storage_rpmb_ops->storage_partition_switch(rpmb_dev, part);
}

EFI_STATUS get_rpmb_counter(void *rpmb_dev, UINT32 *write_counter, const void *key,
			RPMB_RESPONSE_RESULT *result)
{
	return storage_rpmb_ops->get_rpmb_counter(rpmb_dev, write_counter, key, result);
}

EFI_STATUS read_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT *result)
{
	if (!check_bootloader_rpmb_address(blk_addr)) {
		error(L"Cannot access address out of range  for physical read");
		*result = RPMB_RES_ADDRESS_FAILURE;
		return EFI_INVALID_PARAMETER;
	}

	return storage_rpmb_ops->read_rpmb_data(rpmb_dev, blk_count, blk_addr, buffer, key, result);
}

EFI_STATUS write_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT *result)
{
	if (!check_bootloader_rpmb_address(blk_addr)) {
		error(L"Cannot access address out of range for physical write");
		*result = RPMB_RES_ADDRESS_FAILURE;
		return EFI_INVALID_PARAMETER;
	}

	return storage_rpmb_ops->write_rpmb_data(rpmb_dev, blk_count, blk_addr, buffer, key, result);
}

EFI_STATUS rpmb_send_request(void *rpmb_dev,
			rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write)
{
	UINT16 trusty_addr;

	if (BE16_TO_CPU_SWAP(data_frame->req_resp) == RPMB_REQUEST_AUTH_WRITE
		|| BE16_TO_CPU_SWAP(data_frame->req_resp) == RPMB_REQUEST_AUTH_READ) {
		trusty_addr = BE16_TO_CPU_SWAP(data_frame->address);
		if (check_bootloader_rpmb_address(trusty_addr)) {
			error(L"Cannot access address out of range  for trusty usage");
			return EFI_INVALID_PARAMETER;
		}
	}

	return storage_rpmb_ops->rpmb_send_request(rpmb_dev, data_frame, count, is_rel_write);
}

EFI_STATUS rpmb_get_response(void *rpmb_dev,
			rpmb_data_frame *data_frame, UINT8 count)
{
	return storage_rpmb_ops->rpmb_get_response(rpmb_dev, data_frame, count);
}

EFI_STATUS program_rpmb_key_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	return storage_rpmb_ops->program_rpmb_key_frame(rpmb_dev, data_in_frame, in_cnt, data_out_frame, out_cnt);
}

EFI_STATUS get_rpmb_counter_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	return storage_rpmb_ops->get_rpmb_counter_frame(rpmb_dev, data_in_frame, in_cnt, data_out_frame, out_cnt);
}

EFI_STATUS read_rpmb_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	return storage_rpmb_ops->read_rpmb_data_frame(rpmb_dev, data_in_frame, in_cnt, data_out_frame, out_cnt);
}

EFI_STATUS write_rpmb_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	return storage_rpmb_ops->write_rpmb_data_frame(rpmb_dev, data_in_frame, in_cnt, data_out_frame, out_cnt);
}
