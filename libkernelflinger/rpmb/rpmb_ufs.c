/*
 * Copyright (c) 2018, Intel Corporation
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
#include "rpmb_ufs.h"
#include "rpmb_storage_common.h"
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"
#include "storage.h"

static EFI_EXT_SCSI_PASS_THRU_PROTOCOL *def_rpmb_ufs_scsi_passthru;
UINT8 target[TARGET_MAX_BYTES] = {0x00};

EFI_STATUS get_ufs_passthru(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL **passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL **)rpmb_dev;

	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;
	EFI_GUID guid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	extern struct storage STORAGE(STORAGE_UFS);
	static struct storage *supported_storage = &STORAGE(STORAGE_UFS);

	if (initialized && def_rpmb_ufs_scsi_passthru) {
		*passthru = def_rpmb_ufs_scsi_passthru;
		return EFI_SUCCESS;
	}

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is ufs device for the device handle with pass through");
			goto find;
		}
	}

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return ret;
	}

	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is ufs device with pass through");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

find:

	ret = LibLocateProtocol(&guid, (void **)&def_rpmb_ufs_scsi_passthru);
	if (EFI_ERROR(ret)) {
		error(L"failed to get UFS pass thru protocol");
		return ret;
	}
	*passthru = def_rpmb_ufs_scsi_passthru;
	initialized = TRUE;

	debug(L"get ufs pass through");

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return RPMB_PARTITION in order to
      be comptitable with EMMC
*/
EFI_STATUS get_ufs_partition_num_passthru(void *rpmb_dev, UINT8 *current_part)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !current_part)
		return EFI_INVALID_PARAMETER;

	*current_part = RPMB_PARTITION;

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return OK in order to
      be comptitable with EMMC
*/
EFI_STATUS ufs_partition_switch_passthru(void *rpmb_dev, __attribute__((__unused__)) UINT8 part)
{
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	debug(L"ufs parition switching successfully");

	return EFI_SUCCESS;
}

EFI_STATUS ufs_rpmb_send_request_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count,
	__attribute__((unused)) BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET packet = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;
	struct command_descriptor_block_security_protocol cdb;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_SECURITY_PROTOCOL_OUT;
	cdb.sec_protocol = 0xEC;
	cdb.inc_512 = 0;
	cdb.sec_protocol_specific = BE16_TO_CPU_SWAP(0x0001);
	cdb.allocation_transfer_length = BE32_TO_CPU_SWAP(RPMB_DATA_FRAME_SIZE * count);

	packet.Timeout = BLOCK_TIMEOUT * count;
	packet.OutDataBuffer = (void *)data_frame;
	packet.Cdb = &cdb;
	packet.OutTransferLength = RPMB_DATA_FRAME_SIZE * count;
	packet.CdbLength = sizeof(cdb);
	packet.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_WRITE;

	ret = uefi_call_wrapper(passthru->PassThru, 5, passthru, &target[0], UFS_RPMB_LUN, &packet, NULL);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send RPMB request");
		return ret;
	}
	debug(L"send_request status = %0x", packet.TargetStatus);
	return ret;
}

EFI_STATUS ufs_rpmb_get_response_passthru(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count)
{
	EFI_STATUS ret;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET packet = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;
	struct command_descriptor_block_security_protocol cdb;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!passthru || !data_frame)
		return EFI_INVALID_PARAMETER;

	ZeroMem(&cdb, sizeof(cdb));

	cdb.op_code = UFS_SECURITY_PROTOCOL_IN;
	cdb.sec_protocol = 0xEC;
	cdb.inc_512 = 0;
	cdb.sec_protocol_specific = BE16_TO_CPU_SWAP(0x0001);
	cdb.allocation_transfer_length = BE32_TO_CPU_SWAP(RPMB_DATA_FRAME_SIZE * count);

	packet.Timeout = BLOCK_TIMEOUT * count;
	packet.InDataBuffer = (void *)data_frame;
	packet.Cdb = &cdb;
	packet.InTransferLength = RPMB_DATA_FRAME_SIZE * count;
	packet.CdbLength = sizeof(cdb);
	packet.DataDirection = EFI_EXT_SCSI_DATA_DIRECTION_READ;

	ret = uefi_call_wrapper(passthru->PassThru, 5, passthru, &target[0], UFS_RPMB_LUN, &packet, NULL);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send RPMB request");
		return ret;
	}
	debug(L"get_response status = %0x", packet.TargetStatus);
	return ret;
}


static EFI_STATUS ufs_rpmb_request_response_passthru(void *rpmb_dev,
		rpmb_data_frame *request_data_frame, rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = ufs_rpmb_send_request_passthru(rpmb_dev, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = ufs_rpmb_get_response_passthru(rpmb_dev, response_data_frame, res_count);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get rpmb response");
		return ret;
	}


	if (BE16_TO_CPU_SWAP(response_data_frame->req_resp) != expected) {
		error(L"The response is not expected, expected resp=0x%08x, returned resp=0x%08x",
		expected, response_data_frame->req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(response_data_frame->result);
	debug(L"response result is %0x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS ufs_read_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT32 i;
	UINT8 random[16] = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	data_out_frame = AllocatePool(sizeof(rpmb_data_frame) * blk_count);
	if (!data_out_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	memset(&data_in_frame, 0, sizeof(data_in_frame));
	memset(data_out_frame, 0, sizeof(rpmb_data_frame) * blk_count);
	data_in_frame.address = CPU_TO_BE16_SWAP(blk_addr);
	data_in_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_AUTH_READ);
	ret = generate_random_numbers(random, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}
	ret = memcpy_s(data_in_frame.nonce, sizeof(data_in_frame.nonce), random, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret))
		goto out;
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &data_in_frame, data_out_frame, 1,
			blk_count, RPMB_RESPONSE_AUTH_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (rpmb_check_mac(key, data_out_frame, blk_count) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	if (memcmp(&random, &data_out_frame[blk_count - 1].nonce, RPMB_NONCE_SIZE)) {
		debug(L"Random is not expected in out data frame");
		ret = EFI_ABORTED;
		goto out;
	}
	for (i = 0; i < blk_count; i++) {
		ret = memcpy_s((UINT8 *)buffer + i * 256, 256, data_out_frame[i].data, 256);
		if (EFI_ERROR(ret))
			goto out;
	}

out:

	if (data_out_frame)
		FreePool(data_out_frame);

	return ret;
}

EFI_STATUS ufs_get_counter_passthru(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame counter_frame;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!result || !write_counter || !passthru)
		return EFI_INVALID_PARAMETER;

	memset(&counter_frame, 0, sizeof(counter_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}

	debug(L"ufs_get_counter_passthru: ufs_rpmb_request_response_passthru");
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &counter_frame, &counter_frame,
		1, 1, RPMB_RESPONSE_COUNTER_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (rpmb_check_mac(key, &counter_frame, 1) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = BE32_TO_CPU_SWAP(counter_frame.write_counter);
	debug(L"current counter is 0x%0x", *write_counter);

out:

	return ret;
}

EFI_STATUS ufs_write_rpmb_data_passthru(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 write_counter;
	rpmb_data_frame status_frame;
	rpmb_data_frame *data_in_frame = NULL;
	UINT32 i;
	UINT8 mac[RPMB_DATA_MAC];
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"write rpmb data: number of block =%d from blk %d", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	data_in_frame = AllocatePool(sizeof(rpmb_data_frame));
	if (!data_in_frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	ret = ufs_get_counter_passthru(rpmb_dev, &write_counter, key, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get counter");
		goto out;
	}

	for (i = 0; i < blk_count; i++) {
		memset(data_in_frame, 0, sizeof(rpmb_data_frame));
		data_in_frame->address = CPU_TO_BE16_SWAP(blk_addr + i);
		data_in_frame->block_count = CPU_TO_BE16_SWAP(1);
		data_in_frame->req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_AUTH_WRITE);
		data_in_frame->write_counter = CPU_TO_BE32_SWAP(write_counter);
		ret = memcpy_s(&data_in_frame->data, sizeof(data_in_frame->data),
					   (UINT8 *)buffer + i * 256, 256);
		if (EFI_ERROR(ret))
			goto out;

		if (rpmb_calc_hmac_sha256(data_in_frame, 1,
				key, RPMB_KEY_SIZE,
				mac, RPMB_MAC_SIZE) == 0) {
			ret = EFI_INVALID_PARAMETER;
			goto out;
		}

		ret = memcpy_s(data_in_frame->key_mac, sizeof(data_in_frame->key_mac), mac, RPMB_DATA_MAC);
		if (EFI_ERROR(ret))
			goto out;
		ret = ufs_rpmb_send_request_passthru(rpmb_dev, data_in_frame, 1, TRUE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to send request to rpmb");
			goto out;
		}

		memset(&status_frame, 0, sizeof(status_frame));
		status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		ret = ufs_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame, 1, 1,
			RPMB_RESPONSE_AUTH_WRITE, result);
		if (EFI_ERROR(ret))
			goto out;

		if (write_counter >= BE32_TO_CPU_SWAP(status_frame.write_counter)) {
			efi_perror(ret, L"RPMB write counter not incremeted returned counter is 0x%0x",
			status_frame.write_counter);
			ret = EFI_ABORTED;
			goto out;
		}
		write_counter++;
	}

out:
	if (data_in_frame)
		FreePool(data_in_frame);

	return ret;
}

EFI_STATUS ufs_program_key_passthru(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_frame, status_frame;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"enter ufs_program_key");

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!key || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	memset(&data_frame, 0, sizeof(data_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	ret = memcpy_s(data_frame.key_mac, sizeof(data_frame.key_mac), key, RPMB_KEY_SIZE);
	if (EFI_ERROR(ret))
		return ret;
	ret = ufs_rpmb_send_request_passthru(rpmb_dev, &data_frame, 1, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		return ret;
	}

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = ufs_rpmb_request_response_passthru(rpmb_dev, &status_frame, &status_frame,
		1, 1, RPMB_RESPONSE_KEY_WRITE, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request response rpmb");
		return ret;
	}

	return ret;
}

EFI_STATUS ufs_program_key_frame_passthru(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_RESPONSE_RESULT rpmb_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"enter ufs_program_key");

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!data_in_frame || !data_out_frame || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = ufs_rpmb_send_request_passthru(rpmb_dev, (rpmb_data_frame *)data_in_frame, in_cnt, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request rpmb");
		return ret;
	}

	memset(data_out_frame, 0, sizeof(rpmb_data_frame) * out_cnt);
	data_out_frame->req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = ufs_rpmb_request_response_passthru(rpmb_dev, data_out_frame, data_out_frame,
		out_cnt, out_cnt, RPMB_RESPONSE_KEY_WRITE, &rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to request response rpmb");
		return ret;
	}

	return ret;
}

EFI_STATUS ufs_get_counter_frame_passthru(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_RESPONSE_RESULT rpmb_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!data_in_frame || !data_out_frame || !passthru)
		return EFI_INVALID_PARAMETER;

	debug(L"ufs_get_counter_passthru: ufs_rpmb_request_response_passthru");
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, (rpmb_data_frame *)data_in_frame, data_out_frame,
		in_cnt, out_cnt, RPMB_RESPONSE_COUNTER_READ, &rpmb_result);

	return ret;
}

EFI_STATUS ufs_read_rpmb_data_frame_passthru(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_RESPONSE_RESULT rpmb_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!data_in_frame || !data_out_frame || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = ufs_rpmb_request_response_passthru(rpmb_dev, (rpmb_data_frame *)data_in_frame, data_out_frame, in_cnt,
			out_cnt, RPMB_RESPONSE_AUTH_READ, &rpmb_result);

	return ret;
}

EFI_STATUS ufs_write_rpmb_data_frame_passthru(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	RPMB_RESPONSE_RESULT rpmb_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_rpmb_ufs_scsi_passthru;

	if (!data_in_frame || !data_out_frame || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = ufs_rpmb_send_request_passthru(rpmb_dev, (rpmb_data_frame *)data_in_frame, in_cnt, TRUE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	memset(data_out_frame, 0, sizeof(rpmb_data_frame) * out_cnt );
	data_out_frame->req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
	ret = ufs_rpmb_request_response_passthru(rpmb_dev, data_out_frame, data_out_frame, out_cnt, out_cnt,
			RPMB_RESPONSE_AUTH_WRITE, &rpmb_result);

	return ret;
}

rpmb_ops_func_t ufs_rpmb_ops_passthru = {
	.get_storage_protocol = get_ufs_passthru,
	.program_rpmb_key = ufs_program_key_passthru,
	.get_storage_partition_num = get_ufs_partition_num_passthru,
	.storage_partition_switch = ufs_partition_switch_passthru,
	.get_rpmb_counter = ufs_get_counter_passthru,
	.read_rpmb_data = ufs_read_rpmb_data_passthru,
	.write_rpmb_data = ufs_write_rpmb_data_passthru,
	.rpmb_send_request = ufs_rpmb_send_request_passthru,
	.rpmb_get_response = ufs_rpmb_get_response_passthru,
	.program_rpmb_key_frame = ufs_program_key_frame_passthru,
	.get_rpmb_counter_frame = ufs_get_counter_frame_passthru,
	.read_rpmb_data_frame = ufs_read_rpmb_data_frame_passthru,
	.write_rpmb_data_frame = ufs_write_rpmb_data_frame_passthru
};

rpmb_ops_func_t* get_ufs_storage_rpmb_ops()
{
	return &ufs_rpmb_ops_passthru;
}
