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
#include "rpmb_virtual.h"
#include "rpmb_storage_common.h"
#include "protocol/ufs.h"
#include "protocol/ScsiPassThruExt.h"
#include "storage.h"

#define PAGE_SIZE			4096
#define MAX_COMMAND_RPMB		3
#define VIRTIO_IOCTL_RPMB_CMD		0xc008b551
#define VIRTIO_RPMB_F_REL_WRITE		0x2
#define VIRTIO_RPMB__F_WRITE		0x01
#define UNUSED_PARAM			__attribute__((__unused__))

static EFI_EXT_SCSI_PASS_THRU_PROTOCOL *def_virtual_rpmb_scsi_passthru;

typedef struct {
	UINT32 rpmb_flag;
	UINT32 n_rpmb_frame;
	rpmb_data_frame *addr_rpmb_frame;
} virtio_rpmb_cmd;

typedef struct {
	UINT64 n_cmds;
	virtio_rpmb_cmd cmds[MAX_COMMAND_RPMB + 1];
} virtio_rpmb_ioctl_seq_data;

static rpmb_data_frame *virtual_rpmb_get_frame_address(VOID *virtio_buffer, UINT32 index)
{
	virtio_rpmb_ioctl_seq_data *seq_data = NULL;
	virtio_rpmb_cmd *cmds, *cmd;
	rpmb_data_frame *frames;
	UINT32 number_cmds, offset = 0;
	UINT32 i;

	if (!virtio_buffer || index > MAX_COMMAND_RPMB)
		return NULL;

	seq_data = (virtio_rpmb_ioctl_seq_data *)virtio_buffer;
	number_cmds = seq_data->n_cmds;
	if (number_cmds > MAX_COMMAND_RPMB)
		return NULL;

	cmds = (virtio_rpmb_cmd *)&seq_data->cmds[0];
	if (!cmds)
		return NULL;

	frames = (rpmb_data_frame *)&seq_data->cmds[number_cmds + 1];
	if (!frames)
		return NULL;

	for (i = 0; i < index; i++) {
		cmd = &cmds[i];
		if (!cmd)
			return NULL;
		offset += cmd->n_rpmb_frame;
	}

	return (rpmb_data_frame *)&frames[offset];
}

static EFI_STATUS virtual_rpmb_copy_virtio_buffer_to_data(virtio_rpmb_ioctl_seq_data *seq_data_dest,
	VOID *virtio_buffer_src)
{
	EFI_STATUS ret;
	virtio_rpmb_ioctl_seq_data *seq_data = NULL;
	virtio_rpmb_cmd *cmds = NULL;
	rpmb_data_frame *addr_rpmb_frame = NULL;
	UINT32 i;

	if (!virtio_buffer_src || !seq_data_dest)
		return EFI_INVALID_PARAMETER;

	seq_data = (virtio_rpmb_ioctl_seq_data *)virtio_buffer_src;
	seq_data_dest->n_cmds = seq_data->n_cmds;
	cmds = (virtio_rpmb_cmd *)&seq_data->cmds[0];
	for (i = 0; i < seq_data_dest->n_cmds; i++) {
		seq_data_dest->cmds[i].rpmb_flag = cmds[i].rpmb_flag;
		seq_data_dest->cmds[i].n_rpmb_frame = cmds[i].n_rpmb_frame;
		addr_rpmb_frame = virtual_rpmb_get_frame_address(virtio_buffer_src, i);
		if (!addr_rpmb_frame) {
			debug(L"cmds[%d].addr_rpmb_frame is NULL", i);
			return EFI_INVALID_PARAMETER;
		}
		ret = memcpy_s(seq_data_dest->cmds[i].addr_rpmb_frame, sizeof(rpmb_data_frame), addr_rpmb_frame,
					   seq_data->cmds[i].n_rpmb_frame * sizeof(rpmb_data_frame));
		if (EFI_ERROR(ret))
			return ret;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS virtual_rpmb_copy_data_to_virtio_buffer(VOID *virtio_buffer,
	virtio_rpmb_ioctl_seq_data *src_seq_data)
{
	EFI_STATUS ret;
	virtio_rpmb_ioctl_seq_data *seq_data = NULL;
	virtio_rpmb_cmd *cmds;

	UINT32 i;

	if (!virtio_buffer || !src_seq_data)
		return EFI_INVALID_PARAMETER;

	seq_data = (virtio_rpmb_ioctl_seq_data *)virtio_buffer;
	seq_data->n_cmds = src_seq_data->n_cmds;
	cmds = (virtio_rpmb_cmd *)&seq_data->cmds[0];
	for (i = 0; i < seq_data->n_cmds; i++) {
		cmds[i].rpmb_flag = src_seq_data->cmds[i].rpmb_flag;
		cmds[i].n_rpmb_frame = src_seq_data->cmds[i].n_rpmb_frame;
		cmds[i].addr_rpmb_frame = virtual_rpmb_get_frame_address(virtio_buffer, i);
		if (!cmds[i].addr_rpmb_frame) {
			debug(L"cmds[%d].addr_rpmb_frame is NULL", i);
			return EFI_INVALID_PARAMETER;
		}
		ret = memcpy_s(cmds[i].addr_rpmb_frame, sizeof(rpmb_data_frame),
					   src_seq_data->cmds[i].addr_rpmb_frame,
					   src_seq_data->cmds[i].n_rpmb_frame * sizeof(rpmb_data_frame));
		if (EFI_ERROR(ret))
			return ret;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS virtual_rpmb_send_virtio_data(void *rpmb_dev, UINT16 rpmb_req, rpmb_data_frame *rpmb_data_in,
	UINT32 count_in, rpmb_data_frame *rpmb_data_out, UINT32 count_out)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame response_frame;
	UINT32 rpmb_flag;
	virtio_rpmb_ioctl_seq_data virtio_seq_data;
	UINT32 number_rpmb_command_frame = 0;
	UINT32 out_data_buffer_size;
	VOID *out_data_buffer = NULL;
	VOID *freeAddr = NULL;
	virtio_rpmb_ioctl_seq_data *seq_data = NULL;
	EFI_EXT_SCSI_PASS_THRU_SCSI_REQUEST_PACKET packet = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;
	UINT32 total_frames = count_in + count_out;

	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	rpmb_flag = VIRTIO_RPMB__F_WRITE;
	if (rpmb_req == RPMB_REQUEST_KEY_WRITE || rpmb_req == RPMB_REQUEST_AUTH_WRITE)
		rpmb_flag |= VIRTIO_RPMB_F_REL_WRITE;

	memset(&virtio_seq_data, 0, sizeof(virtio_seq_data));
	virtio_seq_data.cmds[number_rpmb_command_frame].rpmb_flag = rpmb_flag;
	virtio_seq_data.cmds[number_rpmb_command_frame].n_rpmb_frame = count_in;
	virtio_seq_data.cmds[number_rpmb_command_frame].addr_rpmb_frame = rpmb_data_in;
	number_rpmb_command_frame++;

	if (rpmb_req == RPMB_REQUEST_KEY_WRITE || rpmb_req == RPMB_REQUEST_AUTH_WRITE) {
		response_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);
		virtio_seq_data.cmds[number_rpmb_command_frame].rpmb_flag = VIRTIO_RPMB__F_WRITE;
		virtio_seq_data.cmds[number_rpmb_command_frame].n_rpmb_frame = 1;
		virtio_seq_data.cmds[number_rpmb_command_frame].addr_rpmb_frame = &response_frame;
		number_rpmb_command_frame++;
		total_frames++;
	}

	virtio_seq_data.cmds[number_rpmb_command_frame].rpmb_flag = 0;
	virtio_seq_data.cmds[number_rpmb_command_frame].n_rpmb_frame = count_out;
	virtio_seq_data.cmds[number_rpmb_command_frame].addr_rpmb_frame = rpmb_data_out;
	number_rpmb_command_frame++;

	virtio_seq_data.n_cmds = number_rpmb_command_frame;

	out_data_buffer_size = sizeof(UINT64) + number_rpmb_command_frame *
		sizeof(virtio_rpmb_cmd) + total_frames * sizeof(rpmb_data_frame);

	ret = alloc_aligned(&freeAddr, &out_data_buffer, out_data_buffer_size, PAGE_SIZE);
	if (EFI_ERROR (ret)) {
		efi_perror(ret, L"Failed to alloc align memory");
		return ret;
	}
	if (!out_data_buffer)
		return EFI_OUT_OF_RESOURCES;

	ret = virtual_rpmb_copy_data_to_virtio_buffer(out_data_buffer, &virtio_seq_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to  copy data to virtio buffer");
		goto exit;
	}

	packet.OutDataBuffer = out_data_buffer;
	packet.OutTransferLength = out_data_buffer_size;
	ret = uefi_call_wrapper(passthru->PassThru, 5, passthru, NULL, 0, &packet, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to  send virtio data");
		goto exit;
	}

	seq_data = (virtio_rpmb_ioctl_seq_data *)packet.OutDataBuffer;
	if (!seq_data) {
		debug(L"virtual_rpmb_send_virtio_data... seq_data is NULL");
		ret = EFI_INVALID_PARAMETER;
		goto exit;
	}

	ret = virtual_rpmb_copy_virtio_buffer_to_data(&virtio_seq_data, packet.OutDataBuffer);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to  virtual_rpmb_copy_virtio_buffer_to_data");

exit:
	if (freeAddr)
		FreePool(freeAddr);

	return ret;
}

EFI_STATUS get_virtual_rpmb_protocol(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL **passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL **)rpmb_dev;

	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;
	EFI_GUID guid = EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
	extern struct storage STORAGE(STORAGE_VIRTUAL);
	static struct storage *supported_storage = &STORAGE(STORAGE_VIRTUAL);

	if (initialized && def_virtual_rpmb_scsi_passthru) {
		*passthru = def_virtual_rpmb_scsi_passthru;
		return EFI_SUCCESS;
	}

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is vitual media device for the device handle with pass through");
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
			debug(L"Is vitual media device with pass through");
			break;
		}
	}

	if (i == nb_handle)
		return EFI_UNSUPPORTED;

find:

	ret = LibLocateProtocol(&guid, (void **)&def_virtual_rpmb_scsi_passthru);
	if (EFI_ERROR(ret)) {
		error(L"failed to get virtual pass thru protocol");
		return ret;
	}
	*passthru = def_virtual_rpmb_scsi_passthru;
	initialized = TRUE;

	debug(L"get virtual pass through protocol");

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to get partition number since the interface
      read/write includes the partition number, therefore always return RPMB_PARTITION in order to
      be compatible with EMMC
*/
EFI_STATUS virtual_rpmb_get_partition_num(void *rpmb_dev, UINT8 *current_part)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!passthru || !current_part)
		return EFI_INVALID_PARAMETER;

	*current_part = RPMB_PARTITION;

	return ret;
}

/* For reading/writing UFS RPMB, which is not required to switch partition since the interface
      read/write includes the partition number, therefore always return OK in order to
      be compatible with EMMC
*/
EFI_STATUS virtual_rpmb_partition_switch(void *rpmb_dev, __attribute__((__unused__)) UINT8 part)
{
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!passthru)
		return EFI_INVALID_PARAMETER;

	debug(L"virtual media parition switching successfully");

	return EFI_SUCCESS;
}

EFI_STATUS virtual_rpmb_send_request(UNUSED_PARAM void *rpmb_dev, UNUSED_PARAM rpmb_data_frame *data_frame,
	UNUSED_PARAM UINT8 count, UNUSED_PARAM BOOLEAN is_rel_write)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS virtual_rpmb_get_response(UNUSED_PARAM void *rpmb_dev, UNUSED_PARAM rpmb_data_frame *data_frame,
	UNUSED_PARAM UINT8 count)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS virtual_rpmb_read_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_in_frame;
	rpmb_data_frame *data_out_frame = NULL;
	UINT16 res_result;
	UINT32 i;
	UINT8 random[16] = {0};
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"virtual_rpmb_read_data read number of block = 0x%08x from blk 0x%08x", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

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
		return ret;

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_AUTH_READ, &data_in_frame, 1, data_out_frame, blk_count);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_read_data: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(data_out_frame[0].req_resp) != RPMB_RESPONSE_AUTH_READ) {
		error(L"The response is not expected, expected resp = 0x%08x", data_out_frame[0].req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(data_out_frame[0].result);
	debug(L"virtual_rpmb_read_data: response result is 0x%08x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

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

EFI_STATUS virtual_rpmb_get_counter(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame counter_frame, status_frame;
	UINT16 res_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!result || !write_counter || !passthru)
		return EFI_INVALID_PARAMETER;

	efi_perror(ret, L"virtual_rpmb_get_counter...");

	memset(&counter_frame, 0, sizeof(counter_frame));
	memset(&status_frame, 0, sizeof(status_frame));
	counter_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_COUNTER_READ);
	ret = generate_random_numbers(counter_frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_COUNTER_READ, &counter_frame, 1, &status_frame, 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_get_counter: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(status_frame.req_resp) != RPMB_RESPONSE_COUNTER_READ) {
		error(L"virtual_rpmb_get_counter: response is not expected, expected resp = 0x%08x", status_frame.req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(status_frame.result);
	debug(L"virtual_rpmb_get_counter: response result is 0x%08x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	if (key && (rpmb_check_mac(key, &status_frame, 1) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = BE32_TO_CPU_SWAP(status_frame.write_counter);
	debug(L"virtual_rpmb_get_counter: current counter is 0x%08x", *write_counter);

out:

	return ret;
}

EFI_STATUS virtual_rpmb_write_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 write_counter;
	rpmb_data_frame status_frame;
	rpmb_data_frame data_in_frame[blk_count];
	UINT32 i;
	UINT16 res_result;
	UINT8 mac[RPMB_DATA_MAC];
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"write rpmb data: number of block = 0x%08x from blk 0x%08x", blk_count, blk_addr);
	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!buffer || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	ret = virtual_rpmb_get_counter(rpmb_dev, &write_counter, key, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get counter");
		goto out;
	}

	for (i = 0; i < blk_count; i++) {
		memset(&data_in_frame[i], 0, sizeof(data_in_frame[i]));
		data_in_frame[i].address = CPU_TO_BE16_SWAP(blk_addr);
		data_in_frame[i].block_count = CPU_TO_BE16_SWAP(blk_count);
		data_in_frame[i].req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_AUTH_WRITE);
		data_in_frame[i].write_counter = CPU_TO_BE32_SWAP(write_counter);
		ret = memcpy_s(&data_in_frame[i].data, sizeof(data_in_frame[0].data),
					   (UINT8 *)buffer + i * 256, 256);
		if (EFI_ERROR(ret))
			goto out;
	}

	if (rpmb_calc_hmac_sha256(data_in_frame, blk_count,
			key, RPMB_KEY_SIZE,
			mac, RPMB_MAC_SIZE) == 0) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	ret = memcpy_s(data_in_frame[blk_count - 1].key_mac, sizeof(data_in_frame[0].key_mac),
				   mac, RPMB_DATA_MAC);
	if (EFI_ERROR(ret))
		goto out;

	memset(&status_frame, 0, sizeof(status_frame));
	status_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_STATUS);

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_AUTH_WRITE, data_in_frame, blk_count, &status_frame, 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_write_data: failed to send virtio data");
		goto out;
	}

	if (BE16_TO_CPU_SWAP(status_frame.req_resp) != RPMB_RESPONSE_AUTH_WRITE) {
		error(L"The response is not expected, expected resp = 0x%08x, received resp = 0x%08x",
			RPMB_RESPONSE_AUTH_WRITE, BE16_TO_CPU_SWAP(status_frame.req_resp));
		ret = EFI_ABORTED;
		goto out;
	}

	res_result = BE16_TO_CPU_SWAP(status_frame.result);
	debug(L"response result is 0x%08x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		ret = EFI_ABORTED;
		goto out;
	}

	if (write_counter >= BE32_TO_CPU_SWAP(status_frame.write_counter)) {
		efi_perror(ret, L"RPMB write counter not incremeted returned counter is 0x%08x",
		status_frame.write_counter);
		ret = EFI_ABORTED;
		goto out;
	}
	write_counter++;

out:
	return ret;
}

EFI_STATUS virtual_rpmb_program_key(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	rpmb_data_frame data_frame, status_frame;
	UINT16 res_result;
	EFI_EXT_SCSI_PASS_THRU_PROTOCOL *passthru = (EFI_EXT_SCSI_PASS_THRU_PROTOCOL *)rpmb_dev;

	debug(L"program virtual rpmb key");

	if (passthru == NULL)
		passthru = def_virtual_rpmb_scsi_passthru;

	if (!key || !result || !passthru)
		return EFI_INVALID_PARAMETER;

	memset(&data_frame, 0, sizeof(data_frame));
	memset(&status_frame, 0, sizeof(status_frame));
	data_frame.req_resp = CPU_TO_BE16_SWAP(RPMB_REQUEST_KEY_WRITE);
	ret = memcpy_s(data_frame.key_mac, sizeof(data_frame.key_mac), key, RPMB_KEY_SIZE);
	if (EFI_ERROR(ret))
		return ret;

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_KEY_WRITE, &data_frame, 1, &status_frame, 1);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_program_key: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(status_frame.req_resp) != RPMB_RESPONSE_KEY_WRITE) {
		error(L"The response is not expected, expected resp = 0x%08x, received resp = 0x%08x",
			RPMB_RESPONSE_KEY_WRITE, BE16_TO_CPU_SWAP(status_frame.req_resp));
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(status_frame.result);
	debug(L"response result is 0x%08x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS virtual_rpmb_read_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,\
	rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT16 res_result;

	if (!data_in_frame || !data_out_frame)
		return EFI_INVALID_PARAMETER;

	memset(data_out_frame, 0, sizeof(rpmb_data_frame) * out_cnt);

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_AUTH_READ, (rpmb_data_frame *)data_in_frame, in_cnt, 
		data_out_frame, out_cnt);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_read_data: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(data_out_frame[0].req_resp) != RPMB_RESPONSE_AUTH_READ) {
		error(L"The response is not expected, expected resp = 0x%08x", data_out_frame[0].req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(data_out_frame[0].result);
	debug(L"virtual_rpmb_read_data: response result is 0x%08x", res_result);
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS virtual_rpmb_get_counter_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,\
	rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT16 res_result;

	if (!data_in_frame || !data_out_frame)
		return EFI_INVALID_PARAMETER;
	memset(data_out_frame, 0, sizeof(rpmb_data_frame)*out_cnt);

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_COUNTER_READ, (rpmb_data_frame *)data_in_frame, in_cnt, data_out_frame, out_cnt);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_get_counter: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(data_out_frame->req_resp) != RPMB_RESPONSE_COUNTER_READ) {
		error(L"virtual_rpmb_get_counter: response is not expected, expected resp = 0x%08x", data_out_frame->req_resp);
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(data_out_frame->result);
	debug(L"virtual_rpmb_get_counter: response result is 0x%08x", res_result);
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS virtual_rpmb_write_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,\
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT16 res_result;

	if (!data_in_frame || !data_out_frame)
		return EFI_INVALID_PARAMETER;
	memset(data_out_frame, 0, sizeof(rpmb_data_frame)*out_cnt);

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_AUTH_WRITE, (rpmb_data_frame *)data_in_frame, in_cnt,
		data_out_frame, out_cnt);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_write_data: failed to send virtio data");
		goto out;
	}

	if (BE16_TO_CPU_SWAP(data_out_frame->req_resp) != RPMB_RESPONSE_AUTH_WRITE) {
		error(L"The response is not expected, expected resp = 0x%08x, received resp = 0x%08x",
			RPMB_RESPONSE_AUTH_WRITE, BE16_TO_CPU_SWAP(data_out_frame->req_resp));
		ret = EFI_ABORTED;
		goto out;
	}

	res_result = BE16_TO_CPU_SWAP(data_out_frame->result);
	debug(L"response result is 0x%08x", res_result);
	if (res_result) {
		debug(L"RPMB operation failed");
		ret = EFI_ABORTED;
	}
out:
	return ret;
}

EFI_STATUS virtual_rpmb_program_key_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,\
        rpmb_data_frame *data_out_frame, UINT32 out_cnt)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT16 res_result;

	debug(L"program virtual rpmb key");

	if (!data_in_frame || !data_out_frame)
		return EFI_INVALID_PARAMETER;

	ret = virtual_rpmb_send_virtio_data(rpmb_dev, RPMB_REQUEST_KEY_WRITE, (rpmb_data_frame *)data_in_frame, in_cnt, data_out_frame, out_cnt);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"virtual_rpmb_program_key: failed to send virtio data");
		return ret;
	}

	if (BE16_TO_CPU_SWAP(data_out_frame->req_resp) != RPMB_RESPONSE_KEY_WRITE) {
		error(L"The response is not expected, expected resp = 0x%08x, received resp = 0x%08x",
			RPMB_RESPONSE_KEY_WRITE, BE16_TO_CPU_SWAP(data_out_frame->req_resp));
		return EFI_ABORTED;
	}

	res_result = BE16_TO_CPU_SWAP(data_out_frame->result);
	debug(L"response result is 0x%08x", res_result);
	if (res_result) {
		debug(L"RPMB operation failed");
		return EFI_ABORTED;
	}

	return ret;
}

rpmb_ops_func_t virtual_rpmb_ops = {
	.get_storage_protocol = get_virtual_rpmb_protocol,
	.program_rpmb_key = virtual_rpmb_program_key,
	.get_storage_partition_num = virtual_rpmb_get_partition_num,
	.storage_partition_switch = virtual_rpmb_partition_switch,
	.get_rpmb_counter = virtual_rpmb_get_counter,
	.read_rpmb_data = virtual_rpmb_read_data,
	.write_rpmb_data = virtual_rpmb_write_data,
	.rpmb_send_request = virtual_rpmb_send_request,
	.rpmb_get_response = virtual_rpmb_get_response,
	.program_rpmb_key_frame = virtual_rpmb_program_key_frame,
	.get_rpmb_counter_frame = virtual_rpmb_get_counter_frame,
	.read_rpmb_data_frame = virtual_rpmb_read_data_frame,
	.write_rpmb_data_frame = virtual_rpmb_write_data_frame
};

rpmb_ops_func_t *get_virtual_storage_rpmb_ops()
{
	return &virtual_rpmb_ops;
}
