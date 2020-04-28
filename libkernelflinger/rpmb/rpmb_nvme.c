/*
 * Copyright (c) 2018, Intel Corporation
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
 *
 */

#include <lib.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "rpmb_nvme.h"
#include "rpmb_storage_common.h"
#include "protocol/DevicePath.h"
#include "protocol/NvmExpressPassthru.h"
#include "protocol/StorageSecurityCommand.h"
#include "storage.h"

extern struct storage STORAGE(STORAGE_NVME);

static EFI_STORAGE_SECURITY_COMMAND_PROTOCOL * def_rpmb_nvme_ssp;
static EFI_DEVICE_PATH *nvme_get_device_path(EFI_HANDLE disk_handle)
{
	static struct storage *supported_storage = &STORAGE(STORAGE_NVME);
	EFI_STATUS ret;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	UINTN i;
	EFI_DEVICE_PATH *device_path = NULL;

	if (disk_handle != NULL) {
		device_path = DevicePathFromHandle(disk_handle);
		if (supported_storage->probe(device_path)) {
			debug(L"Is nvme device for the device handle with pass through");
			return device_path;
		}
	}

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&BlockIoProtocol, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to locate Block IO Protocol");
		return NULL;
	}

	for (i = 0; i < nb_handle; i++) {
		device_path = DevicePathFromHandle(handles[i]);
		if (supported_storage->probe(device_path)) {
			debug(L"Is nvme device with pass through");
			return device_path;
		}
	}

	return NULL;
}

EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *nvme_security_func(void *rpmb_dev)
{
	EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *ssp = (EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *)rpmb_dev;

	if (ssp == NULL)
		ssp = def_rpmb_nvme_ssp;

	return ssp;
}

EFI_STATUS nvme_get_security_protocol(void **rpmb_dev, EFI_HANDLE disk_handle)
{
	static BOOLEAN initialized = FALSE;
	EFI_GUID gEfiStorageSecurityCommandProtocolGuid = EFI_STORAGE_SECURITY_COMMAND_PROTOCOL_GUID;
	EFI_STORAGE_SECURITY_COMMAND_PROTOCOL	*ssp = NULL;
	EFI_DEVICE_PATH *dp;
	EFI_HANDLE Device;
	EFI_STATUS Status;

	if (initialized && def_rpmb_nvme_ssp) {
		*rpmb_dev = def_rpmb_nvme_ssp;
		return EFI_SUCCESS;
	}

	dp = nvme_get_device_path(disk_handle);
	if (dp == NULL)
		return EFI_UNSUPPORTED;

	Status = uefi_call_wrapper(BS->LocateDevicePath, 3, &gEfiStorageSecurityCommandProtocolGuid, &dp, &Device);
	if (!EFI_ERROR(Status))
		Status = uefi_call_wrapper(BS->HandleProtocol, 3, Device, &gEfiStorageSecurityCommandProtocolGuid, (void **)&ssp);

	if (EFI_ERROR(Status))
		return Status;

	initialized = TRUE;
	def_rpmb_nvme_ssp = ssp;
	return EFI_SUCCESS;
}

#define NVME_COMMAND_TIMEOUT_NS         ((UINT64) 5 * 1000 * 1000) // 5 seconds
#define NVME_RPMB_SECURITY_SPECIFIC     0x0001
#define NVME_SECURITY_PROTOCOL          0xEA
#define NVME_RPMB_TARGET                0
#define NVME_RPMB_SECTOR_SIZE           512

struct nvme_rpmb_data_frame {
	UINT8 stuff[222 - RPMB_MAC_SIZE + 1];
	UINT8 key_mac[RPMB_MAC_SIZE];
	UINT8 target;
	UINT8 nonce[16];
	UINT32 write_counter;
	UINT32 address;
	UINT32 sector_count;
	UINT16 result;
	UINT16 req_resp;
} __attribute__((packed));

static INT32 nvme_rpmb_calc_hmac_sha256(void *data, int cnt,
		const UINT8 key[], UINT32 key_size,
		UINT8 mac[], UINT32 mac_size)
{
	HMAC_CTX ctx;
	INT32 ret = 1;

	HMAC_CTX_init(&ctx);
	ret = HMAC_Init_ex(&ctx, key, key_size, EVP_sha256(), NULL);
	if (ret == 0)
		goto out;

	ret = HMAC_Update(&ctx, data, cnt);
	if (!ret)
		goto out;

	ret = HMAC_Final(&ctx, mac, &mac_size);
	if (ret == 0)
		goto out;
	if (mac_size != RPMB_MAC_SIZE) {
		ret = 0;
		goto out;
	}

out:
	HMAC_CTX_cleanup(&ctx);

	return ret;
}

static INT32 nvme_rpmb_check_mac(const UINT8 *key, struct nvme_rpmb_data_frame *frames, UINT8 cnt)
{
	UINT8 mac[RPMB_MAC_SIZE];
	INT32 ret = 1;
	int num;

	num = NVME_RPMB_SECTOR_SIZE * cnt + sizeof(struct nvme_rpmb_data_frame);
	num -= offsetof(struct nvme_rpmb_data_frame, target);
	ret = nvme_rpmb_calc_hmac_sha256(&frames->target, num, key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
	if (ret == 0) {
		debug(L"calculate hmac failed");
		return ret;
	}

	if (memcmp(mac, frames->key_mac, RPMB_MAC_SIZE)) {
		debug(L"RPMB hmac mismatch resule MAC");
		return 0;
	}

	return ret;
}

EFI_STATUS nvme_security_rpmb_send_request_impl(void *rpmb_dev, void *data_frame_in, UINT8 count,
	__attribute__((unused)) BOOLEAN is_rel_write)
{
	EFI_STATUS ret;
	UINT32 MediaId = 0;
	EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *ssp = nvme_security_func(rpmb_dev);
	struct nvme_rpmb_data_frame *data_frame = (struct nvme_rpmb_data_frame *)data_frame_in;

	if (!ssp || !data_frame)
		return EFI_INVALID_PARAMETER;

	ret = ssp->SendData(
				ssp,
				MediaId,
				NVME_COMMAND_TIMEOUT_NS,     // Timeout 10-sec
				NVME_SECURITY_PROTOCOL,      // SecurityProtocol
				NVME_RPMB_SECURITY_SPECIFIC, // SecurityProtocolSpecifcData
				256 * count,                 // PayloadBufferSize,
				data_frame                   // PayloadBuffer
				);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send RPMB request");
		return ret;
	}

	return ret;
}

EFI_STATUS nvme_security_rpmb_get_response_impl(void *rpmb_dev, void *data_frame_in, UINT8 count)
{
	EFI_STATUS ret;
	UINT32 MediaId = 0;
	UINTN rcv_size = 0;
	EFI_STORAGE_SECURITY_COMMAND_PROTOCOL *ssp = nvme_security_func(rpmb_dev);
	struct nvme_rpmb_data_frame *data_frame = (struct nvme_rpmb_data_frame *)data_frame_in;

	if (!ssp || !data_frame)
		return EFI_INVALID_PARAMETER;

	ret = ssp->ReceiveData(
				ssp,
				MediaId,
				NVME_COMMAND_TIMEOUT_NS,     // Timeout 10-sec
				NVME_SECURITY_PROTOCOL,      // SecurityProtocol
				NVME_RPMB_SECURITY_SPECIFIC, // SecurityProtocolSpecifcData
				256 * count,                 // PayloadBufferSize,
				data_frame,                  // PayloadBuffer
				&rcv_size                    // PayloadTransferSize
				);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to recv RPMB response");
		return ret;
	}

	return ret;
}

static EFI_STATUS nvme_security_rpmb_request_response(void *rpmb_dev,
		struct nvme_rpmb_data_frame *request_data_frame,
		struct nvme_rpmb_data_frame *response_data_frame, UINT8 req_count,
		UINT8 res_count, UINT16 expected, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT16 res_result;

	ret = nvme_security_rpmb_send_request_impl(rpmb_dev, request_data_frame, req_count, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	ret = nvme_security_rpmb_get_response_impl(rpmb_dev, response_data_frame, res_count);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get rpmb response");
		return ret;
	}

	res_result = response_data_frame->result;
	*result = (RPMB_RESPONSE_RESULT)res_result;
	debug(L"response result is %0x", res_result);
	*result = (RPMB_RESPONSE_RESULT)res_result;
	if (res_result) {
		debug(L"RPMB operation failed %0x", res_result);
		return EFI_ABORTED;
	}

	if (response_data_frame->req_resp != expected) {
		error(L"The response is not expected, expected resp=0x%08x, returned resp=0x%08x",
			expected, response_data_frame->req_resp);
		return EFI_ABORTED;
	}

	return ret;
}

EFI_STATUS nvme_rpmb_get_counter(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct nvme_rpmb_data_frame frame;
	struct nvme_rpmb_data_frame frame_out;

	if (!result || !write_counter)
		return EFI_INVALID_PARAMETER;

	memset(&frame, 0, sizeof(frame));
	frame.target = NVME_RPMB_TARGET;
	frame.req_resp = RPMB_REQUEST_COUNTER_READ;
	ret = generate_random_numbers(frame.nonce, RPMB_NONCE_SIZE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to generate random numbers");
		goto out;
	}

	ret = nvme_security_rpmb_request_response(rpmb_dev, &frame, &frame_out,
		1, 1, RPMB_RESPONSE_COUNTER_READ, result);
	if (EFI_ERROR(ret))
		goto out;

	if (key && (nvme_rpmb_check_mac(key, &frame_out, 0) == 0)) {
		debug(L"nvme_rpmb_get_counter: rpmb_check_mac failed");
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = frame_out.write_counter;
	debug(L"current counter is 0x%0x", *write_counter);

out:
	return ret;
}

EFI_STATUS nvme_rpmb_program_key(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct nvme_rpmb_data_frame frame;
	struct nvme_rpmb_data_frame frame_out;

	if (!result || !key)
		return EFI_INVALID_PARAMETER;

	memset(&frame, 0, sizeof(frame));
	frame.target = NVME_RPMB_TARGET;
	frame.req_resp = RPMB_REQUEST_KEY_WRITE;
	ret = memcpy_s(frame.key_mac, sizeof(frame.key_mac), key, RPMB_KEY_SIZE);
	if (EFI_ERROR(ret))
		return ret;
	ret = nvme_security_rpmb_send_request_impl(rpmb_dev, &frame, 1, FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	memset(&frame, 0, sizeof(frame));
	frame.target = NVME_RPMB_TARGET;
	frame.req_resp = RPMB_REQUEST_STATUS;
	ret = nvme_security_rpmb_request_response(rpmb_dev, &frame, &frame_out,
		1, 1, RPMB_RESPONSE_KEY_WRITE, result);

	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to send request to rpmb");

	return ret;
}

EFI_STATUS nvme_rpmb_read_data_impl(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct nvme_rpmb_data_frame frame;
	struct nvme_rpmb_data_frame *frame_out = NULL;
	int outsize;

	outsize = sizeof(struct nvme_rpmb_data_frame) + NVME_RPMB_SECTOR_SIZE * blk_count;
	frame_out = (struct nvme_rpmb_data_frame *)AllocatePool(outsize);
	if (!frame_out) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	memset(&frame, 0, sizeof(frame));
	frame.target = NVME_RPMB_TARGET;
	frame.req_resp = RPMB_REQUEST_AUTH_READ;
	frame.sector_count = (UINT32)blk_count;
	frame.address = (UINT32)blk_addr;
	generate_random_numbers(frame.nonce, RPMB_NONCE_SIZE);
	ret = nvme_security_rpmb_request_response(rpmb_dev, &frame, frame_out,
		1, outsize/sizeof(struct nvme_rpmb_data_frame), RPMB_RESPONSE_AUTH_READ, result);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		return ret;
	}

	if (key && (nvme_rpmb_check_mac(key, frame_out, blk_count) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	if (memcmp(frame.nonce, frame_out->nonce, RPMB_NONCE_SIZE)) {
		debug(L"Random is not expected in out data frame");
		ret = EFI_ABORTED;
		goto out;
	}

	if (frame_out->address != (UINT32)blk_addr) {
		ret = EFI_ABORTED;
		goto out;
	}

	ret = memcpy_s((UINT8 *)buffer, blk_count * NVME_RPMB_SECTOR_SIZE, &frame_out[1],
				   blk_count * NVME_RPMB_SECTOR_SIZE);
out:
	if (frame_out)
		FreePool(frame_out);

	return ret;
}

EFI_STATUS nvme_rpmb_read_data_half(void *rpmb_dev, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	unsigned char buf[NVME_RPMB_SECTOR_SIZE];

	ret = nvme_rpmb_read_data_impl(rpmb_dev, 1, blk_addr / 2, buf, key, result);
	if (EFI_ERROR(ret))
		return ret;

	ret = memcpy_s(buffer, NVME_RPMB_SECTOR_SIZE / 2,
				   buf + (blk_addr & 1) * NVME_RPMB_SECTOR_SIZE / 2,
				   NVME_RPMB_SECTOR_SIZE / 2);
	return ret;
}

EFI_STATUS nvme_rpmb_read_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;

	debug(L"nvme read rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	while (blk_count > 0) {
		if ((blk_addr & 1) || blk_count == 1) {
			ret = nvme_rpmb_read_data_half(rpmb_dev, blk_addr, buffer, key, result);
			if (EFI_ERROR(ret))
				return ret;

			blk_addr++;
			blk_count--;
			buffer = (char *)buffer + NVME_RPMB_SECTOR_SIZE / 2;
			continue;
		}

		ret = nvme_rpmb_read_data_impl(rpmb_dev, blk_count / 2, blk_addr / 2, buffer, key, result);
		if (EFI_ERROR(ret))
			return ret;

		buffer = (char *)buffer + blk_count / 2 * NVME_RPMB_SECTOR_SIZE;
		blk_addr += blk_count / 2;
		blk_count &= 1;
	}

	return ret;
}

EFI_STATUS nvme_rpmb_write_data_impl(void *rpmb_dev, UINT32 *write_counter, UINT16 blk_count,
		UINT16 blk_addr, void *buffer, const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	struct nvme_rpmb_data_frame *frame = NULL;
	struct nvme_rpmb_data_frame frame_out;
	INT32 hmac_ret = 1;
	int size;
	int num;

	debug(L"write rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	size = sizeof(struct nvme_rpmb_data_frame) + NVME_RPMB_SECTOR_SIZE * blk_count;
	frame = (struct nvme_rpmb_data_frame *)AllocatePool(size);
	if (!frame) {
		ret = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	memset(frame, 0, sizeof(*frame));
	frame->target = NVME_RPMB_TARGET;
	frame->req_resp = RPMB_REQUEST_AUTH_WRITE;
	frame->sector_count = (UINT32)blk_count;
	frame->address = (UINT32)blk_addr;
	frame->write_counter = *write_counter;
	ret = memcpy_s(&frame[1], sizeof(*frame), (UINT8 *)buffer, blk_count * NVME_RPMB_SECTOR_SIZE);
	if (EFI_ERROR(ret))
		goto out;


	num = NVME_RPMB_SECTOR_SIZE * blk_count + sizeof(struct nvme_rpmb_data_frame);
	num -= offsetof(struct nvme_rpmb_data_frame, target);
	hmac_ret = nvme_rpmb_calc_hmac_sha256(&frame->target, num, key, RPMB_KEY_SIZE, frame->key_mac, RPMB_MAC_SIZE);
	if (!hmac_ret) {
		ret = EFI_ABORTED;
		goto out;
	}

	ret = nvme_security_rpmb_send_request_impl(rpmb_dev, frame, size / sizeof(struct nvme_rpmb_data_frame), FALSE);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		goto out;
	}

	memset(frame, 0, sizeof(*frame));
	frame->target = NVME_RPMB_TARGET;
	frame->req_resp = RPMB_REQUEST_STATUS;
	ret = nvme_security_rpmb_request_response(rpmb_dev, frame, &frame_out,
		1, 1, RPMB_RESPONSE_AUTH_WRITE, result);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to send request to rpmb");
		goto out;
	}

	if (frame_out.address != (UINT32)blk_addr) {
		ret = EFI_ABORTED;
		debug(L"nvme_rpmb_write_data: unexpected address");
		goto out;
	}

	if (key && (nvme_rpmb_check_mac(key, &frame_out, 0) == 0)) {
		debug(L"rpmb_check_mac failed");
		ret = EFI_ABORTED;
		goto out;
	}

	*write_counter = frame_out.write_counter;

out:
	if (frame)
		FreePool(frame);

	return ret;
}

EFI_STATUS nvme_rpmb_write_data_half(void *rpmb_dev, UINT32 *write_counter, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	unsigned char buf[NVME_RPMB_SECTOR_SIZE];

	ret = nvme_rpmb_read_data_impl(rpmb_dev, 1, blk_addr / 2, buf, key, result);
	if (EFI_ERROR(ret))
		return ret;

	ret = memcpy_s(buf + (blk_addr & 1) * NVME_RPMB_SECTOR_SIZE / 2,
				   sizeof(buf), buffer, NVME_RPMB_SECTOR_SIZE / 2);
	if (EFI_ERROR(ret))
		return ret;
	ret = nvme_rpmb_write_data_impl(rpmb_dev, write_counter, 1, blk_addr / 2, buf, key, result);

	return ret;
}

EFI_STATUS nvme_rpmb_write_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 write_counter;

	debug(L"write rpmb data: number of block=%d from blk %d", blk_count, blk_addr);
	ret = nvme_rpmb_get_counter(rpmb_dev, &write_counter, key, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get counter");
		return ret;
	}

	while (blk_count > 0) {
		if ((blk_addr & 1) || blk_count == 1) {
			ret = nvme_rpmb_write_data_half(rpmb_dev, &write_counter, blk_addr, buffer, key, result);
			if (EFI_ERROR(ret))
				return ret;

			blk_addr++;
			blk_count--;
			buffer = (char *)buffer + NVME_RPMB_SECTOR_SIZE / 2;
			continue;
		}

		ret = nvme_rpmb_write_data_impl(rpmb_dev, &write_counter, blk_count / 2, blk_addr / 2, buffer, key, result);
		if (EFI_ERROR(ret))
			return ret;

		buffer = (char *)buffer + blk_count / 2 * NVME_RPMB_SECTOR_SIZE;
		blk_addr += blk_count / 2;
		blk_count &= 1;
	}

	return ret;
}

/* For reading/writing NVME RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return RPMB_PARTITION in order to
      be comptitable with EMMC
*/
EFI_STATUS nvme_rpmb_get_partition_num(void *rpmb_dev, UINT8 *current_part)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (rpmb_dev == NULL)
		rpmb_dev = def_rpmb_nvme_ssp;

	if (!rpmb_dev || !current_part)
		return EFI_INVALID_PARAMETER;

	*current_part = RPMB_PARTITION;

	return ret;
}

/* For reading/writing NVME RPMB, which is not required to swtich partition since the interface
      read/write includes the parition number, therefore always return OK in order to
      be comptitable with EMMC
*/
EFI_STATUS nvme_rpmb_partition_switch(void *rpmb_dev, __attribute__((__unused__)) UINT8 part)
{
	if (rpmb_dev == NULL)
		rpmb_dev = def_rpmb_nvme_ssp;

	if (!rpmb_dev)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}

EFI_STATUS nvme_security_rpmb_send_request(void *rpmb_dev, rpmb_data_frame *data_frame, UINT8 count,
	BOOLEAN is_rel_write)
{
	return nvme_security_rpmb_send_request_impl(rpmb_dev, (void *)data_frame, count, is_rel_write);
}

EFI_STATUS nvme_security_rpmb_get_response(void *rpmb_dev, rpmb_data_frame *data_frame_in, UINT8 count)
{
	return nvme_security_rpmb_get_response_impl(rpmb_dev, (void *)data_frame_in, count);
}

rpmb_ops_func_t nvme_rpmb_ops_passthru = {
	.get_storage_protocol = nvme_get_security_protocol,
	.program_rpmb_key = nvme_rpmb_program_key,
	.get_storage_partition_num = nvme_rpmb_get_partition_num,
	.storage_partition_switch = nvme_rpmb_partition_switch,
	.get_rpmb_counter = nvme_rpmb_get_counter,
	.read_rpmb_data = nvme_rpmb_read_data,
	.write_rpmb_data = nvme_rpmb_write_data,
	.rpmb_send_request = nvme_security_rpmb_send_request,
	.rpmb_get_response = nvme_security_rpmb_get_response,
};

rpmb_ops_func_t *get_nvme_storage_rpmb_ops()
{
	return &nvme_rpmb_ops_passthru;
}

