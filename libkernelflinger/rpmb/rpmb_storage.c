/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: genshen <genshen.li@intel.com>
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
#include <openssl/sha.h>
#include "protocol/Mmc.h"
#include "protocol/SdHostIo.h"
#include "sdio.h"
#include "storage.h"
#include "rpmb.h"
#include "rpmb_storage.h"
#include "security.h"

#define RPMB_DEVICE_STATE_BLOCK_COUNT            1
#define RPMB_DEVICE_STATE_BLOCK_ADDR_NATIVE      2
#define RPMB_ROLLBACK_INDEX_BLOCK_ADDR_NATIVE    3
#define RPMB_DEVICE_STATE_BLOCK_ADDR_VIRTUAL     130
#define RPMB_ROLLBACK_INDEX_BLOCK_ADDR_VIRTUAL   131
#define RPMB_DEVICE_STATE_BLOCK_ADDR             get_device_state_block_addr()
#define RPMB_ROLLBACK_INDEX_BLOCK_ADDR           get_rollback_index_block_addr()
#define RPMB_BLOCK_SIZE                          256
#define RPMB_ROLLBACK_INDEX_COUNT_PER_BLOCK      (RPMB_BLOCK_SIZE/8)
#define RPMB_ROLLBACK_INDEX_BLOCK_TOTAL_COUNT    8
#define DEVICE_STATE_MAGIC 0xDC
#define RPMB_ALL_BLOCK_TOTAL_COUNT        10

static rpmb_sim_real_storage_interface_t rpmb__sim_real_storage_ops;
static UINT8 rpmb_key[RPMB_KEY_SIZE] = { 0 };
static UINT8 rpmb_buffer[RPMB_BLOCK_SIZE];
/*
 * 0~6 is magic
 * 7~38 is rpmb key
 * 39~41 is write counter
 */
#define TEEDATA_KEY_MAGIC               "key_sim"
#define TEEDATA_KEY_MAGIC_ADDR          0
#define TEEDATA_KEY_MAGIC_LENGTH        7

static UINT8 *derived_key;
static UINT8 number_derived_key;

static void dump_rpmb_key(__attribute__((unused)) UINT8 *key)
{
#if 1  // Change to 1 for debug the RPMB keys
	CHAR16 buf[RPMB_KEY_SIZE * 2 + 2];
	UINT16 i;

	for (i = 0; i < RPMB_KEY_SIZE; i++)
		SPrint(buf + i * 2, sizeof(buf) - i * 2, L"%02x", key[i]);
	debug(L"Key: %s", buf);
#endif
}

static UINT32 get_device_state_block_addr(VOID)
{
	if (is_boot_device_virtual())
		return RPMB_DEVICE_STATE_BLOCK_ADDR_VIRTUAL;
	else
		return RPMB_DEVICE_STATE_BLOCK_ADDR_NATIVE;
}

static UINT32 get_rollback_index_block_addr(VOID)
{
	if (is_boot_device_virtual())
		return RPMB_ROLLBACK_INDEX_BLOCK_ADDR_VIRTUAL;
	else
		return RPMB_ROLLBACK_INDEX_BLOCK_ADDR_NATIVE;
}

EFI_STATUS set_rpmb_derived_key_ex(IN VOID *kbuf, IN size_t kbuf_len, IN size_t num_key, IN int is_firmware_key)
{
	static int firmware_key_set = 0;
	EFI_STATUS ret = EFI_SUCCESS;
	UINT8 i;

	/* RPMB provision could happen in Firmware or AOS loader phase.
	 * For example: early ABL does not support RPMB provision, so AOS Loader take this role.
	 * From ABL 1908, ABL provide capability to do RPMB provision and it will
	 * pass down RPMB key accordingly.
	 *
	 * If RPMB key from firmware has been set, we should skip AOS loader deriving RPMB Key.
	 * The reason is: if firmware passdown RPMB key, it means RPMB has been provisioned
	 * this key in firmware phase already. AOS Loader should use this key for RPMB access.
	 */
	if (firmware_key_set && is_firmware_key == 0)
		return EFI_SUCCESS;

	if ((num_key > RPMB_NUMBER_KEY) || !kbuf || ((num_key * RPMB_KEY_SIZE) > kbuf_len))
		return EFI_INVALID_PARAMETER;

	if (derived_key)
		FreePool(derived_key);

	derived_key = AllocatePool(num_key * RPMB_KEY_SIZE);
	if (!derived_key) {
		ret = EFI_OUT_OF_RESOURCES;
		efi_perror(ret, L"Allocate pool error");
		return ret;
	}

	for (i = 0; i < num_key; i++) {
		memcpy(derived_key + i * RPMB_KEY_SIZE, kbuf + i * RPMB_KEY_SIZE, RPMB_KEY_SIZE);
		dump_rpmb_key(derived_key + i * RPMB_KEY_SIZE);
	}
	number_derived_key = num_key;

	if (is_firmware_key)
		firmware_key_set = 1;

	return ret;
}

EFI_STATUS set_rpmb_derived_key(IN VOID *kbuf, IN size_t kbuf_len, IN size_t num_key)
{
	return set_rpmb_derived_key_ex(kbuf, kbuf_len, num_key, 0);
}


EFI_STATUS get_rpmb_derived_key(OUT UINT8 **d_key, OUT UINT8 *number_d_key)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (!d_key || !number_d_key)
		return EFI_INVALID_PARAMETER;

	if (!derived_key)
		return EFI_NOT_FOUND;

	*number_d_key = number_derived_key;
	*d_key = derived_key;

	return ret;
}

void clear_rpmb_key(void)
{
	if (derived_key && number_derived_key) {
		memset(derived_key, 0, number_derived_key * RPMB_KEY_SIZE);
		number_derived_key = 0;
		FreePool(derived_key);
		derived_key = NULL;
	}

	memset(rpmb_key, 0, RPMB_KEY_SIZE);
}

void set_rpmb_key(UINT8 *key)
{
	memcpy(rpmb_key, key, RPMB_KEY_SIZE);
}

void get_rpmb_key(UINT8 *key)
{
	memcpy(key, rpmb_key, RPMB_KEY_SIZE);
}

EFI_STATUS clear_teedata_flag(void)
{
	EFI_STATUS ret;
	uint8_t data[TEEDATA_KEY_MAGIC_LENGTH + RPMB_KEY_SIZE] = {0};

	debug(L"enter clear teedata flag.");

	ret = simulate_write_rpmb_data(TEEDATA_KEY_MAGIC_ADDR, data, TEEDATA_KEY_MAGIC_LENGTH + RPMB_KEY_SIZE);
	if (EFI_ERROR(ret)) {
		debug(L"clear teedata_flag failed for magic.");
		return ret;
	}

	debug(L"end clear teedata flag , success");

	return EFI_SUCCESS;
}

#ifndef USER
static EFI_STATUS erase_simulate_rpmb_all_blocks(void)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 blk_offset = 0;
	UINT16 i = 0;

	memset(rpmb_buffer, 0, sizeof(rpmb_buffer));

	for (i = 0; i < RPMB_ALL_BLOCK_TOTAL_COUNT; i++) {
		blk_offset = i * RPMB_BLOCK_SIZE;
		ret = simulate_write_rpmb_data(blk_offset, rpmb_buffer, RPMB_BLOCK_SIZE);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to write simulate rpmb data");
			return ret;
		}
	}

	return ret;
}

EFI_STATUS erase_rpmb_all_blocks(void)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;
	BOOLEAN sbflags;

	sbflags = is_eom_and_secureboot_enabled();

	if (sbflags) {
		ret = write_rpmb_data(NULL, RPMB_ALL_BLOCK_TOTAL_COUNT, 0, rpmb_buffer, rpmb_key, &rpmb_result);
		debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to erase rpmb partition");
			return ret;
		}
	} else {
		ret = erase_simulate_rpmb_all_blocks();
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to erase teedata partition");
			return ret;
		}
	}

	return EFI_SUCCESS;
}
#endif

BOOLEAN is_rpmb_programed(void)
{
	return rpmb__sim_real_storage_ops.is_rpmb_programed();
}

EFI_STATUS program_rpmb_key_in_sim_real(UINT8 *key)
{
	return rpmb__sim_real_storage_ops.program_rpmb_key(key);
}

EFI_STATUS rpmb_read_counter_in_sim_real(const void *key, RPMB_RESPONSE_RESULT *result)
{
	return rpmb__sim_real_storage_ops.rpmb_read_counter(key, result);
}

EFI_STATUS write_rpmb_device_state(UINT8 state)
{
	return rpmb__sim_real_storage_ops.write_rpmb_device_state(state);
}

EFI_STATUS read_rpmb_device_state(UINT8 *state)
{
	return rpmb__sim_real_storage_ops.read_rpmb_device_state(state);
}

EFI_STATUS write_rpmb_rollback_index(size_t index, UINT64 in_rollback_index)
{
	return rpmb__sim_real_storage_ops.write_rpmb_rollback_index(index, in_rollback_index);
}

EFI_STATUS read_rpmb_rollback_index(size_t index, UINT64 *out_rollback_index)
{
	return rpmb__sim_real_storage_ops.read_rpmb_rollback_index(index, out_rollback_index);
}

EFI_STATUS write_rpmb_keybox_magic(UINT16 offset, void *buffer)
{
	return rpmb__sim_real_storage_ops.write_rpmb_keybox_magic(offset, buffer);
}

EFI_STATUS read_rpmb_keybox_magic(UINT16 offset, void *buffer)
{
	return rpmb__sim_real_storage_ops.read_rpmb_keybox_magic(offset, buffer);
}

static BOOLEAN is_rpmb_programed_real(void)
{
	EFI_STATUS ret;
	UINT32 write_counter;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = get_rpmb_counter(NULL, &write_counter, (const void *)rpmb_key, &rpmb_result);
	debug(L"get_counter ret=%d, wc=%d", ret, write_counter);
	if (EFI_ERROR(ret) && (rpmb_result == RPMB_RES_NO_AUTH_KEY_PROGRAM)) {
		debug(L"rpmb key is not programmed");
		return FALSE;
	}
	return TRUE;
}

static EFI_STATUS program_rpmb_key_real(UINT8 *key)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	memcpy(rpmb_key, key, RPMB_KEY_SIZE);
	ret = program_rpmb_key(NULL, (const void *)key, &rpmb_result);

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to program rpmb key");
		return ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS rpmb_read_counter_real(const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS ret;
	UINT32 write_counter;

	ret = get_rpmb_counter(NULL, &write_counter, key, result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read counter for physical rpmb");
		return ret;
	}
	return EFI_SUCCESS;

}

static EFI_STATUS write_rpmb_device_state_real(UINT8 state)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = read_rpmb_data(NULL, RPMB_DEVICE_STATE_BLOCK_COUNT, RPMB_DEVICE_STATE_BLOCK_ADDR, rpmb_buffer, rpmb_key, &rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read device state");
		return ret;
	}

	rpmb_buffer[0] = DEVICE_STATE_MAGIC;
	rpmb_buffer[1] = state;
	ret = write_rpmb_data(NULL, RPMB_DEVICE_STATE_BLOCK_COUNT, RPMB_DEVICE_STATE_BLOCK_ADDR, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write device state");
		return ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS read_rpmb_device_state_real(UINT8 *state)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = read_rpmb_data(NULL, RPMB_DEVICE_STATE_BLOCK_COUNT, RPMB_DEVICE_STATE_BLOCK_ADDR, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read device state");
		return ret;
	}

	if (rpmb_buffer[0] != DEVICE_STATE_MAGIC) {
		return EFI_NOT_FOUND;
	}
	*state = rpmb_buffer[1];
	debug(L"magic=%2x,state=%2x", rpmb_buffer[0], rpmb_buffer[1]);
	return EFI_SUCCESS;
}

static EFI_STATUS write_rpmb_rollback_index_real(size_t index, UINT64 in_rollback_index)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;
	UINT16 blk_addr = RPMB_ROLLBACK_INDEX_BLOCK_ADDR;
	UINT16 blk_offset;

	blk_addr += index / RPMB_ROLLBACK_INDEX_COUNT_PER_BLOCK;
	blk_offset = (index % RPMB_ROLLBACK_INDEX_COUNT_PER_BLOCK) * sizeof(UINT64);

	ret = read_rpmb_data(NULL, 1, blk_addr, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read rollback index");
		return ret;
	}

	if (!memcmp(&in_rollback_index, rpmb_buffer + blk_offset, sizeof(UINT64))) {
		return EFI_SUCCESS;
	}

	memcpy(rpmb_buffer + blk_offset, &in_rollback_index, sizeof(UINT64));
	ret = write_rpmb_data(NULL, 1, blk_addr, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write rollback index");
		return ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS read_rpmb_rollback_index_real(size_t index, UINT64 *out_rollback_index)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;
	UINT16 blk_addr = RPMB_ROLLBACK_INDEX_BLOCK_ADDR;
	UINT16 blk_offset;

	blk_addr += index / RPMB_ROLLBACK_INDEX_COUNT_PER_BLOCK;
	blk_offset = (index % RPMB_ROLLBACK_INDEX_COUNT_PER_BLOCK) * sizeof(UINT64);
	ret = read_rpmb_data(NULL, 1, blk_addr, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read rollback index");
		return ret;
	}
	memcpy(out_rollback_index, rpmb_buffer + blk_offset, sizeof(UINT64));
	debug(L"rollback index=%16x", *out_rollback_index);
	return EFI_SUCCESS;
}

static EFI_STATUS write_rpmb_keybox_magic_real(UINT16 offset, void *buffer)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = read_rpmb_data(NULL, 1, offset, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read keybox magic data");
		return ret;
	}

	if (!memcmp(buffer, rpmb_buffer, sizeof(uint32_t))) {
		return EFI_SUCCESS;
	}

	memcpy(rpmb_buffer, buffer, sizeof(uint32_t));
	ret = write_rpmb_data(NULL, 1, offset, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write keybox magic data");
		return ret;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS read_rpmb_keybox_magic_real(UINT16 offset, void *buffer)
{
	EFI_STATUS ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = read_rpmb_data(NULL, 1, offset, rpmb_buffer, rpmb_key, &rpmb_result);
	debug(L"ret=%d, rpmb_result=%d", ret, rpmb_result);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read keybox magic data");
		return ret;
	}

	memcpy(buffer, rpmb_buffer, sizeof(uint32_t));

	return EFI_SUCCESS;
}

static BOOLEAN is_rpmb_programed_simulate(void)
{
	EFI_STATUS ret;
	UINT32 write_counter;
	RPMB_RESPONSE_RESULT rpmb_result;

	ret = simulate_get_rpmb_counter(&write_counter, (const void *)rpmb_key, &rpmb_result);
	debug(L"get_counter ret=%d, wc=%d", ret, write_counter);
	if (EFI_ERROR(ret) && (rpmb_result == RPMB_RES_NO_AUTH_KEY_PROGRAM)) {
		debug(L"rpmb key is not programmed");
		return FALSE;
	}
	return TRUE;
}

static EFI_STATUS program_rpmb_key_simulate(UINT8 *key)
{
	EFI_STATUS efi_ret;
	RPMB_RESPONSE_RESULT rpmb_result;

	memcpy(rpmb_key, key, RPMB_KEY_SIZE);
	efi_ret = simulate_program_rpmb_key((const void *)key, &rpmb_result);

	if (EFI_ERROR(efi_ret)) {
		efi_perror(efi_ret, L"Failed to program rpmb key");
		return efi_ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS rpmb_read_counter_simulate(const void *key, RPMB_RESPONSE_RESULT *result)
{
	EFI_STATUS efi_ret;
	UINT32 write_counter;

	efi_ret = simulate_get_rpmb_counter(&write_counter, key, result);
	if (EFI_ERROR(efi_ret) && *result != RPMB_RES_NO_AUTH_KEY_PROGRAM) {
		efi_perror(efi_ret, L"Failed to read counter for simulate");
		return efi_ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS write_rpmb_device_state_simulate(UINT8 state)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = RPMB_DEVICE_STATE_BLOCK_ADDR * RPMB_BLOCK_SIZE;
	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, RPMB_BLOCK_SIZE);
	/*gpt not updated, force success*/
	if (ret == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read device state");
		return ret;
	}

	rpmb_buffer[0] = DEVICE_STATE_MAGIC;
	rpmb_buffer[1] = state;
	ret = simulate_write_rpmb_data(byte_offset, rpmb_buffer, RPMB_BLOCK_SIZE);
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write device state");
		return ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS read_rpmb_device_state_simulate(UINT8 *state)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = RPMB_DEVICE_STATE_BLOCK_ADDR * RPMB_BLOCK_SIZE;
	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, RPMB_BLOCK_SIZE);
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read device state");
		return ret;
	}

	if (rpmb_buffer[0] != DEVICE_STATE_MAGIC) {
		return EFI_NOT_FOUND;
	}
	*state = rpmb_buffer[1];
	debug(L"magic=%2x,state=%2x", rpmb_buffer[0], rpmb_buffer[1]);
	return EFI_SUCCESS;
}

static EFI_STATUS write_rpmb_rollback_index_simulate(size_t index, UINT64 in_rollback_index)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = RPMB_ROLLBACK_INDEX_BLOCK_ADDR * RPMB_BLOCK_SIZE + index * sizeof(UINT64);

	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, sizeof(UINT64));
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read rollback index");
		return ret;
	}

	/*gpt not updated, force success*/
	if (ret == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}

	if (!memcmp(&in_rollback_index, rpmb_buffer, sizeof(UINT64))) {
		return EFI_SUCCESS;
	}

	memcpy(rpmb_buffer, &in_rollback_index, sizeof(UINT64));
	ret = simulate_write_rpmb_data(byte_offset, rpmb_buffer, sizeof(UINT64));
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write rollback index");
		return ret;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS read_rpmb_rollback_index_simulate(size_t index, UINT64 *out_rollback_index)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = RPMB_ROLLBACK_INDEX_BLOCK_ADDR * RPMB_BLOCK_SIZE + index * sizeof(UINT64);
	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, sizeof(UINT64));
	debug(L"ret=%d", ret);
	/*gpt not updated, force success*/
	if (ret == EFI_NOT_FOUND) {
		*out_rollback_index = 0;
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read rollback index");
		return ret;
	}
	memcpy(out_rollback_index, rpmb_buffer, sizeof(UINT64));
	debug(L"rollback index=%16x", *out_rollback_index);
	return EFI_SUCCESS;
}

static EFI_STATUS write_rpmb_keybox_magic_simulate(UINT16 offset, void *buffer)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = offset * RPMB_BLOCK_SIZE;
	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, sizeof(uint32_t));
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read keybox magic data");
		return ret;
	}

	/*gpt not updated, force success*/
	if (ret == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}

	if (!memcmp(buffer, rpmb_buffer, sizeof(uint32_t))) {
		return EFI_SUCCESS;
	}

	memcpy(rpmb_buffer, buffer, sizeof(uint32_t));
	ret = simulate_write_rpmb_data(byte_offset, rpmb_buffer, sizeof(uint32_t));
	debug(L"ret=%d", ret);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to write keybox magic data");
		return ret;
	}
	return EFI_SUCCESS;

}

static EFI_STATUS read_rpmb_keybox_magic_simulate(UINT16 offset, void *buffer)
{
	EFI_STATUS ret;
	UINT32 byte_offset;

	byte_offset = offset * RPMB_BLOCK_SIZE;
	ret = simulate_read_rpmb_data(byte_offset, rpmb_buffer, sizeof(uint32_t));
	debug(L"ret=%d", ret);
	/*gpt not updated, force success*/
	if (ret == EFI_NOT_FOUND) {
		memset(buffer, 0, sizeof(uint32_t));
		return EFI_SUCCESS;
	}

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read keybox magic data");
		return ret;
	}

	memcpy(buffer, rpmb_buffer, sizeof(uint32_t));

	return EFI_SUCCESS;
}

EFI_STATUS rpmb_key_init(void)
{
	UINT8 key[RPMB_KEY_SIZE] = {0};
	UINT8 *out_key;
	UINT8 number_derived_key = 0;
	UINT16 i;
	RPMB_RESPONSE_RESULT result;
	EFI_STATUS ret = EFI_SUCCESS;

	if (is_boot_device_virtual() || is_eom_and_secureboot_enabled()) {
		ret = clear_teedata_flag();
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Clear teedata flag failed");
			return ret;
		}
	}

	ret = get_rpmb_derived_key(&out_key, &number_derived_key);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"get_rpmb_derived_key failed");
		return ret;
	}

	for (i = 0; i < number_derived_key; i++) {
		memcpy(key, out_key + i * RPMB_KEY_SIZE, RPMB_KEY_SIZE);
		dump_rpmb_key(key);
		ret = rpmb_read_counter_in_sim_real(key, &result);
		if (ret == EFI_SUCCESS || result == RPMB_RES_NO_AUTH_KEY_PROGRAM)
			break;

		if (result != RPMB_RES_AUTH_FAILURE) {
			efi_perror(ret, L"rpmb_read_counter unexpected error: %d.", result);
			goto err_get_rpmb_key;
		}
	}

	if (i >= number_derived_key) {
		error(L"All RPMB keys are not match!");
		goto err_get_rpmb_key;
	}

	if (i != 0)
		debug(L"RPMB seed/key changed to %d ", i);

	if (!is_rpmb_programed()) {
		debug(L"RPMB key is not programmed, use the first derived key.");
		ret = program_rpmb_key_in_sim_real(key);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"RPMB key program failed");
			return ret;
		}
	} else {
		debug(L"RPMB already programmed");
		set_rpmb_key(key);
	}

	// Should output this info, since there maybe some error log about some keys failed at before.
	log(L"Init RPMB key successfully\n");
	dump_rpmb_key(key);

err_get_rpmb_key:
	memset(key, 0, sizeof(key));

	return ret;
}

BOOLEAN try_physical_rpmb = TRUE;
void set_try_physical_rpmb(BOOLEAN new_try)
{
	try_physical_rpmb = new_try;
}

BOOLEAN try_simulate_rpmb = TRUE;
void set_try_simulate_rpmb(BOOLEAN new_try)
{
	try_simulate_rpmb = new_try;
}

EFI_STATUS rpmb_storage_init(void)
{
	EFI_STATUS ret = EFI_SUCCESS;
	BOOLEAN real = FALSE;

#ifndef RPMB_SIMULATE
	if (!is_live_boot() && try_physical_rpmb) {
		// For USB live boot case, always use simulate RPMB.
		// For virtual storage, always use real rpmb interface but the decision to
		// use simulate or physical are in device module side not in android osloader.
		// For other cases, Check life cycle and secure boot.
		if (is_boot_device_virtual())
			real = TRUE;
		else
			real = is_eom_and_secureboot_enabled();

		if (real) {
			// If life cycle is END USER and secure boot is enabled,
			// then init the physical RPMB now
			ret = rpmb_init(get_boot_device_handle());
			if (EFI_ERROR(ret)) {
				if (ret != EFI_NOT_FOUND) {
					efi_perror(ret, L"Init physical RPMB failed");
					return ret;
				}
				debug(L"Can't find physical RPMB, use simulate RPMB now");
				real = FALSE;
 				ret = EFI_SUCCESS;
			}
		}
	}
#endif

	if (real) {
		debug(L"Use physical RPMB");
		rpmb__sim_real_storage_ops.is_rpmb_programed = is_rpmb_programed_real;
		rpmb__sim_real_storage_ops.program_rpmb_key = program_rpmb_key_real;
		rpmb__sim_real_storage_ops.rpmb_read_counter = rpmb_read_counter_real;
		rpmb__sim_real_storage_ops.write_rpmb_device_state = write_rpmb_device_state_real;
		rpmb__sim_real_storage_ops.read_rpmb_device_state = read_rpmb_device_state_real;
		rpmb__sim_real_storage_ops.write_rpmb_rollback_index = write_rpmb_rollback_index_real;
		rpmb__sim_real_storage_ops.read_rpmb_rollback_index = read_rpmb_rollback_index_real;
		rpmb__sim_real_storage_ops.write_rpmb_keybox_magic = write_rpmb_keybox_magic_real;
		rpmb__sim_real_storage_ops.read_rpmb_keybox_magic = read_rpmb_keybox_magic_real;
	} else {
		if (!try_simulate_rpmb)
			return EFI_NOT_FOUND;

		debug(L"Use simulate RPMB");
		rpmb__sim_real_storage_ops.is_rpmb_programed = is_rpmb_programed_simulate;
		rpmb__sim_real_storage_ops.program_rpmb_key = program_rpmb_key_simulate;
		rpmb__sim_real_storage_ops.rpmb_read_counter = rpmb_read_counter_simulate;
		rpmb__sim_real_storage_ops.write_rpmb_device_state = write_rpmb_device_state_simulate;
		rpmb__sim_real_storage_ops.read_rpmb_device_state = read_rpmb_device_state_simulate;
		rpmb__sim_real_storage_ops.write_rpmb_rollback_index = write_rpmb_rollback_index_simulate;
		rpmb__sim_real_storage_ops.read_rpmb_rollback_index = read_rpmb_rollback_index_simulate;
		rpmb__sim_real_storage_ops.write_rpmb_keybox_magic = write_rpmb_keybox_magic_simulate;
		rpmb__sim_real_storage_ops.read_rpmb_keybox_magic = read_rpmb_keybox_magic_simulate;
	}

	return ret;
}

EFI_STATUS get_rpmb_keys(IN UINT32 num_partition, OUT UINT8 rpmb_key_list[][RPMB_MAX_KEY_SIZE])
{
	/* initially hardcoded all rpmb keys as 0 */
	memset(rpmb_key_list, 0, num_partition * RPMB_MAX_KEY_SIZE);

	// Now only the first partition is supported, and only use 32 bytes
#if RPMB_KEY_SIZE > RPMB_MAX_KEY_SIZE
#error RPMB_KEY_SIZE should less or equal than RPMB_MAX_KEY_SIZE
#endif
	memcpy(rpmb_key_list[0], rpmb_key, RPMB_KEY_SIZE);

	return EFI_SUCCESS;
}
