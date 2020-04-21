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

#ifndef _RPMB_STORAGE_COMMON_H
#define _RPMB_STORAGE_COMMON_H

#include <lib.h>

#define RPMB_PARTITION			3
#define RPMB_DATA_FRAME_SIZE		512
#define RPMB_DATA_MAC			32
#define RPMB_KEY_SIZE			32
#define RPMB_MAC_SIZE			32
#define RPMB_ERROR_MASK			0x07
#define RPMB_NONCE_SIZE			16

#define RPMB_RESPONSE_KEY_WRITE		0x0100
#define RPMB_RESPONSE_COUNTER_READ	0x0200
#define RPMB_RESPONSE_AUTH_WRITE	0x0300
#define RPMB_RESPONSE_AUTH_READ		0x0400
#define RPMB_RESPONSE_READ_RESULT	0x0500

#define RPMB_REQUEST_KEY_WRITE		0x0001
#define RPMB_REQUEST_COUNTER_READ	0x0002
#define RPMB_REQUEST_AUTH_WRITE		0x0003
#define RPMB_REQUEST_AUTH_READ		0x0004
#define RPMB_REQUEST_STATUS		0x0005

#define CPU_TO_BE16_SWAP(x)	\
	 ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
#define CPU_TO_BE32_SWAP(x)	\
	 ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
	 (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))
#define BE16_TO_CPU_SWAP(x)	\
	 ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
#define BE32_TO_CPU_SWAP(x)	\
	 ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
	 (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))

typedef enum {
	RPMB_RES_OK,
	RPMB_RES_GENERAL_FAILURE,
	RPMB_RES_AUTH_FAILURE,
	RPMB_RES_COUNTER_FAILURE,
	RPMB_RES_ADDRESS_FAILURE,
	RPMB_RES_WRITE_FAILURE,
	RPMB_RES_READ_FAILURE,
	RPMB_RES_NO_AUTH_KEY_PROGRAM,
	RPMB_RES_WRITE_COUNTER_EXPIRED = 0X80,
} RPMB_RESPONSE_RESULT;

#pragma pack(1)
typedef struct {
	UINT8 stuff[196];
	UINT8 key_mac[32];
	UINT8 data[256];
	UINT8 nonce[16];
	UINT32 write_counter;
	UINT16 address;
	UINT16 block_count;
	UINT16 result;
	UINT16 req_resp;
} rpmb_data_frame;
#pragma pack()

typedef struct rpmb_ops_func {
	EFI_STATUS (*get_storage_protocol)(void **rpmb_dev, EFI_HANDLE disk_handle);
	EFI_STATUS (*program_rpmb_key)(void *rpmb_dev,
			const void *key, RPMB_RESPONSE_RESULT * result);
	EFI_STATUS (*get_storage_partition_num)(void *rpmb_dev,
			UINT8 * current_part);
	EFI_STATUS (*storage_partition_switch)(void *rpmb_dev, UINT8 part);
	EFI_STATUS (*get_rpmb_counter)(void *rpmb_dev,
			UINT32 *write_counter, const void *key,
			RPMB_RESPONSE_RESULT * result);

	EFI_STATUS (*read_rpmb_data)(void *rpmb_dev,
			UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT * result);
	EFI_STATUS (*write_rpmb_data)(void *rpmb_dev,
			UINT16 blk_count, UINT16 blk_addr, void *buffer,
			const void *key, RPMB_RESPONSE_RESULT * result);

	EFI_STATUS (*rpmb_send_request)(void *rpmb_dev,
			rpmb_data_frame * data_frame, UINT8 count,
			BOOLEAN is_rel_write);
	EFI_STATUS(*rpmb_get_response)(void *rpmb_dev,
			rpmb_data_frame * data_frame, UINT8 count);
	EFI_STATUS (*program_rpmb_key_frame)(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
	EFI_STATUS (*get_rpmb_counter_frame)(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
	EFI_STATUS (*read_rpmb_data_frame)(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
	EFI_STATUS (*write_rpmb_data_frame)(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);

}rpmb_ops_func_t;

INT32 rpmb_check_mac(const UINT8 *key, rpmb_data_frame *frames, UINT8 cnt);
INT32 rpmb_calc_hmac_sha256(rpmb_data_frame *frames, UINT8 blocks_cnt,
		const UINT8 key[], UINT32 key_size,
		UINT8 mac[], UINT32 mac_size);

#endif	/* _RPMB_STORAGE_COMMON_H */
