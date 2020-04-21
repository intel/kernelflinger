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

#ifndef _RPMB_H_
#define _RPMB_H_

#include <lib.h>
#include "rpmb_storage_common.h"

EFI_STATUS rpmb_init(EFI_HANDLE disk_handle);
EFI_STATUS get_storage_protocol(void **rpmb_dev, EFI_HANDLE disk_handle);
EFI_STATUS program_rpmb_key(void *rpmb_dev, const void *key, RPMB_RESPONSE_RESULT *result);
EFI_STATUS get_storage_partition_num(void *rpmb_dev, UINT8 *current_part);
EFI_STATUS storage_partition_switch(void *rpmb_dev, UINT8 part);
EFI_STATUS get_rpmb_counter(void *rpmb_dev, UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result);
EFI_STATUS read_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result);
EFI_STATUS write_rpmb_data(void *rpmb_dev, UINT16 blk_count, UINT16 blk_addr, void *buffer,
		const void *key, RPMB_RESPONSE_RESULT *result);
EFI_STATUS rpmb_send_request(void *rpmb_dev,
		rpmb_data_frame *data_frame, UINT8 count, BOOLEAN is_rel_write);
EFI_STATUS rpmb_get_response(void *rpmb_dev,
		rpmb_data_frame *data_frame, UINT8 count);
EFI_STATUS program_rpmb_key_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
EFI_STATUS get_rpmb_counter_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
EFI_STATUS read_rpmb_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);
EFI_STATUS write_rpmb_data_frame(void *rpmb_dev, const rpmb_data_frame *data_in_frame, UINT32 in_cnt,
        rpmb_data_frame *data_out_frame, UINT32 out_cnt);


EFI_STATUS simulate_get_rpmb_counter(UINT32 *write_counter, const void *key,
		RPMB_RESPONSE_RESULT *result);
EFI_STATUS simulate_program_rpmb_key(const void *key,
		RPMB_RESPONSE_RESULT *result);
EFI_STATUS simulate_read_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size);
EFI_STATUS simulate_write_rpmb_data(UINT32 offset, void *buffer,
		UINT32 size);

#endif	/* _RPMB_H_ */
