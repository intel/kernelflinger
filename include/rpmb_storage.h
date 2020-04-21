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
#ifndef _RPMB_STORAGE_H_
#define _RPMB_STORAGE_H_

#include "rpmb.h"

#define RPMB_KEY_SIZE    32
#define RPMB_SEED_SIZE  32
#define RPMB_NUMBER_KEY  10
#define MMC_PROD_NAME_WITH_PSN_LEN   15
#define RPMB_MAX_PARTITION_NUMBER 6
#define RPMB_MAX_KEY_SIZE 64

typedef struct rpmb_sim_real_storage_interface {
	BOOLEAN (*is_rpmb_programed)(void);
	EFI_STATUS (*program_rpmb_key)(UINT8 *key);
	EFI_STATUS (*rpmb_read_counter)(const void *key, RPMB_RESPONSE_RESULT *result);

	EFI_STATUS (*write_rpmb_device_state)(UINT8 state);
	EFI_STATUS (*read_rpmb_device_state)(UINT8 *state);

	EFI_STATUS (*write_rpmb_rollback_index)(size_t index, UINT64 in_rollback_index);
	EFI_STATUS (*read_rpmb_rollback_index)(size_t index, UINT64 *out_rollback_index);

	EFI_STATUS (*write_rpmb_keybox_magic)(UINT16 offset, void *buffer);
	EFI_STATUS (*read_rpmb_keybox_magic)(UINT16 offset, void *buffer);
} rpmb_sim_real_storage_interface_t;

EFI_STATUS rpmb_storage_init(void);
EFI_STATUS get_rpmb_derived_key(OUT UINT8 **d_key, OUT UINT8 *number_d_key);
EFI_STATUS set_rpmb_derived_key(IN VOID *kbuf, IN size_t kbuf_len, IN size_t num_key);
EFI_STATUS set_rpmb_derived_key_ex(IN VOID *kbuf, IN size_t kbuf_len, IN size_t num_key, IN int is_firmware_key);
void clear_rpmb_key(void);
void set_rpmb_key(UINT8 *key);
void get_rpmb_key(UINT8 *key);
EFI_STATUS rpmb_key_init(void);
EFI_STATUS get_rpmb_keys(IN UINT32 num_partition, OUT UINT8 rpmb_key_list[][RPMB_MAX_KEY_SIZE]);
EFI_STATUS clear_teedata_flag(void);
EFI_STATUS erase_rpmb_all_blocks(void);
EFI_STATUS rpmb_read_counter_in_sim_real(const void *key, RPMB_RESPONSE_RESULT *result);

BOOLEAN is_rpmb_programed(void);
EFI_STATUS program_rpmb_key_in_sim_real(UINT8 *key);

EFI_STATUS write_rpmb_device_state(UINT8 state);
EFI_STATUS read_rpmb_device_state(UINT8 *state);

EFI_STATUS write_rpmb_rollback_index(size_t index, UINT64 in_rollback_index);
EFI_STATUS read_rpmb_rollback_index(size_t index, UINT64 *out_rollback_index);

EFI_STATUS write_rpmb_keybox_magic(UINT16 offset, void *buffer);
EFI_STATUS read_rpmb_keybox_magic(UINT16 offset, void *buffer);
#endif
