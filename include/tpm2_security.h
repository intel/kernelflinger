/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: Anisha Kulkarni <anisha.dattatraya.kulkarni@intel.com>
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

#ifndef _TPM2_SECURITY_H_
#define _TPM2_SECURITY_H_

#include <efi.h>
#include <efilib.h>
#include <lib.h>

#define TRUSTY_SEED_SIZE		32

EFI_STATUS tpm2_init(void);
EFI_STATUS tpm2_end(void);

EFI_STATUS tpm2_fuse_trusty_seed(void);
EFI_STATUS tpm2_read_trusty_seed(UINT8 seed[TRUSTY_SEED_SIZE]);

EFI_STATUS tpm2_fuse_perm_attr(void *data, uint32_t size);

EFI_STATUS tpm2_fuse_vbmeta_key_hash(void *data, uint32_t size);

EFI_STATUS tpm2_fuse_bootloader_policy(void *data, uint32_t size);

EFI_STATUS read_device_state_tpm2(UINT8 *state);
EFI_STATUS write_device_state_tpm2(UINT8 state);
EFI_STATUS read_rollback_index_tpm2(size_t rollback_index_slot, uint64_t *out_rollback_index);
EFI_STATUS write_rollback_index_tpm2(size_t rollback_index_slot, uint64_t rollback_index);

#ifndef USER
EFI_STATUS tpm2_show_index(UINT32 index, uint8_t *out_buffer, UINTN out_buffer_size);
EFI_STATUS tpm2_delete_index(UINT32 index);
#endif  // USER

EFI_STATUS tpm2_fuse_lock_owner(void);
EFI_STATUS tpm2_fuse_provision_seed(void);
#endif /* _TPM2_SECURITY_H_ */
