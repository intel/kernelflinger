/*
 * Copyright (c) 2023, Intel Corporation
 * All rights reserved.
 *
 * Author: Jingdong Lu <jingdong.lu@intel.com>
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

#ifndef _IVSHMEM_H_
#define _IVSHMEM_H_

#include <stdbool.h>
#include <lib.h>

#define TEE_TPM2_INIT                   0x00000001
#define TEE_TPM2_END                    0x00000002
#define TEE_TPM2_READ_DEVICE_STATE      0x00000003
#define TEE_TPM2_WRITE_DEVICE_STATE     0x00000004
#define TEE_TPM2_READ_ROLLBACK_INDEX    0x00000005
#define TEE_TPM2_WRITE_ROLLBACK_INDEX   0x00000006
#define TEE_TPM2_BOOTLOADER_NEED_INIT   0x00000007
#define TEE_TPM2_FUSE_LOCK_OWNER        0x00000008
#define TEE_TPM2_FUSE_PROVISION_SEED    0x00000009
#define TEE_TPM2_SHOW_INDEX             0x0000000A
#define TEE_TPM2_DELETE_INDEX           0x0000000B

EFI_STATUS ivshmem_init(void);

void ivshmem_rot_interrupt(void);

struct tpm2_int_req {
        UINT32 cmd;
        volatile INT32 ret;
        UINT32 size;
        UINT8  payload[0];
};

void ivshmem_rollback_index_interrupt(struct tpm2_int_req* req);

#endif /* _IVSHMEM_H_ */
