/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Author: Ming Tan <ming.tan@intel.com>
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
#ifndef _SECURITY_EFI_H_
#define _SECURITY_EFI_H_

#include <efi.h>
#include <efilib.h>

#define BOOTLOADER_SEED_MAX_ENTRIES  10
#define SECURITY_EFI_TRUSTY_SEED_LEN 64

/* structure of seed info */
typedef struct {
	UINT8 svn;
	UINT8 padding[3];
	UINT8 seed[SECURITY_EFI_TRUSTY_SEED_LEN];
} __attribute__((packed)) seed_info_t;

EFI_STATUS get_seeds(IN UINT32 *num_seeds, OUT VOID *seed_list);

EFI_STATUS stop_bls_proto(void);

#endif // _SECURITY_EFI_H_
