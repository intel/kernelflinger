/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
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

#ifndef _FLASH_H_
#define _FLASH_H_

#include <efi.h>

extern BOOLEAN new_install_device;

EFI_STATUS flash_skip(UINT64 size);
EFI_STATUS flash_write(VOID *data, UINTN size);
EFI_STATUS flash_fill(UINT32 pattern, UINTN size);

/* return value for flash() function */

#define REFRESH_PARTITION_VAR 0x1

EFI_STATUS flash(VOID *data, UINTN size, CHAR16 *label);
EFI_STATUS flash_file(EFI_HANDLE image, CHAR16 *filename, CHAR16 *label);
EFI_STATUS erase_by_label(CHAR16 *label);
EFI_STATUS garbage_disk(void);
EFI_STATUS flash_partition(VOID *data, UINTN size, CHAR16 *label);
EFI_STATUS fill_zero(EFI_BLOCK_IO *bio, UINT64 start, UINT64 end);

#endif	/* _FLASH_H_ */
