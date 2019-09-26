/*
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#ifndef _SHELL_SERVICE_H_
#define _SHELL_SERVICE_H_

#include <efi.h>

EFI_STATUS ss_printf(const CHAR16 *fmt, ...);
EFI_STATUS ss_read_number(const char *arg, const char *name, UINT64 *value);
void ss_hexdump(unsigned char *buf, UINTN length,
		EFI_PHYSICAL_ADDRESS address, BOOLEAN canonical);

#ifndef __LP64__
EFI_STATUS ss_pae_map(EFI_PHYSICAL_ADDRESS *address, UINT64 length);
#endif

typedef struct {
	const char *name;
	const char *summary;
	const char *help;
	EFI_STATUS (*main)(INTN argc, const char **argv);
} shcmd_t;

#endif	/*  _SHELL_SERVICE_H_ */
