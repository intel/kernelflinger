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

#include <lib.h>
#include <acpi.h>
#include <pae.h>

#include "hexdump.h"

static EFI_STATUS hexdump_main(INTN argc, const char **argv)
{
	EFI_STATUS ret = EFI_INVALID_PARAMETER;
	EFI_PHYSICAL_ADDRESS address, real;
	UINT64 length;

	if (argc != 3)
		return EFI_INVALID_PARAMETER;

	ret = ss_read_number(argv[1], "ADDRESS", &address);
	if (EFI_ERROR(ret))
		return EFI_INVALID_PARAMETER;
	real = address;

	ret = ss_read_number(argv[2], "LENGTH", &length);
	if (EFI_ERROR(ret))
		return EFI_INVALID_PARAMETER;

#ifndef __LP64__
	if (address > UINT32_MAX) {
		ret = ss_pae_map(&address, length);
		if (EFI_ERROR(ret))
			return ret;
	}
#endif

	ss_hexdump((unsigned char *)address, length, real, TRUE);

#ifndef __LP64__
	pae_exit();
#endif

	return EFI_SUCCESS;
}

shcmd_t hexdump_shcmd = {
	.name = "hexdump",
	.summary = "Hexdump a memory region",
	.help = "Usage: hexdump ADDRESS LENGTH",
	.main = hexdump_main
};
