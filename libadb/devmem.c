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
#include <pae.h>

#include "devmem.h"

static const CHAR16 *VALUE_FORMAT[] = {
	L"0x%02x\n", L"0x%04x\n", L"0x%08x\n", NULL, L"0x%016x\n"
};

#define READ_OR_WRITE(DO_READ, WIDTH, ADDRESS, VALUE)		\
	do {							\
		if (DO_READ)					\
			VALUE = *(volatile WIDTH *)ADDRESS;	\
		else						\
			*(volatile WIDTH *)ADDRESS = VALUE;	\
	} while (0)

static EFI_STATUS devmem_main(INTN argc, const char **argv)
{
	EFI_STATUS ret = EFI_SUCCESS;
	EFI_PHYSICAL_ADDRESS address, width = 8 * sizeof(UINT32), value;

	switch (argc) {
	case 4:
		ret = ss_read_number(argv[3], "VALUE", &value);
		if (EFI_ERROR(ret))
			return ret;
	case 3:
		ret = ss_read_number(argv[2], "WIDTH", &width);
		if (EFI_ERROR(ret))
			return ret;
	case 2:
		ret = ss_read_number(argv[1], "ADDRESS", &address);
		if (EFI_ERROR(ret))
			return ret;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

#ifndef __LP64__
	if (address > UINT32_MAX) {
		ret = ss_pae_map(&address, sizeof(UINT64));
		if (EFI_ERROR(ret))
			return ret;
	}
#endif

	switch (width) {
	case 8:
		READ_OR_WRITE(argc < 4, UINT8, address, value);
		break;
	case 16:
		READ_OR_WRITE(argc < 4, UINT16, address, value);
		break;
	case 32:
		READ_OR_WRITE(argc < 4, UINT32, address, value);
		break;
	case 64:
		READ_OR_WRITE(argc < 4, UINT64, address, value);
		break;
	default:
		ss_printf(L"Invalid '%d' WIDTH parameter\n", width);
		ret = EFI_INVALID_PARAMETER;
	}

#ifndef __LP64__
	pae_exit();
#endif

	if (EFI_ERROR(ret))
		return ret;

	if (argc < 4)
		return ss_printf(VALUE_FORMAT[width >> 4], value);

	return ret;
}

shcmd_t devmem_shcmd = {
	.name = "devmem",
	.summary = "Read/write from physical address",
	.help = "Usage: devmem ADDRESS [WIDTH [VALUE]]\n"
	"\n"
	"Read/write from physical address\n"
	"\n"
	"    ADDRESS  Address to act upon\n"
	"    WIDTH    Width (8/16/...)\n"
	"    VALUE    Data to be written",
	.main = devmem_main
};
