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

#include "ioport.h"

static const char * const usage = "Usage:\n\
  inb|inw|inl IOPORT\n\
  outb|outw|outl IOPORT DATA";

static inline UINT8 inb(int port)
{
	UINT8 val;
	__asm__ __volatile__("inb %w1, %b0" : "=a"(val) : "Nd"(port));
	return val;
}

static inline UINT16 inw(int port)
{
	UINT16 val;
	__asm__ __volatile__("inw %w1, %w0" : "=a"(val) : "Nd"(port));
	return val;
}

static inline void outb(UINT8 val, int port)
{
	__asm__ __volatile__("outb %b0, %w1" : : "a"(val), "Nd"(port));
}

static inline void outw(UINT16 val, int port)
{
	__asm__ __volatile__("outw %w0, %w1" : : "a"(val), "Nd"(port));
}

static const CHAR16 *VALUE_FORMAT[] = {
	['b'] = L"0x%02x\n",
	['w'] = L"0x%04x\n",
	['l'] = L"0x%08x\n"
};

static EFI_STATUS ioport_main(INTN argc, const char **argv)
{
	EFI_STATUS ret;
	UINT64 ioport, data;

	if (!(argc == 2 && argv[0][0] == 'i') &&
	    !(argc == 3 && argv[0][0] == 'o'))
		return EFI_INVALID_PARAMETER;

	ret = ss_read_number(argv[1], "IOPORT", &ioport);
	if (EFI_ERROR(ret))
		return EFI_INVALID_PARAMETER;

	switch (argv[0][0]) {
	case 'i':
		switch (argv[0][2]) {
		case 'b':
			data = inb(ioport);
			break;
		case 'w':
			data = inw(ioport);
			break;
		case 'l':
			data = inl(ioport);
			break;
		}
		ss_printf(VALUE_FORMAT[(unsigned char)argv[0][2]], data);
		break;

	case 'o':
		ret = ss_read_number(argv[2], "DATA", &data);
		if (EFI_ERROR(ret))
			return EFI_INVALID_PARAMETER;

		switch (argv[0][3]) {
		case 'b':
			outb(data, ioport);
			break;
		case 'w':
			outw(data, ioport);
			break;
		case 'l':
			outl(data, ioport);
			break;
		}
		break;
	}

	return EFI_SUCCESS;
}

shcmd_t inb_shcmd = {
	.name = "inb",
	.summary = "Perform a byte size read operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};
shcmd_t inw_shcmd = {
	.name = "inw",
	.summary = "Perform a word size (16 bits) read operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};
shcmd_t inl_shcmd = {
	.name = "inl",
	.summary = "Perform a long size (32 bits) read operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};
shcmd_t outb_shcmd = {
	.name = "outb",
	.summary = "Perform a byte size write operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};
shcmd_t outw_shcmd = {
	.name = "outw",
	.summary = "Perform a word size (16 bits) write operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};

shcmd_t outl_shcmd = {
	.name = "outl",
	.summary = "Perform a long size (32 bits) write operation on the given I/O port",
	.help = usage,
	.main = ioport_main
};
