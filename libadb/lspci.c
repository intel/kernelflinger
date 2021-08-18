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
#include "lspci.h"
#include "pci_class.h"

typedef union {
	struct {
		UINT8 function : 3;
		UINT8 device : 5;
		UINT8 bus : 8;
	};
	UINT16 raw;
} pci_dev_t;

typedef struct {
	UINT16 vendor;
	UINT16 device;
	UINT16 command;
	UINT16 status;
	UINT8 revision;
	struct {
		UINT8 interface;
		UINT8 sub;
		UINT8 base;
	} class;
} __attribute__((packed)) pci_header_t;

static UINT32 pci_read_config32(pci_dev_t dev, UINT16 reg)
{
	outl(0x80000000 | dev.raw << 8 | (reg & ~3), 0xcf8);
	return inl(0xcfc + (reg & 3));
}

static void pci_read_config(pci_dev_t dev, void *buf, UINT16 count)
{
	UINTN i;

	for (i = 0; i < count; i += sizeof(UINT32))
		*(UINT32 *)&buf[i] = pci_read_config32(dev, i);
}

enum class_fmt {
	DEFAULT,
	NUMERIC,
	BOTH
};

static UINTN dump_size, class_fmt;

static const struct {
	const char *option;
	UINTN *variable;
	UINTN value;
} OPTIONS[] = {
	{ .option = "-x", .variable = &dump_size, .value = 0x40 },
	{ .option = "-xxx", .variable = &dump_size, .value = 0x100 },
	{ .option = "-n", .variable = &class_fmt, .value = NUMERIC },
	{ .option = "-nn", .variable = &class_fmt, .value = BOTH }
};

static EFI_STATUS lspci_main(INTN argc, const char **argv)
{
	UINTN i, j;
	pci_dev_t dev;
	pci_header_t header;
	unsigned char *buf = NULL;
	const char *class;

	dump_size = class_fmt = 0;
	for (i = 1; i < (UINTN)argc; i++) {
		for (j = 0; j < ARRAY_SIZE(OPTIONS); j++) {
			if (!strcmp(argv[i], OPTIONS[j].option)) {
				*(OPTIONS[j].variable) = OPTIONS[j].value;
				break;
			}
		}
		if (j == ARRAY_SIZE(OPTIONS))
			return EFI_INVALID_PARAMETER;
	}

	if (dump_size) {
		buf = AllocatePool(dump_size);
		if (!buf) {
			error(L"Failed to allocate the dump buffer");
			return EFI_OUT_OF_RESOURCES;
		}
	}

	memset_s(&header, sizeof(header), 0, sizeof(header));

	for (i = 0, dev.raw = 0; i <= (UINT16)-1; i++, dev.raw = i) {
		UINT32 val = pci_read_config32(dev, 0);

		if (val == 0xffffffff || val == 0x00000000 ||
		    val == 0x0000ffff || val == 0xffff0000)
			continue;

		pci_read_config(dev, &header, sizeof(header));

		ss_printf(L"%02x:%02x.%d ", dev.bus, dev.device, dev.function);

		class = pci_class_string(header.class.base, header.class.sub);
		switch (class_fmt) {
		case DEFAULT:
			if (class) {
				ss_printf(L"%a", class);
				break;
			}

		case NUMERIC:
			ss_printf(L"%02x%02x", header.class.base,
				  header.class.sub);
			break;

		case BOTH:
			ss_printf(L"%a [%02x%02x]", class,
				  header.class.base, header.class.sub);
			break;
		}

		ss_printf(L": %04x:%04x (rev %02x)\n",
			  header.vendor, header.device, header.revision);

		if (buf) {
			pci_read_config(dev, buf, dump_size);
			ss_hexdump(buf, dump_size, 0, FALSE);
			ss_printf(L"\n");
		}
	}

	if (buf)
		FreePool(buf);

	return EFI_SUCCESS;
}

shcmd_t lspci_shcmd = {
	.name = "lspci",
	.summary = "List the PCI Devices",
	.help = "Usage: lspci [OPTIONS]\n"
	"OPTIONS:\n"
	"-x      Hexdump of the standard part of the config space\n"
	"-xxx    Hexdump of the whole config space\n"
	"-n	Use numeric ID's\n"
	"-nn	Use both textual and numeric ID's",
	.main = lspci_main
};
