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

#include "pci_class.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

typedef struct {
	UINT8 id;
	char *name;
} assoc_t;

static assoc_t UNCLASSIFIED[] = {
	{ 0x00,	"Non-VGA unclassified device" },
	{ 0x01,	"VGA compatible unclassified device" },
	{ 0xFF, NULL }
};

static assoc_t MASS[] = {
	{ 0x00,	"SCSI storage controller" },
	{ 0x01,	"IDE interface" },
	{ 0x02,	"Floppy disk controller" },
	{ 0x03,	"IPI bus controller" },
	{ 0x04,	"RAID bus controller" },
	{ 0x05,	"ATA controller" },
	{ 0x06,	"SATA controller" },
	{ 0x07,	"Serial Attached SCSI controller" },
	{ 0x08,	"Non-Volatile memory controller" },
	{ 0x80,	"Mass storage controller" },
	{ 0xFF, NULL }
};

static assoc_t NETWORK[] = {
	{ 0x00,	"Ethernet controller" },
	{ 0x01,	"Token ring network controller" },
	{ 0x02,	"FDDI network controller" },
	{ 0x03,	"ATM network controller" },
	{ 0x04,	"ISDN controller" },
	{ 0x05,	"WorldFip controller" },
	{ 0x06,	"PICMG controller" },
	{ 0x07,	"Infiniband controller" },
	{ 0x08,	"Fabric controller" },
	{ 0x80,	"Network controller" },
	{ 0xFF, NULL }
};

static assoc_t DISPLAY[] = {
	{ 0x00,	"VGA compatible controller" },
	{ 0x01,	"XGA compatible controller" },
	{ 0x02,	"3D controller" },
	{ 0x80,	"Display controller" },
	{ 0xFF, NULL }
};

static assoc_t MULTIMEDIA[] = {
	{ 0x00,	"Multimedia video controller" },
	{ 0x01,	"Multimedia audio controller" },
	{ 0x02,	"Computer telephony device" },
	{ 0x03,	"Audio device" },
	{ 0x80,	"Multimedia controller" },
	{ 0xFF, NULL }
};

static assoc_t MEMORY[] = {
	{ 0x00,	"RAM memory" },
	{ 0x01,	"FLASH memory" },
	{ 0x80,	"Memory controller" },
	{ 0xFF, NULL }
};

static assoc_t BRIDGE[] = {
	{ 0x00,	"Host bridge" },
	{ 0x01,	"ISA bridge" },
	{ 0x02,	"EISA bridge" },
	{ 0x03,	"MicroChannel bridge" },
	{ 0x04,	"PCI bridge" },
	{ 0x05,	"PCMCIA bridge" },
	{ 0x06,	"NuBus bridge" },
	{ 0x07,	"CardBus bridge" },
	{ 0x08,	"RACEway bridge" },
	{ 0x09,	"Semi-transparent PCI-to-PCI bridge" },
	{ 0x0a,	"InfiniBand to PCI host bridge" },
	{ 0x80,	"Bridge" },
	{ 0xFF, NULL }
};

static assoc_t SIMPLE[] = {
	{ 0x00,	"Serial controller" },
	{ 0x01,	"Parallel controller" },
	{ 0x02,	"Multiport serial controller" },
	{ 0x03,	"Modem" },
	{ 0x04,	"GPIB controller" },
	{ 0x05,	"Smard Card controller" },
	{ 0x80,	"Communication controller" },
	{ 0xFF, NULL }
};

static assoc_t BASE[] = {
	{ 0x00,	"PIC" },
	{ 0x01,	"DMA controller" },
	{ 0x02,	"Timer" },
	{ 0x03,	"RTC" },
	{ 0x04,	"PCI Hot-plug controller" },
	{ 0x05,	"SD Host controller" },
	{ 0x06,	"IOMMU" },
	{ 0x80,	"System peripheral" },
	{ 0xFF, NULL }
};

static assoc_t INPUT[] = {
	{ 0x00,	"Keyboard controller" },
	{ 0x01,	"Digitizer Pen" },
	{ 0x02,	"Mouse controller" },
	{ 0x03,	"Scanner controller" },
	{ 0x04,	"Gameport controller" },
	{ 0x80,	"Input device controller" },
	{ 0xFF, NULL }
};

static assoc_t DOCKING[] = {
	{ 0x00,	"Generic Docking Station" },
	{ 0x80,	"Docking Station" },
	{ 0xFF, NULL }
};

static assoc_t PROCESSOR[] = {
	{ 0x00,	"386" },
	{ 0x01,	"486" },
	{ 0x02,	"Pentium" },
	{ 0x10,	"Alpha" },
	{ 0x20,	"Power PC" },
	{ 0x30,	"MIPS" },
	{ 0x40,	"Co-processor" },
	{ 0xFF, NULL }
};

static assoc_t SERIAL[] = {
	{ 0x00,	"FireWire (IEEE 1394" },
	{ 0x01,	"ACCESS Bus" },
	{ 0x02,	"SSA" },
	{ 0x03,	"USB controller" },
	{ 0x04,	"Fibre Channel" },
	{ 0x05,	"SMBus" },
	{ 0x06,	"InfiniBand" },
	{ 0x07,	"IPMI Interface" },
	{ 0x08,	"SERCOS interface" },
	{ 0x09,	"CANBUS" },
	{ 0xFF, NULL }
};

static assoc_t WIRELESS[] = {
	{ 0x00,	"IRDA controller" },
	{ 0x01,	"Consumer IR controller" },
	{ 0x10,	"RF controller" },
	{ 0x11,	"Bluetooth" },
	{ 0x12,	"Broadband" },
	{ 0x20,	"802.1a controller" },
	{ 0x21,	"802.1b controller" },
	{ 0x80,	"Wireless controller" },
	{ 0xFF, NULL }
};

static assoc_t INTELLIGENT[] = {
	{ 0x00,	"I2O" },
	{ 0xFF, NULL }
};

static assoc_t SATELLITE[] = {
	{ 0x01,	"Satellite TV controller" },
	{ 0x02,	"Satellite audio communication controller" },
	{ 0x03,	"Satellite voice communication controller" },
	{ 0x04,	"Satellite data communication controller" },
	{ 0xFF, NULL }
};

static assoc_t ENCRYPTION[] = {
	{ 0x00,	"Network and computing encryption device" },
	{ 0x10,	"Entertainment encryption device" },
	{ 0x80,	"Encryption controller" },
	{ 0xFF, NULL }
};

static assoc_t SIGNAL[] = {
	{ 0x00,	"DPIO module" },
	{ 0x01,	"Performance counters" },
	{ 0x10,	"Communication synchronizer" },
	{ 0x20,	"Signal processing management" },
	{ 0x80,	"Signal processing controller" },
	{ 0xFF, NULL }
};

static assoc_t PROCESSING[] = {
	{ 0x00,	"Processing accelerators" },
	{ 0x01,	"AI Inference Accelerator" },
	{ 0xFF, NULL }
};

static const struct {
	UINT8 id;
	char *name;
	assoc_t *subclass;
} CLASSES[] = {
	{ 0x00, "Unclassified", (assoc_t *)&UNCLASSIFIED },
	{ 0x01, "Mass storage controller", (assoc_t *)&MASS },
	{ 0x02, "Network controller", (assoc_t *)&NETWORK },
	{ 0x03, "Display controller", (assoc_t *)&DISPLAY },
	{ 0x04, "Multimedia device", (assoc_t *)&MULTIMEDIA },
	{ 0x05, "Memory controller", (assoc_t *)&MEMORY },
	{ 0x06, "Bridge device", (assoc_t *)&BRIDGE },
	{ 0x07, "Simple communication controllers", (assoc_t *)&SIMPLE },
	{ 0x08, "Base system peripherals", (assoc_t *)&BASE },
	{ 0x09, "Input devices", (assoc_t *)&INPUT },
	{ 0x0A, "Docking stations", (assoc_t *)&DOCKING },
	{ 0x0B, "Processors", (assoc_t *)&PROCESSOR },
	{ 0x0C, "Serial bus controllers", (assoc_t *)&SERIAL },
	{ 0x0D, "Wireless controller", (assoc_t *)&WIRELESS },
	{ 0x0E, "Intelligent I/O controllers", (assoc_t *)&INTELLIGENT },
	{ 0x0F, "Satellite communication controllers", (assoc_t *)&SATELLITE },
	{ 0x10, "Encryption/Decryption controllers", (assoc_t *)&ENCRYPTION },
	{ 0x11, "Signal processing controllers", (assoc_t *)&SIGNAL },
	{ 0x12, "Processing accelerators", (assoc_t *)&PROCESSING },
	{ 0x13, "Non-Essential Instrumentation", NULL },
	{ 0x40, "Coprocessor", NULL }
};

const char *pci_class_string(UINT8 base, UINT8 sub)
{
	UINTN i, j;
	assoc_t *subclass;

	for (i = 0; i < ARRAY_SIZE(CLASSES); i++)
		if (base == CLASSES[i].id) {
			subclass = CLASSES[i].subclass;
			if (!subclass)
				return CLASSES[i].name;

			for (j = 0; subclass[j].name; j++)
				if (sub == subclass[j].id)
					return subclass[j].name;

			return CLASSES[i].name;
		}

	return NULL;
}
