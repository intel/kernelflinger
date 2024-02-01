/*
 * Copyright (c) 2023, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jingdong Lu <jingdong.lu@intel.com>
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

#include "ivshmem.h"

#define PCI_MAX_DEV_NUM     32
#define PCI_MAX_FUNC_NUM    8

#define PCI_CONFIG_ADDRESS_REGISTER 0xCF8
#define PCI_CONFIG_DATA_REGISTER    0xCFC

#define IVSHMEM_VENDOR_ID	0x1AF4
#define IVSHMEM_DEVICE_ID	0x1110

#define IVPOSITION_OFF	0x08
#define DOORBELL_OFF	0x0C

#define ROT_INTERRUPT			0x1
#define ROLLBACK_INDEX_INTERRUPT	0x2

#define IVSHMEM_DEFAULT_SIZE	0x400000
#define IVSHMEM_ROT_OFFSET	0x100000

/*
 * struct pci_type0_config - Type 00h Configuration Space Header
 * @vendor_id:              The manufacturer of the device identifier.
 * @device_id:              The particular device identifier.
 * @command:                Control over a device's ability to generate and
 *                          respond to PCI cycles.
 * @status:                 Record status information for PCI bus related
 *                          events.
 * @revision_id:            Device specific revision identifier.
 * @class_code:             Identify the generic function of the device.
 * @cache_line_size:        Specify the system cacheline size.
 * @latency_timer:          The value of the Latency Timer for this PCI bus
 *                          master in units of PCI bus clocks.
 * @header_type:            Identify the layout of the second part of the
 *                          predefined header.
 * @bist:                   Control and status of Built-in Self Test.
 * @base_addr_reg0:         Base Address register 0
 * @base_addr_reg1:         Base Address register 1
 * @base_addr_reg2:         Base Address register 2
 * @base_addr_reg3:         Base Address register 3
 * @base_addr_reg4:         Base Address register 4
 * @base_addr_reg5:         Base Address register 5
 * @cardbus_cis_pointer:    Used by those devices that want to share silicon
 *                          between CardBus and PCI.
 * @subsystem_vendor_id:    Vendor of the add-in card or subsystem.
 * @subsystem_id:           Vendor specific identifier.
 * @expansion_rom_base:     Base address and size information for expansion ROM.
 * @capabilities_pointer:   Point to a linked list of new capabilities
 *                          implemented by this device.
 * @rsvd:                   Reserved.
 * @interrupt_line:         Communicate interrupt line routing information.
 * @interrupt_pin:          Interrupt pin the device (or device function) uses.
 * @min_gnt:                Specify how long a burst period the device needs
 *                          assuming a clock rate of 33 MHz.
 * @max_lat:                Specify how often the device needs to gain access
 *                          to the PCI bus.
 */
struct pci_type0_config {
	UINT16 vendor_id;
	UINT16 device_id;
	UINT16 command;
	UINT16 status;
	UINT8 revision_id;
	UINT8 class_code[3];
	UINT8 cache_line_size;
	UINT8 latency_timer;
	UINT8 header_type;
	UINT8 bist;
	UINT32 base_addr_reg0;
	UINT32 base_addr_reg1;
	UINT32 base_addr_reg2;
	UINT32 base_addr_reg3;
	UINT32 base_addr_reg4;
	UINT32 base_addr_reg5;
	UINT32 cardbus_cis_pointer;
	UINT16 subsystem_vendor_id;
	UINT16 subsystem_id;
	UINT32 expansion_rom_base;
	UINT8 capabilities_pointer;
	UINT8 rsvd[7];
	UINT8 interrupt_line;
	UINT8 interrupt_pin;
	UINT8 min_gnt;
	UINT8 max_lat;
};

/* PCI config header fileds */
#define PCI_CONFIG_VENDOR_ID_OFFSET \
    offsetof(struct pci_type0_config, vendor_id)
#define PCI_CONFIG_COMMAND_OFFSET offsetof(struct pci_type0_config, command)
#define PCI_CONFIG_STATUS_OFFSET offsetof(struct pci_type0_config, status)
#define PCI_CONFIG_REVISION_OFFSET offsetof(struct pci_type0_config, revision_id)
#define PCI_CONFIG_BAR0_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg0)
#define PCI_CONFIG_BAR1_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg1)
#define PCI_CONFIG_BAR2_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg2)
#define PCI_CONFIG_CAP_PTR_OFFSET \
    offsetof(struct pci_type0_config, capabilities_pointer)

/*
 * Memory Space bit in Command Register.
 * Control a device's response to Memory Space access.
 */
#define CMD_MEM_SPACE_BIT_POSITION 1

/**
 * union pci_config_address - PCI configuration address
 * @bits:           PCI configuration address in bits
 * @bits.reg:       Register ID of PCI device
 * @bits.function:  Function ID of PCI device
 * @bits.device:    Device ID of PCI device
 * @bits.bus:       Bus ID of PCI device
 * @bits.reserved:  Reserved fields
 * @bits.enable:    Enable bit
 * @uint32:         32-bit value of union
 */
typedef union {
	struct {
		UINT32 reg:8;
		UINT32 function:3;
		UINT32 device:5;
		UINT32 bus:8;
		UINT32 reserved:7;
		UINT32 enable:1;
	} __attribute__((packed))  bits;
	UINT32 uint32;
} __attribute__((packed))  pci_config_address_t;

struct ivshmem_device {
	UINT8 dev;
	UINT8 func;
	UINT8 revision;

	UINT32 bar0_addr;
	UINT32 bar0_len;
	UINT32 bar1_addr;
	UINT32 bar1_len;
	UINT32 bar2_addr;
	UINT32 bar2_len;
};

static struct ivshmem_device g_ivshmem_dev;

UINT64 g_ivshmem_rot_addr = 0;

static UINT8 hw_read_port_8(UINT16 port)
{
	UINT8 val8;

	__asm__ __volatile__ (
		"in %1, %0"
		: "=a" (val8)
		: "d" (port)
	);

	return val8;
}

static UINT16 hw_read_port_16(UINT16 port)
{
    UINT16 val16;

    __asm__ __volatile__ (
        "in %1, %0"
        : "=a" (val16)
        : "d" (port)
    );

    return val16;
}

static UINT32 hw_read_port_32(UINT16 port)
{
    UINT32 val32;

    __asm__ __volatile__ (
        "in %1, %0"
        : "=a" (val32)
        : "d" (port)
    );

    return val32;
}

static void hw_write_port_8(UINT16 port, UINT8 val8)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val8)
    );
}

static void hw_write_port_16(UINT16 port, UINT16 val16)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val16)
    );
}

static void hw_write_port_32(UINT16 port, UINT32 val32)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val32)
    );
}

static UINT8 pci_read8(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_8(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x3));
}

static UINT16 pci_read16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_16(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x3));
}

static UINT32 pci_read32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_32(PCI_CONFIG_DATA_REGISTER);
}

static void pci_write16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg, UINT8 value)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    hw_write_port_16(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x2), value);
}

static void pci_write32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg, UINT32 value)
{
	pci_config_address_t addr;

	addr.uint32 = 0;
	addr.bits.bus = bus;
	addr.bits.device = device;
	addr.bits.function = function;
	addr.bits.reg = reg;
	addr.bits.enable = 1;

	hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
	hw_write_port_32(PCI_CONFIG_DATA_REGISTER, value);
}

#define mb()        __asm__ volatile ("mfence":::"memory");
#define wmb()       __asm__ volatile ("sfence":::"memory");
#define rmb()       __asm__ volatile ("lfence":::"memory");

static inline UINT32 io_read_32(const volatile void* addr) {
	UINT32 out;

	__asm__ __volatile__("movl (%%edx), %%eax" : "=a"(out) : "d"(addr));
	rmb();

	return out;
}

static inline void io_write_32(volatile void* addr, UINT32 val) {
	wmb();
	__asm__ __volatile__("movl %%eax, (%%edx)" ::"a"(val), "d"(addr) : "memory");
}

static UINT32 pci_resource_start(UINT8 bus, UINT8 device, UINT8 function,
        UINT8 bar_off)
{
	return (pci_read32(bus, device, function, bar_off) & 0xFFFFFFF0);
}

static UINT32 pci_resource_len(UINT8 bus, UINT8 device, UINT8 function,
        UINT8 bar_off)
{
	UINT32 bar = 0, len = 0;

	bar = pci_read32(bus, device, function, bar_off);
	pci_write32(bus, device, function, bar_off, 0xFFFFFFFF);
	len = pci_read32(bus, device, function, bar_off);
	pci_write32(bus, device, function, bar_off, bar);
	if (len == 0x0) {
		return 0x0;
	} else {
		return (~(len & 0xFFFFFFF0) + 1);
	}
}

static bool ivshmem_get_dev_func(void)
{
	UINT8 device, function;

	/*
	 * PCI devices reside in bus zero by default.
	 *
	 * Traverse all devices and functions of bus zero to find virtio console
	 * device. To speed up probe, read 32 bits combination of vendor ID and
	 * device ID directly insteading of read 16 bits twice.
	 */
	for (device = 0; device < PCI_MAX_DEV_NUM; device++) {
		for (function = 0; function < PCI_MAX_FUNC_NUM; function++) {
			if (pci_read32(0, device, function, PCI_CONFIG_VENDOR_ID_OFFSET) ==
					(IVSHMEM_VENDOR_ID | (IVSHMEM_DEVICE_ID << 16))) {
				g_ivshmem_dev.dev = device;
				g_ivshmem_dev.func = function;
				return true;
			}
		}
	}

	return false;
}

EFI_STATUS ivshmem_init(void)
{
	UINT8 dev, func;
	UINT16 val16 = 0;

	if (ivshmem_get_dev_func()) {
		info(L"Found IVSHMEM device 0x%x/0x%x", g_ivshmem_dev.dev, g_ivshmem_dev.func);
	} else {
		error(L"IVSHMEM device not found!");
		return EFI_NOT_FOUND;
	}

	dev = g_ivshmem_dev.dev;
	func = g_ivshmem_dev.func;
	g_ivshmem_dev.revision = pci_read8(0, dev, func, PCI_CONFIG_REVISION_OFFSET);
	info(L"IVSHMEM device: revision=0x%x", g_ivshmem_dev.revision);

	/* Enable BAR address MMIO support. */
	val16 = pci_read16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET);
	val16 |= 1 << CMD_MEM_SPACE_BIT_POSITION;
	pci_write16(0, dev, func, PCI_CONFIG_COMMAND_OFFSET, val16);

	g_ivshmem_dev.bar0_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
	g_ivshmem_dev.bar0_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR0_OFFSET);
	info(L"IVSHMEM device: bar0 addr=0x%x, len=0x%x",
		g_ivshmem_dev.bar0_addr, g_ivshmem_dev.bar0_len);

	g_ivshmem_dev.bar2_addr = pci_resource_start(0, dev, func, PCI_CONFIG_BAR2_OFFSET);
	g_ivshmem_dev.bar2_len = pci_resource_len(0, dev, func, PCI_CONFIG_BAR2_OFFSET);
	info(L"IVSHMEM device: bar2 addr=0x%x, len=0x%x",
			g_ivshmem_dev.bar2_addr, g_ivshmem_dev.bar2_len);
	if (g_ivshmem_dev.bar2_len < IVSHMEM_DEFAULT_SIZE) {
		error(L"IVSHMEM device: bar2 size too small");
		return EFI_BUFFER_TOO_SMALL;
	}

	g_ivshmem_rot_addr = g_ivshmem_dev.bar2_addr + IVSHMEM_ROT_OFFSET;
	info(L"IVSHMEM device: rot_addr=0x%lx", g_ivshmem_rot_addr);

	if (g_ivshmem_dev.revision == 1) {
		info(L"IVSHMEM device: ivposition=%d",
			io_read_32((void *)((UINT64)(g_ivshmem_dev.bar0_addr + IVPOSITION_OFF))));
	}

	return EFI_SUCCESS;
}

void ivshmem_rot_interrupt(void)
{
	io_write_32((void *)((UINT64)(g_ivshmem_dev.bar0_addr + DOORBELL_OFF)),
		ROT_INTERRUPT);
}

#define NOT_READY_MAGIC 0x12ABCDEF

void ivshmem_rollback_index_interrupt(struct tpm2_int_req* req)
{
	if (NULL == req)
		return;

	if (0 == g_ivshmem_rot_addr) {
		debug(L"Error! ivshmem is not initialized.");
		return;
	}

	//offset 1 page reserved for rot.
	UINT64 rollback_index_addr = g_ivshmem_rot_addr + 0x1000;
	struct tpm2_int_req * p_req = (struct tpm2_int_req *)rollback_index_addr;

	req->ret = NOT_READY_MAGIC;
	UINT32 req_size = sizeof(struct tpm2_int_req) + req->size;
	if (req_size > 0x1000) {
		info(L"req size is too large(0x%X), abort...", req_size);
		return;
	}
	memcpy(p_req, req, req_size);

	io_write_32((void *)((UINT64)(g_ivshmem_dev.bar0_addr + DOORBELL_OFF)), ROLLBACK_INDEX_INTERRUPT);

	while (NOT_READY_MAGIC == p_req->ret) {
		//just wait for int handler return
	}

	memcpy(req, p_req, req_size);

	return;
}

