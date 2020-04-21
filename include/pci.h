/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
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
 * This file defines bootlogic data structures, try to keep it without
 * any external definitions in order to ease export of it.
 */

#ifndef _PCI_H_
#define _PCI_H_

#include <efi.h>
#include <efilib.h>

#define PCI_DEVICE_ID_ANY 0xFFFF

typedef struct _pci_device_ids
{
	UINT16 vendor_id;
	UINT16 device_id;
} pci_device_ids_t;

/**
 * get_pci_device_path:
 * @p - Pointer to a EFI_DEVICE_PATH structure
 *
 * Checks if the Device Path given as parameter contains a PCI Device Node
 *
 * Returns:
 * a pointer to a PCI_DEVICE_PATH structure
 * NULL if the device path given as parameter doesn't contain a PCI Device Node
 */
PCI_DEVICE_PATH *get_pci_device_path(EFI_DEVICE_PATH *p);

/**
 * get_pci_device:
 * @p - Pointer to a EFI_DEVICE_PATH structure
 * @p_pciio - A corresponding EFI_PCI_IO_PROTOCOL handle if a PCI device was
 *            found in the Device Path parameter
 *
 * Queries a Device Path to check if support the PciIoProtocol
 *
 * Returns:
 * EFI_SUCCESS if the input path contains a PCI device
 * an EFI error protocol handle could not be opened
 */
EFI_STATUS get_pci_device(IN EFI_DEVICE_PATH *p, OUT EFI_PCI_IO **p_pciio);

/**
 * get_pci_ids:
 * @pciio - The EFI_PCI_IO_PROTOCOL handle for a device
 * @ids - Vendor and Device Ids
 *
 * Reads the Vendor and Device IDs from the PCI configuration space
 *
 * Returns:
 * EFI_SUCCESS - The operation succeeded
 * an EFI Error if the values could not be read
 */
EFI_STATUS get_pci_ids(IN EFI_PCI_IO *pciio, OUT pci_device_ids_t *ids);

#endif	/* _PCI_H_ */
