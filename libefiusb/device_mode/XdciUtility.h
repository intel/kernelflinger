/** @file
  Copyright (c) 2006 - 2017, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _XDCI_UTILITY_H_
#define _XDCI_UTILITY_H_

#include "XdciCommon.h"
#include "protocol/UsbDeviceLib.h"

VOID
PrintDeviceDescriptor (
  IN USB_DEVICE_DESCRIPTOR    *DevDesc
  );

VOID
PrintConfigDescriptor (
  IN EFI_USB_CONFIG_DESCRIPTOR    *ConfigDesc
  );

VOID
PrintInterfaceDescriptor (
  IN EFI_USB_INTERFACE_DESCRIPTOR    *IfDesc
  );

VOID
PrintEpDescriptor (
  IN EFI_USB_ENDPOINT_DESCRIPTOR    *EpDesc
  );

VOID
PrintEpCompDescriptor (
  IN EFI_USB_ENDPOINT_COMPANION_DESCRIPTOR    *EpDesc
  );

VOID
PrintStringDescriptor (
  IN USB_STRING_DESCRIPTOR    *StrDesc
  );

VOID
PrintDeviceRequest (
  IN EFI_USB_DEVICE_REQUEST    *DevReq
  );

#ifdef SUPPORT_SUPER_SPEED
VOID
PrintBOSDescriptor (
  IN EFI_USB_BOS_DESCRIPTOR    *BosDesc
  );
#endif
#endif

