/** @file
  Copyright (c) 2006 - 2017, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _USB_DEVICE_MODE_DXE_H_
#define _USB_DEVICE_MODE_DXE_H_

#include "protocol/UsbIo.h"
#include "protocol/UsbDeviceModeProtocol.h"

////
/// Function declaration
///
EFI_STATUS
UsbdSetupHdlr (
  IN EFI_USB_DEVICE_REQUEST    *CtrlRequest
  );

extern EFI_USB_DEVICE_MODE_PROTOCOL  mUsbDeviceModeProtocol;
#endif

