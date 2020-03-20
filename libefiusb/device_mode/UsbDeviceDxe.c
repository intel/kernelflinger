/** @file
  Copyright (c) 2006 - 2017, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include <lib.h>
#include <efiapi.h>
#include <uefi_utils.h>
#include <vars.h>
#include "pci.h"
#include "UsbDeviceDxe.h"
#include "UsbDeviceMode.h"
#include "XdciDWC.h"

static EFI_HANDLE xdci_handle = 0, xhci_handle = 0;
PCI_DEVICE_PATH xhci_path = {.Device = -1, .Function = -1};
UINTN XhciMmioBarAddr = 0;

VOID
EFIAPI
PlatformSpecificInit (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT32      XhciMmioBarHigh = 0;
  EFI_PCI_IO  *PciIo;
  UINT32      BitValue;
  UINT32      BitMask;
  UINT16      DelayTime = 10000;
  UINT16      LoopTime;

  // Provide protocol interface
  // Get the PCI I/O Protocol on PciHandle
  Status = uefi_call_wrapper(BS->OpenProtocol,
		   6,
		   xhci_handle,
		   &PciIoProtocol,
		   (VOID **) &PciIo,
		   g_parent_image,
		   xhci_handle,
		   EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
	goto ErrorExit1;
  }

  Status = uefi_call_wrapper(PciIo->Pci.Read,
		   5,
		   PciIo,
		   EfiPciIoWidthUint32,
		   R_XHCI_BAR0,
		   1,
		   &XhciMmioBarAddr);
  if (EFI_ERROR (Status)) {
	goto ErrorExit1;
  }
  if ((XhciMmioBarAddr & B_XHCI_BAR0_TYPE) == B_XHCI_BAR0_64_BIT) {
	  Status = uefi_call_wrapper(PciIo->Pci.Read,
			   5,
			   PciIo,
			   EfiPciIoWidthUint32,
			   R_XHCI_BAR_HIGH,
			   1,
			   &XhciMmioBarHigh);
  }
  if (EFI_ERROR (Status)) {
	goto ErrorExit1;
  }
  XhciMmioBarAddr = ((UINT64) XhciMmioBarHigh << 32) | XhciMmioBarAddr;
  XhciMmioBarAddr &= B_XHCI_MEM_BASE_BA;

  DEBUG ((DEBUG_INFO, "XhciMmioBarAddr=0x%016lx\n",  XhciMmioBarAddr));

  //
  // Step 1: Enable OTG device Mode
  //
  MmioWrite32 ((UINTN)(XhciMmioBarAddr + R_XHCI_MEM_DUAL_ROLE_CFG0), 0x1310800);

  //
   // Step 2: 0x80DC register, has a status bit to acknowledge the role change in Bit 29
   //
  BitMask	= (UINT32) (0x20000000);
  BitValue = (UINT32) (1 << 29);

  for (LoopTime = 0; LoopTime < DelayTime; LoopTime++) {
	 if ((MmioRead32 ((UINTN)(XhciMmioBarAddr + R_XHCI_MEM_DUAL_ROLE_CFG1)) & BitMask) == (BitValue & BitMask)) {
	   break;
	 } else {
	   uefi_call_wrapper(BS->Stall, 1, 100);
	 }
  }

ErrorExit1:

  return;
}

static
VOID
EFIAPI
UsbDeviceDxeExitBootService (
  __attribute__((unused))EFI_EVENT Event,
  VOID *Context
  )
{
  USB_XDCI_DEV_CONTEXT  *UsbXdciDevContext;

  UsbXdciDevContext = (USB_XDCI_DEV_CONTEXT *) Context;
  DEBUG ((EFI_D_INFO, "UsbDeviceDxeExitBootService enter\n"));

  if (UsbXdciDevContext->XdciPollTimer != NULL) {
    uefi_call_wrapper(BS->SetTimer,
          3,
          UsbXdciDevContext->XdciPollTimer,
          TimerCancel,
          0);

    uefi_call_wrapper(BS->CloseEvent, 1, UsbXdciDevContext->XdciPollTimer);
    UsbXdciDevContext->XdciPollTimer = NULL;
  }

  return;
}

static EFI_STATUS find_usb_device_controller (EFI_HANDLE Controller)
{
  EFI_STATUS status = EFI_UNSUPPORTED;
  EFI_PCI_IO *pci;
  USB_CLASSC class_reg;
  UINTN seg;
  UINTN bus;
  UINTN dev;
  UINTN fun;

  status = uefi_call_wrapper(BS->OpenProtocol,
           6,
           Controller,
           &PciIoProtocol,
           (VOID **) &pci,
           g_parent_image,
           Controller,
           EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (status))
    return status;

  status = uefi_call_wrapper(pci->Pci.Read,
           5,
           pci,
           EfiPciIoWidthUint8,
           PCI_CLASSCODE_OFFSET,
           sizeof (USB_CLASSC) / sizeof (UINT8),
           &class_reg);

  if (EFI_ERROR (status))
    return status;

  // Test whether the controller belongs to USB device type
  // 0x0C03FE / 0x0C0380

  if ((class_reg.BaseCode == PCI_CLASS_SERIAL) &&
      (class_reg.SubClassCode == PCI_CLASS_SERIAL_USB) &&
      ((class_reg.ProgInterface == PCI_IF_USBDEV) ||
      (class_reg.ProgInterface == 0x80))) {
    return EFI_SUCCESS;
  }


  if ((class_reg.BaseCode == PCI_CLASS_SERIAL) &&
    (class_reg.SubClassCode == PCI_CLASS_SERIAL_USB) &&
    (class_reg.ProgInterface == PCI_IF_XHCI)) {

    status = uefi_call_wrapper(pci->GetLocation,
             5,
             pci,
             &seg,
             &bus,
             &dev,
             &fun);
    xhci_path.Device = (UINT8)dev;
    xhci_path.Function = (UINT8)fun;
	xhci_handle = Controller;
  }

  return EFI_UNSUPPORTED;
}

EFI_GUID gEfiEventExitBootServicesGuid  =  EventExitBootServices;

static EFI_STATUS usb_device_mode_start (EFI_HANDLE Controller, EFI_USB_DEVICE_MODE_PROTOCOL **usb_device)
{
  EFI_STATUS Status;
  USB_XDCI_DEV_CONTEXT *UsbXdciDevContext = NULL;
  EFI_PCI_IO *PciIo;
  EFI_EVENT ExitBootServicesEvent;
  UINT32                XdciMmioBarHigh = 0;

  // Provide protocol interface
  // Get the PCI I/O Protocol on PciHandle
  Status = uefi_call_wrapper(BS->OpenProtocol,
           6,
           Controller,
           &PciIoProtocol,
           (VOID **) &PciIo,
           g_parent_image,
           Controller,
           EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
    goto ErrorExit;
  }

  UsbXdciDevContext = AllocateZeroPool (sizeof (USB_XDCI_DEV_CONTEXT));
  if (UsbXdciDevContext == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ErrorExit;
  }

  // Initialize the driver context
  //
  UsbXdciDevContext->StartUpController = FALSE;
  UsbXdciDevContext->XdciHandle = Controller;
  UsbXdciDevContext->Signature = EFI_USB_DEV_SIGNATURE;

  Status = uefi_call_wrapper(PciIo->Pci.Read,
           5,
           PciIo,
           EfiPciIoWidthUint32,
           R_OTG_BAR0,
           1,
           &UsbXdciDevContext->XdciMmioBarAddr);

  if ((UsbXdciDevContext->XdciMmioBarAddr & B_OTG_BAR0_TYPE) == B_OTG_BAR0_64_BIT) {
	  Status = uefi_call_wrapper(PciIo->Pci.Read,
	           5,
	           PciIo,
	           EfiPciIoWidthUint32,
	           R_OTG_BAR_HIGH,
	           1,
	           &XdciMmioBarHigh);
  }

  UsbXdciDevContext->XdciMmioBarAddr = ((UINT64) XdciMmioBarHigh << 32) | (UsbXdciDevContext->XdciMmioBarAddr & B_OTG_BAR0_BA);
  DEBUG ((EFI_D_INFO, "USB DEV mode IO addr 0x%016lx\n", UsbXdciDevContext->XdciMmioBarAddr));

  UINT8  command8 = 0x6;
  Status = uefi_call_wrapper(PciIo->Pci.Write,
           5,
           PciIo,
           EfiPciIoWidthUint8,
           R_XDCI_CMD_OFF,
           1,
           &command8);
  //read after write to ensure the former write take effect
  command8 = 0;
  Status = uefi_call_wrapper(PciIo->Pci.Read,
           5,
           PciIo,
           EfiPciIoWidthUint8,
           R_XDCI_CMD_OFF,
           1,
           &command8);

  UINT32 command32 = 0;
  Status = uefi_call_wrapper(PciIo->Pci.Write,
           5,
           PciIo,
           EfiPciIoWidthUint32,
           R_XDCI_GEN_REGRW1,
           1,
           &command32);

  CopyMem (&(UsbXdciDevContext->UsbDevModeProtocol),
     &mUsbDeviceModeProtocol,
     sizeof (EFI_USB_DEVICE_MODE_PROTOCOL));

  Status = uefi_call_wrapper(BS->CreateEventEx,
           6,
           EVT_NOTIFY_SIGNAL,
           TPL_NOTIFY,
           UsbDeviceDxeExitBootService,
           UsbXdciDevContext,
           &gEfiEventExitBootServicesGuid,
           &ExitBootServicesEvent);
  if (EFI_ERROR (Status))
    goto ErrorExit;

  *usb_device = &(UsbXdciDevContext->UsbDevModeProtocol);

  return Status;

ErrorExit:

  if (UsbXdciDevContext != NULL) {
    if (UsbXdciDevContext->XdciPollTimer != NULL) {
      uefi_call_wrapper(BS->CloseEvent,
            1,
            UsbXdciDevContext->XdciPollTimer);
      UsbXdciDevContext->XdciPollTimer = NULL;
    }
    FreePool (UsbXdciDevContext);
  }

  efi_perror(Status, L"ERROR - install driver failed - Exit\n");
  return Status;
}

static BOOLEAN usb_xdci_enabled(void)
{
  EFI_STATUS ret;
  UINTN NumberHandles, Index;
  EFI_HANDLE *Handles;

  ret = LibLocateHandle(ByProtocol,
            &PciIoProtocol,
            NULL,
            &NumberHandles,
            &Handles);
  if (EFI_ERROR(ret)) {
    efi_perror(ret, L"LibLocateProtocol: Handle not found\n");
    return ret;
  }

  for (Index=0; Index < NumberHandles; Index++) {
    ret = find_usb_device_controller(Handles[Index]);
    if (!EFI_ERROR(ret)) {
      xdci_handle = Handles[Index];
      break;
    }
  }

  if (Handles) {
    FreePool (Handles);
  }

  if (!EFI_ERROR(ret))
    return TRUE;

  return FALSE;
}

EFI_STATUS init_usb_device_mode_protocol(EFI_USB_DEVICE_MODE_PROTOCOL **usb_device)
{
  EFI_STATUS ret = EFI_UNSUPPORTED;

  if (usb_xdci_enabled()) {
    ret = usb_device_mode_start(xdci_handle, usb_device);
  } else {
    efi_perror(ret, L"XDCI is disabled, please enable it in BIOS");
  }

  return ret;
}

