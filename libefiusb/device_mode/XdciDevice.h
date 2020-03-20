/** @file
  Copyright (c) 2006 - 2017, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _USB_DEVICE_H_
#define _USB_DEVICE_H_

//
// @USB_DEV_CONFIG_PARAMS: Struct to be filled in with configuration
// parameters and passed to the init routine for device controller
//
typedef struct {
  USB_CONTROLLER_ID  ControllerId; // Controller ID of the core
  UINT64             BaseAddress;  // Base address of the controller registers and on-chip memory
  UINT32             Flags;        // Initialization flags
  USB_SPEED          Speed;        // Desired USB bus Speed
  USB_ROLE           Role;         // Default USB role
} USB_DEV_CONFIG_PARAMS;

//
// @USB_DEV_CORE: Struct used as a handle for all
// hardware-independent APIs
//
typedef struct {
  const struct UsbDeviceCoreDriver *CoreDriver;
  VOID                                *ControllerHandle;
} USB_DEV_CORE;

typedef
EFI_STATUS
(EFIAPI *USB_DEVICE_CALLBACK_FUNC) (
  IN USB_DEVICE_CALLBACK_PARAM  *Param
  );

EFI_STATUS
UsbDeviceInit (
  IN USB_DEV_CONFIG_PARAMS    *ConfigParams,
  IN OUT VOID                 **DevCoreHandle
  );

EFI_STATUS
UsbDeviceDeinit (
  IN VOID                      *DevCoreHandle,
  IN UINT32                    Flags
  );

EFI_STATUS
UsbDeviceRegisterCallback (
  IN VOID                      *DevCoreHandle,
  IN USB_DEVICE_EVENT_ID       EventId,
  IN USB_DEVICE_CALLBACK_FUNC  CallbackFunc
  );

EFI_STATUS
UsbDeviceUnregisterCallback (
  IN VOID                      *DevCoreHandle,
  IN USB_DEVICE_EVENT_ID       EventId
  );

EFI_STATUS
UsbDeviceIsrRoutine (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbDeviceIsrRoutineTimerBased (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbXdciDeviceConnect (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbDeviceDisconnect (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbDeviceGetSpeed (
  IN VOID                      *DevCoreHandle,
  IN USB_SPEED                 *Speed
  );

EFI_STATUS
UsbDeviceSetLinkState (
  IN VOID                      *DevCoreHandle,
  IN USB_DEVICE_SS_LINK_STATE  State
  );

EFI_STATUS
UsbDeviceSetAddress (
  IN VOID                      *DevCoreHandle,
  IN UINT32                    Address
  );

EFI_STATUS
UsbDeviceSetConfiguration (
  IN VOID                      *DevCoreHandle,
  IN UINT32                    ConfigNum
  );

EFI_STATUS
UsbDeviceInitEp (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEpEnable (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEpDisable (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEpStall (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEpClearStall (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEpSetNrdy (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

EFI_STATUS
UsbDeviceEp0RxSetup (
  IN VOID                      *DevCoreHandle,
  IN UINT8                     *Buffer
  );

EFI_STATUS
UsbDeviceEp0RxStatus (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbDeviceEp0TxStatus (
  IN VOID                      *DevCoreHandle
  );

EFI_STATUS
UsbXdciDeviceEpTxData (
  IN VOID                      *DevCoreHandle,
  IN USB_XFER_REQUEST          *XferReq
  );

EFI_STATUS
UsbXdciDeviceEpRxData (
  IN VOID                      *DevCoreHandle,
  IN USB_XFER_REQUEST          *XferReq
  );

EFI_STATUS
UsbDeviceEpCancelTransfer (
  IN VOID                      *DevCoreHandle,
  IN USB_EP_INFO               *EpInfo
  );

#endif

