/** @file
    Copyright (c) 2009 - 2014, Intel Corporation. All rights reserved.<BR>
    This program and the accompanying materials
    are licensed and made available under the terms and conditions of the BSD License
    which accompanies this distribution.  The full text of the license may be found at
    http://opensource.org/licenses/bsd-license.php

    THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
    WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _EFI_XDCI_LIB_H_
#define _EFI_XDCI_LIB_H_

#include "UsbIo.h"

#define MAX_DESCRIPTOR_SIZE         64
#define STRING_ARR_SIZE             (MAX_DESCRIPTOR_SIZE - 2)
#define USB_ADDRESS_TABLE_SIZE      16  //4

//
// Endpoint Zero
//
#define USB_EP0_MAX_PKT_SIZE_HS     0x40 // High Speed mode is explicitly set as 64 bytes
#define USB_EP0_MAX_PKT_SIZE_SS     0x9  // Must be 0x9 (2^9 = 512 Bytes) in SuperSpeed mode
#define USB_EPO_MAX_PKT_SIZE_ALL    512  // Overall max bytes for any type

//
// Bulk Endpoints
//
#define USB_BULK_EP_PKT_SIZE_HS     0x200 // Bulk-Endpoint HighSpeed
#define USB_BULK_EP_PKT_SIZE_SS     0x400 // Bulk-Endpoint SuperSpeed
#define USB_BULK_EP_PKT_SIZE_MAX    USB_BULK_EP_PKT_SIZE_SS

//
// Transmit Direction Bits
//
#define USB_ENDPOINT_DIR_OUT                 0x00

//
// Endpoint Companion Bulk Attributes
//
#define USB_EP_BULK_BM_ATTR_MASK    0x1F

//
// Configuration Modifiers (Attributes)
//
#define USB_BM_ATTR_RESERVED        0x80
#define USB_BM_ATTR_SELF_POWERED    0x40
#define USB_BM_ATTR_REMOTE_WAKE     0X20

//
// USB BCD version
//
#define USB_BCD_VERSION_LS          0x0110
#define USB_BCD_VERSION_HS          0x0200
#define USB_BCD_VERSION_SS          0x0320

//
// Device RequestType Flags
//
#define USB_RT_TX_DIR_H_TO_D        (0x0)       // Tx direction Host to Device
#define USB_RT_TX_DIR_D_TO_H        (0x1 << 7)  // Tx direction Device to Host
#define USB_RT_TX_DIR_MASK          (0x80)

//
// USB request type
//
#define USB_REQ_TYPE_MASK           (0x60)

//
// Usb control transfer target
//
#define USB_TARGET_MASK             (0x1F)

//
// Device GetStatus bits
//
#define USB_STATUS_SELFPOWERED      (0x01)
#define USB_STATUS_REMOTEWAKEUP     (0x02)

//
// USB Device class identifiers
//
#define USB_DEVICE_MS_CLASS         (0x08)
#define USB_DEVICE_VENDOR_CLASS     (0xFF)

//
// USB Descriptor types
//
#define USB_DESC_TYPE_BOS                    0x0F
#define USB_DESC_TYPE_DEVICE_CAPABILITY      0x10
#define USB_DESC_TYPE_SS_ENDPOINT_COMPANION  0x30
#pragma pack(1)

#ifdef SUPPORT_SUPER_SPEED
//
// USB device capability Type Codes
// USB3 Table 9-13
//
typedef enum {
  WirelessUSB = 0x01,
  USB2Extension,
  SuperSpeedUSB,
  ContainerID,
  SuperSpeedPlusUSB = 0x0A
} USB_DEVICE_CAP_TYPE_CODE;
#endif


//
// USB device states from USB spec sec 9.1
//
typedef enum {
	UsbDevStateOff = 0,
	UsbDevStateInit,
	UsbDevStateAttached,
	UsbDevStatePowered,
	UsbDevStateDefault,
	UsbDevStateAddress,
	UsbDevStateConfigured,
	UsbDevStateSuspended,
	UsbDevStateError
} USB_DEVICE_STATE;


//
// The following set of structs are used during USB data transaction
// operatitions, including requests and completion events.
//
#pragma pack(1)

typedef struct {
	UINT32     EndpointNum;
	UINT8      EndpointDir;
	UINT8      EndpointType;
	UINT32     Length;
	VOID       *Buffer;
} EFI_USB_DEVICE_XFER_INFO;

//
// SuperSpeed Endpoint companion descriptor
// USB3 table 9-22
//
typedef struct {
	UINT8      Length;
	UINT8      DescriptorType;
	UINT8      MaxBurst;
	UINT8      Attributes;
	UINT16     BytesPerInterval;
} EFI_USB_ENDPOINT_COMPANION_DESCRIPTOR;

typedef struct {
	EFI_USB_ENDPOINT_DESCRIPTOR              *EndpointDesc;
	EFI_USB_ENDPOINT_COMPANION_DESCRIPTOR    *EndpointCompDesc;
} USB_DEVICE_ENDPOINT_INFO, USB_DEVICE_ENDPOINT_OBJ;

typedef struct {
	VOID        *Buffer;
	UINT32      Length;
} USB_DEVICE_IO_INFO;

typedef struct {
	USB_DEVICE_IO_INFO           IoInfo;
	USB_DEVICE_ENDPOINT_INFO     EndpointInfo;
} USB_DEVICE_IO_REQ;

//
// Optional string descriptor
//
typedef struct {
	UINT8           Length;
	UINT8           DescriptorType;
	UINT16          LangID[STRING_ARR_SIZE];
} USB_STRING_DESCRIPTOR;


//
// The following structures abstract the device descriptors a class
// driver needs to provide to the USBD core.
// These structures are filled & owned by the class/function layer.
//
typedef struct {
	EFI_USB_INTERFACE_DESCRIPTOR         *InterfaceDesc;
	USB_DEVICE_ENDPOINT_OBJ              *EndpointObjs;
} USB_DEVICE_INTERFACE_OBJ;

typedef struct {
	EFI_USB_CONFIG_DESCRIPTOR     *ConfigDesc;
	VOID                          *ConfigAll;
	USB_DEVICE_INTERFACE_OBJ      *InterfaceObjs;
} USB_DEVICE_CONFIG_OBJ;

#ifdef SUPPORT_SUPER_SPEED
//
// SuperSpeed Binary Device Object Store(BOS) descriptor
// USB3 9.6.2
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT16     TotalLength;
  UINT8      NumDeviceCaps;
} EFI_USB_BOS_DESCRIPTOR;

//
// Generic Header of Device Capability descriptor
// USB3 9.6.2.2
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT8      DevCapabilityType;
  UINT8      CapDependent;
} EFI_USB_SS_DEVICE_CAP_DESCRIPTOR;

//
// USB2.0 Extension descriptor
// USB3 Table 9-14
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT8      DeviceCapabilityType;
  UINT32     Attributes;
} EFI_USB_USB2_EXT_CAP_DESCRIPTOR;


//
// SuperSpeed USB Device Capability descriptor
// USB3 Table 9-15
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT8      DeviceCapabilityType;
  UINT8      Attributes;
  UINT16     SpeedSupported;
  UINT8      FunctionalitySupport;
  UINT8      U1DevExitLat;
  UINT16     U2DevExitLat;
} EFI_USB_SS_USB_DEV_CAP_DESCRIPTOR;

//
// Container ID descriptor
// USB3 Table 9-16
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT8      DeviceCapabilityType;
  UINT8      Reserved;
  UINT8      UUID[16];
} EFI_USB_CONTAINER_ID_DESCRIPTOR;

//
// Container ID descriptor
// USB3 Table 9-16
//
typedef struct {
  UINT8      Length;
  UINT8      DescriptorType;
  UINT8      DeviceCapabilityType;
  UINT8      ReservedByte;
  UINT32     Attributes;
  UINT16     FunctionalitySupport;
  UINT16     ReservedWord;
  UINT32     SublinkSpeedAttr[2];
} EFI_USB_SS_PLUS_USB_DEV_CAP_DESCRIPTOR;

#endif

typedef
EFI_STATUS
(EFIAPI *EFI_USB_CONFIG_CALLBACK) (
	IN UINT8                      CfgVal
	);

typedef
EFI_STATUS
(EFIAPI *EFI_USB_SETUP_CALLBACK) (
	IN EFI_USB_DEVICE_REQUEST     *CtrlRequest,
	IN USB_DEVICE_IO_INFO         *IoInfo
	);

typedef
EFI_STATUS
(EFIAPI *EFI_USB_DATA_CALLBACK) (
  IN EFI_USB_DEVICE_XFER_INFO   *XferInfo
  );

typedef struct {
	USB_DEVICE_DESCRIPTOR       *DeviceDesc;
	USB_DEVICE_CONFIG_OBJ       *ConfigObjs;
	USB_STRING_DESCRIPTOR       *StringTable;
#ifdef SUPPORT_SUPER_SPEED
	EFI_USB_BOS_DESCRIPTOR      *BosDesc;
#endif
	UINT8                       StrTblEntries;
	EFI_USB_CONFIG_CALLBACK     ConfigCallback;
	EFI_USB_SETUP_CALLBACK      SetupCallback;
	EFI_USB_DATA_CALLBACK       DataCallback;
} USB_DEVICE_OBJ;


//
// Main USBD driver object structure containing all data necessary
// for USB device mode processing at this layer
//
typedef struct {
	USB_DEVICE_OBJ              *UsbdDevObj;      /* pointer to a Device Object */
	VOID                        *XdciDrvObj;       /* Opaque handle to DCI driver */
	BOOLEAN                     XdciInitialized;   /* flag to specify if the DCI driver is initialized */
	USB_DEVICE_CONFIG_OBJ       *ActiveConfigObj; /* pointer to currently active configuraiton */
	USB_DEVICE_STATE            State;            /* current state of the USB Device state machine */
	UINT8                       Address;          /* configured device address */
} USB_DEVICE_DRIVER_OBJ;

#pragma pack()

#endif
