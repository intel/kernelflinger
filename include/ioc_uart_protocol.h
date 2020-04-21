/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: kui.wen@intel.com
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

#ifndef _IOC_UART_PROTOCOL_H_
#define _IOC_UART_PROTOCOL_H_

#include <efi.h>

#define EFI_IOC_UART_PROTOCOL_GUID \
	{0x6152f300, 0x957f, 0x40b2, {0x9e, 0x4b, 0xe9, 0x22, 0x37, 0xa6, 0x66, 0xed}}

typedef struct _IOC_UART_PROTOCOL IOC_UART_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_SET_SUPPRESS_HEART_BEAT_TIMEOUT) (
	IN IOC_UART_PROTOCOL *This,
	IN UINT32 timeout
	);

typedef
EFI_STATUS
(EFIAPI *EFI_NOTIFY_IOC_CM_READY) (
	IN IOC_UART_PROTOCOL *This
	);

typedef
EFI_STATUS
(EFIAPI * EFI_FLASH_IOC_FIRMWARE) (
	IN IOC_UART_PROTOCOL * This,
	IN UINT8 * file_content,
	IN UINT32 file_size
);

struct _IOC_UART_PROTOCOL {
	EFI_SET_SUPPRESS_HEART_BEAT_TIMEOUT SetSuppressHeartBeatTimeout;
	EFI_NOTIFY_IOC_CM_READY NotifyIOCCMReady;
	EFI_FLASH_IOC_FIRMWARE flash_ioc_firmware;
} __attribute__((packed));

#endif	/* _IOC_UART_PROTOCOL_H_ */
