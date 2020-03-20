/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Author: Meng Xianglin <xianglinx.meng@intel.com>
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

#include <lib.h>
#include <uefi_utils.h>
#include <vars.h>
#include "efiapi.h"
#include "CpuIo2.h"

EFI_GUID gEfiCpuIo2ProtocolGuid = EFI_CPU_IO2_PROTOCOL_GUID;
static EFI_CPU_IO2_PROTOCOL  *mCpuIo = NULL;

UINT32 MmioRead32(UINTN address)
{
	EFI_STATUS ret;
	UINT64 data;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFFFFFFFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Read,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint32,
				 address,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  read data from 0x%x", address);
		return 0xFFFFFFFF;
	}

	return (UINT32)data;
}

UINT16 MmioRead16(UINTN address)
{
	EFI_STATUS ret;
	UINT64 data;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFFFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Read,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint16,
				 address,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  read data from 0x%x", address);
		return 0xFFFF;
	}

	return (UINT16)data;
}

UINT8 MmioRead8(UINTN address)
{
	EFI_STATUS ret;
	UINT64 data;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Read,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint8,
				 address,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  read data from 0x%x", address);
		return 0xFF;
	}

	return (UINT8)data;
}

UINT32 MmioWrite32(UINTN add, UINT32 data)
{
	EFI_STATUS ret;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFFFFFFFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Write,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint32,
				 add,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  write data to 0x%x", add);
		return 0xFFFFFFFF;
	}
	efi_perror(EFI_SUCCESS, L"write data 0x%x to 0x%016lx", data, add);

	return data;
}

UINT16 MmioWrite16(UINTN add, UINT16 data)
{
	EFI_STATUS ret;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFFFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Write,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint16,
				 add,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  write data to 0x%x", add);
		return 0xFFFF;
	}

	return data;
}

UINT8 MmioWrite8(UINTN add, UINT8 data)
{
	EFI_STATUS ret;

	if (mCpuIo == NULL) {
		ret = LibLocateProtocol (&gEfiCpuIo2ProtocolGuid,
					 (VOID **) &mCpuIo);
		if (EFI_ERROR(ret) || (mCpuIo == NULL)) {
			efi_perror(ret, L"Can't locate cpu io protocol");
			return 0xFF;
		}
	}

	ret = uefi_call_wrapper (mCpuIo->Mem.Write,
				 5,
				 mCpuIo,
				 EfiCpuIoWidthUint8,
				 add,
				 1,
				 &data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Fail to  write data to 0x%x", add);
		return 0xFF;
	}

	return data;
}
