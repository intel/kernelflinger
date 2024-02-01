/** @file
  Null instance of RegisterFilterLib.

  Copyright (c) 2021 Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <efi.h>
#include <efiapi.h>
#include <RegisterFilterLib.h>

/**
  Filter IO read operation before read IO port.
  It is used to filter IO read operation.

  It will return the flag to decide whether require read real IO port.
  It can be used for emulation environment.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in,out]   Buffer   The destination buffer to store the results.

  @retval TRUE         Need to excute the IO read.
  @retval FALSE        Skip the IO read.

**/

BOOLEAN
EFIAPI
FilterBeforeIoRead1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN OUT VOID         *Buffer
  )
{
  return TRUE;
}

/**
  Trace IO read operation after read IO port.
  It is used to trace IO operation.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The destination buffer to store the results.

**/
VOID
EFIAPI
FilterAfterIoRead1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return;
}

/**
  Filter IO Write operation before wirte IO port.
  It is used to filter IO operation.

  It will return the flag to decide whether require read write IO port.
  It can be used for emulation environment.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.

  @retval TRUE         Need to excute the IO write.
  @retval FALSE        Skip the IO write.

**/
BOOLEAN
EFIAPI
FilterBeforeIoWrite1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return TRUE;
}

  /**
  Trace IO Write operation after wirte IO port.
  It is used to trace IO operation.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The source buffer from which to Write data.

**/
VOID
EFIAPI
FilterAfterIoWrite1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return;
}

/**
  Filter memory IO before Read operation.

  It will return the flag to decide whether require read real MMIO.
  It can be used for emulation environment.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in,out]   Buffer   The destination buffer to store the results.

  @retval TRUE         Need to excute the MMIO read.
  @retval FALSE        Skip the MMIO read.

**/
BOOLEAN
EFIAPI
FilterBeforeMmIoRead1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN OUT VOID         *Buffer
  )
{
  return TRUE;
}

/**
  Tracer memory IO after read operation.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The destination buffer to store the results.

**/
VOID
EFIAPI
FilterAfterMmIoRead1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return;
}

/**
  Filter memory IO before write operation.

  It will return the flag to decide whether require wirte real MMIO.
  It can be used for emulation environment.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.

  @retval TRUE         Need to excute the MMIO write.
  @retval FALSE        Skip the MMIO write.

**/
BOOLEAN
EFIAPI
FilterBeforeMmIoWrite1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return TRUE;
}

/**
  Tracer memory IO after write operation.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.

**/
VOID
EFIAPI
FilterAfterMmIoWrite1 (
__attribute__((__unused__))  IN FILTER_IO_WIDTH  Width,
__attribute__((__unused__))  IN UINTN            Address,
__attribute__((__unused__))  IN VOID             *Buffer
  )
{
  return;
}

/**
  Filter MSR before read operation.

  It will return the flag to decide whether require read real MSR.
  It can be used for emulation environment.

  @param  Index                     The Register index of the MSR.
  @param  Value                     Point to the data will be read from the MSR.

  @retval TRUE         Need to excute the MSR read.
  @retval FALSE        Skip the MSR read.

**/
BOOLEAN
EFIAPI
FilterBeforeMsrRead1 (
__attribute__((__unused__))  IN UINT32        Index,
__attribute__((__unused__))  IN OUT UINT64    *Value
  )
{
  return TRUE;
}

/**
  Trace MSR after read operation.

  @param  Index                     The Register index of the MSR.
  @param  Value                     Point to the data has been be read from the MSR.

**/
VOID
EFIAPI
FilterAfterMsrRead1 (
__attribute__((__unused__))  IN UINT32    Index,
__attribute__((__unused__))  IN UINT64    *Value
  )
{
  return;
}

/**
  Filter MSR before write operation.

  It will return the flag to decide whether require write real MSR.
  It can be used for emulation environment.

  @param  Index                     The Register index of the MSR.
  @param  Value                     Point to the data want to be written to the MSR.

  @retval TRUE         Need to excute the MSR write.
  @retval FALSE        Skip the MSR write.

**/
BOOLEAN
EFIAPI
FilterBeforeMsrWrite1 (
__attribute__((__unused__))  IN UINT32    Index,
__attribute__((__unused__))  IN UINT64    *Value
  )
{
  return TRUE;
}

/**
  Trace MSR after write operation.

  @param  Index                     The Register index of the MSR.
  @param  Value                     Point to the data has been be written to the MSR.

**/
VOID
EFIAPI
FilterAfterMsrWrite1 (
__attribute__((__unused__))  IN UINT32    Index,
__attribute__((__unused__))  IN UINT64    *Value
  )
{
  return;
}
