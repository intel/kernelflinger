/** @file
  Common I/O Library routines.

  Copyright (c) 2006 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Base.h"
#include "BaseIoLibIntrinsicInternal.h"

/**
  Reads a 64-bit I/O port.

  Reads the 64-bit I/O port specified by Port. The 64-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 64-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 64-bit boundary, then ASSERT().

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT64
EFIAPI
IoRead64 (
__attribute__((__unused__))  IN      UINTN                     Port
  )
{
  ASSERT (FALSE);
  return 0;
}

/**
  Writes a 64-bit I/O port.

  Writes the 64-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 64-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 64-bit boundary, then ASSERT().

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written the I/O port.

**/
UINT64
EFIAPI
IoWrite64 (
__attribute__((__unused__))  IN      UINTN                     Port,
__attribute__((__unused__))  IN      UINT64                    Value
  )
{
  ASSERT (FALSE);
  return 0;
}


/**
  Reads an 8-bit MMIO register.

  Reads the 8-bit MMIO register specified by Address. The 8-bit read value is
  returned. This function must guarantee that all MMIO read and write
  operations are serialized.

  If 8-bit MMIO register operations are not supported, then ASSERT().

  @param  Address The MMIO register to read.

  @return The value read.

**/
UINT8
EFIAPI
MmioRead8 (
  IN      UINTN                     Address
  )
{
  UINT8                             Value;
  BOOLEAN                           Flag;

  Flag = FilterBeforeMmIoRead1 (FilterWidth8, Address, &Value);
  if (Flag) {
    MemoryFence ();
    Value = *(volatile UINT8*)Address;
    MemoryFence ();
  }
  FilterAfterMmIoRead1 (FilterWidth8, Address, &Value);

  return Value;
}

/**
  Writes an 8-bit MMIO register.

  Writes the 8-bit MMIO register specified by Address with the value specified
  by Value and returns Value. This function must guarantee that all MMIO read
  and write operations are serialized.

  If 8-bit MMIO register operations are not supported, then ASSERT().

  @param  Address The MMIO register to write.
  @param  Value   The value to write to the MMIO register.

  @return Value.

**/
UINT8
EFIAPI
MmioWrite8 (
  IN      UINTN                     Address,
  IN      UINT8                     Value
  )
{
  BOOLEAN                           Flag;

  Flag = FilterBeforeMmIoWrite1 (FilterWidth8, Address, &Value);
  if (Flag) {
    MemoryFence ();
    *(volatile UINT8*)Address = Value;
    MemoryFence ();
  }
  FilterAfterMmIoWrite1 (FilterWidth8, Address, &Value);

  return Value;
}

/**
  Reads a 16-bit MMIO register.

  Reads the 16-bit MMIO register specified by Address. The 16-bit read value is
  returned. This function must guarantee that all MMIO read and write
  operations are serialized.

  If 16-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 16-bit boundary, then ASSERT().

  @param  Address The MMIO register to read.

  @return The value read.

**/
UINT16
EFIAPI
MmioRead16_1 (
  IN      UINTN                     Address
  )
{
  UINT16                            Value;
  BOOLEAN                           Flag;

  ASSERT ((Address & 1) == 0);
  Flag = FilterBeforeMmIoRead1 (FilterWidth16, Address, &Value);
  if (Flag) {
    MemoryFence ();
    Value = *(volatile UINT16*)Address;
    MemoryFence ();
  }
  FilterAfterMmIoRead1 (FilterWidth16, Address, &Value);

  return Value;
}

/**
  Writes a 16-bit MMIO register.

  Writes the 16-bit MMIO register specified by Address with the value specified
  by Value and returns Value. This function must guarantee that all MMIO read
  and write operations are serialized.

  If 16-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 16-bit boundary, then ASSERT().

  @param  Address The MMIO register to write.
  @param  Value   The value to write to the MMIO register.

  @return Value.

**/
UINT16
EFIAPI
MmioWrite16_1 (
  IN      UINTN                     Address,
  IN      UINT16                    Value
  )
{
  BOOLEAN                           Flag;

  ASSERT ((Address & 1) == 0);

  Flag = FilterBeforeMmIoWrite1 (FilterWidth16, Address, &Value);
  if (Flag) {
    MemoryFence ();
    *(volatile UINT16*)Address = Value;
    MemoryFence ();
  }
  FilterAfterMmIoWrite1 (FilterWidth16, Address, &Value);

  return Value;
}

/**
  Reads a 32-bit MMIO register.

  Reads the 32-bit MMIO register specified by Address. The 32-bit read value is
  returned. This function must guarantee that all MMIO read and write
  operations are serialized.

  If 32-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 32-bit boundary, then ASSERT().

  @param  Address The MMIO register to read.

  @return The value read.

**/
UINT32
EFIAPI
MmioRead32 (
  IN      UINTN                     Address
  )
{
  UINT32                            Value;
  BOOLEAN                           Flag;

  ASSERT ((Address & 3) == 0);

  Flag = FilterBeforeMmIoRead1 (FilterWidth32, Address, &Value);
  if (Flag) {
    MemoryFence ();
    Value = *(volatile UINT32*)Address;
    MemoryFence ();
  }
  FilterAfterMmIoRead1 (FilterWidth32, Address, &Value);

  return Value;
}

/**
  Writes a 32-bit MMIO register.

  Writes the 32-bit MMIO register specified by Address with the value specified
  by Value and returns Value. This function must guarantee that all MMIO read
  and write operations are serialized.

  If 32-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 32-bit boundary, then ASSERT().

  @param  Address The MMIO register to write.
  @param  Value   The value to write to the MMIO register.

  @return Value.

**/
UINT32
EFIAPI
MmioWrite32 (
  IN      UINTN                     Address,
  IN      UINT32                    Value
  )
{
  BOOLEAN                           Flag;

  ASSERT ((Address & 3) == 0);

  Flag = FilterBeforeMmIoWrite1 (FilterWidth32, Address, &Value);
  if (Flag) {
    MemoryFence ();
    *(volatile UINT32*)Address = Value;
    MemoryFence ();
  }
  FilterAfterMmIoWrite1 (FilterWidth32, Address, &Value);

  return Value;
}

/**
  Reads a 64-bit MMIO register.

  Reads the 64-bit MMIO register specified by Address. The 64-bit read value is
  returned. This function must guarantee that all MMIO read and write
  operations are serialized.

  If 64-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 64-bit boundary, then ASSERT().

  @param  Address The MMIO register to read.

  @return The value read.

**/
UINT64
EFIAPI
MmioRead64 (
  IN      UINTN                     Address
  )
{
  UINT64                            Value;
  BOOLEAN                           Flag;

  ASSERT ((Address & 7) == 0);

  Flag = FilterBeforeMmIoRead1 (FilterWidth64, Address, &Value);
  if (Flag) {
    MemoryFence ();
    Value = *(volatile UINT64*)Address;
    MemoryFence ();
  }
  FilterAfterMmIoRead1 (FilterWidth64, Address, &Value);

  return Value;
}

/**
  Writes a 64-bit MMIO register.

  Writes the 64-bit MMIO register specified by Address with the value specified
  by Value and returns Value. This function must guarantee that all MMIO read
  and write operations are serialized.

  If 64-bit MMIO register operations are not supported, then ASSERT().
  If Address is not aligned on a 64-bit boundary, then ASSERT().

  @param  Address The MMIO register to write.
  @param  Value   The value to write to the MMIO register.

**/
UINT64
EFIAPI
MmioWrite64 (
  IN      UINTN                     Address,
  IN      UINT64                    Value
  )
{
  BOOLEAN                           Flag;

  ASSERT ((Address & 7) == 0);

  Flag = FilterBeforeMmIoWrite1 (FilterWidth64, Address, &Value);
  if (Flag) {
    MemoryFence ();
    *(volatile UINT64*)Address = Value;
    MemoryFence ();
  }
  FilterAfterMmIoWrite1 (FilterWidth64, Address, &Value);

  return Value;
}
