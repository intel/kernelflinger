/** @file
  Implement TPM2 helper functions.

Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <efi.h>
#include <efilib.h>
#include "Tpm2Help.h"
#include "Tcg2Protocol.h"

typedef struct {
  TPMI_ALG_HASH              HashAlgo;
  UINT16                     HashSize;
  UINT32                     HashMask;
} INTERNAL_HASH_INFO;

STATIC INTERNAL_HASH_INFO mHashInfo[] = {
  {TPM_ALG_SHA1,          SHA1_DIGEST_SIZE,     HASH_ALG_SHA1},
  {TPM_ALG_SHA256,        SHA256_DIGEST_SIZE,   HASH_ALG_SHA256},
  {TPM_ALG_SM3_256,       SM3_256_DIGEST_SIZE,  HASH_ALG_SM3_256},
  {TPM_ALG_SHA384,        SHA384_DIGEST_SIZE,   HASH_ALG_SHA384},
  {TPM_ALG_SHA512,        SHA512_DIGEST_SIZE,   HASH_ALG_SHA512},
};

/**
  Return size of digest.

  @param[in] HashAlgo  Hash algorithm

  @return size of digest
**/
UINT16
EFIAPI
GetHashSizeFromAlgo (
  IN TPMI_ALG_HASH    HashAlgo
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof(mHashInfo)/sizeof(mHashInfo[0]); Index++) {
    if (mHashInfo[Index].HashAlgo == HashAlgo) {
      return mHashInfo[Index].HashSize;
    }
  }
  return 0;
}

/**
  Switches the endianness of a 16-bit integer.

  This function swaps the bytes in a 16-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 16-bit unsigned value.

  @return The byte swapped Value.

**/

UINT16
EFIAPI
SwapBytes16 (
  IN      UINT16                    Operand
  )
{
  return (UINT16) ((Operand << 8) | (Operand >> 8));
}

/**
  Switches the endianness of a 32-bit integer.

  This function swaps the bytes in a 32-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 32-bit unsigned value.

  @return The byte swapped Value.

**/

UINT32
EFIAPI
SwapBytes32 (
  IN      UINT32                    Operand
  )
{
  UINT32  LowerBytes;
  UINT32  HigherBytes;

  LowerBytes  = (UINT32) SwapBytes16 ((UINT16) Operand);
  HigherBytes = (UINT32) SwapBytes16 ((UINT16) (Operand >> 16));

  return (LowerBytes << 16 | HigherBytes);
}

/**
  Switches the endianness of a 64-bit integer.

  This function swaps the bytes in a 64-bit unsigned value to switch the value
  from little endian to big endian or vice versa. The byte swapped value is
  returned.

  @param  Value A 64-bit unsigned value.

  @return The byte swapped Value.

**/

UINT64
EFIAPI
SwapBytes64 (
  IN      UINT64                    Operand
  )
{
  UINT64  LowerBytes;
  UINT64  HigherBytes;

  LowerBytes  = (UINT64) SwapBytes32 ((UINT32) Operand);
  HigherBytes = (UINT64) SwapBytes32 ((UINT32) (Operand >> 32));

  return (LowerBytes << 32 | HigherBytes);
}

/**
  Writes a 32-bit value to memory that may be unaligned.

  This function writes the 32-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 32-bit value that may be unaligned.
  @param  Value   The 32-bit value to write to Buffer.

  @return The 32-bit value to write to Buffer.

**/

UINT32
EFIAPI
WriteUnaligned32 (
  OUT     UINT32                    *Buffer,
  IN      UINT32                    Value
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer = Value;
}

/**
  Writes a 16-bit value to memory that may be unaligned.

  This function writes the 16-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 16-bit value that may be unaligned.
  @param  Value   16-bit value to write to Buffer.

  @return The 16-bit value to write to Buffer.

**/

UINT16
EFIAPI
WriteUnaligned16 (
  OUT     UINT16                    *Buffer,
  IN      UINT16                    Value
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer = Value;
}

/**
  Reads a 16-bit value from memory that may be unaligned.

  This function returns the 16-bit value pointed to by Buffer. The function
  guarantees that the read operation does not produce an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 16-bit value that may be unaligned.

  @return The 16-bit value read from Buffer.

**/

UINT16
EFIAPI
ReadUnaligned16 (
  IN CONST UINT16              *Buffer
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer;
}

/**
  Reads a 32-bit value from memory that may be unaligned.

  This function returns the 32-bit value pointed to by Buffer. The function
  guarantees that the read operation does not produce an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 32-bit value that may be unaligned.

  @return The 32-bit value read from Buffer.

**/

UINT32
EFIAPI
ReadUnaligned32 (
  IN      CONST UINT32              *Buffer
  )

{
  ASSERT (Buffer != NULL);

  return *Buffer;
}

/**
  Writes a 64-bit value to memory that may be unaligned.

  This function writes the 64-bit value specified by Value to Buffer. Value is
  returned. The function guarantees that the write operation does not produce
  an alignment fault.

  If the Buffer is NULL, then ASSERT().

  @param  Buffer  A pointer to a 64-bit value that may be unaligned.
  @param  Value   The 64-bit value to write to Buffer.

  @return The 64-bit value to write to Buffer.

**/

UINT64
EFIAPI
WriteUnaligned64 (
  OUT     UINT64                    *Buffer,
  IN      UINT64                    Value
  )
{
  ASSERT (Buffer != NULL);

  return *Buffer = Value;
}

/**
  Copy AuthSessionIn to TPM2 command buffer.

  @param [in]  AuthSessionIn   Input AuthSession data
  @param [out] AuthSessionOut  Output AuthSession data in TPM2 command buffer

  @return AuthSession size
**/

UINT32
EFIAPI
CopyAuthSessionCommand (
  IN      TPMS_AUTH_COMMAND         *AuthSessionIn, OPTIONAL
  OUT     UINT8                     *AuthSessionOut
  )
{
  UINT8  *Buffer;

  Buffer = (UINT8 *)AuthSessionOut;

  //
  // Add in Auth session
  //
  if (AuthSessionIn != NULL) {
    //  sessionHandle
    WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(AuthSessionIn->sessionHandle));
    Buffer += sizeof(UINT32);

    // nonce
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->nonce.size));
    Buffer += sizeof(UINT16);

    CopyMem (Buffer, AuthSessionIn->nonce.buffer, AuthSessionIn->nonce.size);
    Buffer += AuthSessionIn->nonce.size;

    // sessionAttributes
    *(UINT8 *)Buffer = *(UINT8 *)&AuthSessionIn->sessionAttributes;
    Buffer++;

    // hmac
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->hmac.size));
    Buffer += sizeof(UINT16);

    CopyMem (Buffer, AuthSessionIn->hmac.buffer, AuthSessionIn->hmac.size);
    Buffer += AuthSessionIn->hmac.size;
  } else {
    //  sessionHandle
    WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(TPM_RS_PW));
    Buffer += sizeof(UINT32);

    // nonce = nullNonce
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
    Buffer += sizeof(UINT16);

    // sessionAttributes = 0
    *(UINT8 *)Buffer = 0x00;
    Buffer++;

    // hmac = nullAuth
    WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
    Buffer += sizeof(UINT16);
  }

  return (UINT32)(Buffer - (UINT8 *)AuthSessionOut);
}
