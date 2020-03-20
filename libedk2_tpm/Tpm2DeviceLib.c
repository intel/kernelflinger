/** @file
  Implement TPM2 SubmitCommand.

Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved. <BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <efi.h>
#include <efiapi.h>
#include "Tpm2Help.h"
#include "Tcg2Protocol.h"
#include "Tpm2DeviceLib.h"

EFI_STATUS
EFIAPI
Tpm2SubmitCommand (
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN OUT UINT32        *OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
  EFI_STATUS                Status;
  TPM2_RESPONSE_HEADER      *Header;

  EFI_GUID gEfiTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
  EFI_TCG2_PROTOCOL *mTcg2Protocol;

 Status = LibLocateProtocol (&gEfiTcg2ProtocolGuid, (void **) &mTcg2Protocol);
    if (EFI_ERROR (Status) || mTcg2Protocol == NULL ) {
      //
      // Tcg2 protocol is not installed. So, TPM2 is not present.
      //
      return EFI_NOT_FOUND;
    }
  //
  // Assume when Tcg2 Protocol is ready, RequestUseTpm already done.
  //
  Status = mTcg2Protocol->SubmitCommand (
                            mTcg2Protocol,
                            InputParameterBlockSize,
                            InputParameterBlock,
                            *OutputParameterBlockSize,
                            OutputParameterBlock
                            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Header = (TPM2_RESPONSE_HEADER *)OutputParameterBlock;
  *OutputParameterBlockSize = SwapBytes32 (Header->paramSize);

  return EFI_SUCCESS;
}

