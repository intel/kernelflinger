/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
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
 */

#include <lib.h>
#include <hecisupport.h>

/*
 * Send message with ack
 */
static EFI_STATUS heci_send_w_ack(uint8_t *Message, uint32_t Length, uint32_t *RecLength, uint8_t HostAddress, uint8_t DevAddr)
{
	EFI_STATUS ret = EFI_NOT_READY;

	EFI_GUID guid = HECI_PROTOCOL_GUID;
	EFI_HECI_PROTOCOL *protocol = NULL;

	ret = LibLocateProtocol(&guid, (void **)&protocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get heciprotocol");
		return ret;
	}

	ret = uefi_call_wrapper(protocol->SendwACK, 5, (UINT32 *)Message, Length, RecLength, HostAddress, DevAddr);
	debug(L"uefi_call_wrapper(SendwACK) =  %d", ret);

	return ret;
}

/*
 *  Determine SEC mode.
 */
static EFI_STATUS heci_get_sec_mode (unsigned *sec_mode)
{
	EFI_STATUS ret;

	EFI_GUID guid = HECI_PROTOCOL_GUID;
	EFI_HECI_PROTOCOL *protocol = NULL;

	ret = LibLocateProtocol(&guid, (void **)&protocol);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get heciprotocol");
		return ret;
	}

	ret = uefi_call_wrapper(protocol->GetSeCMode, 1, sec_mode);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	debug(L"HECI sec_mode %X", *sec_mode);
	return ret;
}

BOOLEAN heci_is_eop_received(void)
{
	EFI_STATUS ret;
	uint32_t EopStatus;
	uint32_t HeciSendLength;
	uint32_t HeciRecvLength;
	GEN_END_OF_POST *GetEopStatus;
	GEN_GET_EOP_STATUS_ACK __attribute__((__unused__)) *Resp;
	uint32_t SeCMode;
	uint8_t DataBuffer[sizeof(GEN_GET_EOP_STATUS_ACK)];

	ret = heci_get_sec_mode(&SeCMode);
	if (EFI_ERROR(ret) || (SeCMode != SEC_MODE_NORMAL)) {
		return FALSE;
	}
	debug(L"GetSeCMode successful");
	memset_s(DataBuffer, sizeof(DataBuffer), 0, sizeof(DataBuffer));
	GetEopStatus = (GEN_END_OF_POST*)DataBuffer;
	GetEopStatus->MKHIHeader.Fields.GroupId = EOP_GROUP_ID;
	GetEopStatus->MKHIHeader.Fields.Command = EOP_GET_STATUS_ID;

	HeciSendLength = sizeof(GEN_END_OF_POST);
	HeciRecvLength = sizeof(DataBuffer);

	ret = heci_send_w_ack (
	             DataBuffer,
	             HeciSendLength,
	             &HeciRecvLength,
	             BIOS_FIXED_HOST_ADDR,
	             PREBOOT_FIXED_SEC_ADDR);
	Resp = (GEN_GET_EOP_STATUS_ACK *)DataBuffer;
	EopStatus = Resp->EopStatus & 0xFF;            /* 0 - received; other - not received */
	if (EFI_ERROR(ret) || EopStatus) {
		return FALSE;
	}
	debug(L"Eop has been received");

	return TRUE;
}
/*
* Send End of Post
 */
EFI_STATUS heci_end_of_post(void)
{
	EFI_STATUS ret;

	uint32_t HeciSendLength;
	uint32_t HeciRecvLength;
	GEN_END_OF_POST *SendEOP;
	GEN_END_OF_POST_ACK __attribute__((__unused__)) *EOPResp;
	uint32_t SeCMode;
	uint8_t DataBuffer[sizeof(GEN_END_OF_POST_ACK)];

	debug(L"Start Send HECI Message: EndOfPost");
	ret = heci_get_sec_mode(&SeCMode);
	if (EFI_ERROR(ret) || (SeCMode != SEC_MODE_NORMAL)) {
		return ret;
	}
	debug(L"GetSeCMode successful");

	memset_s(DataBuffer, sizeof(DataBuffer), 0, sizeof(DataBuffer));

	SendEOP = (GEN_END_OF_POST*)DataBuffer;
	SendEOP->MKHIHeader.Fields.GroupId = EOP_GROUP_ID;
	SendEOP->MKHIHeader.Fields.Command = EOP_CMD_ID;

	debug(L"GEN_END_OF_POST size is %x", sizeof(GEN_END_OF_POST));
	HeciSendLength = sizeof(GEN_END_OF_POST);
	HeciRecvLength = sizeof(DataBuffer);

	ret = heci_send_w_ack (
	             DataBuffer,
	             HeciSendLength,
	             &HeciRecvLength,
	             BIOS_FIXED_HOST_ADDR,
	             PREBOOT_FIXED_SEC_ADDR);

	EOPResp = (GEN_END_OF_POST_ACK*)DataBuffer;

	debug(L"Group    =%08x", EOPResp->Header.Fields.GroupId);
	debug(L"Command  =%08x", EOPResp->Header.Fields.Command);
	debug(L"IsRespone=%08x", EOPResp->Header.Fields.IsResponse);
	debug(L"Result   =%08x", EOPResp->Header.Fields.Result);
	debug(L"RequestedActions   =%08x", EOPResp->Data.RequestedActions);

	return ret;
}

