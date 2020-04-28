/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <lib.h>
#include <uefi_utils.h>
#include <vars.h>
#include <efitcp.h>
#include <smbios.h>

#include "tcp.h"

/* TCP/IP structures  */
static EFI_HANDLE tcp_handle;
static EFI_GUID TCP_GUID = EFI_TCP4_PROTOCOL;
static EFI_SERVICE_BINDING *tcp_srv_binding;
static EFI_TCP4 *tcp_connection;
static EFI_TCP4 *tcp_listener;

/* Connection management  */
static EFI_TCP4_LISTEN_TOKEN accept_token;
static EFI_TCP4_CLOSE_TOKEN close_token;

/* RX data structures  */
#define MAX_TOKEN 16
#define RX_FRAG_SIZE 2048  /* Fragment size greater or equal to TCP
			      MSS  */
typedef struct token {
	EFI_TCP4_IO_TOKEN token;
	UINT32 requested;
} token_t;
static token_t rx_token[MAX_TOKEN];
static EFI_TCP4_RECEIVE_DATA rx_data[MAX_TOKEN];
static CHAR8 rx_frag_buf[MAX_TOKEN][RX_FRAG_SIZE];

/* TX data structures  */
static UINTN next_tx_token;
static token_t tx_token[MAX_TOKEN];
static EFI_TCP4_TRANSMIT_DATA tx_data[MAX_TOKEN];

/* Events  */
static BOOLEAN events_created;

/* Caller data  */
static start_callback_t start_callback;
static data_callback_t rx_callback;
static data_callback_t tx_callback;

static struct rx {
	char *buf;
	UINT32 size;
	UINT32 requested;
	UINT32 received;
	BOOLEAN receiving;
} rx;

static EFI_STATUS request_data(token_t *token, UINT32 max_size)
{
	EFI_STATUS ret;
	UINTN size = min(max_size, (UINT32)RX_FRAG_SIZE);
	EFI_TCP4_RECEIVE_DATA *data = token->token.Packet.RxData;

	data->DataLength = size;
	data->FragmentTable[0].FragmentLength = size;

	token->requested = size;
	rx.requested += size;

	ret = uefi_call_wrapper(tcp_connection->Receive, 2,
				tcp_connection, &token->token);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"TCP Receive failed");

	return ret;
}

/* Event handlers */
static void EFIAPI data_sent(__attribute__((__unused__)) EFI_EVENT evt,
			     void *ctx)
{
	token_t *token = (token_t *)ctx;
	EFI_TCP4_TRANSMIT_DATA *data = token->token.Packet.TxData;

	if (token->requested != data->DataLength) {
		error(L"TCP sent failed. %d bytes sent instead of %d",
		      data->DataLength, token->requested);
		return;
	}

	token->requested = 0;
	tx_callback(data->FragmentTable[0].FragmentBuffer,
		    data->FragmentTable[0].FragmentLength);
}

static void EFIAPI data_received(__attribute__((__unused__)) EFI_EVENT evt, void *ctx)
{
	EFI_STATUS ret;
	token_t *token = (token_t *)ctx;
	EFI_TCP4_RECEIVE_DATA *data = token->token.Packet.RxData;

	if (token->token.CompletionToken.Status == EFI_CONNECTION_FIN) {
		rx.receiving = FALSE;

		if (!events_created)
			return;

		ret = uefi_call_wrapper(tcp_connection->Close, 2,
					tcp_connection, &close_token);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"TCP Close failed");

		return;
	}

	if (EFI_ERROR(token->token.CompletionToken.Status)) {
		rx.receiving = FALSE;
		efi_perror(token->token.CompletionToken.Status,
			   L"TCP data received failed");
		return;
	}

	ret = memcpy_s(rx.buf + rx.received, rx.size,
				   data->FragmentTable[0].FragmentBuffer,
				   data->FragmentTable[0].FragmentLength);
	if (EFI_ERROR(ret)) {
		rx.receiving = FALSE;
		return;
	}

	rx.received += data->FragmentTable[0].FragmentLength;
	rx.requested -= token->requested;

	if (rx.requested < rx.size - rx.received)
		request_data(token, rx.size - rx.received - rx.requested);

	if (rx.received == rx.size) {
		rx.receiving = FALSE;
		rx_callback(rx.buf, rx.received);
	}
}

static void EFIAPI connection_accepted(__attribute__((__unused__)) EFI_EVENT evt,
				       void *ctx)
{
	EFI_TCP4_LISTEN_TOKEN *token = (EFI_TCP4_LISTEN_TOKEN *)ctx;
	EFI_STATUS ret;

	if (EFI_ERROR(token->CompletionToken.Status)) {
		efi_perror(token->CompletionToken.Status,
			   L"connection_accepted with bad status");
		return;
	}

	ret = uefi_call_wrapper(BS->OpenProtocol, 6,
				token->NewChildHandle,
				&TCP_GUID,
				(VOID **)&tcp_connection,
				g_parent_image,
				NULL,
				EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open TCP connection");
		return;
	}

	start_callback();
}

static void EFIAPI connection_closed(__attribute__((__unused__)) EFI_EVENT evt,
				     __attribute__((__unused__)) void *ctx)
{
	EFI_STATUS ret;

	ret = uefi_call_wrapper(tcp_connection->Configure, 2,
				tcp_connection, NULL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"TCP Configure failed");
		return;
	}

	tcp_connection = NULL;

	ret = uefi_call_wrapper(tcp_listener->Accept, 2,
				tcp_listener, &accept_token);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"TCP Accept failed");
		return;
	}
}

static void init_rx_tx_structures()
{
	UINTN i;

	for (i = 0; i < MAX_TOKEN; i++) {
		rx_data[i].UrgentFlag = FALSE;
		rx_data[i].FragmentCount = 1;
		rx_data[i].FragmentTable[0].FragmentBuffer = rx_frag_buf[i];
		rx_token[i].token.Packet.RxData = &rx_data[i];

		tx_data[i].Push = TRUE;
		tx_data[i].Urgent = FALSE;
		tx_data[i].FragmentCount = 1;
		tx_token[i].token.Packet.TxData = &tx_data[i];
	}
}

static EFI_STATUS create_events()
{
	EFI_STATUS ret;
	UINTN i = 0, j = 0, k;

	ret = uefi_call_wrapper(BS->CreateEvent, 5,
				EVT_NOTIFY_SIGNAL,
				TPL_CALLBACK,
				connection_accepted,
				&accept_token,
				&accept_token.CompletionToken.Event);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create TCP Accept event");
		return ret;
	}

	ret = uefi_call_wrapper(BS->CreateEvent, 5,
				EVT_NOTIFY_SIGNAL,
				TPL_CALLBACK,
				connection_closed,
				&close_token,
				&close_token.CompletionToken.Event);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create TCP Close event");
		goto accept;
	}

	for (i = 0; i < MAX_TOKEN; i++) {
		ret = uefi_call_wrapper(BS->CreateEvent, 5,
					EVT_NOTIFY_SIGNAL,
					TPL_CALLBACK,
					data_sent,
					&tx_token[i],
					&tx_token[i].token.CompletionToken.Event);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to create TCP Transmit event");
			goto close;
		}
	}

	for (j = 0; j < MAX_TOKEN; j++) {
		ret = uefi_call_wrapper(BS->CreateEvent, 5,
					EVT_NOTIFY_SIGNAL,
					TPL_CALLBACK,
					data_received,
					&rx_token[j],
					&rx_token[j].token.CompletionToken.Event);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to create TCP Receive event");
			goto transmit;
		}
	}

	events_created = TRUE;
	return EFI_SUCCESS;

accept:
	uefi_call_wrapper(BS->CloseEvent, 1,
			  close_token.CompletionToken.Event);
close:
	uefi_call_wrapper(BS->CloseEvent, 1,
			  accept_token.CompletionToken.Event);
transmit:
	for (k = 0; k < i; k++)
		uefi_call_wrapper(BS->CloseEvent, 1,
				  tx_token[k].token.CompletionToken.Event);
	for (k = 0; k < j; k++)
		uefi_call_wrapper(BS->CloseEvent, 1,
				  rx_token[k].token.CompletionToken.Event);
	return ret;
}

void close_events()
{
	EFI_STATUS ret;
	UINTN i;

	ret = uefi_call_wrapper(BS->CloseEvent, 1,
				close_token.CompletionToken.Event);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to close TCP Close event");

	ret = uefi_call_wrapper(BS->CloseEvent, 1,
				accept_token.CompletionToken.Event);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed close TCP Accept event");

	for (i = 0; i < MAX_TOKEN; i++) {
		ret = uefi_call_wrapper(BS->CloseEvent, 1,
					tx_token[i].token.CompletionToken.Event);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to close TCP Transmit %d event", i);
	}

	for (i = 0; i < MAX_TOKEN; i++) {
		ret = uefi_call_wrapper(BS->CloseEvent, 1,
					rx_token[i].token.CompletionToken.Event);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to close TCP Receive %d event", i);
	}

	events_created = FALSE;
}

static EFI_STATUS ip_configuration(UINT32 port, EFI_IPv4_ADDRESS *address)
{
	EFI_STATUS ret;
	EFI_IP4_MODE_DATA ip_data;
	EFI_TCP4_CONFIG_DATA tcp_config = {
		.TypeOfService = 0x00,
		.TimeToLive = 255,
		.AccessPoint = {
			.UseDefaultAddress = TRUE,
			.StationAddress = { {0, 0, 0, 0} }, /* ignored - use default */
			.SubnetMask = { {0, 0, 0, 0} },	    /* ignored - use default */
			.StationPort = port,
			.RemoteAddress = { {0, 0, 0, 0} }, /* accept any */
			.RemotePort = 0, /* accept any */
			.ActiveFlag = FALSE
		},
		.ControlOption = NULL
	};
	memset((UINT8 *)&ip_data, 0, sizeof(ip_data));

	ret = uefi_call_wrapper(tcp_listener->Configure, 2,
				tcp_listener, &tcp_config);
	if (EFI_ERROR(ret) && ret != EFI_NO_MAPPING) {
		efi_perror(ret, L"Failed to configure IP stack");
		return ret;
	}

	/* DHCP still ongoing. */
	if (ret == EFI_NO_MAPPING) {
		do {
			ret = uefi_call_wrapper(tcp_listener->GetModeData, 5,
						tcp_listener, NULL, NULL, &ip_data, NULL, NULL);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Failed to get IP mode data");
				return ret;
			}
		} while (!ip_data.IsConfigured);
		ret = uefi_call_wrapper(tcp_listener->Configure, 2,
					tcp_listener, &tcp_config);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to configure IP stack");
			return ret;
		}
	}

	if (!ip_data.IsConfigured) {
		ret = uefi_call_wrapper(tcp_listener->GetModeData, 5,
					tcp_listener, NULL, NULL, &ip_data, NULL, NULL);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to get IP mode data");
			return ret;
		}
	}

	ret = memcpy_s(address, sizeof(*address), &ip_data.ConfigData.StationAddress, sizeof(*address));
	return ret;
}

EFI_STATUS tcp_start(UINT32 port, start_callback_t start_cb,
		     data_callback_t rx_cb, data_callback_t tx_cb,
		     EFI_IPv4_ADDRESS *station_address)
{
	EFI_GUID tcp_srv_binding_guid = EFI_TCP4_SERVICE_BINDING_PROTOCOL;
	EFI_HANDLE *handles;
	UINTN nb_handle = 0;
	EFI_STATUS ret;

	if (!start_cb || !rx_cb || !tx_cb || !station_address)
		return EFI_INVALID_PARAMETER;

	start_callback = start_cb;
	rx_callback = rx_cb;
	tx_callback = tx_cb;

	ret = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
				&tcp_srv_binding_guid, NULL, &nb_handle, &handles);
	if (EFI_ERROR(ret)) {
		debug(L"Failed to locate TCP service binding protocol");
		return EFI_UNSUPPORTED;
	}

	/* Use the first network device. */
	ret = uefi_call_wrapper(BS->OpenProtocol, 6,
				handles[0],
				&tcp_srv_binding_guid,
				(VOID **)&tcp_srv_binding,
				g_parent_image,
				NULL,
				EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	FreePool(handles);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open TCP service binding protocol");
		return ret;
	}

	ret = uefi_call_wrapper(tcp_srv_binding->CreateChild, 2,
				tcp_srv_binding, &tcp_handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to create TCP child");
		return ret;
	}

	ret = uefi_call_wrapper(BS->OpenProtocol, 6,
				tcp_handle,
				&TCP_GUID,
				(VOID **)&tcp_listener,
				g_parent_image,
				NULL,
				EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open TCP protocol");
		goto err;
	}

	init_rx_tx_structures();

	ret = create_events();
	if (EFI_ERROR(ret))
		goto err;

	ret = ip_configuration(port, station_address);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"IP configuration failed");
		goto err;
	}

	ret = uefi_call_wrapper(tcp_listener->Accept, 2,
				tcp_listener, &accept_token);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"TCP Accept failed");
		goto err;
	}

	return EFI_SUCCESS;

err:
	tcp_stop();
	return ret;
}

EFI_STATUS tcp_write(void *buf, UINT32 size)
{
	EFI_STATUS ret;
	token_t *token;
	EFI_TCP4_TRANSMIT_DATA *data;

	if (tx_token[next_tx_token].requested != 0)
		return EFI_NOT_READY;

	token = &tx_token[next_tx_token];
	next_tx_token = (next_tx_token + 1) % MAX_TOKEN;
	data = token->token.Packet.TxData;

	token->requested = size;
	data->DataLength = size;
	data->FragmentTable[0].FragmentLength = size;
	data->FragmentTable[0].FragmentBuffer = buf;

	ret = uefi_call_wrapper(tcp_connection->Transmit, 2,
				tcp_connection, &token->token);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"TCP Transmit failed");

	return ret;
}

EFI_STATUS tcp_read(void *buf, UINT32 size)
{
	EFI_STATUS ret;
	UINTN i;

	if (rx.receiving)
		return EFI_NOT_READY;

	rx.buf = buf;
	rx.size = size;
	rx.received = rx.requested = 0;
	rx.receiving = TRUE;

	for (i = 0; i < MAX_TOKEN && size; i++) {
		ret = request_data(&rx_token[i], size);
		if (EFI_ERROR(ret)) {
			rx.receiving = FALSE;
			return ret;
		}
		size -= rx_token[i].requested;
	}

	return EFI_SUCCESS;
}

EFI_STATUS tcp_stop(void)
{
	EFI_STATUS ret;
	UINTN index;

	if (events_created)
		close_events();

	if (tcp_connection) {
		close_token.AbortOnClose = FALSE;

		ret = uefi_call_wrapper(BS->CreateEvent, 5, 0, 0, NULL, NULL,
					&close_token.CompletionToken.Event);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to create TCP Close event");
			return ret;
		}

		ret = uefi_call_wrapper(tcp_connection->Close, 2,
					tcp_connection, &close_token);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"TCP Close failed");
			return ret;
		}

		ret = uefi_call_wrapper(BS->WaitForEvent, 3,
					1, &close_token.CompletionToken.Event, &index);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"TCP Wait for event failed");
			return ret;
		}

		if (EFI_ERROR(close_token.CompletionToken.Status)) {
			efi_perror(close_token.CompletionToken.Status,
				   L"TCP Close with bad status");
			return close_token.CompletionToken.Status;
		}

		ret = uefi_call_wrapper(BS->CloseEvent, 1,
					close_token.CompletionToken.Event);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to close TCP Close event");
			return ret;
		}

		ret = uefi_call_wrapper(tcp_connection->Configure, 2,
					tcp_connection, NULL);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"TCP Configure for connection failed");
			return ret;
		}
		tcp_connection = NULL;
	}

	if (tcp_listener) {
		ret = uefi_call_wrapper(tcp_listener->Configure, 2,
					tcp_listener, NULL);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"TCP Configure for listener failed");
			return ret;
		}
		tcp_listener = NULL;
	}

	if (tcp_srv_binding) {
		ret = uefi_call_wrapper(tcp_srv_binding->DestroyChild, 2,
					tcp_srv_binding, tcp_handle);
		if (EFI_ERROR(ret) && ret != EFI_UNSUPPORTED) {
			efi_perror(ret, L"TCP service DestroyChild failed");
			return ret;
		}
		tcp_srv_binding = NULL;
	}

	return EFI_SUCCESS;
}

EFI_STATUS tcp_run(void)
{
	if (!tcp_connection)
		return EFI_SUCCESS;

	return uefi_call_wrapper(tcp_connection->Poll, 1,
				 tcp_connection);
}
