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
#include <endian.h>
#include <fastboot.h>
#include <usb.h>
#include <tcp.h>
#include <transport.h>

/* USB */
#define FASTBOOT_IF_SUBCLASS		0x42
#define FASTBOOT_IF_PROTOCOL		0x03
#define FASTBOOT_STR_CONFIGURATION	L"USB-Update"
#define FASTBOOT_STR_INTERFACE		L"Fastboot"

static const UINT32 BLK_DOWNLOAD = 8 * 1024 * 1024;

static EFI_STATUS fastboot_usb_start(start_callback_t start_cb,
				     data_callback_t rx_cb,
				     data_callback_t tx_cb)
{
	return usb_start(FASTBOOT_IF_SUBCLASS, FASTBOOT_IF_PROTOCOL,
			 FASTBOOT_STR_CONFIGURATION,
			 FASTBOOT_STR_INTERFACE,
			 start_cb, rx_cb, tx_cb);
}

EFI_STATUS fastboot_usb_read(void *buf, UINT32 size)
{
	return usb_read(buf, min(BLK_DOWNLOAD, size));
}

/* TCP */
static const UINT32 TCP_PORT = 5554;
static const CHAR8 PROTOCOL_VERSION[4] = "FB01";

typedef enum tcp_state {
	OFFLINE,
	INITIALIZING,
	READY,
	WAITING_DATA_SIZE,
	WAITING_DATA,
	ERROR
} tcp_state_t;
static tcp_state_t tcp_state;

static struct rx {
	char *buf;
	UINT32 size;
	UINT32 used;
} rx;
static UINT64 remaining_data;

static start_callback_t start_callback;
static data_callback_t rx_callback;
static data_callback_t tx_callback;

static void fastboot_tcp_start_cb(void)
{
	static char version[sizeof(PROTOCOL_VERSION)];
	EFI_STATUS ret;

	tcp_state = INITIALIZING;

	ret = tcp_write((VOID *)PROTOCOL_VERSION, sizeof(PROTOCOL_VERSION));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tcp_write failed during initialization");
		return;
	}

	ret = tcp_read(version, sizeof(version));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"tcp_read failed during initialization");
		return;
	}
}

static void transport_tcp_rx_cb(void *buf, UINT32 size)
{
	EFI_STATUS ret;

	switch (tcp_state) {
	case INITIALIZING:
		if (size != sizeof(PROTOCOL_VERSION) ||
		    strncmp((CHAR8 *)buf, (CHAR8 *)PROTOCOL_VERSION, size)) {
			error(L"Invalid fastboot TCP protocol version");
			tcp_state = ERROR;
			return;
		}

		remaining_data = 0;
		tcp_state = READY;
		start_callback();
		return;

	case WAITING_DATA_SIZE:
		if (size != sizeof(remaining_data) || buf != &remaining_data) {
			error(L"Waiting data size %d", size);
			return;
		}

		remaining_data = be64toh(remaining_data);

		tcp_state = WAITING_DATA;
		ret = tcp_read(rx.buf, min(rx.size, remaining_data));
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"transport_tcp_rx tcp_read failed");
			return;
		}
		return;

	case WAITING_DATA:
		if (size + rx.used > rx.size || size > remaining_data) {
			error(L"received too much data");
			tcp_state = ERROR;
			return;
		}

		rx.used += size;
		remaining_data -= size;
		if (rx.used == rx.size || remaining_data == 0) {
			tcp_state = READY;
			rx_callback(rx.buf, rx.used);
			return;
		}

		/* Still more data to read.  */
		ret = tcp_read(rx.buf + rx.used, min(rx.size - rx.used,
						     remaining_data));
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Transport_tcp_rx tcp_read failed");
		return;

	default:
		error(L"Inconsistent TCP state %d at rx", tcp_state);
	}
}

static void transport_tcp_tx_cb(void *buf, UINT32 size)
{
	if (tcp_state == READY)
		tx_callback(buf, size);
}

static void print_tcpip_information(EFI_IPv4_ADDRESS *address)
{
#define TCPIP_INFO_FMT L"Fastboot is listening on TCP %d.%d.%d.%d:%d"

	ui_print(TCPIP_INFO_FMT, address->Addr[0], address->Addr[1],
		 address->Addr[2], address->Addr[3], TCP_PORT);
	debug(TCPIP_INFO_FMT, address->Addr[0], address->Addr[1],
	      address->Addr[2], address->Addr[3], TCP_PORT);
}

static EFI_STATUS fastboot_tcp_start(start_callback_t start_cb,
				     data_callback_t rx_cb,
				     data_callback_t tx_cb)
{
	EFI_STATUS ret;
	EFI_IPv4_ADDRESS station_address;

	start_callback = start_cb;
	rx_callback = rx_cb;
	tx_callback = tx_cb;

	ret = tcp_start(TCP_PORT, fastboot_tcp_start_cb,
			transport_tcp_rx_cb, transport_tcp_tx_cb,
			&station_address);
	if (EFI_ERROR(ret))
		return ret;

	print_tcpip_information(&station_address);

	return EFI_SUCCESS;
}

EFI_STATUS fastboot_tcp_write(void *buf, UINT32 size)
{
	EFI_STATUS ret;
	static char write_buf[MAGIC_LENGTH + sizeof(UINT64)];

	if (tcp_state != READY) {
		error(L"Inconsistent TCP state %d at write", tcp_state);
		return EFI_NOT_STARTED;
	}

	if (size + sizeof(UINT64) > sizeof(write_buf)) {
		error(L"Invalid size %d", size);
		return EFI_INVALID_PARAMETER;
	}

	*((UINT64 *)write_buf) = htobe64(size);
	ret = memcpy_s(write_buf + sizeof(UINT64), sizeof(write_buf), buf, size);
	if (EFI_ERROR(ret))
		return ret;

	return tcp_write(write_buf, size + sizeof(UINT64));
}

EFI_STATUS fastboot_tcp_read(void *buf, UINT32 size)
{
	EFI_STATUS ret;

	if (tcp_state != READY) {
		error(L"Inconsistent TCP state %d at read", tcp_state);
		return EFI_INVALID_PARAMETER;
	}

	rx.buf = buf;
	rx.size = size;
	rx.used = 0;
	tcp_state = WAITING_DATA_SIZE;

	ret = tcp_read(&remaining_data, sizeof(remaining_data));
	if (EFI_ERROR(ret))
		efi_perror(ret, L"fastboot_tcp_read failed");

	return ret;
}

/* Transport */
static transport_t FASTBOOT_TRANSPORT[] = {
	{
		.name = "USB for fastboot",
		.start = fastboot_usb_start,
		.stop = usb_stop,
		.run = usb_run,
		.read = fastboot_usb_read,
		.write = usb_write
	},
	{
		.name = "TCP for fastboot",
		.start = fastboot_tcp_start,
		.stop = tcp_stop,
		.run = tcp_run,
		.read = fastboot_tcp_read,
		.write = fastboot_tcp_write
	}
};

EFI_STATUS fastboot_transport_register(void)
{
	return transport_register(FASTBOOT_TRANSPORT,
				  ARRAY_SIZE(FASTBOOT_TRANSPORT));
}

void fastboot_transport_unregister(void)
{
	transport_unregister();
}
