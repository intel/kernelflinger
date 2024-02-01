/*
 * Copyright (c) 2015, Intel Corporation
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

#include "adb.h"
#include "adb_socket.h"
#include "service.h"

struct asock {
	UINT32 local;
	UINT32 remote;
	adb_pkt_t msg;
	adb_pkt_t wrt;
	unsigned char data[ADB_MAX_PAYLOAD];
	service_t *service;
	void *context;
};

static struct asock asocks[MAX_ADB_SOCKET];

/* Host to device */
EFI_STATUS asock_open(UINT32 remote, service_t *service, char *arg)
{
	static adb_pkt_t fail_msg = { .msg.data_length = 0 };
	EFI_STATUS ret;
	asock_t s = NULL;
	UINTN i;

	if (!remote || !service) {
		error(L"Invalid remote or service");
		ret = EFI_INVALID_PARAMETER;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(asocks); i++)
		if (asocks[i].local == 0) {
			s = &asocks[i];
			s->local = i + 1;
			break;
		}

	if (!s) {
		ret = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	s->remote = remote;
	s->service = service;
	s->context = NULL;

	ret = service->open(arg, &s->context);
	if (EFI_ERROR(ret))
		goto err;

	debug(L"socket %d/%d created for service %a", s->local, remote, service->name);

	ret = asock_send_okay(s);
	if (EFI_ERROR(ret)) {
		service->close(s);
		efi_perror(ret, L"Failed to send OKAY message");
		goto err;
	}

	ret = s->service->ready(s);
	if (EFI_ERROR(ret)) {
		service->close(s);
		goto err;
	}

	return EFI_SUCCESS;

err:
	if (s)
		s->local = 0;
	efi_perror(ret, L"Failed to open socket for %d remote", remote);
	return adb_send_pkt(&fail_msg, A_CLSE, 0, remote);
}

EFI_STATUS asock_close(asock_t s)
{
	EFI_STATUS ret;

	if (!s)
		return EFI_INVALID_PARAMETER;

	ret = s->service->close(s);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to close service on socket %d/%d",
			   s->local, s->remote);
		return ret;
	}

	debug(L"socket %d/%d closed", s->local, s->remote);
	s->local = 0;

	return EFI_SUCCESS;
}

EFI_STATUS asock_okay(asock_t s)
{
	if (!s)
		return EFI_INVALID_PARAMETER;

	return s->service->okay(s);
}

EFI_STATUS asock_read(asock_t s, unsigned char *data, UINT32 length)
{
	if (!s)
		return EFI_INVALID_PARAMETER;

	return s->service->read(s, data, length);
}

/* Device to host */
EFI_STATUS asock_write(asock_t s, unsigned char *data, UINT32 length)
{
	EFI_STATUS ret;

	if (!s || length > adb_max_payload)
		return EFI_INVALID_PARAMETER;

#ifdef CRASHMODE_USE_ADB
	ret = memdump(s->data, sizeof(s->data), data, length);
#elif
	ret = memcpy_s(s->data, sizeof(s->data), data, length);
#endif

	if (EFI_ERROR(ret))
		return ret;
	s->wrt.data = s->data;
	s->wrt.msg.data_length = length;
	return adb_send_pkt(&s->wrt, A_WRTE, s->local, s->remote);
}

EFI_STATUS asock_send_okay(asock_t s)
{
	if (!s)
		return EFI_INVALID_PARAMETER;

	return adb_send_pkt(&s->msg, A_OKAY, s->local, s->remote);
}

EFI_STATUS asock_send_close(asock_t s)
{
	if (!s)
		return EFI_INVALID_PARAMETER;

	return adb_send_pkt(&s->msg, A_CLSE, s->local, s->remote);
}

/* Tools */
void *asock_context(asock_t s)
{
	return s ? s->context : NULL;
}

asock_t asock_find(UINT32 local, UINT32 remote)
{
	asock_t s;

	if (local == 0 || local > ARRAY_SIZE(asocks))
		return NULL;

	s = &asocks[local - 1];
	if (s->local == local && s->remote == remote)
		return s;

	error(L"socket %d/%d not found", local, remote);
	return NULL;
}

void asock_close_all()
{
	UINTN i;

	for (i = 0; i < ARRAY_SIZE(asocks); i++)
		if (asocks[i].local)
			asock_close(&asocks[i]);
}
