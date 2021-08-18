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

#include "adb_socket.h"
#include "service.h"
#include "reader.h"

#define ID_STAT MKID('S','T','A','T')
#define ID_RECV MKID('R','E','C','V')
#define ID_DATA MKID('D','A','T','A')
#define ID_DONE MKID('D','O','N','E')
#define ID_QUIT MKID('Q','U','I','T')

typedef enum state {
	FREE,
	ESTABLISHED,
	STAT,
	RECV,
	SENDING_DATA,
	CLOSED
} state_t;

typedef union {
	UINT32 id;
	struct {
		UINT32 id;
		UINT32 namelen;
	} req;
	struct {
		UINT32 id;
		UINT32 mode;
		UINT32 size;
		UINT32 time;
	} stat;
	struct {
		UINT32 id;
		UINT32 size;
	} data;
} sync_msg_t;

#define SYNC_DATA_MAX (64 * 1024)

typedef struct {
	state_t state;
	reader_ctx_t reader_ctx;
	BOOLEAN need_more_data;
	unsigned char *buf;
	UINT64 buf_cur;
	UINT64 buf_len;
	UINT64 sent;
} sync_ctx_t;
static sync_ctx_t CONTEXTS[MAX_ADB_SOCKET];

static EFI_STATUS sync_service_open(const char *arg, void **ctx_p)
{
	sync_ctx_t *ctx = NULL;
	UINTN i;

	if (!arg || !ctx_p || strcmp((CHAR8 *)arg, (CHAR8 *)""))
		return EFI_INVALID_PARAMETER;

	for (i = 0; i < ARRAY_SIZE(CONTEXTS); i++)
		if (CONTEXTS[i].state == FREE)
			ctx = &CONTEXTS[i];

	if (!ctx) {
		error(L"Failed to allocate sync service context structure");
		return EFI_OUT_OF_RESOURCES;
	}

	ctx->state = ESTABLISHED;

	*ctx_p = ctx;

	return EFI_SUCCESS;
}

static EFI_STATUS sync_service_ready(__attribute__((__unused__)) asock_t s)
{
	return EFI_SUCCESS;
}

static EFI_STATUS sync_service_close(asock_t s)
{
	sync_ctx_t *ctx = asock_context(s);

	if (!ctx)
		return EFI_INVALID_PARAMETER;

	if (ctx->state == SENDING_DATA)
		reader_close(&ctx->reader_ctx);

	ctx->state = FREE;

	return EFI_SUCCESS;
}

static EFI_STATUS send_done(asock_t s, sync_ctx_t *ctx)
{
	sync_msg_t msg;

	reader_close(&ctx->reader_ctx);

	ctx->state = ESTABLISHED;

	msg.req.id = ID_DONE;
	msg.req.namelen = 0;
	return asock_write(s, (unsigned char *)&msg, sizeof(msg.req));
}

#define DATA_PROGRESS_THRESHOLD (5 * 1024 * 1024)

static EFI_STATUS send_more_data(asock_t s, sync_ctx_t *ctx)
{
	EFI_STATUS ret;
	UINT32 sent;
	sync_msg_t msg;

	/* Need to load more data. */
	if (ctx->need_more_data) {
		ctx->buf_len = SYNC_DATA_MAX;

		ret = reader_read(&ctx->reader_ctx, &ctx->buf, &ctx->buf_len);
		if (EFI_ERROR(ret))
			return ret;
		if (ctx->buf_len == 0) /* No more data to send. */
			return send_done(s, ctx);

		msg.data.id = ID_DATA;
		msg.data.size = ctx->buf_len;
		ctx->buf_cur = 0;
		ctx->need_more_data = FALSE;

		return asock_write(s, (unsigned char *)&msg, sizeof(msg.data));
	}

	sent = min((UINTN)adb_max_payload, ctx->buf_len - ctx->buf_cur);
	ret = asock_write(s, ctx->buf + ctx->buf_cur, sent);
	if (EFI_ERROR(ret))
		return ret;

	ctx->buf_cur = ctx->buf_cur + sent;
	if (ctx->buf_cur == ctx->buf_len)
		ctx->need_more_data = TRUE;

	ctx->sent += sent;
	if (ctx->sent >= DATA_PROGRESS_THRESHOLD &&
	    ctx->sent % DATA_PROGRESS_THRESHOLD < sent)
		debug(L"%d MB have been sent", ctx->sent / 1024 / 1024);

	return ret;
}

static EFI_STATUS sync_service_okay(asock_t s)
{
	EFI_STATUS ret = EFI_SUCCESS;
	sync_ctx_t *ctx = asock_context(s);

	if (!ctx)
		return EFI_INVALID_PARAMETER;

	if (ctx->state == SENDING_DATA)
		ret = send_more_data(s, ctx);

	return ret;
}

static EFI_STATUS sync_service_reader_open(sync_ctx_t *ctx, unsigned char *data, UINT32 length)
{
	EFI_STATUS ret;
	char path[length + 1];

	ret = memcpy_s(path, sizeof(path), data, length);
	if (EFI_ERROR(ret))
		return ret;

	path[length] = '\0';

	return reader_open(&ctx->reader_ctx, path);
}

#define REGULAR_FILE_STAT_MODE 0x000081b6

static EFI_STATUS sync_service_stat(asock_t s, sync_ctx_t *ctx, unsigned char *data, UINT32 length)
{
	EFI_STATUS ret, write_ret;
	sync_msg_t msg;
	EFI_TIME now;

	asock_send_okay(s);

	ctx->state = ESTABLISHED;

	memset_s(&msg, sizeof(msg), 0, sizeof(msg.stat));
	msg.stat.id = ID_STAT;

	ret = sync_service_reader_open(ctx, data, length);
	if (EFI_ERROR(ret))
		goto fail;

	reader_close(&ctx->reader_ctx);

	msg.stat.mode = REGULAR_FILE_STAT_MODE;

	ret = uefi_call_wrapper(RT->GetTime, 2, &now, NULL);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get the current time");
		msg.stat.time = 0;
        } else
		msg.stat.time = efi_time_to_ctime(&now);

fail:
	write_ret = asock_write(s, (unsigned char *)&msg, sizeof(msg.stat));
	return EFI_ERROR(ret) ? ret : write_ret;
}

static EFI_STATUS sync_service_recv(asock_t s, sync_ctx_t *ctx, unsigned char *data, UINT32 length)
{
	EFI_STATUS ret;

	ret = asock_send_okay(s);
	if (EFI_ERROR(ret))
		return ret;

	ret = sync_service_reader_open(ctx, data, length);
	if (EFI_ERROR(ret))
		return ret;

	ctx->sent = 0;
	ctx->state = SENDING_DATA;
	ctx->need_more_data = TRUE;

	return send_more_data(s, ctx);
}

static EFI_STATUS sync_service_read(asock_t s, unsigned char *data, UINT32 length)
{
	EFI_STATUS ret;
	sync_msg_t *msg = (sync_msg_t *) data;
	sync_ctx_t *ctx = asock_context(s);

	if (!ctx) {
		error(L"sync service: invalid context");
		goto fail;
	}

	switch (ctx->state) {
	case ESTABLISHED:
		if (length < sizeof(msg->req)) {
			error(L"sync service: message is too short");
			goto fail;
		}
		if (msg->id == ID_STAT) {
			ctx->state = STAT;
			if (length == sizeof(msg->req))
				return asock_send_okay(s);
			return sync_service_stat(s, ctx, data + sizeof(msg->req),
						 msg->req.namelen);
		}
		if (msg->id == ID_RECV) {
			ctx->state = RECV;
			if (length == sizeof(msg->req))
				return asock_send_okay(s);
			return sync_service_recv(s, ctx, data + sizeof(msg->req),
						 msg->req.namelen);
		}
		if (msg->id == ID_QUIT)
			return asock_send_close(s);
		error(L"sync service: unexpected message 0x%08X", msg->id);
		goto fail;

	case STAT:
		return sync_service_stat(s, ctx, data, length);

	case RECV:
		return sync_service_recv(s, ctx, data, length);

	default:
		error(L"sync service: unexpected state %d", ctx->state);
		goto fail;
	}

fail:
	ret = asock_send_close(s);
	return ret ? ret : EFI_INVALID_PARAMETER;
}

service_t sync_service = {
	.name	= "sync",
	.open	= sync_service_open,
	.ready	= sync_service_ready,
	.close	= sync_service_close,
	.okay	= sync_service_okay,
	.read	= sync_service_read
};
