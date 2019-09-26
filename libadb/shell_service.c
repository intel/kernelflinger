/*
 * Copyright (c) 2019, Intel Corporation
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
#include <pae.h>

#include "adb_socket.h"
#include "service.h"
#include "shell_service.h"

#include "devmem.h"
#include "hexdump.h"
#include "ioport.h"
#include "lsacpi.h"
#include "lspartition.h"

#define MAX_ARGS	8

typedef struct {
	shcmd_t *cmd;
	char *arg;
	INTN argc;
	const char *argv[MAX_ARGS];
	char *buf;
	UINTN buf_size;
} shell_ctx_t;

static shcmd_t help_shcmd, list_shcmd;
static shcmd_t *SHCMD[] = {
	&devmem_shcmd,
	&help_shcmd,
	&hexdump_shcmd,
	&inb_shcmd,
	&inl_shcmd,
	&inw_shcmd,
	&list_shcmd,
	&lsacpi_shcmd,
	&lspartition_shcmd,
	&outb_shcmd,
	&outl_shcmd,
	&outw_shcmd
};

static void free_shell_ctx(shell_ctx_t *ctx)
{
	if (ctx->arg)
		FreePool(ctx->arg);
	if (ctx->buf)
		FreePool(ctx->buf);
	FreePool(ctx);
}

static shcmd_t *get_command(const char *name)
{
	UINTN i;

	for (i = 0; i < ARRAY_SIZE(SHCMD); i++)
		if (!strcmp(SHCMD[i]->name, name))
			return SHCMD[i];

	return NULL;
}

static EFI_STATUS shell_service_open(const char *arg, void **ctx_p)
{
	EFI_STATUS ret = EFI_INVALID_PARAMETER;
	shell_ctx_t *ctx;

	ctx = AllocateZeroPool(sizeof(*ctx));
	if (!ctx) {
		error(L"Failed to allocate shell service context structure");
		ret = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	/* If no command is supplied, let's list the commands.  */
	if (*arg == '\0') {
		ctx->cmd = &list_shcmd;
		ctx->argc = 1;
		ctx->argv[0] = ctx->cmd->name;
		goto ready;
	}

	ctx->arg = strdup(arg);
	if (!ctx->arg) {
		error(L"Failed to duplicate arg string");
		ret = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	ret = string_to_argv(ctx->arg, &ctx->argc, (CHAR8 **)ctx->argv,
			     ARRAY_SIZE(ctx->argv), " ", " ");
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to split string into argv");
		goto err;
	}

	ctx->cmd = get_command(ctx->argv[0]);
	if (!ctx->cmd) {
		error(L"Unknown command '%a'", ctx->argv[0]);
		ret = EFI_INVALID_PARAMETER;
		goto err;
	}

ready:
	*ctx_p = ctx;
	return EFI_SUCCESS;

err:
	free_shell_ctx(ctx);
	return ret;
}

static asock_t current_socket;
static EFI_STATUS shell_service_ready(asock_t s)
{
	EFI_STATUS ret = EFI_SUCCESS;
	shell_ctx_t *ctx = asock_context(s);

	current_socket = s;
	ret = ctx->cmd->main(ctx->argc, ctx->argv);
	if (ret == EFI_INVALID_PARAMETER)
		ss_printf(L"%a\n", ctx->cmd->help);
	else if (EFI_ERROR(ret))
		ss_printf(L"'%a' failed with error %r", ctx->cmd->name, ret);
	current_socket = NULL;

	if (ctx->buf)
		ret = asock_write(s, ctx->buf, ctx->buf_size - 1);
	else
		ret = asock_send_close(s);

	return ret;
}

static EFI_STATUS shell_service_close(asock_t s)
{
	free_shell_ctx(asock_context(s));
	return EFI_SUCCESS;
}

static EFI_STATUS shell_service_okay(asock_t s)
{
	return asock_send_close(s);
}

static EFI_STATUS shell_service_read(__attribute__((__unused__)) asock_t s,
				     __attribute__((__unused__)) unsigned char *data,
				     __attribute__((__unused__)) UINT32 length)
{
	return EFI_UNSUPPORTED;
}

service_t shell_service = {
	.name	= "shell",
	.open	= shell_service_open,
	.ready	= shell_service_ready,
	.close	= shell_service_close,
	.okay	= shell_service_okay,
	.read	= shell_service_read
};

static EFI_STATUS help_main(INTN argc, const char **argv)
{
	shcmd_t *cmd;

	if (argc != 2)
		return EFI_INVALID_PARAMETER;

	cmd = get_command(argv[1]);
	if (!cmd) {
		ss_printf(L"Unknown command '%a'\n", argv[1]);
		return EFI_INVALID_PARAMETER;
	}

	ss_printf(L"%a\n", cmd->help);
	return EFI_SUCCESS;
}

static shcmd_t help_shcmd = {
	.name = "help",
	.summary = "Print usage for a command",
	.help = "Usage: help <COMMAND>",
	.main = help_main
};

static EFI_STATUS list_main(INTN argc,
			    __attribute__((__unused__)) const char **argv)
{
	const char TITLE[] = "Command";
	UINTN i, max_len;
	CHAR16 fmt[16] = { 0 };

	if (argc != 1)
		return EFI_INVALID_PARAMETER;

	max_len = sizeof(TITLE) - 1;
	for (i = 0; i < ARRAY_SIZE(SHCMD); i++)
		max_len = max(max_len, strlen(SHCMD[i]->name));

	SPrint(fmt, sizeof(fmt), L"%%-.%da  %%a\n", max_len);
	ss_printf(fmt, TITLE, "Description\n-");
        for (i = 0; i < ARRAY_SIZE(SHCMD); i++)
		ss_printf(fmt, SHCMD[i]->name, SHCMD[i]->summary);

	return EFI_SUCCESS;
}

static shcmd_t list_shcmd = {
	.name = "list",
	.summary = "List the commands",
	.help = "Usage: list",
	.main = list_main
};

#define BUFFER_SIZE 512

/* This function is to be called by the shell command implementation.
   It adds formatted text to a buffer which is sent through the adb
   socket once the command has exited (end of its main function). */
EFI_STATUS ss_printf(const CHAR16 *fmt, ...)
{
	va_list args;
	UINTN length;
	CHAR16 buf16[BUFFER_SIZE];
	shell_ctx_t *ctx = asock_context(current_socket);
	EFI_STATUS ret;

	va_start(args, fmt);
	length = VSPrint(buf16, sizeof(buf16), (CHAR16 *)fmt, args) + 1;
	va_end(args);

	if (!ctx->buf) {
		ctx->buf = AllocatePool(length);
		if (!ctx->buf)
			goto err;

		ret = str_to_stra(ctx->buf, buf16, length);
		ctx->buf_size += length;
	} else {
		ctx->buf = ReallocatePool(ctx->buf, ctx->buf_size,
					  ctx->buf_size + length - 1);
		if (!ctx->buf)
			goto err;

		ret = str_to_stra(ctx->buf + ctx->buf_size - 1, buf16, length);
		ctx->buf_size += length - 1;
	}

	return ret;

err:
	efi_perror(EFI_OUT_OF_RESOURCES, L"ss_printf() failed, %r");
	return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS ss_read_number(const char *arg, const char *name, UINT64 *value)
{
	char *endptr;

	if (!arg || !name || !value)
		return EFI_INVALID_PARAMETER;

	*value = strtoull(arg, &endptr, 0);
	if (*endptr != '\0') {
		ss_printf(L"Failed to parse '%a' %a parameter\n", arg, name);
		return EFI_INVALID_PARAMETER;
	}

	return EFI_SUCCESS;
}

#define PRINT_SIZE (sizeof(UINT64) * 2)

static CHAR16 *get_address_format(EFI_PHYSICAL_ADDRESS address)
{
	static CHAR16 fmt[8];
	UINTN i;

	for (i = 0; address != 0; i++)
		address /= 16;

	SPrint(fmt, sizeof(fmt), L"%%0%dllx", i);
	return fmt;
}

void ss_hexdump(unsigned char *buf, UINTN length,
		EFI_PHYSICAL_ADDRESS address, BOOLEAN canonical)
{
	CHAR16 *addr_fmt;
	char ascii[PRINT_SIZE + 1] = { '\0' };
	unsigned char *cur, *end;
	UINTN col;

	addr_fmt = get_address_format(address + length);
	memset(ascii, '.', sizeof(ascii) - 1);
	end = (char *)(UINTN)(buf + length);
	for (col = 0, cur = (char *)(UINTN)buf;
	     cur != end;
	     address++, cur++, col = (col + 1) % PRINT_SIZE) {
		if (col == 0)
			ss_printf(addr_fmt, address);

		ss_printf(L" %a%02x", col % sizeof(UINT64) ? "" : " ", *cur);

		if (*cur >= ' ' && *cur <= '~')
			ascii[col] = *cur;
		else
			ascii[col] = '.';

		if (col == PRINT_SIZE - 1) {
			if (canonical) {
				ss_printf(L"  |%a|", ascii);
				memset(ascii, '.', sizeof(ascii) - 1);
			}
			ss_printf(L"\n");
		}
	}

	if (col != 0) {
		for (; col < PRINT_SIZE; col++)
			ss_printf(L" %a  ", col % sizeof(UINT64) ? "" : " ");
		if (canonical)
			ss_printf(L"  |%a|", ascii);
		ss_printf(L"\n");
	}
}

#ifndef __LP64__
EFI_STATUS ss_pae_map(EFI_PHYSICAL_ADDRESS *address, UINT64 length)
{
	EFI_STATUS ret;
	unsigned char *to;
	EFI_MEMORY_DESCRIPTOR *map;
        UINTN nr_entries, key, entry_sz;
        UINT32 entry_ver;
	UINT64 len = length;

	map = LibMemoryMap(&nr_entries, &key, &entry_sz, &entry_ver);
	if (!map)
		return EFI_OUT_OF_RESOURCES;

	ret = pae_init((CHAR8 *)map, nr_entries, entry_sz);
	if (EFI_ERROR(ret))
		return ret;

	ret = pae_map(*address, &to, &len);
	if (EFI_ERROR(ret))
		goto err;

	if (len != length) {
		ret = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	*address = (EFI_PHYSICAL_ADDRESS)to;
	return EFI_SUCCESS;

err:
	pae_exit();
	return ret;
}
#endif
