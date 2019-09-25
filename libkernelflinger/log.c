/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <efi.h>
#include <efilib.h>

#include "log.h"
#include "lib.h"
#include "vars.h"

static SERIAL_IO_INTERFACE *serial;

#define SERIAL_BAUD_RATE	115200
#define SERIAL_FIFO_DEPTH	1
#define SERIAL_TIMEOUT		1
#define SERIAL_PARITY		1
#define SERIAL_DATA_BITS	8
#define SERIAL_STOP_BITS	1

#define BUFFER_SIZE 512
static CHAR16 buf16[BUFFER_SIZE];
static CHAR8 buf8[BUFFER_SIZE];

#define LOG_BUF_SIZE 4096
static CHAR8 log_buf[LOG_BUF_SIZE];
static UINTN pos, last_pos;

static CHAR8 data_buf[LOG_BUF_SIZE];
static UINTN buf_pos = 0;
static EFI_FILE *log_file;

EFI_STATUS log_flush_to_var(BOOLEAN nonvol)
{
	static volatile BOOLEAN running;
	EFI_STATUS ret;
	CHAR8 *buf, *cur;
	UINTN size;

	if (running)
		return EFI_ALREADY_STARTED;

	running = TRUE;

#ifdef USER
	if (!is_UEFI())
		return EFI_SUCCESS;

	if (!device_is_provisioning())
		return EFI_SUCCESS;
#endif

	if (last_pos) {		/* Manage roll-over */
		size = last_pos < pos ? pos : last_pos;

		cur = buf = AllocatePool(size);
		if (!buf) {
			ret = EFI_OUT_OF_RESOURCES;
			goto out;
		}

		if (pos < last_pos) {
			memcpy(buf, log_buf + pos, last_pos - pos);
			cur += last_pos - pos;
		}
		memcpy(cur, log_buf, pos);
	} else {
		size = pos;
		buf = log_buf;
	}

	ret = set_efi_variable(&loader_guid, LOG_VAR,
			       size, buf, nonvol, TRUE);
	if (last_pos)
		FreePool(buf);

out:
	running = FALSE;
	return ret;
}

static void log_append_to_buffer(CHAR8 *msg, UINTN length)
{
	if (length > LOG_BUF_SIZE)
		return;

	if (pos + length >= LOG_BUF_SIZE) {
		last_pos = pos;
		pos = 0;
	}

	memcpy(log_buf + pos, msg, length);
	pos += length;
}

static EFI_STATUS serial_init()
{
	EFI_STATUS ret;
	EFI_GUID guid = SERIAL_IO_PROTOCOL;

	ret = LibLocateProtocol(&guid, (void **)&serial);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(serial->SetAttributes, 7, serial,
				SERIAL_BAUD_RATE, SERIAL_FIFO_DEPTH,
				SERIAL_TIMEOUT, SERIAL_PARITY,
				SERIAL_DATA_BITS, SERIAL_STOP_BITS);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_call_wrapper(serial->Reset, 1, serial);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

EFI_STATUS log_open_output_file(EFI_HANDLE handle, const CHAR16 *filename)
{
	EFI_FILE *root;
	EFI_STATUS ret = EFI_SUCCESS;

	root = LibOpenRoot(handle);
	if (!root)
		return EFI_LOAD_ERROR;

#if DEBUG_MESSAGES
	ret = uefi_call_wrapper(root->Open, 5, root, &log_file, (CHAR16 *)filename,
			EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Can't create '%s' logfile",filename);
		return ret;
	}
#endif
	if (!log_file) {
		error(L"Can't create '%s' logfile",filename);
		ret = EFI_NOT_FOUND;
	}

	return ret;
}

void log_to_file(CHAR8 *msg, UINTN *length)
{
	EFI_FILE *file;
	EFI_STATUS ret;

	file = log_file;
	if (!file)
		return;

	if (buf_pos) {
		ret = uefi_call_wrapper(file->Write, 3, file, &buf_pos, data_buf);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Can't write log file with block");
			return;
		}
		buf_pos = 0;
	}
	ret = uefi_call_wrapper(file->Write, 3, file, length, msg);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Can't write log file with a line");
		return;
	}
	uefi_call_wrapper(file->Flush, 1, file);
}

void log_close_output_file(void)
{
	EFI_FILE *file;
	EFI_STATUS ret;

	file = log_file;
	if (!file)
		return;

	ret = uefi_call_wrapper(file->Close, 1, file);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Can't close log file");
	}
}

void vlog(const CHAR16 *fmt, va_list args)
{
	UINTN length;

	if (!serial && EFI_ERROR(serial_init()))
		return;

	length = VSPrint(buf16, sizeof(buf16), (CHAR16 *)fmt, args) + 1;

	if (EFI_ERROR(str_to_stra(buf8, buf16, length)))
		return;

	/* Drop the NUL termination character */
	length--;
	if (EFI_ERROR(uefi_call_wrapper(serial->Write, 3, serial, &length, buf8)))
		return;

	log_append_to_buffer(buf8, length);

#if DEBUG_MESSAGES
	if (!log_file) {
		if (buf_pos + length >= LOG_BUF_SIZE ) {
			length = (LOG_BUF_SIZE ) - buf_pos;
		}
		if (length) {
			memcpy(data_buf + buf_pos, buf8, length);
			buf_pos += length;
		}
	}
#endif
	if (log_file)
		log_to_file(buf8, &length);
}

void log(const CHAR16 *fmt, ...)
{
	va_list args;

	if (!serial && EFI_ERROR(serial_init()))
		return;

	va_start(args, fmt);
	vlog(fmt, args);
	va_end(args);
}
