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

#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

typedef void (*data_callback_t)(void *buf, unsigned len);
typedef void (*start_callback_t)(void);

typedef struct transport {
	const char *name;
	EFI_STATUS (*start)(start_callback_t start_cb,
			    data_callback_t rx_cb,
			    data_callback_t tx_cb);
	EFI_STATUS (*stop)(void);
	EFI_STATUS (*run)(void);
	EFI_STATUS (*read)(void *buf, UINT32 size);
	EFI_STATUS (*write)(void *buf, UINT32 size);
} transport_t;

EFI_STATUS transport_register(transport_t *trans, UINTN nb);
void transport_unregister(void);

EFI_STATUS transport_start(start_callback_t start_cb,
			   data_callback_t rx_cb,
			   data_callback_t tx_cb);
EFI_STATUS transport_stop(void);
EFI_STATUS transport_run(void);
EFI_STATUS transport_read(void *buf, UINT32 len);
EFI_STATUS transport_write(void *buf, UINT32 len);

#endif	/* _TRANSPORT_H_ */
