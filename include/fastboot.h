/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
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

#ifndef _FASTBOOT_H_
#define _FASTBOOT_H_

#include <efidef.h>
#include <lib.h>
#include <vars.h>

#define MAGIC_LENGTH 64

/* GUID for variables used to communicate with Fastboot */
extern const EFI_GUID fastboot_guid;

typedef void (*fastboot_handle) (INTN argc, CHAR8 **argv);

struct fastboot_cmd {
	const char *name;
	enum device_state min_state;
	fastboot_handle handle;
};

typedef struct cmdlist *cmdlist_t;

struct download_buffer {
	void *data;
	UINTN size;
	UINTN max_size;
};

struct download_buffer *fastboot_download_buffer(void);

struct fastboot_cmd *fastboot_get_root_cmd(const char *name);
EFI_STATUS fastboot_register(struct fastboot_cmd *cmd);
EFI_STATUS fastboot_register_into(cmdlist_t *list, struct fastboot_cmd *cmd);
void fastboot_cmdlist_unregister(cmdlist_t *list);
void fastboot_run_cmd(cmdlist_t list, const char *name, INTN argc, CHAR8 **argv);
void fastboot_run_root_cmd(const char *name, INTN argc, CHAR8 **argv);

EFI_STATUS fastboot_publish(const char *name, const char *value);
void fastboot_okay(const char *fmt, ...);
void fastboot_fail(const char *fmt, ...);
void fastboot_info(const char *fmt, ...);
EFI_STATUS fastboot_info_long_string(char *str, void *context);

EFI_STATUS fastboot_set_command_buffer(char *buffer, UINTN size);
EFI_STATUS fastboot_start(void **bootimage, void **efiimage,
			  UINTN *imagesize, enum boot_target *target);
EFI_STATUS fastboot_stop(void *bootimage, void *efiimage, UINTN imagesize,
			 enum boot_target target);
void fastboot_free(void);
EFI_STATUS refresh_partition_var(void);

void fastboot_reboot(enum boot_target target, CHAR16 *msg);

#endif	/* _FASTBOOT_H_ */
