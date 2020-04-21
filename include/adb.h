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

#ifndef _ADB_H_
#define _ADB_H_

#include <efi.h>
#include <efilib.h>

#define MKID(a,b,c,d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

/* ADB protocol types */
#define A_SYNC MKID('S','Y','N','C')
#define A_CNXN MKID('C','N','X','N')
#define A_OPEN MKID('O','P','E','N')
#define A_OKAY MKID('O','K','A','Y')
#define A_CLSE MKID('C','L','S','E')
#define A_WRTE MKID('W','R','T','E')
#define A_AUTH MKID('A','U','T','H')

typedef struct adb_msg {
	UINT32 command;		/* command identifier constant      */
	UINT32 arg0;		/* first argument                   */
	UINT32 arg1;		/* second argument                  */
	UINT32 data_length;	/* length of payload (0 is allowed) */
	UINT32 data_check;	/* checksum of data payload         */
	UINT32 magic;		/* command ^ 0xffffffff             */
} adb_msg_t;

#define ADB_MIN_PAYLOAD 4096
#define ADB_MAX_PAYLOAD 262144

/* Negociated (CONNECT hand-shake) maximum buffer size */
extern UINT32 adb_max_payload;

typedef struct adb_pkt {
	adb_msg_t msg;
	unsigned char *data;
} adb_pkt_t;

EFI_STATUS adb_init();
EFI_STATUS adb_run();
EFI_STATUS adb_exit();
enum boot_target adb_get_boot_target(void);
void adb_set_boot_target(enum boot_target bt);

EFI_STATUS adb_send_pkt(adb_pkt_t *pkt, UINT32 command, UINT32 arg0, UINT32 arg1);

#endif	/* _ADB_H_ */
