/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#ifndef _UX_H_
#define _UX_H_

#include <efi.h>
#include <efilib.h>

#include "targets.h"

enum ux_error_code {
        MIN_ERROR_CODE = 0,
        NO_ERROR_CODE = 0,
        RED_STATE_CODE,
        BAD_RECOVERY_CODE,
        DEVICE_UNLOCKED_CODE,
        SECURE_BOOT_CODE,
        BOOTIMAGE_UNTRUSTED_CODE,
        CRASH_EVENT_CODE,
        NOT_BOOTABLE_CODE,
        LIVE_BOOT_CODE,
        MAX_ERROR_CODE
};

/* Prompt the user with the appropriate message accordingly to the
 * error_code.  Depending on the POWER_OFF the user will be informed
 * that device will power-off or continue to boot.  Optionally, the
 * supplied GVB hash will be included.  It returns either NORMAL_BOOT
 * either POWER_OFF depending on the user choice.  */
enum boot_target ux_prompt_user(enum ux_error_code error_code,
				BOOLEAN power_off, UINT8 boot_state,
				UINT8 *hash, UINTN hash_size);

/* Prompt the user with the appropriate message accordingly to the
 * error_code and let him choose the next boot target.  If the build
 * is a USERDEBUG or ENG variant, it offers a minimal adb
 * implementation to dump data from memory and partition.  In that
 * case, the boot_target can also be provided using the adb reboot
 * [TARGET].  */
enum boot_target ux_prompt_user_for_boot_target(enum ux_error_code code);

/* Display a low_battery image during DELAY seconds and exit.  */
VOID ux_display_low_battery(UINTN delay);
VOID ux_display_empty_battery(VOID);

VOID ux_display_vendor_splash(VOID);

#endif
