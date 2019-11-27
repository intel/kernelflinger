/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
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
#include <efiapi.h>
#include <efilib.h>

#include "vars.h"
#include "lib.h"
#include "security.h"
#include "android.h"
#include "options.h"
#include "power.h"
#include "trusty_common.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"

EFI_STATUS load_tos_image(OUT VOID **bootimage)
{
        EFI_STATUS ret;
        UINT8 verify_state = BOOT_STATE_GREEN;
        UINT8 verify_state_new;
        AvbSlotVerifyData *slot_data;
        BOOLEAN b_secureboot = is_platform_secure_boot_enabled();

        if (!b_secureboot)
                verify_state = BOOT_STATE_YELLOW;
#ifndef USER
        if (device_is_unlocked())
                verify_state = BOOT_STATE_ORANGE;
#endif

        verify_state_new = verify_state;

        ret = android_image_load_partition_avb("tos", bootimage, &verify_state_new, &slot_data);  // Do not try to switch slot if failed
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"TOS image loading failed");
                return ret;
        }

        if (verify_state != verify_state_new) {
#ifndef USERDEBUG
                error(L"Invalid TOS image. Boot anyway on ENG build");
                ret = EFI_SUCCESS;
#else
                if (b_secureboot) {
                        error(L"TOS image doesn't verify, stop since secure boot enabled");
                        ret = EFI_SECURITY_VIOLATION;
                } else {
                        error(L"TOS image doesn't verify, continue since secure boot disabled");
                        ret = EFI_SUCCESS;
                }
#endif
        }

        return ret;
}
