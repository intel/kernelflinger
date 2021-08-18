/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Matt Wood <matthew.d.wood@intel.com>
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "security.h"
#include "android.h"
#include "lib.h"
#include "vars.h"
#include "life_cycle.h"

/* OsSecureBoot is *not* a standard EFI_GLOBAL variable
 *
 * It's value will be read at ExitBootServices() by the BIOS to run
 * some hooks which will restrain some security features in case of a
 * non os secure boot.
 *
 * It's value is 0 for unsecure, 1 for secure.
 * We say we have an os secure boot when the boot state is green. */
#define OS_SECURE_BOOT_VAR      L"OsSecureBoot"

/* operating system version and security patch level; for
     * version "A.B.C" and patch level "Y-M":
     * os_version = (A * 100 + B) * 100 + C   (7 bits for each of A, B, C)
     * lvl = (year + 2000) * 100 + month      (7 bits for Y, 4 bits for M) */
union android_version {
    UINT32 value;
    struct {
        UINT32 month:4;
        UINT32 year:7;
        UINT32 version_C:7;
        UINT32 version_B:7;
        UINT32 version_A:7;
     } __attribute__((packed)) split;
};

static struct rot_data_t rot_data;

EFI_STATUS raw_pub_key_sha256(IN const UINT8 *pub_key,
            IN UINTN pub_key_len,
            OUT UINT8 **hash_p)
{
        int ret;
        static UINT8 hash[SHA256_DIGEST_LENGTH];

        ret = EVP_Digest(pub_key, pub_key_len, hash, NULL, EVP_sha256(), NULL);
        if (ret == 0) {
            error(L"Failed to hash the RoT bitstream");
            return EFI_INVALID_PARAMETER;
        }
        *hash_p = hash;

        return EFI_SUCCESS;
}

EFI_STATUS set_os_secure_boot(BOOLEAN secure)
{
        EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
        UINT8 value = secure ? 1 : 0;

        debug(L"Setting os secure boot to %d", value);
        return set_efi_variable(&global_guid, OS_SECURE_BOOT_VAR, sizeof(value),
                                &value, FALSE, TRUE);
}

/* Update the struct rot_data for startup_information */
EFI_STATUS update_rot_data(IN VOID *bootimage, IN UINT8 boot_state,
                        IN VBDATA *vb_data)
{
        EFI_STATUS ret = EFI_SUCCESS;
        enum device_state state;
        struct boot_img_hdr *boot_image_header;
        UINT8 *temp_hash;
        union android_version temp_version;

        if (!bootimage)
                return EFI_INVALID_PARAMETER;

        boot_image_header = (struct boot_img_hdr *)bootimage;

        /* Initialize the rot data structure */
        rot_data.version = ROT_DATA_STRUCT_VERSION2;
        state = get_current_state();
        switch (state) {
                case UNLOCKED:
                        rot_data.deviceLocked = 0;
                        break;
                case LOCKED:
                        rot_data.deviceLocked = 1;
                        break;
                default:
                        debug(L"Unknown device state");
                        return EFI_UNSUPPORTED;
        }
        rot_data.verifiedBootState = boot_state;
        temp_version.value = boot_image_header->os_version;
        rot_data.osVersion = (temp_version.split.version_A * 100 + temp_version.split.version_B) * 100 + temp_version.split.version_C;
        rot_data.patchMonthYear = (temp_version.split.year + 2000) * 100 + temp_version.split.month;
        rot_data.keySize = SHA256_DIGEST_LENGTH;

        if (vb_data) {
                ret = rot_pub_key_sha256(vb_data, &temp_hash);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to compute key hash");
                        return ret;
                }
                CopyMem(rot_data.keyHash256, temp_hash, rot_data.keySize);
        } else {
                memset_s(rot_data.keyHash256, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
                barrier();
        }
        return ret;
}

/* initialize the struct rot_data for startup_information */
EFI_STATUS init_rot_data(UINT32 boot_state)
{
    /* Initialize the rot data structure */
    rot_data.version = ROT_DATA_STRUCT_VERSION2;
    rot_data.deviceLocked = 1;
    rot_data.verifiedBootState = boot_state;

    rot_data.osVersion = 0;
    rot_data.patchMonthYear = 0;
    rot_data.keySize = SHA256_DIGEST_LENGTH;

    /* TBD: keyHash should be the key which used to sign vbmeta.ias */
    memset_s(rot_data.keyHash256, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);

    return EFI_SUCCESS;
}

/* Return rot data instance pointer */
struct rot_data_t* get_rot_data()
{
	return &rot_data;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

