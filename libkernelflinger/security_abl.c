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
#include <lib.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include "security_interface.h"
#include "rpmb_storage.h"
#include "life_cycle.h"
#include "security.h"

#ifdef RPMB_STORAGE
#define SECURITY_ABL_SEED_LEN 32
#define SECURITY_ABL_SEED_MAX_ENTRIES 4

 /* structure of seed info */
 typedef struct _seed_info {
	 uint8_t svn;
	 uint8_t padding[3];
	 uint8_t seed[SECURITY_ABL_SEED_LEN];
 } __attribute__((packed)) seed_info_t;

 typedef struct device_sec_info{
	 uint32_t size_of_this_struct;
	 /* version info
		 0: baseline structure
		 1: add xx new field
	 */
	/* version of the struct. 0x0001 for this version */
	uint32_t 			Version;
	uint32_t			num_seeds;
	seed_info_t 		seed_list[SECURITY_ABL_SEED_MAX_ENTRIES];
 } __attribute__((packed)) device_sec_info_t;

EFI_STATUS derive_rpmb_key_with_seed(IN VOID *seed, OUT VOID *rpmb_key)
{
        EFI_STATUS ret;
        UINT8 serial[MMC_PROD_NAME_WITH_PSN_LEN] = {0};
        char *serialno;
        /* HWCRYPTO Server App UUID */
        const EFI_GUID  crypo_uuid = { 0x23fe5938, 0xccd5, 0x4a78,
                { 0x8b, 0xaf, 0x0f, 0x3d, 0x05, 0xff, 0xc2, 0xdf } };

        if (!seed || !rpmb_key)
                return EFI_INVALID_PARAMETER;

        serialno = get_serial_number();

        if (!serialno)
                return EFI_NOT_FOUND;

        /* Clear Byte 2 and 0 for CID[6] PRV and CID[0] CRC for eMMC Field Firmware Updates
        * serial[0] = cid[0];    -- CRC
        * serial[2] = cid[6];    -- PRV
        */
        ret = memcpy_s(serial, sizeof(serial), serialno, sizeof(serial));
        if (EFI_ERROR(ret))
            return ret;

        serial[0] ^= serial[0];
        serial[2] ^= serial[2];

        if (!HKDF(rpmb_key, RPMB_KEY_SIZE, EVP_sha256(),
                (const uint8_t *)seed, RPMB_SEED_SIZE,
                (const uint8_t *)&crypo_uuid, sizeof(EFI_GUID),
                (const uint8_t *)serial, sizeof(serial))) {
                error(L"HDKF failed \n");
                return EFI_INVALID_PARAMETER;
        }

        return EFI_SUCCESS;
}

 EFI_STATUS set_device_security_info(IN VOID *security_data)
 {
 	EFI_STATUS ret;
	device_sec_info_t *dev_sec;
	UINT8 rpmb_key[SECURITY_ABL_SEED_MAX_ENTRIES * RPMB_KEY_SIZE];
	UINT8 i;
	uint32_t seed_cnt;

	if (!security_data)
		return EFI_INVALID_PARAMETER;

	dev_sec = (device_sec_info_t *)security_data;
	if (dev_sec->size_of_this_struct != sizeof(device_sec_info_t))
		return EFI_INVALID_PARAMETER;

	seed_cnt = min(dev_sec->num_seeds, SECURITY_ABL_SEED_MAX_ENTRIES);
	for (i = 0; i < seed_cnt; i++)
	{
		if (EFI_SUCCESS != derive_rpmb_key_with_seed(dev_sec->seed_list[i].seed, rpmb_key + i * RPMB_KEY_SIZE))
		{
			memset_s(rpmb_key + i * RPMB_KEY_SIZE, RPMB_KEY_SIZE, 0, RPMB_KEY_SIZE);
			break;
		}
		memset_s(dev_sec->seed_list[i].seed, SECURITY_ABL_SEED_LEN, 0, SECURITY_ABL_SEED_LEN);
	}

	if (i > 0)
		ret = set_rpmb_derived_key(rpmb_key, sizeof(rpmb_key), i);
	else
		ret = EFI_NOT_FOUND;

	if (EFI_ERROR(ret))
	{
		efi_perror(ret, L"Failed to generate the rpmb key");
	}

	return ret;
 }
#else

EFI_STATUS set_device_security_info(__attribute__((unused)) IN VOID *security_data)
{
	return EFI_UNSUPPORTED;
}
#endif

BOOLEAN is_platform_secure_boot_enabled(VOID)
{
        EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
        EFI_STATUS ret;
        UINT8 value;
        UINTN cursize;
        UINT8 *curdata;

        ret = get_efi_variable(&global_guid, SECURE_BOOT_VAR, &cursize, (VOID **)&curdata, NULL);
        if (EFI_ERROR(ret))
        {
                efi_perror(ret, L"Failed to get secure boot var");
                return FALSE;
        }
        value = curdata[0];

        debug(L"Getting abl secure boot to value[%d], size[%d]", value, cursize);

        return value == 1;
}

BOOLEAN is_eom_and_secureboot_enabled(VOID)
{
        BOOLEAN sbflags;
        EFI_STATUS ret;
        BOOLEAN enduser;

        ret = life_cycle_is_enduser(&enduser);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Failed to get eom var");
                return FALSE;
        }

        sbflags = is_platform_secure_boot_enabled();

        return sbflags && enduser;
}

EFI_STATUS set_platform_secure_boot(UINT8 secure)
{
        EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

        debug(L"Setting abl secure boot to %d", secure);
        return set_efi_variable(&global_guid, SECURE_BOOT_VAR, sizeof(secure),
                                &secure, FALSE, FALSE);
}
