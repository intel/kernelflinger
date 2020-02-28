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

#include "security_interface.h"
#include "lib.h"
#include "security.h"
#include "storage.h"
#include "security_efi.h"
#include "protocol/BootloaderSeedProtocol.h"
#ifdef USE_TPM
#include "tpm2_security.h"
#endif

#ifdef RPMB_STORAGE
#include "rpmb_storage.h"

static UINT8 fixed_rpmb_keys[][RPMB_KEY_SIZE] = {
#ifdef FIXED_RPMB_KEY
		FIXED_RPMB_KEY
#else
		"\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31",
		"12345ABCDEF1234512345ABCDEF12345"
#endif
};

#define BLS_MAX_RPMB_KEY 6
static BOOTLOADER_RPMB_KEY bls_rpmb_key[BLS_MAX_RPMB_KEY];
#endif

static EFI_GUID bls_guid = BOOTLOADER_SEED_PROTOCOL_GUID;
static BOOTLOADER_SEED_PROTOCOL *bls_proto = NULL;

static BOOTLOADER_SEED_PROTOCOL *get_bls_proto(void)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (!bls_proto)
		ret = LibLocateProtocol(&bls_guid, (void **)&bls_proto);

	if (EFI_ERROR(ret) || !bls_proto)
		debug(L"Failed to locate bootloader seed protocol");

	return bls_proto;
}

EFI_STATUS stop_bls_proto(void)
{
	BOOTLOADER_SEED_PROTOCOL *bls;
	EFI_STATUS ret = EFI_SUCCESS;

	bls = get_bls_proto();
	if (!bls)
		return ret;

	ret = uefi_call_wrapper(bls->EndOfService, 0);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"call EndOfService of bootloader seed protocol fail");
		return ret;
	}

	debug(L"call EndOfService of bootloader seed protocol success");
	return ret;
}

/* Now the input security_data should be NULL. */
EFI_STATUS set_device_security_info(__attribute__((unused)) IN void *security_data)
{
	EFI_STATUS ret = EFI_SUCCESS;

#ifdef RPMB_STORAGE
	BOOTLOADER_SEED_PROTOCOL *bls;
	UINT8 key_count = BLS_MAX_RPMB_KEY;
	UINT8 rpmb_keys[BLS_MAX_RPMB_KEY][RPMB_KEY_SIZE];
	UINT8 i;

	// Set the fixed RPMB key
	if (is_live_boot()) {
		// For USB live boot case, always use one fixed RPMB key.
		return set_rpmb_derived_key(fixed_rpmb_keys, RPMB_KEY_SIZE, 1);
	}

	bls = get_bls_proto();
	if (bls) {
		ret = uefi_call_wrapper(bls->GetRpmbKey, 2, &key_count, bls_rpmb_key);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"call GetRpmbKey of bootloader seed protocol fail");
			ret = set_rpmb_derived_key(fixed_rpmb_keys,
				sizeof(fixed_rpmb_keys), ARRAY_SIZE(fixed_rpmb_keys));
			return ret;
		}

		debug(L"call GetRpmbKey of bootloader seed protocol success");

		for(i = 0; i < key_count; i++)
			memcpy(rpmb_keys[i], bls_rpmb_key[i].rpmb_key, RPMB_KEY_SIZE);

		ret = set_rpmb_derived_key(rpmb_keys, key_count * RPMB_KEY_SIZE, key_count);
		return ret;
	}

	// Try to several possible fixed RPMB keys
	ret = set_rpmb_derived_key(fixed_rpmb_keys, sizeof(fixed_rpmb_keys), ARRAY_SIZE(fixed_rpmb_keys));
#endif

	return ret;
}

EFI_STATUS set_platform_secure_boot(__attribute__((unused)) IN UINT8 secure)
{
	return EFI_UNSUPPORTED;
}

/* UEFI specification 2.4. Section 3.3
 * The platform firmware is operating in secure boot mode if the value
 * of the SetupMode variable is 0 and the SecureBoot variable is set
 * to 1. A platform cannot operate in secure boot mode if the
 * SetupMode variable is set to 1. The SecureBoot variable should be
 * treated as read- only.
 */
BOOLEAN is_platform_secure_boot_enabled(VOID)
{
	EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
	EFI_STATUS ret;
	UINT8 value;

	ret = get_efi_variable_byte(&global_guid, SETUP_MODE_VAR, &value);
	if (EFI_ERROR(ret))
		return FALSE;

	if (value != 0)
		return FALSE;

	ret = get_efi_variable_byte(&global_guid, SECURE_BOOT_VAR, &value);
	if (EFI_ERROR(ret))
		return FALSE;

	return value == 1;
}

BOOLEAN is_eom_and_secureboot_enabled(VOID)
{
	BOOLEAN sbflags;
	BOOLEAN enduser = TRUE;

	sbflags = is_platform_secure_boot_enabled();

	return sbflags && enduser;
}

/* initially hardcoded all seeds as 0, and svn is expected as descending order */
EFI_STATUS get_seeds(IN UINT32 *num_seeds, OUT VOID *seed_list)
{
	EFI_STATUS ret = EFI_SUCCESS;
	seed_info_t *tmp;
	UINT32 i;
#ifdef USE_TPM
	UINT8 seed[TRUSTY_SEED_SIZE];
#endif
	BOOTLOADER_SEED_PROTOCOL *bls;
	BOOTLOADER_SEED_INFO_LIST blist;

	for (i = 0; i < BOOTLOADER_SEED_MAX_ENTRIES; i++) {
		tmp = (seed_info_t *)(seed_list + i * sizeof(seed_info_t));
		tmp->svn = BOOTLOADER_SEED_MAX_ENTRIES - i - 1;
		memset(tmp->seed, 0, SECURITY_EFI_TRUSTY_SEED_LEN);
	}
	*num_seeds = BOOTLOADER_SEED_MAX_ENTRIES;

	bls = get_bls_proto();
	if (bls) {
		ret = uefi_call_wrapper(bls->GetSeedInfoList, 1, &blist);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"call GetSeedInfoList fail");
			return ret;
		}

		debug(L"call GetSeedInfoList success");
		*num_seeds = blist.NumOfSeeds;
		memcpy(seed_list, blist.SeedList, sizeof(blist.SeedList));
		memset(&blist, 0, sizeof(blist));
		barrier();
		return ret;
	}

#ifdef USE_TPM
	if (is_live_boot() || !is_platform_secure_boot_enabled())
		return EFI_SUCCESS;

	ret = tpm2_read_trusty_seed(seed);
	if (EFI_ERROR(ret)) {
		if (ret == EFI_NOT_FOUND)
			return EFI_SUCCESS;

		efi_perror(ret, L"Failed to read trusty seed from TPM");
		return ret;
	}

	debug(L"Success read seed from TPM");
	*num_seeds = 1;
	tmp = (seed_info_t *)seed_list;
	tmp->svn = BOOTLOADER_SEED_MAX_ENTRIES - 1;
	memcpy(tmp->seed, seed, TRUSTY_SEED_SIZE);
	memset(seed, 0, sizeof(seed));
	barrier();
#endif

	return EFI_SUCCESS;
}

EFI_STATUS get_attkb_key(OUT VOID * key)
{
	EFI_STATUS ret = EFI_SUCCESS;
	BOOTLOADER_SEED_PROTOCOL *bls;

	bls = get_bls_proto();
	if (bls) {
		ret = uefi_call_wrapper(bls->GetAttKBEncKey, 1, key);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Get attkb key failed");
			return ret;
		}
	}
	return ret;
}
