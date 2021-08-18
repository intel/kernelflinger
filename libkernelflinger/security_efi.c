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

#define BOOTLOADER_SEED_MAX_ENTRIES  10

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

static EFI_STATUS bls_get_seed_list(BOOTLOADER_SEED_INFO_LIST *blist)
{
	EFI_STATUS ret = EFI_SUCCESS;
	BOOTLOADER_SEED_PROTOCOL *bls;

	bls = get_bls_proto();
	if (bls) {
		ret = uefi_call_wrapper(bls->GetSeedInfoList, 1, blist);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"call GetSeedInfoList fail");
			return ret;
		}

		debug(L"call GetSeedInfoList success");
	}

	return ret;
}

static UINT32 bls_get_max_svn_index(BOOTLOADER_SEED_INFO_LIST *blist)
{
	UINT32 i, max_svn_idx = 0;

#ifdef USERDEBUG
	/* if no seed found, use dummy seed for userdebug build */
	if (blist->NumOfSeeds == 0) {
		debug(L"No seed found, use dummy seed");
		memset_s(blist, sizeof(BOOTLOADER_SEED_INFO_LIST), 0, sizeof(BOOTLOADER_SEED_INFO_LIST));
		return 0;
	}
#endif
	if ((blist->NumOfSeeds == 0) || (blist->NumOfSeeds > BOOTLOADER_SEED_MAX_ENTRIES))
		return -1;

	for (i = 1; i < blist->NumOfSeeds; i++) {
		if (blist->SeedList[i].cse_svn > blist->SeedList[max_svn_idx].cse_svn) {
			max_svn_idx = i;
		}
	}

	return max_svn_idx;
}


static EFI_STATUS bls_get_seed(VOID *seed)
{
	EFI_STATUS ret = EFI_SUCCESS;
	BOOTLOADER_SEED_INFO_LIST blist;
	INT32 max_svn_idx;

	memset_s(&blist, sizeof(BOOTLOADER_SEED_INFO_LIST), 0, sizeof(BOOTLOADER_SEED_INFO_LIST));

	ret = bls_get_seed_list(&blist);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"failed to get bls seed list");
		return ret;
	}

	max_svn_idx = bls_get_max_svn_index(&blist);
	if (max_svn_idx < 0) {
		error(L"get max svn idx error");
		memset_s(&blist, sizeof(BOOTLOADER_SEED_INFO_LIST), 0, sizeof(BOOTLOADER_SEED_INFO_LIST));
		barrier();
		return EFI_NOT_FOUND;
	}

	ret = memcpy_s(seed, SECURITY_EFI_TRUSTY_SEED_LEN,
			(const void *)blist.SeedList[max_svn_idx].seed, SECURITY_EFI_TRUSTY_SEED_LEN);

	return ret;
}

#ifdef USE_TPM
static EFI_STATUS tpm2_get_seed(VOID *seed)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (is_live_boot())
		return EFI_SUCCESS;

	ret = tpm2_read_trusty_seed(seed);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read trusty seed from TPM");
		return ret;
	}
	debug(L"Success read seed from TPM");

	return ret;
}
#endif

EFI_STATUS get_seed(OUT VOID *seed)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (!seed)
		return EFI_INVALID_PARAMETER;

	memset_s(seed, SECURITY_EFI_TRUSTY_SEED_LEN, 0, SECURITY_EFI_TRUSTY_SEED_LEN);

#ifdef USE_TPM
	ret = tpm2_get_seed(seed);
#else
	ret = bls_get_seed(seed);
#endif

	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read trusty seed");
		return ret;
	}

	return ret;
}
