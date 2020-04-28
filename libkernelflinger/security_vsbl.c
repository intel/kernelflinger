/*
 * Copyright (c) 2018, Intel Corporation
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
#include "security_interface.h"
#include "rpmb_storage.h"
#include "life_cycle.h"
#include "security.h"

#ifdef RPMB_STORAGE

// Seed Type
#define SEED_ENTRY_TYPE_RPMBSEED		0x2

typedef struct _image_boot_param{
	UINT32 SizeOfThisStruct;
	UINT32 Version;
	UINT64 SeedListInfoAddr;
	UINT64 PlatformInfoAddr;
	UINT64 VmmBootParamAddr;
} image_boot_param_t;

typedef struct _seed_list{
	UINT8       Revision;
	UINT8       Reserved0[3];
	UINT32      BufferSize;       // Will contain the total size allocated for Seed List
	UINT8       TotalSeedCount;   // How many Seed Entries ( useed + dseed + rpmb)
	UINT8       Reserved[3];
} seed_list_t;

// Structure of each Seed Entry. Each Seed Entry is appended after the seed_list_t "Header" structure.
typedef struct _seed_entry {
	UINT8     Type;           // Seed info struct: svn_seed_info or Rpmbseed
	UINT8     Usage;          // If same type, is it used or dseed.
						// For RPMB, // Bit 0 => 0 = RPMB Seed is based on card serial number
						// 1 = RPMB Seed is not based on card serial number. Based on Zero based Serial Number.
	UINT8     Index;          // If Same type and Usage, which seed Idx is this: {0,1,2,3,...}
	UINT8     Reserved;
	UINT16    Flags;          // Reserved for future use
	UINT16    SeedEntrySize;  // Total size: if SVN seed, this is sizeof (SVN_SEED_INFO) + sizeof(SEED_ENTRY)
						// Total size: if RPMB seed, this is RPMB seed size:BOOTLOADER_SEED_LEN + sizeof(SEED_ENTRY)
	UINT8     Seed[0];        // Data of the Seed struct: SVN_SEED_INFO data or RPMB seed data
} seed_entry_t;

EFI_STATUS parse_rpmb_key_from_boot_param(IN VOID * boot_param)
{
	image_boot_param_t *image_boot_param = (image_boot_param_t *)boot_param;
	seed_list_t *SeedListCmdlinePtr = NULL;
	seed_entry_t *SeedEntryData = NULL;
	UINT32 Index, num_rpmb_key = 0;
	UINT8 *RpmbSeedInfo = NULL;
	UINT8 rpmb_key[RPMB_MAX_PARTITION_NUMBER][RPMB_KEY_SIZE];
	EFI_STATUS ret = EFI_SUCCESS;

	if (!image_boot_param)
		return EFI_INVALID_PARAMETER;

	SeedListCmdlinePtr = (seed_list_t *)(UINTN)image_boot_param->SeedListInfoAddr;
	if (!SeedListCmdlinePtr) {
		ret = EFI_INVALID_PARAMETER;
		efi_perror(ret, L"SeedListCmdlinePtr is NULL");
		return ret;
	}

	if ((SeedListCmdlinePtr != NULL) && (SeedListCmdlinePtr->BufferSize > 0)) {
		debug(L"TotalSeedCount: %d", SeedListCmdlinePtr->TotalSeedCount);
		debug(L"BufferSize: %d", SeedListCmdlinePtr->BufferSize);

		SeedEntryData = (seed_entry_t  *)((UINT8 *)SeedListCmdlinePtr + sizeof(seed_list_t));
		if (SeedListCmdlinePtr->TotalSeedCount > 0) {
			for (Index = 0; Index < SeedListCmdlinePtr->TotalSeedCount; Index++) {
				debug(L"SeedEntryData Pointer: 0x%x", (UINT8 *)SeedEntryData);
				if (SeedEntryData->Type == SEED_ENTRY_TYPE_RPMBSEED) {
					debug(L"Type: %x", SeedEntryData->Type);
					debug(L"Usage: %x", SeedEntryData->Usage);
					debug(L"Index: %x", SeedEntryData->Index);
					debug(L"SeedEntrySize: %x", SeedEntryData->SeedEntrySize);
					RpmbSeedInfo = (UINT8 *)SeedEntryData->Seed;
					if (!RpmbSeedInfo) {
						ret = EFI_ABORTED;
						efi_perror(ret, L"RpmbSeedInfo is NULL");
						return ret;
					}
					if (num_rpmb_key < RPMB_MAX_PARTITION_NUMBER) {
						ret = memcpy_s(rpmb_key[num_rpmb_key], sizeof(rpmb_key), RpmbSeedInfo,
									   RPMB_KEY_SIZE);
						if (EFI_ERROR(ret))
							return ret;
						num_rpmb_key++;
					}
					memset(RpmbSeedInfo, 0x0, RPMB_KEY_SIZE);
					barrier();
				}
				debug(L"Increment SeedEntryData Pointer to point to next seed entry");
				SeedEntryData  = (seed_entry_t *)((UINT8 *)SeedEntryData + SeedEntryData->SeedEntrySize);
			}

			if (num_rpmb_key == 0) {
				ret = EFI_NOT_FOUND;
				efi_perror(ret, L"RPMB key not found");
				return ret;
			}
			ret = set_rpmb_derived_key(rpmb_key, sizeof(rpmb_key), num_rpmb_key);
			if (EFI_ERROR(ret))
				efi_perror(ret, L"Failed to generate the rpmb key");
		} else {
			ret = EFI_NOT_FOUND;
		}
	}

	return ret;
}

EFI_STATUS set_device_security_info(IN VOID * vsbl_cmdline_seed_rpmb)
{
	UINT32 *size_structure = NULL;
	EFI_STATUS ret = EFI_SUCCESS;

	if (!vsbl_cmdline_seed_rpmb) {
		efi_perror(ret, L"sbl cmdline for seed/rpmb is NULL");
		return EFI_INVALID_PARAMETER;
	}

	size_structure = (UINT32 *)vsbl_cmdline_seed_rpmb;
	debug(L"size of structure = 0x%0x ", *size_structure);
	if (*size_structure == sizeof (image_boot_param_t))
		ret = parse_rpmb_key_from_boot_param(vsbl_cmdline_seed_rpmb);
	else
		return EFI_ABORTED;

	return ret;
}

#else

EFI_STATUS set_device_security_info(__attribute__((unused)) IN VOID * security_data)
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
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get secure boot var");
		return FALSE;
	}
	value = curdata[0];

	debug(L"Getting platform secure boot to value[%d], size[%d]", value, cursize);

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

	debug(L"Setting platform secure boot to %d", secure);
	return set_efi_variable(&global_guid, SECURE_BOOT_VAR, sizeof(secure),
							&secure, FALSE, FALSE);
}
