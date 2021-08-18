/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <lib.h>
#include <vars.h>
#include <efi.h>
#include <efilib.h>
#include <gpt.h>
#include <log.h>

#define MAX_KEYBOX_SIZE    16384
#define KB_HEAD_OFFSET     0

typedef struct keybox_header {
	uint8_t magic[12];
	uint32_t size;
	uint8_t keybox[0];
} keybox_header_t;

EFI_STATUS flash_keybox(VOID *data, UINTN size)
{
	EFI_STATUS ret = EFI_SUCCESS;
	uint64_t partoffset;
	struct gpt_partition_interface gpart;
	keybox_header_t kb_header =
		{
			.magic = "MAGICKEYBOX",
			.size = size,
		};

	if (!data) {
		error(L"keybox data is NULL!");
		return EFI_INVALID_PARAMETER;
	}

	if (size > MAX_KEYBOX_SIZE) {
		error(L"keybox size exceeded limit");
		return EFI_INVALID_PARAMETER;
	}

	ret = gpt_get_partition_by_label(L"teedata", &gpart, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition teedata not found");
		goto exit;
	}

	partoffset = gpart.part.starting_lba * gpart.bio->Media->BlockSize;

	ret = uefi_call_wrapper(
				gpart.dio->WriteDisk,
				5,
				gpart.dio,
				gpart.bio->Media->MediaId,
				partoffset + KB_HEAD_OFFSET,
				sizeof(keybox_header_t),
				(void *)&kb_header);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Could not write keybox header to disk.");
		goto exit;
	}

	ret = uefi_call_wrapper(
				gpart.dio->WriteDisk,
				5,
				gpart.dio,
				gpart.bio->Media->MediaId,
				sizeof(keybox_header_t) + partoffset + KB_HEAD_OFFSET,
				size,
				data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Could not write keybox to disk.");
		goto exit;
	}

exit:
	memset_s(data, size, 0, size);
	barrier();
	return ret;
}
