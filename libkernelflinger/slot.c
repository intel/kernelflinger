/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
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

#include <lib.h>
#include <vars.h>
#include <gpt.h>
#include <android.h>
#include <slot.h>
#include <endian.h>

/* Constants.  */
const CHAR16 *SLOT_STORAGE_PART = MISC_LABEL;
#define MAX_NB_SLOT	ARRAY_SIZE(((struct bootloader_control *)0)->slot_info)
#define MAX_LABEL_LEN	64

static const UINTN MAX_PRIORITY    = 15;
static const UINTN MAX_RETRIES     = 7;
static const char  SUFFIX_FMT[]    = "_%c";
static const char  SLOT_START_CHAR = 'a';
static const UINTN SUFFIX_LEN      = 2;

#define SUFFIX_INDEX(suffix) (suffix[1] - SLOT_START_CHAR)

/* A/B metadata structure. */
typedef struct slot_metadata slot_metadata_t;
typedef struct bootloader_control boot_ctrl_t;

/* Internal. */
static BOOLEAN is_used;
static char _suffixes[MAX_NB_SLOT * sizeof(SUFFIX_FMT)];
static char *suffixes[MAX_NB_SLOT];
static char *cur_suffix;	/* Point to one of the suffixes, or
				   NULL if there is no active slot. */
static boot_ctrl_t boot_ctrl;
static slot_metadata_t *slots = boot_ctrl.slot_info;

static const CHAR16 *label_with_suffix(const CHAR16 *label, const char *suffix)
{
	EFI_STATUS ret;
	static CHAR16 res_label[MAX_LABEL_LEN];
	UINTN label_len, i, j;

	label_len = StrLen(label);

	res_label[0] = '\0';
	if ((label_len + SUFFIX_LEN + 1) * sizeof(CHAR16) > sizeof(res_label)) {
		error(L"Not enough space to build the actual label");
		return res_label;
	}

	ret = memcpy_s(res_label, sizeof(res_label), label, label_len * sizeof(*label));
	if (EFI_ERROR(ret))
		return res_label;

	for (i = label_len, j = 0; j < SUFFIX_LEN; i++, j++)
		res_label[i] = suffix[j];
	res_label[label_len + SUFFIX_LEN] = '\0';

	return res_label;
}

static UINTN get_part_nb_slot(const CHAR16 *label)
{
	EFI_STATUS ret;
	UINTN i;
	const CHAR16 *new_label;
	struct gpt_partition_interface gparti;

	for (i = 0; i < MAX_NB_SLOT; i++) {
		new_label = label_with_suffix(label, suffixes[i]);
		if (!new_label) {
			error(L"Failed to create %s label with suffix", label);
			return 0;
		}

		ret = gpt_get_partition_by_label(new_label, &gparti, LOGICAL_UNIT_USER);
		if (ret == EFI_NOT_FOUND)
			return i;
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to lookup for %s partition");
			return 0;
		}
	}

	return i;
}

static inline EFI_STATUS sync_boot_ctrl(BOOLEAN out)
{
	EFI_STATUS ret;
	struct gpt_partition_interface gparti;
	UINT64 offset;

	ret = gpt_get_partition_by_label(SLOT_STORAGE_PART, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return ret;

	offset = gparti.part.starting_lba * gparti.bio->Media->BlockSize +
		offsetof(struct bootloader_message_ab, slot_suffix);

	return uefi_call_wrapper((out ? gparti.dio->ReadDisk : gparti.dio->WriteDisk),
				 5, gparti.dio,
				 gparti.bio->Media->MediaId,
				 offset, sizeof(boot_ctrl), &boot_ctrl);
}

static EFI_STATUS read_boot_ctrl(void)
{
	return sync_boot_ctrl(TRUE);
}

static EFI_STATUS slot_crc32(UINT32 *crc32)
{
	EFI_STATUS ret;

	ret = uefi_call_wrapper(BS->CalculateCrc32, 3, &boot_ctrl,
				offsetof(struct bootloader_control, crc32_le),
				crc32);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"CalculateCrc32 boot service failed");

	return ret;
}

static EFI_STATUS write_boot_ctrl(void)
{
	EFI_STATUS ret;
	UINT32 crc32;

	if (boot_ctrl.magic == BOOT_CTRL_MAGIC) {
		ret = slot_crc32(&crc32);
		if (EFI_ERROR(ret))
			return ret;
		boot_ctrl.crc32_le = htole32(crc32);
	}

	return sync_boot_ctrl(FALSE);
}

static BOOLEAN is_suffix(const char *suffix)
{
	UINTN i;

	for (i = 0; i < boot_ctrl.nb_slot; i++)
		if (!strncmp((CHAR8 *)suffix, (CHAR8 *)suffixes[i], SUFFIX_LEN + 1))
			return TRUE;

	return FALSE;
}

static slot_metadata_t *get_slot(const char *suffix)
{
	if (!use_slot()) {
		error(L"Slot management is disabled");
		return NULL;
	}

	if (!suffix || !*suffix || !is_suffix(suffix)) {
		error(L"Invalid slot suffix");
		return NULL;
	}

	return &slots[SUFFIX_INDEX(suffix)];
}

static slot_metadata_t *highest_priority_slot(void)
{
	UINTN i, cur;

	for (cur = 0, i = 1; i < boot_ctrl.nb_slot; i++)
		if (slots[i].priority > slots[cur].priority)
			cur = i;

	if (slots[cur].priority == 0)
		return NULL;

	return &slots[cur];
}

static EFI_STATUS disable_slot(slot_metadata_t *slot, BOOLEAN store)
{
	EFI_STATUS ret;

	memset(slot, 0, sizeof(*slot));
	cur_suffix = NULL;

	if (!store)
		return EFI_SUCCESS;

	ret = write_boot_ctrl();
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to disable slot");

	return ret;
}

static EFI_STATUS select_highest_priority_slot(void)
{
	EFI_STATUS ret;
	slot_metadata_t *slot;

	cur_suffix = NULL;
	for (;;) {
		slot = highest_priority_slot();
		if (!slot)
			return EFI_NOT_FOUND;

		if (slot->tries_remaining == 0 &&
		    slot->successful_boot == 0) {
			ret = disable_slot(slot, TRUE);
			if (EFI_ERROR(ret))
				return ret;
		}

		cur_suffix = suffixes[slot - slots];
		break;
	}

	return EFI_SUCCESS;
}

EFI_STATUS slot_init(void)
{
	EFI_STATUS ret;
	UINT32 crc32;
	UINTN i;

	for (i = 0; i < MAX_NB_SLOT; i++) {
		suffixes[i] = _suffixes + i * sizeof(SUFFIX_FMT);
		efi_snprintf((CHAR8 *)suffixes[i], sizeof(suffixes[i]),
			     (CHAR8 *)SUFFIX_FMT, SLOT_START_CHAR + i);
	}

	ret = read_boot_ctrl();
	if (EFI_ERROR(ret)) {
		if (ret == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		efi_perror(ret, L"Failed to read A/B metadata");
		return ret;
	}

	if (!boot_ctrl.magic) {
		debug(L"No A/B metadata");
		return EFI_SUCCESS;
	}

	if (boot_ctrl.magic != BOOT_CTRL_MAGIC) {
		error(L"A/B metadata is corrupted, re-initialize");
		slot_reset();
	}

	ret = slot_crc32(&crc32);
	if (EFI_ERROR(ret))
		return ret;

	if (crc32 != le32toh(boot_ctrl.crc32_le) ||
	    boot_ctrl.nb_slot > MAX_NB_SLOT) {
		error(L"A/B metadata is corrupted, re-initialize");
		slot_reset();
	}

	is_used = TRUE;

	ret = select_highest_priority_slot();
	if (EFI_ERROR(ret))
		debug(L"No slot selected");
	else
		debug(L"Slot '%a' selected", cur_suffix);

	return EFI_SUCCESS;
}

BOOLEAN use_slot(void)
{
	return is_used;
}

const CHAR16 *slot_label(const CHAR16 *base)
{
	EFI_STATUS ret;
	const CHAR16 *label;
	struct gpt_partition_interface gparti;

	if (!use_slot())
		return base;

	if (!base || !cur_suffix)
		return NULL;

	label = label_with_suffix(base, cur_suffix);
	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return base;

	return label;
}

const CHAR16 *slot_base(const CHAR16 *label)
{
	EFI_STATUS ret;
	static CHAR16 res_base[MAX_LABEL_LEN];
	UINTN label_len, base_len;
	char suffix[SUFFIX_LEN + 1];

	if (!use_slot() || !label)
		return label;

	label_len = StrLen(label);
	if (label_len < SUFFIX_LEN)
		return NULL;

	str_to_stra((CHAR8 *)suffix, &label[label_len - SUFFIX_LEN],
		    sizeof(suffix));
	if (!is_suffix(suffix))
		return NULL;

	base_len = label_len - SUFFIX_LEN;
	ret = memcpy_s(res_base, sizeof(res_base), label, base_len * sizeof(CHAR16));
	if (EFI_ERROR(ret))
		return NULL;

	res_base[base_len] = '\0';
	return res_base;
}

const char *slot_get_active(void)
{
	return use_slot() ? cur_suffix : NULL;
}

static void lower_other_slots_priority(slot_metadata_t *except)
{
	UINTN i;

	for (i = 0; i < boot_ctrl.nb_slot; i++)
		if (&slots[i] != except && slots[i].priority) {
			slots[i].priority--;
			if (!slots[i].priority)
				disable_slot(&slots[i], FALSE);
		}
}

EFI_STATUS slot_set_active(const char *suffix)
{
	slot_metadata_t *slot;
	UINTN i;
	const char *suffix_translate[] = {"_a", "_b"};

	if(*suffix == 'a')
		suffix = suffix_translate[0];
	else if (*suffix == 'b')
		suffix = suffix_translate[1];

	slot = get_slot(suffix);
	if (!slot)
		return EFI_NOT_FOUND;

	/* Lower priority of all other slots so they are all less than
	   MAX_PRIORITY in a way that preserves existing order
	   priority. */
	for (i = 0; i < boot_ctrl.nb_slot; i++)
		if (&slots[i] != slot && slots[i].priority == MAX_PRIORITY)
			lower_other_slots_priority(slot);

	slot->priority = MAX_PRIORITY;
	slot->tries_remaining = MAX_RETRIES;
	slot->successful_boot = 0;
	slot->verity_corrupted = 0;

	cur_suffix = suffixes[SUFFIX_INDEX(suffix)];

	return write_boot_ctrl();
}

UINTN slot_get_suffixes(char **suffixes_p[])
{
	if (!use_slot())
		return 0;

	*suffixes_p = suffixes;
	return boot_ctrl.nb_slot;
}

const char *slot_get_successful(const char *suffix)
{
	slot_metadata_t *slot;

	slot = get_slot(suffix);
	if (!slot)
		return NULL;

	return slot->successful_boot ? "yes" : "no";
}

const char *slot_get_unbootable(const char *suffix)
{
	slot_metadata_t *slot;

	slot = get_slot(suffix);
	if (!slot)
		return NULL;

	return slot->priority == 0 ? "yes" : "no";
}

const char *slot_get_retry_count(const char *suffix)
{
	static char res[2];
	slot_metadata_t *slot;
	int len;

	slot = get_slot(suffix);
	if (!slot)
		return NULL;

	len = efi_snprintf((CHAR8 *)res, sizeof(res), (CHAR8 *)"%d",
			   slot->tries_remaining);
	if (len < 0 || len >= (int)sizeof(res))
		return NULL;

	return res;
}

BOOLEAN slot_get_verity_corrupted(void)
{
	slot_metadata_t *slot;

	if (!use_slot())
		return FALSE;

	if (!cur_suffix)
		return FALSE;

	slot = get_slot(cur_suffix);
	if (!slot)
		return FALSE;

	return slot->verity_corrupted == 1 ? TRUE : FALSE;
}

/* Actions */
EFI_STATUS slot_set_verity_corrupted(BOOLEAN corrupted)
{
	slot_metadata_t *slot;
	UINT8 corrupted_val = corrupted ? 1 : 0;

	if (!use_slot())
		return EFI_SUCCESS;

	if (!cur_suffix)
		return EFI_NOT_READY;

	slot = get_slot(cur_suffix);
	if (!slot)
		return EFI_DEVICE_ERROR;

	if (slot->verity_corrupted == corrupted_val)
		return EFI_SUCCESS;

	slot->verity_corrupted = corrupted_val;
	return write_boot_ctrl();
}

EFI_STATUS slot_reset(void)
{
	EFI_STATUS ret;
	UINTN nb_slot;

	cur_suffix = NULL;

	nb_slot = get_part_nb_slot(BOOT_LABEL);
	if (!nb_slot) {
		/* Current partition scheme does not have BOOT
		 * partition with slots. Disable slot management. */
		is_used = FALSE;
		memset(&boot_ctrl, 0, sizeof(boot_ctrl));
		ret = write_boot_ctrl();
		/* If the SLOT_STORAGE_PART does not exist anymore
		   there is no need to clear the slot A/B data from
		   that partition. */
		if (ret == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		return ret;
	}

	if (nb_slot > MAX_NB_SLOT) {
		error(L"Current partition scheme has unexpected number of slots");
		return EFI_UNSUPPORTED;
	}

	memset(&boot_ctrl, 0, sizeof(boot_ctrl));
	boot_ctrl.magic = BOOT_CTRL_MAGIC;
	boot_ctrl.version = BOOT_CTRL_VERSION;
	boot_ctrl.nb_slot = nb_slot;
	is_used = TRUE;

	return write_boot_ctrl();
}

EFI_STATUS slot_restore(void)
{
	return use_slot() ? write_boot_ctrl() : EFI_SUCCESS;
}

EFI_STATUS slot_boot(enum boot_target target)
{
	slot_metadata_t *slot;

	if (!use_slot() || !is_bootimg_target(target))
		return EFI_SUCCESS;

	if (target == RECOVERY && !recovery_in_boot_partition()) {
		if (!boot_ctrl.recovery_tries_remaining)
			return EFI_INVALID_PARAMETER;

		if (!get_slot_fallback())
			return EFI_SUCCESS;

		boot_ctrl.recovery_tries_remaining--;
		return write_boot_ctrl();
	}

	slot = get_slot(cur_suffix);
	if (!slot)
		return EFI_INVALID_PARAMETER;

	if (slot->successful_boot)
		return EFI_SUCCESS;

	if (slot->tries_remaining == 0) {
		error(L"No remaining tries for active slot");
		return EFI_NOT_FOUND;
	}

	if (get_slot_fallback())
		slot->tries_remaining--;
	boot_ctrl.recovery_tries_remaining = MAX_RETRIES;

	return write_boot_ctrl();
}

EFI_STATUS slot_boot_failed(enum boot_target target)
{
	EFI_STATUS ret;
	slot_metadata_t *slot;

	if (!use_slot() || !is_bootimg_target(target))
		return EFI_SUCCESS;

	if (target == RECOVERY && !recovery_in_boot_partition())
		return EFI_SUCCESS;

	slot = get_slot(cur_suffix);
	if (!slot) {
		error(L"No active slot");
		return EFI_NOT_FOUND;
	}

	ret = disable_slot(slot, TRUE);
	if (EFI_ERROR(ret))
		return ret;

	select_highest_priority_slot();

	return EFI_SUCCESS;
}

UINT8 slot_recovery_tries_remaining()
{
	if (!use_slot())
		return 0;

	return boot_ctrl.recovery_tries_remaining;
}

void slot_set_active_cached(const char *suffix)
{
	if (suffixes == NULL || SUFFIX_INDEX(suffix) < 0 || SUFFIX_INDEX(suffix) >= (int)(sizeof(suffixes) / sizeof(suffixes[0])))
		cur_suffix = NULL;
	else
		cur_suffix = suffixes[SUFFIX_INDEX(suffix)];
	return;
}

EFI_STATUS slot_init_use_misc(void)
{
	/* Slot_init() has initialize the current suffix. */
	return EFI_SUCCESS;
}

EFI_STATUS disable_slot_by_index(UINT8 slot_index)
{
	if (slot_index >= MAX_NB_SLOT) {
		error(L"Invalid slot id %d", (int)slot_index);
		return EFI_INVALID_PARAMETER;
	}
	return disable_slot(&slots[slot_index], TRUE);
}
