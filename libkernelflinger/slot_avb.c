/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
 *         Li Biyi <biyix.li@intel.com>
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
#include <libavb_ab.h>
#include <libavb_user/uefi_avb_ops.h>

/* Constants.  */
const CHAR16 *SLOT_STORAGE_PART = MISC_LABEL;
#define MAX_NB_SLOT	ARRAY_SIZE(((struct AvbABData *)0)->slots)
#define MAX_LABEL_LEN	64

static const UINTN MAX_PRIORITY    = 15;
static const UINTN MAX_RETRIES     = 7;
static const char  SUFFIX_FMT[]    = "_%c";
static const char  SLOT_START_CHAR = 'a';
static const UINTN SUFFIX_LEN      = 2;

#define SUFFIX_INDEX(suffix) (suffix[1] - SLOT_START_CHAR)

/* A/B metadata structure. */
typedef struct AvbABSlotData slot_metadata_t;
typedef struct AvbABData boot_ctrl_t;

/* Internal. */
static BOOLEAN is_used;
static char _suffixes[MAX_NB_SLOT * sizeof(SUFFIX_FMT)];
static char *suffixes[MAX_NB_SLOT];
static char *cur_suffix;
/* Point to one of the suffixes, or NULL if there is no active slot. */

struct AvbABOps ab_ops;
static AvbOps *ops;
static boot_ctrl_t boot_ctrl;
static AvbABSlotData *slots = boot_ctrl.slots;

static const CHAR16 *label_with_suffix(const CHAR16 *label, const char *suffix)
{
	static CHAR16 res_label[MAX_LABEL_LEN] = {'\0'};
	UINTN label_len, i, j;

	label_len = StrLen(label);

	res_label[0] = '\0';
	if ((label_len + SUFFIX_LEN + 1) * sizeof(CHAR16) > sizeof(res_label)) {
		error(L"Not enough space to build the actual label");
		return res_label;
	}

	memcpy(res_label, label, label_len * sizeof(*label));
	for (i = label_len, j = 0; j < SUFFIX_LEN; i++, j++)
		res_label[i] = suffix[j];
	res_label[label_len + SUFFIX_LEN] = '\0';
	return res_label;
}

UINTN get_part_nb_slot(const CHAR16 *label)
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
	if (out)
		avb_ab_data_read(&ab_ops, &boot_ctrl);
	else
		avb_ab_data_write(&ab_ops, &boot_ctrl);

	return EFI_SUCCESS;
}

static EFI_STATUS read_boot_ctrl(void)
{
	return sync_boot_ctrl(TRUE);
}

static EFI_STATUS write_boot_ctrl(void)
{
	return sync_boot_ctrl(FALSE);
}

static BOOLEAN is_suffix(const char *suffix)
{
	UINTN i;

	for (i = 0; i < MAX_NB_SLOT; i++)
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

	read_boot_ctrl();
	return &slots[SUFFIX_INDEX(suffix)];
}

static slot_metadata_t *highest_priority_slot(void)
{
	UINTN i, cur;

	for (cur = 0, i = 1; i < MAX_NB_SLOT; i++)
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
	CHAR8 *magic;
	UINTN i;
	UINTN nb_slot;

	ab_ops.read_ab_metadata = avb_ab_data_read;
	ab_ops.write_ab_metadata = avb_ab_data_write;

	ops = uefi_avb_ops_new();
	if (ops == NULL)
		error(L"Error allocating AvbOps when slot_init.");

	ab_ops.ops = ops;

	for (i = 0; i < MAX_NB_SLOT; i++) {
		suffixes[i] = _suffixes + i * sizeof(SUFFIX_FMT);
		efi_snprintf((CHAR8 *)suffixes[i], sizeof(suffixes[i]),
			     (CHAR8 *)SUFFIX_FMT, SLOT_START_CHAR + i);
	}

	nb_slot = get_part_nb_slot(BOOT_LABEL);
	if (!nb_slot) {
		/* Current partition scheme does not have BOOT
		 * partition with slots. Disable slot management. */
		is_used = FALSE;
		return EFI_SUCCESS;
	}

	cur_suffix = NULL;
	avb_ab_data_init(&boot_ctrl);

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
	debug(L"Avb magic 0x%x, 0x%x, 0x%x, 0x%x", boot_ctrl.magic[0], boot_ctrl.magic[1], boot_ctrl.magic[2], boot_ctrl.magic[3]);

	magic = (CHAR8 *)AVB_AB_MAGIC;
	if ((boot_ctrl.magic[0] == magic[0]) && \
		(boot_ctrl.magic[1] == magic[1]) && \
		(boot_ctrl.magic[2] == magic[2]) && \
		(boot_ctrl.magic[3] == magic[3])) {
		debug(L"Avb magic is right");
	} else {
		error(L"A/B metadata is corrupted, re-initialize");
		slot_reset();
	}

	is_used = TRUE;
	return EFI_SUCCESS;
}

BOOLEAN use_slot(void)
{
	return is_used;
}

const CHAR16 *slot_label(const CHAR16 *base)
{
	const CHAR16 *label;
	UINTN nb_slot;

	if (!use_slot())
		return base;

	if (!base)
		return NULL;

	nb_slot = get_part_nb_slot(base);
	if (!nb_slot) {
		/*
		 * Current partition scheme does not have slots.
		 */
		return base;
	}

	if (!base || !slot_get_active())
		return NULL;

	label = label_with_suffix(base, slot_get_active());

	return label;
}

const CHAR16 *slot_base(const CHAR16 *label)
{
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
	memcpy(res_base, label, base_len * sizeof(CHAR16));
	res_base[base_len] = '\0';

	return res_base;
}

const char *slot_get_active(void)
{
	AvbSlotVerifyData *data;
	const char *requested_partitions[] = {"boot", NULL};

	if (!use_slot())
		return NULL;

	if (cur_suffix) {
		debug(L"slot_get_active direct return %a", cur_suffix);
		return cur_suffix;
	}
	avb_ab_flow(&ab_ops, requested_partitions, AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,\
			AVB_HASHTREE_ERROR_MODE_RESTART, &data);
	if (!data)
		return NULL;

	slot_set_active_cached(data->ab_suffix);
	debug(L"slot_get_active from misc return %a", cur_suffix);
	avb_slot_verify_data_free(data);

	return cur_suffix;
}

EFI_STATUS slot_set_active(const char *suffix)
{
	slot_metadata_t *slot;
	const char *suffix_translate[] = {"_a", "_b"};

	if(*suffix == 'a')
		suffix = suffix_translate[0];
	else if (*suffix == 'b')
		suffix = suffix_translate[1];

	slot = get_slot(suffix);
	if (!slot)
		return EFI_NOT_FOUND;

	/*
	 * Lower priority of all other slots so they are all less than
	 * MAX_PRIORITY in a way that preserves existing order
	 * priority.
	 */

	avb_ab_mark_slot_active(&ab_ops, SUFFIX_INDEX(suffix));
	slot_set_active_cached(suffix);
	return EFI_SUCCESS;
}

UINTN slot_get_suffixes(char **suffixes_p[])
{
	if (!use_slot())
		return 0;

	*suffixes_p = suffixes;
	return MAX_NB_SLOT;
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
	if (!use_slot())
		return FALSE;

	return TRUE;
}

EFI_STATUS slot_set_verity_corrupted(BOOLEAN corrupted)
{
	corrupted = !corrupted;
	return EFI_SUCCESS;
}

EFI_STATUS slot_reset(void)
{
	UINTN nb_slot;
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	cur_suffix = NULL;

	ab_ops.read_ab_metadata = avb_ab_data_read;
	ab_ops.write_ab_metadata = avb_ab_data_write;

	/*
	 * Init avb for fastboot mode, and update misc with default value.
	 */
	if (ops == NULL) {
		ops = uefi_avb_ops_new();
		if (ops == NULL)
			error(L"Error allocating AvbOps when slot_reset.");
	}
	ab_ops.ops = ops;

	nb_slot = get_part_nb_slot(BOOT_LABEL);
	if (!nb_slot) {
		/*
		 * Current partition scheme does not have BOOT
		 * partition with slots. Disable slot management.
		 */
		is_used = FALSE;
		return EFI_SUCCESS;
	}

	if (nb_slot > MAX_NB_SLOT) {
		error(L"Current partition scheme has unexpected number of slots");
		return EFI_UNSUPPORTED;
	}

	ret = gpt_get_partition_by_label(MISC_LABEL, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		error(L"Failed to lookup for MISC partition");
		is_used = FALSE;
		return EFI_SUCCESS;
	}

	is_used = TRUE;

	avb_ab_data_init(&boot_ctrl);
	return write_boot_ctrl();
}

EFI_STATUS slot_restore(void)
{
	return use_slot() ? write_boot_ctrl() : EFI_SUCCESS;
}

EFI_STATUS slot_boot(__attribute__((__unused__)) enum boot_target target)
{
	/*
	 * Just set misc info by avb.
	 */
	return EFI_SUCCESS;
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
	EFI_STATUS ret;
	CHAR8 *magic;

	if (!use_slot())
		return EFI_SUCCESS;

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
	debug(L"Avb magic 0x%x, 0x%x, 0x%x, 0x%x", boot_ctrl.magic[0], boot_ctrl.magic[1], boot_ctrl.magic[2], boot_ctrl.magic[3]);

	magic = (CHAR8 *)AVB_AB_MAGIC;
	if ((boot_ctrl.magic[0] == magic[0]) && \
		(boot_ctrl.magic[1] == magic[1]) && \
		(boot_ctrl.magic[2] == magic[2]) && \
		(boot_ctrl.magic[3] == magic[3])) {
		debug(L"Avb magic is right");
	}

	select_highest_priority_slot();
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
