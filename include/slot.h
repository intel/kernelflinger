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

#ifndef _SLOT_H_
#define _SLOT_H_

#include <efi.h>
#include <efiapi.h>

extern const CHAR16 *SLOT_STORAGE_PART;

EFI_STATUS slot_init(void);

/* Get current suffix directly from misc, used in FASTBOOT mode. */
EFI_STATUS slot_init_use_misc(void);

/* Return TRUE if slot management is in used, FALSE otherwise. */
BOOLEAN use_slot(void);

/* Given a partition label BASE, it returns the label of the partition
 * with the active slot suffix if such a partition exist.  If slot AB
 * management is not in used, it returns BASE. NULL is returned in
 * case of error. */
const CHAR16 *slot_label(const CHAR16 *base);

/* Given a partition LABEL, it returns the partition label without the
 * slot suffix (not necessarly the active slot suffix).  If slot
 * management is not in used, it returns the given partition label.
 * NULL is returned in case of error. */
const CHAR16 *slot_base(const CHAR16 *label);

/* Returns the active slot suffix, NULL if none or if slot AB
 * management is not in used. */
const char *slot_get_active(void);

/* Sets the slot, associated to SUFFIX, as active. */
EFI_STATUS slot_set_active(const char *suffix);

/* Sets the active slot cached, associated to SUFFIX, as active.
 * This function maybe used after some other functions changed the
 * active slot stored in storage directly, then call this function
 * to update the active slot in memory cached. */
void slot_set_active_cached(const char *suffix);

/* Returns the number and the array of slot suffixes. */
UINTN slot_get_suffixes(char **suffixes_p[]);

/* Returns "yes" if the slot associated to SUFFIX has successfully
 * booted, "no" otherwise.  NULL is returned if SUFFIX is not a valid
 * slot suffix. */
const char *slot_get_successful(const char *suffix);

/* Returns "yes" if the slot associated to SUFFIX is unbootable, "no"
 * otherwise.  NULL is returned if SUFFIX is not a valid slot
 * suffix. */
const char *slot_get_unbootable(const char *suffix);

/* Returns the number of the retry count remaining of the slot
 * associated to SUFFIX as a string.  NULL is returned if SUFFIX is
 * not a valid slot suffix. */
const char *slot_get_retry_count(const char *suffix);

/* Returns TRUE if the active is corrupted from a dm-verity point of
 * view.  FALSE is returned if slot AB management is not in used or if
 * an error is encountered. */
BOOLEAN slot_get_verity_corrupted(void);

/* Sets the corrupted flag of the active slot to CORRUPTED.
 * EFI_SUCCESS is returned on success or if the corrupted flag has
 * been successfully updated. */
EFI_STATUS slot_set_verity_corrupted(BOOLEAN eio);

/* Parses the current partition scheme.  If slot partitions are found,
 * slot AB management is enabled, slot AB metadata is initialized and
 * stored on disk.  If no slot partition is found, slot AB management
 * is disabled and slot AB metadata is erased from the disk. */
EFI_STATUS slot_reset(void);

/* Stores the slot AB metadata on disk. */
EFI_STATUS slot_restore(void);

/* Given a boot TARGET, decrements the corresponding tries count if
 * necessary. */
EFI_STATUS slot_boot(enum boot_target target);

/* Depending on the boot TARGET, it disables the active slot and
 * select the next valid slot with the highest priority. */
EFI_STATUS slot_boot_failed(enum boot_target target);

/* Returns the number of remaining tries for the Android recovery
 * mode. */
UINT8 slot_recovery_tries_remaining();

/* Disable the slot specified by index */
EFI_STATUS disable_slot_by_index(UINT8 slot_index);

#ifdef USE_SLOT
extern struct AvbABOps ab_ops;
#endif
#endif	/* _SLOT_H_ */
