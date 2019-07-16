/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
 *          Andrew Boie <andrew.p.boie@intel.com>
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
#include "fastboot.h"
#include "flash.h"
#include "fastboot_ui.h"
#include "gpt.h"
#include "intel_variables.h"
#include "android.h"

static cmdlist_t cmdlist;

EFI_STATUS fastboot_flashing_publish(void)
{
#ifdef FASTBOOT_FOR_NON_ANDROID
	return EFI_SUCCESS;
#endif
	EFI_STATUS ret;

	ret = fastboot_publish("secure", device_is_locked() ? "yes" : "no");
	if (EFI_ERROR(ret))
		return ret;

	ret = fastboot_publish("unlocked", device_is_unlocked() ? "yes" : "no");
	if (EFI_ERROR(ret))
		return ret;

	return publish_intel_variables();
}

EFI_STATUS change_device_state(enum device_state new_state, BOOLEAN interactive)
{
	EFI_STATUS ret;

	/* "Eng" builds skip all these security policies */
#ifdef USERDEBUG
	/* Data wipes and UI prompts are skipped if the device is in
	 * provisioning mode to avoid unnecessary steps and user interaction
	 * during provisioning */
	if (!device_is_provisioning()) {
		/* 'eng' or 'userdebug' bootloaders skip the prompts
		 * to make CI automation easier */
#ifdef USE_UI
#ifdef USER
		/*
		 * Disable UI confirm on IVI platform.
		 * There's no physical button design on IVI MRB for confirm input,
		 * so disable UI confirm function even in USE_UI case
		 */
		if (is_UEFI() && interactive && !fastboot_ui_confirm_for_state(new_state)) {
			fastboot_fail("Refusing to change device state");
			return EFI_ACCESS_DENIED;
		}
#endif
#endif
	info(L"Erasing userdata...");
	ret = erase_by_label(L"userdata", TRUE);
	if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND) {
		if (interactive)
			fastboot_fail("Failed to wipe data.");
		return ret;
	}

	if (ret == EFI_NOT_FOUND)
		ui_print(L"No userdata partition to erase.");
	else
		info(L"Erase done.");
	}
#endif

	ret = set_current_state(new_state);
	if (EFI_ERROR(ret)) {
		if (interactive)
			fastboot_fail("Failed to change the device state");
		return ret;
	}

#ifdef USE_UI
	fastboot_ui_refresh();
#endif
	ret = fastboot_flashing_publish();
	if (EFI_ERROR(ret)) {
		if (interactive)
			fastboot_fail("Failed to publish OEM variables");
		return ret;
	}

	if (interactive)
		fastboot_okay("");
	/* Ensure logs variable is deleted on a successful
	   state transition.  */
	del_efi_variable(&loader_guid, LOG_VAR);

	return EFI_SUCCESS;
}

static BOOLEAN is_already_in_state(enum device_state state)
{
	if (get_current_state() == state && !device_is_provisioning()) {
		error(L"Device is already in the required state.");
		fastboot_okay("");
		return TRUE;
	}

	return FALSE;
}

static void cmd_lock(__attribute__((__unused__)) INTN argc,
		     __attribute__((__unused__)) CHAR8 **argv)
{
#ifdef FASTBOOT_FOR_NON_ANDROID
	fastboot_info("lock/Unlock is not supported");
	fastboot_okay("");
	return;
#endif
	if (!is_already_in_state(LOCKED))
		change_device_state(LOCKED, TRUE);
}

static BOOLEAN frp_allows_unlock()
{
	UINT8 persist_byte;
	struct gpt_partition_interface gparti;
	EFI_STATUS ret;
	UINT64 offset;

	ret = gpt_get_partition_by_label(L"persistent", &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return TRUE;	/* Allow if the persistent partition
				   does not exist */

	/* We need to check the last byte of the partition. The gparti
	 * .dio object is a handle to the beginning of the disk */
	offset = ((gparti.part.ending_lba + 1) * gparti.bio->Media->BlockSize) - 1;
	ret = uefi_call_wrapper(gparti.dio->ReadDisk, 5, gparti.dio,
				gparti.bio->Media->MediaId, offset,
				sizeof(persist_byte), &persist_byte);
	if (EFI_ERROR(ret)) {
		/* Pathological if this fails, GPT screwed up? */
		efi_perror(ret, L"Couldn't read persistent partition");
		return FALSE;
	}

	/* Per the specification, value of 1 means unlock is OK */
	return persist_byte == 1;
}

enum unlock_ability {
	UNLOCK_ALLOWED,
	NO_UNLOCK_FRP,
	NO_UNLOCK_CLASS_A
};

static enum unlock_ability get_unlock_ability(void)
{
	if (device_is_provisioning())
		return UNLOCK_ALLOWED;

	if (no_device_unlock())
		return NO_UNLOCK_CLASS_A;

	return frp_allows_unlock() ? UNLOCK_ALLOWED : NO_UNLOCK_FRP;
}

static void cmd_unlock(__attribute__((__unused__)) INTN argc,
		       __attribute__((__unused__)) CHAR8 **argv)
{
#ifdef USER
	EFI_STATUS ret;
#endif
#ifdef FASTBOOT_FOR_NON_ANDROID
	fastboot_info("lock/Unlock is not supported");
	fastboot_okay("");
	return;
#endif

	if (is_already_in_state(UNLOCKED))
		return;

	if (get_unlock_ability() == UNLOCK_ALLOWED) {
#ifdef USER
		ret = android_clear_memory();
		if (EFI_ERROR(ret)) {
			fastboot_fail("Failed to clear memory.  Unlock aborted.");
			return;
		}
#endif
		change_device_state(UNLOCKED, TRUE);
	} else {
#ifdef USER
		fastboot_fail("Unlocking device not allowed");
#else
		fastboot_info("Unlock protection is set");
		fastboot_info("Unlocking anyway since this is not a User build");
		change_device_state(UNLOCKED, TRUE);
#endif
	}
}

static void cmd_get_unlock_ability(__attribute__((__unused__)) INTN argc,
				   __attribute__((__unused__)) CHAR8 **argv)
{
#ifdef FASTBOOT_FOR_NON_ANDROID
	fastboot_info("lock/Unlock is not supported");
	fastboot_okay("");
	return;
#endif
	switch (get_unlock_ability()) {
	case UNLOCK_ALLOWED:
		fastboot_info("The device can be unlocked.");
		break;
	case NO_UNLOCK_FRP:
		fastboot_info("Unlock is disabled.");
		fastboot_info("To enable it, go in the Android Developer Options menu");
		fastboot_info("and activate 'Enable OEM Unlock'.");
		break;
	case NO_UNLOCK_CLASS_A:
		fastboot_info("The device class does not permit to unlock it.");
		break;
	}
	fastboot_okay("");
}

static void cmd_flashing(INTN argc, CHAR8 **argv)
{
	if (argc < 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	fastboot_run_cmd(cmdlist, (char *)argv[1], argc - 1, argv + 1);
}

static struct fastboot_cmd COMMANDS[] = {
#ifdef FASTBOOT_FOR_NON_ANDROID
	{ "lock",		UNKNOWN_STATE,	cmd_lock },
	{ "unlock",		UNKNOWN_STATE,	cmd_unlock },
	{ "get_unlock_ability",	UNKNOWN_STATE,	cmd_get_unlock_ability }
#else
	{ "lock",		LOCKED,	cmd_lock },
	{ "unlock",		LOCKED,	cmd_unlock },
	{ "get_unlock_ability",	LOCKED,	cmd_get_unlock_ability }
#endif
};

static struct fastboot_cmd flashing = { "flashing", LOCKED, cmd_flashing };

EFI_STATUS fastboot_flashing_init(void)
{
	EFI_STATUS ret;
	UINTN i;

	ret = fastboot_flashing_publish();
	if (EFI_ERROR(ret))
		return ret;

	for (i = 0; i < ARRAY_SIZE(COMMANDS); i++) {
		ret = fastboot_register_into(&cmdlist, &COMMANDS[i]);
		if (EFI_ERROR(ret))
			return ret;
	}

	fastboot_register(&flashing);

	return EFI_SUCCESS;
}

void fastboot_flashing_free()
{
	fastboot_cmdlist_unregister(&cmdlist);
}
