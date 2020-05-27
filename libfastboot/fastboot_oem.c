/*
 * Copyright (c) 2014, Intel Corporation
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
#include <vars.h>
#include <storage.h>
#include <slot.h>

#include "uefi_utils.h"
#include "flash.h"
#include "hashes.h"
#include "fastboot.h"
#include "fastboot_ui.h"
#include "gpt.h"
#include "authenticated_action.h"

#include "fastboot_oem.h"
#include "fastboot_flashing.h"
#include "intel_variables.h"
#include "text_parser.h"
#include "libavb/libavb.h"
#include "libavb_user/uefi_avb_ops.h"
#ifdef USE_TPM
#include "tpm2_security.h"
#endif
#include "security.h"
#include "vars.h"
#include "security_interface.h"

#define OFF_MODE_CHARGE		"off-mode-charge"
#define CRASH_EVENT_MENU	"crash-event-menu"
#define SLOT_FALLBACK		"slot-fallback"

static cmdlist_t cmdlist;
#ifdef USE_TPM
static cmdlist_t cmdlist_fuse;
#endif

static EFI_STATUS fastboot_oem_publish(void)
{
	EFI_STATUS ret;

	ret = fastboot_publish(OFF_MODE_CHARGE, get_off_mode_charge() ? "1" : "0");
	if (EFI_ERROR(ret))
		return ret;

	return publish_intel_variables();
}

static EFI_STATUS cmd_oem_set_boolean(INTN argc, CHAR8 **argv,
				      char *name, EFI_STATUS (*set_fun)(BOOLEAN value))
{
	EFI_STATUS ret;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return EFI_INVALID_PARAMETER;
	}

	if (strcmp(argv[1], (CHAR8 *)"1") && strcmp(argv[1], (CHAR8 *)"0")) {
		fastboot_fail("Invalid value");
		error(L"Please specify 1 or 0 to enable/disable %a", name);
		return EFI_INVALID_PARAMETER;
	}

	ret = set_fun(!strcmp(argv[1], (CHAR8 *)"1"));
	if (EFI_ERROR(ret))
		fastboot_fail("Failed to set %a", OFF_MODE_CHARGE);

	return ret;
}

static void cmd_oem_off_mode_charge(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;

	ret = cmd_oem_set_boolean(argc, argv, OFF_MODE_CHARGE, set_off_mode_charge);
	if (EFI_ERROR(ret))
		return;

	ret = fastboot_oem_publish();
	if (EFI_ERROR(ret))
		fastboot_fail("Failed to publish OEM variables");
	else
		fastboot_okay("");
}

static void cmd_oem_crash_event_menu(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;

	ret = cmd_oem_set_boolean(argc, argv, CRASH_EVENT_MENU, set_crash_event_menu);
	if (EFI_ERROR(ret))
		return;

	ret = fastboot_oem_publish();
	if (EFI_ERROR(ret))
		fastboot_fail("Failed to publish OEM variables");
	else
		fastboot_okay("");
}

static void cmd_oem_setvar(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR16 *varname;
	CHAR8 *value = NULL;

	if (argc < 2 || argc > 3) {
		fastboot_fail("Invalid parameter");
		return;
	}

	varname = stra_to_str(argv[1]);
	if (argc == 3)
		value = argv[2];

	if (!value)
		ret = del_efi_variable(&loader_guid, varname);
	else
		ret = set_efi_variable(&loader_guid, varname,
				       strlen(value) + 1, value,
				       TRUE, TRUE);
	if (EFI_ERROR(ret))
		fastboot_fail("Unable to %a '%s' variable",
			      value ? "set" : "clear", varname);
	else
		fastboot_okay("");

	FreePool(varname);
}

static void cmd_oem_reboot(INTN argc, CHAR8 **argv)
{
	enum boot_target bt;
	CHAR16 *target;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	target = stra_to_str(argv[1]);
	if (!target) {
		fastboot_fail("Unable to convert string");
		return;
	}

	bt = name_to_boot_target(target);
	FreePool(target);
	if (bt == UNKNOWN_TARGET) {
		fastboot_fail("Unknown %a boot target", argv[1]);
		return;
	}

	fastboot_reboot(bt, L"Rebooting to requested target ...");
}

static void cmd_oem_fw_update(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	CHAR8 *capsule_buf;
	INTN capsule_buf_len;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	capsule_buf = argv[1];
	capsule_buf_len = strlen(capsule_buf);

	if (capsule_buf[1] < '0' || capsule_buf[1] > '9' || capsule_buf[2] != ':'
		|| capsule_buf_len > 33) {
		fastboot_fail("Illegal capsule buffer");
		return;
	}

	ret = set_efi_variable(&loader_guid, IFWI_CAPSULE_UPDATE, capsule_buf_len + 1,
						   capsule_buf, TRUE, TRUE);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Unable to set %s", IFWI_CAPSULE_UPDATE);
		return;
	}

	fastboot_okay("");
}

static void cmd_oem_garbage_disk(__attribute__((__unused__)) INTN argc,
				 __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret = garbage_disk();

	if (ret == EFI_SUCCESS)
		fastboot_okay("");
	else
		fastboot_fail("Garbage disk failed, %r", ret);
}

static struct oem_hash {
	const CHAR16 *name;
	EFI_STATUS (*hash)(const CHAR16 *name);
	BOOLEAN fail_if_missing;
} OEM_HASH[] = {
#ifdef USE_ACPI
	{ ACPI_LABEL,		get_acpi_hash,		TRUE },
#endif
#ifdef USE_ACPIO
	{ ACPIO_LABEL,		get_acpi_hash,		TRUE },
#endif
	{ BOOT_LABEL,		get_boot_image_hash,	TRUE },
	{ RECOVERY_LABEL,	get_boot_image_hash,	FALSE },
#ifdef USE_TRUSTY
#ifdef USE_MULTIBOOT
	{ MULTIBOOT_LABEL,	get_ias_image_hash,	TRUE },
#endif
	{ TOS_LABEL,		get_boot_image_hash,	TRUE },
#endif
	{ BOOTLOADER_LABEL,	get_bootloader_hash,	FALSE },
	{ VBMETA_LABEL,		get_vbmeta_image_hash,	FALSE },
#ifdef DYNAMIC_PARTITIONS
	{ SUPER_LABEL,		get_super_image_hash,	TRUE }
#else
#ifdef USE_PRODUCT
	{ PRODUCT_LABEL,	get_fs_hash,		TRUE },
#endif
	{ SYSTEM_LABEL,		get_fs_hash,		TRUE },
	{ VENDOR_LABEL,		get_fs_hash,		FALSE }
#endif
};

static void cmd_oem_gethashes(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	UINTN i;

	if (argc == 2) {
		ret = set_hash_algorithm(argv[1]);
		if (EFI_ERROR(ret)) {
			fastboot_fail("Fail to set the algorithm, %r", ret);
			return;
		}
	}

	for (i = 0; i < ARRAY_SIZE(OEM_HASH); i++) {
		ret = OEM_HASH[i].hash(slot_label(OEM_HASH[i].name));
		if (EFI_ERROR(ret)
		    && (ret != EFI_NOT_FOUND || OEM_HASH[i].fail_if_missing)) {
			fastboot_fail("Failed to get hash for %s, %r",
				      OEM_HASH[i].name, ret);
			return;
		}
	}

	fastboot_okay("");
}

static void cmd_oem_set_storage(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	enum storage_type types[STORAGE_ALL + 1];
	INTN i, total_types = 0;
	enum storage_type boot_device_type;
	CHAR8 * lun_str = NULL;
	UINTN user_lun = UFS_DEFAULT_USER_LUN;
	UINTN factory_lun = UFS_DEFAULT_FACTORY_LUN;
	BOOLEAN is_ufs_set = FALSE;

	if (argc < 2) {
		fastboot_info("Supported type: ufs[@lun<user>:<factory>] emmc sata nvme");
#ifdef USB_STORAGE
		fastboot_info("                sdcard usb general");
#else
		fastboot_info("                sdcard general");
#endif
		fastboot_info("Example1: fastboot oem set-storage ufs emmc");
		fastboot_info("Example2: fastboot oem set-storage ufs@lun1:3");
		fastboot_fail("Should add one or more type");
		return;
	}

	for (i = 1; i < argc && total_types < (INTN)ARRAY_SIZE(types); i++) {
		if (!strcmp(argv[i], (CHAR8 *)"emmc")) {
			types[total_types++] = STORAGE_EMMC;
			continue;
		}
		if (!strncmp(argv[i], (CHAR8 *)"ufs",3)) {
			is_ufs_set = TRUE;
			types[total_types++] = STORAGE_UFS;
			lun_str = (CHAR8 *)strcasestr((char *)argv[i], (char *)"@lun");
			if (!lun_str)
				continue;
			if ((strlen(lun_str) > 4) && (lun_str[4] >= '0') &&
			    (lun_str[4] <= ('0'+ UFS_MAX_LUN)))
				user_lun = lun_str[4] - '0';
			if ((strlen(lun_str) > 6) && (lun_str[5] == ':') &&
			    (lun_str[6] <= ('0'+ UFS_MAX_LUN)))
				factory_lun = lun_str[6] - '0';
			continue;
		}
		if (!strcmp(argv[i], (CHAR8 *)"sata")) {
			types[total_types++] = STORAGE_SATA;
			continue;
		}
		if (!strcmp(argv[i], (CHAR8 *)"nvme")) {
			types[total_types++] = STORAGE_NVME;
			continue;
		}
		if (!strcmp(argv[i], (CHAR8 *)"sdcard")) {
			types[total_types++] = STORAGE_SDCARD;
			continue;
		}
		if (!strcmp(argv[i], (CHAR8 *)"usb")) {
#ifdef USB_STORAGE
			types[total_types++] = STORAGE_USB;
#else
			fastboot_info("USB storage is unsupported");
#endif
			continue;
		}
		if (!strcmp(argv[i], (CHAR8 *)"general")) {
			types[total_types++] = STORAGE_GENERAL_BLOCK;
			continue;
		}
		fastboot_fail("Unsupported storage");
		return;
	}

	if (total_types == 0) {
		fastboot_fail("All input types are skipped");
		return;
	}
	if (is_ufs_set == TRUE) {
		if (user_lun > UFS_MAX_LUN || factory_lun > UFS_MAX_LUN ||
		    factory_lun == user_lun) {
			fastboot_fail("UFS LUN number should be from 0 to 7 and exclusive");
			return;
		}
		//must set LUN layout before reading current UFS storage
		set_logical_unit((UINT64) user_lun, (UINT64) factory_lun);
	}
	ret = get_boot_device_type(&boot_device_type);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to get current boot device type");
		return;
	}

	for (i = 0; i < total_types; i++) {
		if ((boot_device_type == types[i]) && (user_lun == UFS_DEFAULT_USER_LUN) &&
		    (factory_lun == UFS_DEFAULT_FACTORY_LUN)) {
			warning(L"Already use such type device");
			fastboot_info("Already use such type device");
			fastboot_okay("");
			return;
		}
		ret = identify_boot_device(types[i]);
		if (!EFI_ERROR(ret))
			break;
	}

	if (i == total_types) {
		fastboot_fail("Failed to find valid storage");
		return;
	}

	if (is_ufs_set == TRUE) {
		//must set LUN layout after storage changed to UFS
		set_logical_unit((UINT64) user_lun, (UINT64) factory_lun);
	}

	set_device_security_info(NULL);

#ifdef USE_TPM
	if (!is_live_boot())
		tpm2_init();
#endif

	ret = gpt_refresh();
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to refresh partition table: %r", ret);
		return;
	}

	refresh_current_state();
	fastboot_flashing_publish();
#ifdef USE_UI
	fastboot_ui_refresh();
#endif

	ret = refresh_partition_var();
	if (EFI_ERROR(ret))
		fastboot_fail("Failed to refresh partition vars: %r", ret);
	else
		fastboot_okay("");
}

#ifndef USER
static void cmd_oem_reprovision(
		__attribute__((__unused__)) INTN argc,
		__attribute__((__unused__)) CHAR8 **argv)
{
	if (EFI_ERROR(reprovision_state_vars())) {
		fastboot_fail("Unable to clear provisioning variables");
		return;
	}
	fastboot_reboot(DNX, L"Rebooting to dnx ...");
}

static void cmd_oem_rm(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io;
	const CHAR8 prefix[] = "/ESP/";
	CHAR8 *filename;
	CHAR16 *filename16;
	CHAR8 *tmp;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	if (strncmp(prefix, argv[1], sizeof(prefix) - 1)) {
		fastboot_fail("File deletion is restricted to the ESP");
		return;
	}

	ret = get_esp_fs(&io);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to get partition ESP");
		return;
	}

	filename = &argv[1][ARRAY_SIZE(prefix) - 1];
	for (tmp = filename; *tmp; tmp++)
		if (*tmp == '/')
			*tmp = '\\';

	filename16 = stra_to_str(filename);
	if (!filename16) {
		efi_perror(ret, L"failed to allocate CHAR16 filename");
		fastboot_fail("failed to allocate CHAR16 filename");
		return;
	}

	ret = uefi_delete_file(io, filename16);
	FreePool(filename16);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to delete file '%a', %r", filename, ret);
		return;
	}

	fastboot_okay("");
}

static void cmd_oem_set_watchdog_counter_max(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;
	unsigned long value;
	char *endptr;

	if (argc != 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	value = strtoul((char *)argv[1], &endptr, 10);
	if (*endptr != '\0' || value > (UINT8)-1) {
		fastboot_fail("Invalid value");
		return;
	}

	ret = set_watchdog_counter_max(value);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to set watchdog counter max, %r", ret);
		return;
	}

	fastboot_okay("");
}

static void cmd_oem_disable_slot_fallback(INTN argc, CHAR8 **argv)
{
	EFI_STATUS ret;

	ret = cmd_oem_set_boolean(argc, argv, SLOT_FALLBACK, set_slot_fallback);
	if (EFI_ERROR(ret))
		return;

	fastboot_okay("");
}

static void cmd_oem_erase_efivars(__attribute__((__unused__)) INTN argc,
				  __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;

	if (argc != 1) {
		fastboot_fail("Invalid parameter");
		return;
	}

	ret = erase_efivars();
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to erase all the EFI variables, %r", ret);
		return;
	}

	fastboot_okay("");
}

#endif

static void cmd_oem_get_logs(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	UINT32 flags;
	char *buf;
	UINTN size;

	if (argc != 1) {
		fastboot_fail("Invalid parameter");
		return;
	}

	ret = get_efi_variable(&loader_guid, LOG_VAR, &size, (VOID **)&buf, &flags);
	if (EFI_ERROR(ret)) {
		fastboot_fail("failed to get log buffer from variable, %r", ret);
		return;
	}

	ret = parse_text_buffer(buf, size, fastboot_info_long_string, NULL);
	FreePool(buf);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to parse log buffer, %r", ret);
		return;
	}

	fastboot_okay("");
}

static void cmd_oem(INTN argc, CHAR8 **argv)
{
	if (argc < 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	fastboot_run_cmd(cmdlist, (char *)argv[1], argc - 1, argv + 1);
}

#ifdef USE_TPM
#ifndef USER
static void cmd_oem_tpm_show_index(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	char *endptr;
	CHAR8 out_buffer[2048];

	if (argc != 2) {
		fastboot_fail("Invalid parameters. Usage: fastboot oem tpm-show-index <index>");
		return;
	}

	ret = tpm2_show_index(strtoul((const char *)argv[1], &endptr, 0), out_buffer, sizeof(out_buffer));
	if (EFI_ERROR(ret)) {
		fastboot_fail("TPM show index failed, %r", ret);
		return;
	}
	fastboot_info_long_string((char *)out_buffer, NULL);

	fastboot_okay("");
}

static void cmd_oem_tpm_delete_index(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	char *endptr;

	if (argc != 2) {
		fastboot_fail("Invalid parameters, Usage: fastboot oem tpm-delete-index <index>");
		return;
	}

	ret = tpm2_delete_index(strtoul((const char *)argv[1], &endptr, 0));
	if (EFI_ERROR(ret)) {
		fastboot_fail("TPM delete index failed, %r", ret);
		return;
	}

	fastboot_okay("");
}
#endif // USER

static void cmd_fuse(INTN argc, CHAR8 **argv)
{
	if (argc < 2) {
		fastboot_fail("Invalid parameter");
		return;
	}

	fastboot_run_cmd(cmdlist_fuse, (char *)argv[1], argc - 1, argv + 1);
}

#ifdef BUILD_ANDROID_THINGS
static void cmd_fuse_atperm(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	struct download_buffer *dl;

	if (argc != 1) {
		fastboot_fail("Invalid parameters");
		return;
	}

	dl = fastboot_download_buffer();

	ret = tpm2_fuse_perm_attr(dl->data, dl->size);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Fusing AT PERM failed, %r", ret);
		return;
	}

	fastboot_okay("");
}
#endif  // BUILD_ANDROID_THINGS

static void cmd_fuse_vbmeta_key_hash(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	struct download_buffer *dl;

	if (argc != 1) {
		fastboot_fail("Invalid parameters");
		return;
	}

	dl = fastboot_download_buffer();

	ret = tpm2_fuse_vbmeta_key_hash(dl->data, dl->size);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Tee verify hash fuse failed, %r", ret);
		return;
	}

	fastboot_okay("");
}

static void cmd_fuse_bootloader_policy(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	struct download_buffer *dl;

	if (argc != 1) {
		fastboot_fail("Invalid parameters");
		return;
	}

	dl = fastboot_download_buffer();

	ret = tpm2_fuse_bootloader_policy(dl->data, dl->size);
	if (EFI_ERROR(ret)) {
		fastboot_fail("Setting Bootloader policy failed, %r", ret);
		return;
	}

	fastboot_okay("");
}

/* lock owner authorization to prevent the created nv from being removed.
IMPORTANCE: this command must be executed after all expected nv index are provisioned */
static void cmd_fuse_tpm2_lock_owner(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	if (argc != 1) {
		fastboot_fail("Invalid parameters");
		return;
	}

	ret = tpm2_fuse_lock_owner();
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to lock owner, %r", ret);
		return;
	}

	fastboot_okay("");
}

static void cmd_fuse_tpm2_provision_trusty_seed(INTN argc, __attribute__((__unused__)) CHAR8 **argv)
{
	EFI_STATUS ret;
	if (argc != 1) {
		fastboot_fail("Invalid parameters");
		return;
	}

	ret = tpm2_fuse_provision_seed();
	if (EFI_ERROR(ret)) {
		fastboot_fail("Failed to provision trusty seed, %r", ret);
		return;
	}

	fastboot_okay("");
}

#endif

static struct fastboot_cmd COMMANDS[] = {
	{ OFF_MODE_CHARGE,		LOCKED,		cmd_oem_off_mode_charge  },
	/* The following commands are not part of the Google
	 * requirements.  They are provided for engineering and
	 * provisioning purpose only.
	 */
	{ CRASH_EVENT_MENU,		LOCKED,		cmd_oem_crash_event_menu  },
	{ "setvar",			UNLOCKED,	cmd_oem_setvar  },
	{ "garbage-disk",		UNLOCKED,	cmd_oem_garbage_disk  },
	{ "reboot",			LOCKED,		cmd_oem_reboot  },
	{ "fw-update",			UNLOCKED,	cmd_oem_fw_update  },
	{ "set-storage",		LOCKED,		cmd_oem_set_storage  },
#ifndef USER
	{ "reprovision",		LOCKED,		cmd_oem_reprovision  },
	{ "rm",				LOCKED,		cmd_oem_rm },
	{ "set-watchdog-counter-max",	LOCKED,		cmd_oem_set_watchdog_counter_max },
	{ SLOT_FALLBACK,		LOCKED,		cmd_oem_disable_slot_fallback },
	{ "erase-efivars",		LOCKED,		cmd_oem_erase_efivars },
#endif
	{ "get-hashes",			LOCKED,		cmd_oem_gethashes  },
	{ "get-provisioning-logs",	LOCKED,		cmd_oem_get_logs },
#ifdef USE_TPM
#ifndef USER
	{ "tpm-show-index",		LOCKED,		cmd_oem_tpm_show_index },
	{ "tpm-delete-index",		LOCKED,		cmd_oem_tpm_delete_index },
#endif // USER
	{ "fuse",			LOCKED,		cmd_fuse }
#endif
};

#ifdef USE_TPM
static struct fastboot_cmd COMMANDS_FUSE[] = {
#ifdef BUILD_ANDROID_THINGS
	{ "at-perm-attr",		LOCKED,		cmd_fuse_atperm },
#endif
	{ "vbmeta-key-hash",		UNLOCKED,	cmd_fuse_vbmeta_key_hash },
	{ "bootloader-policy",		UNLOCKED,	cmd_fuse_bootloader_policy },
	{ "lock-tpm2-owner",		UNLOCKED,	cmd_fuse_tpm2_lock_owner },
	{ "provision-trusty-seed",	UNLOCKED,	cmd_fuse_tpm2_provision_trusty_seed }
};
#endif

static struct fastboot_cmd oem = { "oem", LOCKED, cmd_oem };

EFI_STATUS fastboot_oem_init(void)
{
	EFI_STATUS ret;
	UINTN i;

	ret = fastboot_oem_publish();
	if (EFI_ERROR(ret))
		return ret;

	for (i = 0; i < ARRAY_SIZE(COMMANDS); i++) {
		ret = fastboot_register_into(&cmdlist, &COMMANDS[i]);
		if (EFI_ERROR(ret))
			return ret;
	}

#ifdef USE_TPM
	for (i = 0; i < ARRAY_SIZE(COMMANDS_FUSE); i++) {
		ret = fastboot_register_into(&cmdlist_fuse, &COMMANDS_FUSE[i]);
		if (EFI_ERROR(ret))
			return ret;
	}
#endif

	fastboot_register(&oem);

	return EFI_SUCCESS;
}

void fastboot_oem_free(void)
{
	fastboot_cmdlist_unregister(&cmdlist);

#ifdef USE_TPM
	fastboot_cmdlist_unregister(&cmdlist_fuse);
#endif

}
