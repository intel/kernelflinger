/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Authors: Jeremy Compostella <jeremy.compostella@intel.com>
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
#include <lib.h>
#include <fastboot.h>
#include <vars.h>
#ifdef CRASHMODE_USE_ADB
#include <adb.h>
#endif
#include <hecisupport.h>

#include "options.h"
#if defined(IOC_USE_SLCAN) || defined(IOC_USE_CBC)
#include "ioc_can.h"
#endif
#include "android_vb2.h"
#include "android.h"
#include "slot.h"
#include "timer.h"
#include "security.h"
#include "security_interface.h"
#ifdef RPMB_STORAGE
#include <openssl/hkdf.h>
#include "rpmb.h"
#include "rpmb_storage.h"
#endif
#ifdef USE_TRUSTY
#include "trusty_interface.h"
#include "trusty_common.h"
#endif
#include "storage.h"
#include "acpi.h"
#include "ux.h"

typedef union {
	uint32_t raw;
	struct {
		uint32_t patch_M:4;
		uint32_t patch_Y:7;
		uint32_t version_C:7;
		uint32_t version_B:7;
		uint32_t version_A:7;
	};
} os_version_t;

#define MAX_CMD_BUF 0x1000
static CHAR8 cmd_buf[MAX_CMD_BUF];

#ifdef CRASHMODE_USE_ADB
static EFI_STATUS enter_crashmode(enum boot_target *target)
{
	EFI_STATUS ret;

#ifdef USER
#error "adb in crashmode MUST be disabled on a USER build"
#endif

	ret = adb_init();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to initialize adb");
		return ret;
	}

	debug(L"adb implementation is initialized");
	for (;;) {
		ret = adb_run();
		if (EFI_ERROR(ret))
			break;

		*target = adb_get_boot_target();
		if (*target != UNKNOWN_TARGET)
			break;
	}
	adb_exit();

	return ret;
}
#endif
#ifndef __FORCE_FASTBOOT
static enum boot_target check_bcb(CHAR16 **target_path, BOOLEAN *oneshot)
{
	EFI_STATUS ret;
	struct bootloader_message bcb;
	CHAR16 *target = NULL;
	enum boot_target t;
	CHAR8 *bcb_cmd;
	BOOLEAN dirty;

	*oneshot = FALSE;
	*target_path = NULL;

	ret = read_bcb(MISC_LABEL, &bcb);
	if (EFI_ERROR(ret)) {
		error(L"Unable to read BCB");
		t = NORMAL_BOOT;
		goto out;
	}

	dirty = bcb.status[0] != '\0';
	/* We own the status field; clear it in case there is any stale data */
	bcb.status[0] = '\0';
	bcb_cmd = (CHAR8 *)bcb.command;
	if (!strncmpa(bcb_cmd, (CHAR8 *)"boot-", 5)) {
		target = stra_to_str(bcb_cmd + 5);
		debug(L"BCB boot target: '%s'", target);
	} else if (!strncmpa(bcb_cmd, (CHAR8 *)"bootonce-", 9)) {
		target = stra_to_str(bcb_cmd + 9);
		bcb_cmd[0] = '\0';
		dirty = TRUE;
		debug(L"BCB oneshot boot target: '%s'", target);
		*oneshot = TRUE;
	}

	if (dirty) {
		ret = write_bcb(MISC_LABEL, &bcb);
		if (EFI_ERROR(ret))
			error(L"Unable to update BCB contents!");
	}

	if (!target) {
		t = NORMAL_BOOT;
		goto out;
	}

	t = name_to_boot_target(target);
	if (t != UNKNOWN_TARGET && t != CHARGER)
		goto out;

	error(L"Unknown/Unsupported boot target in BCB: '%s'", target);
	t = NORMAL_BOOT;

out:
	FreePool(target);
	return t;
}
#endif

static EFI_STATUS process_bootimage(void *bootimage, UINTN imagesize)
{
	EFI_STATUS ret;
	VBDATA *param = NULL;
	UINT8 boot_state = BOOT_STATE_GREEN;
	enum boot_target target = NORMAL_BOOT;

	if (!bootimage)
		return EFI_SUCCESS;

#ifndef __FORCE_FASTBOOT
	AvbOps *ops;
	AvbSlotVerifyData *slot_data = NULL;
#ifndef USE_SLOT
	const char *slot_suffix = "";
	AvbSlotVerifyResult verify_result;
#else
	AvbABFlowResult flow_result;
#endif

	const char *requested_partitions[] = {"boot",
#ifdef USE_ACPI
		"acpi",
#endif
#ifdef USE_ACPIO
		"acpio",
#endif
		NULL};
	bool allow_verification_error = FALSE;
	AvbSlotVerifyFlags flags;

#ifdef USE_TRUSTY
	VOID *tosimage = NULL;
#endif
	debug(L"Processing boot image");

	if (device_is_unlocked()) {
 		boot_state = BOOT_STATE_ORANGE;
 	} else if (!is_platform_secure_boot_enabled())
		boot_state  = BOOT_STATE_YELLOW;

	ops = avb_init();
	if (ops) {
		if (ops->read_is_device_unlocked(ops, &allow_verification_error) != AVB_IO_RESULT_OK) {
			avb_fatal("Error determining whether device is unlocked.\n");
			return EFI_ABORTED;
		}
	} else {
		return EFI_OUT_OF_RESOURCES;
	}

	flags = AVB_SLOT_VERIFY_FLAGS_NONE;
	if (allow_verification_error) {
		flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;
	}

#ifdef USE_SLOT
	flow_result = avb_ab_flow(&ab_ops, requested_partitions, flags, AVB_HASHTREE_ERROR_MODE_RESTART, &slot_data);
	ret = get_avb_flow_result(slot_data,
			    allow_verification_error,
			    flow_result,
			    &boot_state);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get avb slot a/b flow result for boot");
		goto fail;
	}
	slot_set_active_cached(slot_data->ab_suffix);
#else
	verify_result = avb_slot_verify(ops,
					requested_partitions,
					slot_suffix,
					flags,
					AVB_HASHTREE_ERROR_MODE_RESTART,
					&slot_data);
	ret = get_avb_result(slot_data,
				allow_verification_error,
				verify_result,
				&boot_state);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get avb result for boot");
		goto fail;
	}
#endif
	param = slot_data;

	ret = android_install_acpi_table_avb(slot_data);
	if (EFI_ERROR(ret)) goto fail;

	set_boottime_stamp(TM_VERIFY_BOOT_DONE);
#ifdef USE_TRUSTY
	ret = update_rot_data(bootimage, boot_state, slot_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init rot params");
		goto fail;
	}

	ret = load_tos_image(&tosimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Load tos image failed");
		goto fail;
	}
	set_boottime_stamp(TM_LOAD_TOS_DONE);
	ret = start_trusty(tosimage);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Unable to start trusty: stop");
		goto fail;
	}
	set_boottime_stamp(TM_PROCRSS_TRUSTY_DONE);
#endif //USE_TRUSTY
fail:
#else
	//Fastboot stored in the SPI gets the capability to load an image
	//(fastboot boot) using the RAMDISK and nothing from the eMMC
	target = MEMORY;
#endif //__FORCE_FASTBOOT
	/* 'fastboot boot' case, only allowed on unlocked devices.*/
	if (device_is_unlocked()) {
		UINT32 crc;

		ret = uefi_call_wrapper(BS->CalculateCrc32, 3, bootimage, imagesize, &crc);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"CalculateCrc32 failed");
			return ret;
		}

		ret = android_image_start_buffer(NULL, bootimage,
							target, boot_state, NULL,
							param, (const CHAR8 *)cmd_buf);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Couldn't load Boot image");
			return ret;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS enter_fastboot_mode(enum boot_target *target)
{
	EFI_STATUS ret;
	void *efiimage, *bootimage;
	UINTN imagesize;

#if defined(IOC_USE_SLCAN) || defined(IOC_USE_CBC)
	ret = notify_ioc_ready();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"notify ioc ready failed");
	}
#endif

	/* Handle corner case that EOP not send before ABL jump to fastboot, will force EOP send.*/
	if (!heci_is_eop_received()) {
		heci_end_of_post();
	}

	for (;;) {
		*target = UNKNOWN_TARGET;
		bootimage = NULL;
		efiimage = NULL;

		ret = fastboot_start(&bootimage, &efiimage, &imagesize, target);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Fastboot mode failed");
			break;
		}

		ret = process_bootimage(bootimage, imagesize);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Process bootimage failed");
			if (bootimage) {
				FreePool(bootimage);
				bootimage = NULL;
			}
			break;
		}

		if (*target == UNKNOWN_TARGET)
			continue;

		if (*target == CRASHMODE)
			break;

		reboot_to_target(*target, EfiResetCold);
	}

	return ret;
}

/*
 *  Boot mode field definitions.
 */
static union bootMode
{
	UINT16 _bits;
	struct {
		UINT16 target           : 5; /* [4:0] */
		UINT16 do_mrc_training  : 1; /* [5] */
		UINT16 do_save_mrc_data : 1; /* [6] */
		UINT16 do_flash_update  : 1; /* [7] */
		UINT16 silent           : 1; /* [8] */
		UINT16 _reserved        : 1; /* [9] */
		UINT16 action           : 2; /* [11:10] 0:boot,1:CLI,2:halt,3:reset */
		UINT16 dipsw            : 4; /* [15:12] */
	};
} bootMode;

static enum boot_target check_command_line(EFI_HANDLE image, CHAR8 *cmd_buf, UINTN max_cmd_size)
{
	EFI_STATUS ret;
	enum boot_target target = FASTBOOT;
	static EFI_LOADED_IMAGE *limg;
	UINTN argc, i, j;
	CHAR16 **argv;
	CHAR16 *options;
	UINTN cmd_len = 0;
	CHAR8 arg8[256] = "";
	UINTN arglen;
#if defined(USE_TRUSTY) || defined(RPMB_STORAGE)
	UINTN num;
#endif

	enum CmdType
	{
		RESET,
		BOOT_TARGET,
		BOOT,
		TRUSTY_PARAM,
		SECUREBOOT,
		BOOTVERSION,
		SERIALNO,
		DEV_SEC_INFO,
		IMAGE_BOOT_PARAMS_ADDR,
		FIRMWARE_BOOTTIME,
		BOOTREASON,
		RPMB,
		STATUS,
	};

	struct Cmdline
	{
		CHAR8 *name;
		UINTN length;
		enum CmdType type;
	};

	struct Cmdline CmdlineArray[] = {
		{
			(CHAR8 *)"ABL.reset=",
			strlen((CHAR8 *)"ABL.reset="),
			RESET
		},
		{
			(CHAR8 *)"ABL.boot_target=",
			strlen((CHAR8 *)"ABL.boot_target="),
			BOOT_TARGET
		},
		{
			(CHAR8 *)"ABL.boot=",
			strlen((CHAR8 *)"ABL.boot="),
			BOOT
		},
		{
			(CHAR8 *)"trusty.param_addr=",
			strlen((CHAR8 *)"trusty.param_addr="),
			TRUSTY_PARAM
		},
		{
			(CHAR8 *)"ABL.secureboot=",
			strlen((CHAR8 *)"ABL.secureboot="),
			SECUREBOOT
		},
		{
			(CHAR8 *)"androidboot.bootloader=",
			strlen((CHAR8 *)"androidboot.bootloader="),
			BOOTVERSION
		},
		{
			(CHAR8 *)"androidboot.bootreason=",
			strlen((CHAR8 *)"androidboot.bootreason="),
			BOOTREASON
		},
		{
			(CHAR8 *)"androidboot.serialno=",
			strlen((CHAR8 *)"androidboot.serialno="),
			SERIALNO
		},
		{
			(CHAR8 *)"dev_sec_info.param_addr=",
			strlen((CHAR8 *)"dev_sec_info.param_addr="),
			DEV_SEC_INFO
		},
		{
			(CHAR8 *)"ABL.svnseed=",
			strlen((CHAR8 *)"ABL.svnseed="),
			DEV_SEC_INFO
		},
		{
			(CHAR8 *)"ImageBootParamsAddr=",
			strlen((CHAR8 *)"ImageBootParamsAddr="),
			IMAGE_BOOT_PARAMS_ADDR
		},
		{
			(CHAR8 *)"fw_boottsc=",
			strlen("fw_boottsc="),
			FIRMWARE_BOOTTIME
		},
		{
			(CHAR8 *)"ABL.rpmb=",
			strlen("ABL.rpmb="),
			RPMB
		},
		{
			(CHAR8 *)"ABL.status=",
			strlen((CHAR8 *)"ABL.status="),
			STATUS
		},
	};

	CHAR8 *nptr = NULL;
	ret = uefi_call_wrapper(BS->OpenProtocol, 6, image,
				&LoadedImageProtocol, (VOID **)&limg,
				image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open LoadedImageProtocol");
		return FASTBOOT;
	}

	ret = get_argv(limg, &argc, &argv, &options);
	if (EFI_ERROR(ret))
		return FASTBOOT;

	cmd_buf[0] = 0;

	for (i = 0; i < argc; i++) {
		debug(L" abl cmd %02d: %s", i, argv[i]);
		arglen = StrLen(argv[i]);

		if (arglen > (int)sizeof(arg8) - 2)
			arglen = sizeof(arg8) - 2;
		debug(L" abl cmd %02d length: %d", i, arglen);

		ret = str_to_stra((CHAR8 *)arg8, argv[i], arglen + 1);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Non-ascii characters in command line");
			return FASTBOOT;
		}

		if (cmd_len + arglen + 1 < max_cmd_size) {
			for (j = 0; j < sizeof(CmdlineArray)/sizeof(CmdlineArray[0]); j++) {
				if((arglen >= CmdlineArray[j].length) && !strncmp(arg8, CmdlineArray[j].name, CmdlineArray[j].length))
					break;
			}

			if (j < sizeof(CmdlineArray)/sizeof(CmdlineArray[0])) {
				switch(CmdlineArray[j].type) {
				/* Parse "ABL.reset=xxx" */
				case RESET:
					set_reboot_reason(argv[i] + CmdlineArray[j].length);
					continue;

				/* Parse "ABL.boot_target=xxxx" */
				case BOOT_TARGET:
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					/* Only handle CRASHMODE case, other mode should be decided by "ABL.boot". */
					if (!strcmp(nptr, (CHAR8 *)"CRASHMODE")) {
						target = CRASHMODE;
						goto out;
					}
					continue;

				/* Parse "ABL.boot=xx" */
				case BOOT:
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					bootMode._bits = (UINT16)strtoul((char *)nptr, 0, 16);
					target = bootMode.target;
					break;
#ifdef USE_TRUSTY
				/* Parse "trusty.param_addr=xxxxx" */
				case TRUSTY_PARAM:
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					num = strtoul((char *)nptr, 0, 16);
					debug(L"Parsed trusty param addr is 0x%x", num);
					set_trusty_param((VOID *)num);
					continue;
#endif //USE_TRUSTY
#ifdef RPMB_STORAGE
				/* Parse "Add legacy DEV_SEC_INFO parameter for backward compatible to ABL usage" */
				case DEV_SEC_INFO:
				case IMAGE_BOOT_PARAMS_ADDR:
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					num = strtoul((char *)nptr, 0, 16);
					debug(L"Parsed device security information addr is 0x%x", num);
					set_device_security_info((VOID *)num);
					continue;

				case RPMB:
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					num = strtoul((char *)nptr, 0, 16);
					debug(L"abl_rpmb_key addr is 0x%x", num);
					set_rpmb_derived_key_ex((VOID *)num, RPMB_KEY_SIZE, 1, 1);
					memset_s((VOID *)num, RPMB_KEY_SIZE, 0, RPMB_KEY_SIZE);
					barrier();
					continue;
#endif //RPMB_STORAGE
				/* Parse "ABL.secureboot=x" */
				case SECUREBOOT: {
					UINT8 val;
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					val = (UINT8)strtoul((char *)nptr, 0, 10);
					ret = set_platform_secure_boot(val);
					if (EFI_ERROR(ret))
						efi_perror(ret, L"Failed to set secure boot");
					break;
				}

				/* Parse "ABL.status=x" */
				case STATUS: {
					union
					{
						struct
						{
							UINT32 secure_boot:1;
							UINT32 measured_boot:1;
							UINT32 dci_debug_npk:1;
							UINT32 eom:1;
						}bit;
						UINT32 val;
					} abl_status;

					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					abl_status.val = (UINT32)strtoul((char *)nptr, 0, 16);
					ret = set_platform_secure_boot(abl_status.bit.secure_boot);
					if (EFI_ERROR(ret))
						efi_perror(ret, L"Failed to set secure boot");
					break;
				}

				/* Parse "fw_boottsc=xxxxx" */
				case FIRMWARE_BOOTTIME: {
					UINT64 VALUE;
					UINT32 cpu_khz;
					nptr = (CHAR8 *)(arg8 + CmdlineArray[j].length);
					VALUE = (UINT64)strtoull((char *)nptr, 0, 10);
					cpu_khz = get_cpu_freq() * 1000;
					//EFI_ENTER_POINT boot time is recorded in ms
					set_efi_enter_point(VALUE /cpu_khz);
					continue;
				}

				/* Parse "android.bootloader=xxxxx" */
				case BOOTVERSION:
					continue;

				/* Parse "android.serialno=xxxxx " */
				case SERIALNO:
					continue;

				/* Parse "androidboot.bootreason=xxxxx " */
				case BOOTREASON:
					continue;

				default:
					continue;
				}
			}

			if (cmd_buf[0] != 0) {
				ret = strncpy_s((CHAR8 *)(cmd_buf + cmd_len), 1, (const CHAR8 *)" ", 1);
				if (EFI_ERROR(ret)) {
					target = FASTBOOT;
					goto out;
				}
				cmd_len++;
			}

			ret = strncpy_s((CHAR8 *)(cmd_buf + cmd_len), arglen, (const CHAR8 *)arg8, arglen);
			if (EFI_ERROR(ret)) {
					target = FASTBOOT;
					goto out;
			}
			cmd_len += arglen;
		}
	}

out:
	debug(L"boot target: %d", target);
	FreePool(argv);
	FreePool(options);
	return target;
}


static EFI_STATUS start_boot_image(VOID *bootimage, UINT8 boot_state,
				enum boot_target boot_target,
				VBDATA *vb_data,
				CHAR8 *abl_cmd_line)
{
	EFI_STATUS ret;
#ifdef USER
	/* per bootloaderequirements.pdf */
	if (boot_state == BOOT_STATE_ORANGE) {
		ret = android_clear_memory();
		if (EFI_ERROR(ret)) {
			error(L"Failed to clear memory. Load image aborted.");
			return ret;
		}
	}
#endif

#ifdef USER
	if (boot_state == BOOT_STATE_RED) {
		if (is_platform_secure_boot_enabled()) {
			return EFI_SECURITY_VIOLATION;
		}
	}
#endif

	set_efi_variable(&fastboot_guid, BOOT_STATE_VAR, sizeof(boot_state),
					&boot_state, FALSE, TRUE);

#ifdef OS_SECURE_BOOT
	ret = set_os_secure_boot(boot_state == BOOT_STATE_GREEN);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to set os secure boot");
#endif

	if (!use_slot()) {
		ret = slot_boot(boot_target);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Failed to write slot boot");
			return ret;
		}
	}

	debug(L"chainloading boot image, boot state is %s\n",
	boot_state_to_string(boot_state));
	ret = android_image_start_buffer(NULL, bootimage,
					 boot_target, boot_state, NULL,
					 vb_data, (const CHAR8 *)abl_cmd_line);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Couldn't load Boot image");

	ret = slot_boot_failed(boot_target);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to write slot failure");

	return ret;
}

EFI_STATUS avb_boot_android(enum boot_target boot_target, CHAR8 *abl_cmd_line)
{
	AvbOps *ops;
	AvbSlotVerifyData *slot_data = NULL;
#ifndef USE_SLOT
	const char *slot_suffix = "";
	AvbSlotVerifyResult verify_result;
#else
	AvbABFlowResult flow_result;
#endif
	const char *requested_partitions[] = {"boot",
#ifdef USE_ACPI
		"acpi",
#endif
#ifdef USE_ACPIO
		"acpio",
#endif
		NULL};
	EFI_STATUS ret;
	VOID *bootimage = NULL;
	UINT8 boot_state = BOOT_STATE_GREEN;
	bool allow_verification_error = FALSE;
	AvbSlotVerifyFlags flags;
	const uint8_t *vbmeta_pub_key;
	UINTN vbmeta_pub_key_len;

	debug(L"Loading boot image");
	if (!use_slot()) {
		if (boot_target == RECOVERY) {
			requested_partitions[0] = "recovery";
		}
	}

	if (device_is_unlocked()) {
 		boot_state = BOOT_STATE_ORANGE;
 	} else if (!is_platform_secure_boot_enabled())
		boot_state  = BOOT_STATE_YELLOW;

	ops = avb_init();
	if (ops) {
		if (ops->read_is_device_unlocked(ops, &allow_verification_error) != AVB_IO_RESULT_OK) {
			avb_fatal("Error determining whether device is unlocked.\n");
			return EFI_ABORTED;
		}
	} else {
		return EFI_OUT_OF_RESOURCES;
	}

	flags = AVB_SLOT_VERIFY_FLAGS_NONE;
	if (allow_verification_error) {
		flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;
	}

#ifdef USE_SLOT
	flow_result = avb_ab_flow(&ab_ops, requested_partitions, flags, AVB_HASHTREE_ERROR_MODE_RESTART, &slot_data);
	ret = get_avb_flow_result(slot_data,
			    allow_verification_error,
			    flow_result,
			    &boot_state);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get avb slot a/b flow result for boot");
		goto fail;
	}
	slot_set_active_cached(slot_data->ab_suffix);

	if (slot_data->ab_suffix) {
		CHAR8 *capsule_buf;
		UINTN capsule_buf_len = 0;
		CHAR16 *AB_SUFFIX = NULL;
		CHAR16 *ABL_AB_SUFFIX = NULL;

		AB_SUFFIX = stra_to_str((const CHAR8 *)slot_data->ab_suffix);
		if (!AB_SUFFIX) {
			error(L"Cannot get a valid AVB flow suffix: %s", slot_data->ab_suffix);
			goto fail;
		}
		ABL_AB_SUFFIX = stra_to_str((const CHAR8 *)abl_cmd_line);
		if (!ABL_AB_SUFFIX) {
			error(L"Cannot get a valid ABL suffix: %s", abl_cmd_line);
			goto fail;
		}
		if (!(StrStr(ABL_AB_SUFFIX, L"ABL.suffix"))) {
			debug(L"ABL.suffix is null");
		} else if (!(StrCmp(AB_SUFFIX, L"_a")) && (!(StrStr(ABL_AB_SUFFIX, L"ABL.suffix=0")))) {
			capsule_buf = (CHAR8 *)"m1:@0";
			capsule_buf_len = strlen(capsule_buf);
		} else if (!(StrCmp(AB_SUFFIX, L"_b")) && (!(StrStr(ABL_AB_SUFFIX, L"ABL.suffix=1")))) {
			capsule_buf = (CHAR8 *)"m2:@0";
			capsule_buf_len = strlen(capsule_buf);
		}

		if (capsule_buf_len != 0 ) {
			error(L"Avb flow suffix %a doesn't equal to ABL suffix, reboot and update ABL.", slot_data->ab_suffix);
			ret = set_efi_variable(&loader_guid, IFWI_CAPSULE_UPDATE, capsule_buf_len + 1,
						   capsule_buf, TRUE, TRUE);
			if (EFI_ERROR(ret)) {
				error(L"Unable to set slot %a into %a", slot_data->ab_suffix, IFWI_CAPSULE_UPDATE);
				goto fail;
			}
			reboot_to_target(NORMAL_BOOT, EfiResetCold);
		}
	}
#else
	verify_result = avb_slot_verify(ops,
					requested_partitions,
					slot_suffix,
					flags,
					AVB_HASHTREE_ERROR_MODE_RESTART,
					&slot_data);
	ret = get_avb_result(slot_data,
				allow_verification_error,
				verify_result,
				&boot_state);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get avb result for boot");
		goto fail;
	}
#endif

	ret = android_query_image_from_avb_result(slot_data, "boot", &bootimage);
	if (EFI_ERROR(ret)) {
		avb_error("Cannot find android image partition!\n");
		goto fail;
	}

	ret = android_install_acpi_table_avb(slot_data);
	if (EFI_ERROR(ret)) goto fail;

	ret = avb_vbmeta_image_verify(slot_data->vbmeta_images[0].vbmeta_data,
			slot_data->vbmeta_images[0].vbmeta_size,
			&vbmeta_pub_key,
			&vbmeta_pub_key_len);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get the vbmeta_pub_key");
		goto fail;
	}

	ret = update_rot_data(bootimage, boot_state, slot_data);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to init rot params");
		goto fail;
	}

	set_boottime_stamp(TM_VERIFY_BOOT_DONE);

        /* install acpi tables before starting trusty */
        ret = setup_acpi_table(bootimage, boot_target);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"setup_acpi_table");
                return ret;
        }

#ifdef USE_TRUSTY
	if (boot_target == NORMAL_BOOT) {
		VOID *tosimage = NULL;
		ret = load_tos_image(&tosimage);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Load tos image failed");
			goto fail;
		}
		set_boottime_stamp(TM_LOAD_TOS_DONE);
		ret = start_trusty(tosimage);
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Unable to start trusty: stop");
			goto fail;
		}
		set_boottime_stamp(TM_PROCRSS_TRUSTY_DONE);
	}
#endif

	if (boot_state == BOOT_STATE_GREEN) {
		avb_update_stored_rollback_indexes_for_slot(ops, slot_data);
	}

	ret = start_boot_image(bootimage, boot_state, boot_target, slot_data, abl_cmd_line);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to start boot image");
		goto fail;
	}

fail:
	if (slot_data)
		avb_slot_verify_data_free(slot_data);

	return ret;
}

#ifdef FASTBOOT_FOR_NON_ANDROID
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
	enum boot_target target;
	void *efiimage, *bootimage;
	UINTN imagesize;

	InitializeLib(image, sys_table);

	if (!get_boot_device()) {
		// Get boot device failed
		error(L"Failed to find boot device");
		return EFI_NO_MEDIA;
        }

	for (;;) {
		log(L"Enter fastboot mode ...\n");
		fastboot_start(&bootimage, &efiimage, &imagesize, &target);
	}
	return EFI_SUCCESS;
}
#else //FASTBOOT_FOR_NON_ANDROID

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table)
{
	enum boot_target target;
	EFI_STATUS ret;

#ifndef __FORCE_FASTBOOT
	BOOLEAN oneshot = FALSE;
	CHAR16 *target_path = NULL;
	enum boot_target bcb_target;
#endif

	set_boottime_stamp(TM_EFI_MAIN);
	InitializeLib(image, sys_table);

#ifdef USE_UI
	ux_display_vendor_splash();
#endif

	target = check_command_line(image, cmd_buf, sizeof(cmd_buf) - 1);
	if (!get_boot_device()) {
		// Get boot device failed
		error(L"Failed to find boot device");
		return EFI_NO_MEDIA;
        }

#ifdef RPMB_STORAGE
	rpmb_storage_init();
#endif

	ret = slot_init();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Slot management initialization failed");
		return ret;
	}

#ifndef __FORCE_FASTBOOT
	debug(L"Before Check BCB target is %d", target);
	bcb_target = check_bcb(&target_path, &oneshot);
	/*The bootloader is expected to load and boot into recovery image upon seeting*/
	/*boot-fastboot in the BCB command. Recovery the parse the BCB message and*/
	/*switches to fastbootd mode*/
	if(oneshot == FALSE && bcb_target == FASTBOOT)
		bcb_target  = RECOVERY;
	debug(L"BCB target is %d", bcb_target);
	if (bcb_target == RECOVERY) {
		target = bcb_target;
	}
	debug(L"After Check BCB target is %d", target);
#endif

	debug(L"target=%d", target);

#ifdef RPMB_STORAGE
	if (target != CRASHMODE) {
		ret = rpmb_key_init();
		if (EFI_ERROR(ret))
			error(L"rpmb key init failure for osloader");
	}
#endif

#ifdef __FORCE_FASTBOOT
	ret = slot_init_use_misc();
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Slot management initialization failed by misc");
		return ret;
	}

	for (;;) {
#ifdef CRASHMODE_USE_ADB
		if (target == CRASHMODE) {
			log(L"Enter crash mode ...\n");
			enter_crashmode(&target);
			continue;
		}
#endif
		log(L"Enter fastboot mode ...\n");
		enter_fastboot_mode(&target);
	}
#else
	if (target == FASTBOOT) {
		ret = slot_init_use_misc();
		if (EFI_ERROR(ret)) {
			efi_perror(ret, L"Slot management initialization failed by misc");
			return ret;
		}
	}

	acpi_set_boot_target(target);

	for (;;) {
		switch (target) {
		case NORMAL_BOOT:
		case RECOVERY:
			set_boottime_stamp(TM_AVB_START);
			ret = avb_boot_android(target, cmd_buf);
			if (EFI_ERROR(ret))
				target = FASTBOOT;
			break;
		case UNKNOWN_TARGET:
#ifndef CRASHMODE_USE_ADB
		case CRASHMODE:
#endif
		case FASTBOOT:
			enter_fastboot_mode(&target);
			break;
#ifdef CRASHMODE_USE_ADB
		case CRASHMODE:
			enter_crashmode(&target);
			break;
#endif
		default:
			reboot_to_target(target, EfiResetCold);
		}
	}
#endif
	return EFI_SUCCESS;
}
#endif //FASTBOOT_FOR_NON_ANDROID
