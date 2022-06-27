/*
 * Copyright (c) 2014, Intel Corporation
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
#include <efilib.h>
#include <lib.h>
#include <vars.h>
#include <ui.h>
#include <security.h>

#include "uefi_utils.h"
#include "fastboot_oem.h"
#include "fastboot_ui.h"
#include "smbios.h"
#include "info.h"

static const ui_textline_t unlocked_headers[] = {
	{ &COLOR_WHITE,		"        Unlock bootloader?",			TRUE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"If you unlock the bootloader, you will",	FALSE },
	{ &COLOR_WHITE,		"be able to install custom operating",		FALSE },
	{ &COLOR_WHITE,		"system software on this device. A custom",	FALSE },
	{ &COLOR_WHITE,		"OS is not subject to the same level of",	FALSE },
	{ &COLOR_WHITE,		"testing as the original OS, and can cause",	FALSE },
	{ &COLOR_WHITE,		"your device and installed applications",	FALSE },
	{ &COLOR_WHITE,		"to stop working properly. Software",		FALSE },
	{ &COLOR_WHITE,		"integrity cannot be guaranteed with a",	FALSE },
	{ &COLOR_WHITE,		"custom OS so any data stored on the",		FALSE },
	{ &COLOR_WHITE,		"device while the bootloader is unlocked",	FALSE },
	{ &COLOR_WHITE,		"may be at risk.",				FALSE },
	{ &COLOR_WHITE,		"",						FALSE },

	{ &COLOR_WHITE,		"To prevent unauthorized access to your",	FALSE },
	{ &COLOR_WHITE,		"personal data, unlocking the bootloader",	FALSE },
	{ &COLOR_RED, 		"will also delete all personal data on",	FALSE },
	{ &COLOR_RED, 		"your device.",					FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ NULL, NULL, FALSE }
};

static ui_textline_t locked_headers[] = {
	{ &COLOR_WHITE,		"         Lock bootloader?", 			TRUE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ &COLOR_WHITE,		"If you lock the bootloader, you will", 	FALSE },
	{ &COLOR_WHITE,		"not be able to install custom operating",	FALSE },
	{ &COLOR_WHITE,		"system software on this device.",		FALSE },
	{ &COLOR_WHITE,		"",						FALSE },

	{ &COLOR_WHITE,		"To prevent unauthorized access to your",	FALSE },
	{ &COLOR_WHITE,		"personal data, locking the bootloader",	FALSE },
	{ &COLOR_RED, 		"will also delete all personal data on",	FALSE },
	{ &COLOR_RED, 		"your device.",					FALSE },
	{ &COLOR_WHITE,		"",						FALSE },
	{ NULL, NULL, FALSE }
};

static struct msg_for_state {
	const ui_textline_t *msg;
	enum device_state state;
} const FASTBOOT_UI_CONFIRM[] = {
	{ unlocked_headers,	UNLOCKED },
	{ locked_headers,	LOCKED }
};

static const char *DROID_IMG_NAME = "droid_operation";

/* Boot menu. */
static ui_boot_action_t BOOT_ACTIONS[] = {
	{ "start",		NULL,	NORMAL_BOOT },
	{ "restartbootloader",	NULL,	FASTBOOT },
	{ "recoverymode",	NULL,	RECOVERY },
	{ "reboot",		NULL,	NORMAL_BOOT },
	{ "power_off",		NULL,	POWER_OFF },
#ifdef CRASHMODE_USE_ADB
	{ "crashmode",		NULL,	CRASHMODE },
#endif
	{ NULL,			NULL,	UNKNOWN_TARGET }
};

static BOOLEAN fastboot_ui_initialized = FALSE;
static UINTN margin;
static UINTN swidth, sheight;
static UINTN area_x;
static UINTN area_y;
static ui_boot_menu_t *boot_menu;

static EFI_STATUS fastboot_ui_clear_dynamic_part(void)
{
	return ui_clear_area(area_x, area_y,
			     swidth - area_x,
			     sheight - area_y - margin);
}

static EFI_GRAPHICS_OUTPUT_BLT_PIXEL *fastboot_ui_default_color(void)
{
	return &COLOR_WHITE;
}

static const char *fastboot_ui_info_ifwi_version(void)
{
	return SMBIOS_GET_STRING(0, BiosVersion);
}

static const char *fastboot_ui_info_serial_number(void)
{
	char *serial = get_serial_number();
	return serial ? serial : "N/A";
}

static const char *fastboot_ui_info_secure_boot(void)
{
	return is_platform_secure_boot_enabled() ? "ENABLED" : "DISABLED";
}

static EFI_GRAPHICS_OUTPUT_BLT_PIXEL *fastboot_ui_info_secure_boot_color(void)
{
	return is_platform_secure_boot_enabled() ? &COLOR_GREEN : &COLOR_RED;
}

struct info_text_fun {
	const char *header;
	const char *(*get_value)(void);
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *(*get_color)(void);
} const FASTBOOT_INFOS[] = {
	{ "PRODUCT NAME",	info_product,			fastboot_ui_default_color },
	{ "VARIANT",		info_variant,			fastboot_ui_default_color },
	{ "HW-REVISION",	info_hw_revision,		fastboot_ui_default_color },
	{ "BOOTLOADER VERSION",	info_bootloader_version,	fastboot_ui_default_color },
	{ "IFWI VERSION",	fastboot_ui_info_ifwi_version,	fastboot_ui_default_color },
	{ "SERIAL NUMBER",	fastboot_ui_info_serial_number,	fastboot_ui_default_color },
	{ "SECURE BOOT",	fastboot_ui_info_secure_boot,	fastboot_ui_info_secure_boot_color },
	{ "LOCK STATE",		get_current_state_string,	get_current_state_color }
};

static const char *FASTBOOT_TITLE = "FASTBOOT MODE";

static UINTN fastboot_ui_info_draw(UINTN x, UINTN y, UINTN width, UINTN height)
{
	UINTN i, line_nb = ARRAY_SIZE(FASTBOOT_INFOS) + 2;
	ui_textline_t *lines;

	lines = AllocateZeroPool(sizeof(*lines) * (line_nb + 1));
	if (!lines)
		goto exit;

	lines[0].str = (char *)FASTBOOT_TITLE;
	lines[0].color = &COLOR_RED;
	lines[0].bold = TRUE;

	lines[1].str = "";

	for (i = 2; i < line_nb; i++) {
		const struct info_text_fun *info = &FASTBOOT_INFOS[i - 2];
		ui_textline_t *line = &lines[i];
		char *value;
		int len;

		line->color = info->get_color();
		if (!line->color) {
			error(L"Failed to get fastboot info line %d color", i);
			goto exit;
		}


		value = (char *)info->get_value();
		if (!value) {
			error(L"Failed to get fastboot info line %d value", i);
			goto exit;
		}

		len = strlen((CHAR8 *)info->header) + strlen((CHAR8 *)value) + 4;
		line->str = AllocatePool(len);
		if (!line->str) {
			error(L"Failed to allocate fastboot line %d buffer len=%d", i, len);
			goto exit;
		}

		len = efi_snprintf((CHAR8 *)line->str, len, (CHAR8 *)"%a - %a",
				   info->header, value);
		if (len < 0) {
			error(L"Failed to format fastboot info line %d", i);
			goto exit;
		}
	}

	ui_textarea_display_text(lines, ui_font_get_default(),
				 x, &y, width, height, NULL);

exit:
	if (lines) {
		for (i = 2; i < line_nb && lines[i].str; i++)
			FreePool(lines[i].str);
		FreePool(lines);
	}
	return y;
}

BOOLEAN fastboot_ui_confirm_for_state(enum device_state target)
{
	UINTN i;
	BOOLEAN result = FALSE;

	/* No way to ask for user confirmation, assume yes. */
	if (!fastboot_ui_initialized)
		return TRUE;

	for (i = 0; i < ARRAY_SIZE(FASTBOOT_UI_CONFIRM); i++)
		if (target == FASTBOOT_UI_CONFIRM[i].state) {
			fastboot_ui_clear_dynamic_part();
			result = ui_confirm(FASTBOOT_UI_CONFIRM[i].msg, swidth - area_x - margin,
					    sheight - area_y - margin, area_x, area_y);

			fastboot_ui_refresh();
		}

	return result;
}

void fastboot_ui_refresh(void)
{
	UINTN y = area_y;

	if (!fastboot_ui_initialized)
		return;

	fastboot_ui_clear_dynamic_part();
	ui_boot_menu_draw(boot_menu, area_x, &y, swidth - area_x - margin);
	y += 20;
	fastboot_ui_info_draw(area_x, y, swidth - area_x - margin,
			      sheight - y - margin);
}

EFI_STATUS fastboot_ui_init(void)
{
	ui_image_t *droid;
	UINTN width, height, x, y;
	EFI_STATUS ret = EFI_SUCCESS;

	ret = ui_init(&swidth, &sheight);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Init screen failed");
		return ret;
	}

	ui_clear_screen();

	/* Use large enough margin to not overlap ui_print/ui_error
	 * area. */
	margin = swidth * 4 / 100;
	ret = EFI_UNSUPPORTED;

	droid = ui_image_get(DROID_IMG_NAME);
	if (!droid) {
		efi_perror(EFI_OUT_OF_RESOURCES,
			   L"Unable to load '%a' image",
			   DROID_IMG_NAME);
		return EFI_OUT_OF_RESOURCES;
	}

	if (swidth > sheight) {	/* Landscape orientation. */
		width = (swidth / 2) - (2 * margin);
		height = droid->height * width / droid->width;
		x = margin;
		y = (sheight / 2) - (height / 2);
	} else {		/* Portrait orientation. */
		height = sheight / 3;
		width = droid->width * height / droid->height;
		x = (swidth / 2) - (width / 2);
		y = margin;
	}

	ret = ui_image_draw_scale(droid, x, y, width, height);
	if (EFI_ERROR(ret))
		return ret;

	if (swidth > sheight) {	/* Landscape orientation. */
		area_x = swidth / 2 + margin;
		area_y = y;
	} else {		/* Portrait orientation. */
		area_x = margin;
		area_y = sheight / 2;
	}

	boot_menu = ui_boot_menu_create(BOOT_ACTIONS);
	if (!boot_menu) {
		error(L"Failed to build boot menu");
		return EFI_OUT_OF_RESOURCES;
	}

	fastboot_ui_initialized = TRUE;

	fastboot_ui_refresh();

	return ret;
}

enum boot_target fastboot_ui_event_handler()
{
	ui_events_t event = EV_NONE;

	event = ui_read_input();
	if (event == EV_NONE)
		return UNKNOWN_TARGET;

	ui_wait_for_key_release();
	return ui_boot_menu_event_handler(boot_menu, event);
}

void fastboot_ui_destroy(void)
{
	ui_boot_menu_free(boot_menu);
	ui_print_clear();
	ui_display_vendor_splash();
	fastboot_ui_initialized = FALSE;
}
