/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
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

#include <ui.h>

#include "lib.h"
#include "ux.h"
#include "vars.h"
#ifdef CRASHMODE_USE_ADB
#include "adb.h"
#endif

#ifdef BUILD_ANDROID_THINGS
#define FIRST_TIMEOUT_SECS	1
#else
#define FIRST_TIMEOUT_SECS	5
#endif
#define SECOND_TIMEOUT_SECS	30

#define PRESS_TO_PAUSE_FMT		"Press %a to pause %a"
#define PRESS_TO_CONTINUE_FMT		"Press %a to continue"


static const ui_textline_t red_state[] = {
	{ &COLOR_LIGHTGRAY,	"Your device has failed verification.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"It is corrupt. It can't be trusted ",	FALSE },
	{ &COLOR_LIGHTGRAY,	"and will not boot.",			FALSE },
	{ NULL, NULL, FALSE}
};

static const ui_textline_t bad_recovery[] = {
	{ &COLOR_LIGHTGRAY,	"Your device has failed verification",	FALSE },
	{ &COLOR_LIGHTGRAY,	"of Recovery Console. It is corrupt.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"It can't be trusted and will not",	FALSE },
	{ &COLOR_LIGHTGRAY,	"boot.",				FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t device_altered_unlocked[] = {
	{ &COLOR_LIGHTGRAY, 	"Your device has been unlocked and",	FALSE },
	{ &COLOR_LIGHTGRAY, 	"can't be trusted.",			FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t secure_boot_off[] = {
	{ &COLOR_LIGHTGRAY,	"Your device has been altered",		FALSE },
	{ &COLOR_LIGHTGRAY,	"from its factory configuration.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"and is no longer in a locked state",	FALSE },
	{ &COLOR_LIGHTGRAY,	"due to UEFI Secure Boot being",	FALSE },
	{ &COLOR_LIGHTGRAY,	"disabled",				FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"If you were not responsible for",	FALSE },
	{ &COLOR_LIGHTGRAY,	"these changes, the security of",	FALSE },
	{ &COLOR_LIGHTGRAY,	"your device may be at risk.",		FALSE },
	{ NULL, NULL, FALSE }
};

static const ui_textline_t device_untrusted_bootimage[] = {
	{ &COLOR_LIGHTGRAY,	"Your device has loaded a different",	FALSE },
	{ &COLOR_LIGHTGRAY,	"operating system.",			FALSE },
	{ NULL, NULL, FALSE }
};

#define CRASHMODE_TIMEOUT_SECS	(5 * 60)
static const ui_textline_t crash_event_message[] = {
	{ &COLOR_LIGHTRED,	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY,	"Multiple crash events have been",	FALSE },
	{ &COLOR_LIGHTGRAY,	"reported.",				FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"Use the above menu to select",		FALSE },
	{ &COLOR_LIGHTGRAY,	"the next boot option.",		FALSE },
	{ &COLOR_LIGHTGRAY,	"If the problem persists, please",	FALSE },
	{ &COLOR_LIGHTGRAY,	"contact the technical assistance.",	FALSE },
#ifndef CRASHMODE_USE_ADB
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"The device will power off in 5",	FALSE },
	{ &COLOR_LIGHTGRAY,	"minutes.",				FALSE },
#endif
	{ NULL, NULL, FALSE }
};
static const ui_textline_t not_bootable_message[] = {
	{ &COLOR_LIGHTRED,	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY,	"No valid boot image found.",		FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"Use the above menu to select",		FALSE },
	{ &COLOR_LIGHTGRAY,	"the next boot option.",		FALSE },
	{ &COLOR_LIGHTGRAY,	"If the problem persists, please",	FALSE },
	{ &COLOR_LIGHTGRAY,	"contact the technical assistance.",	FALSE },
#ifndef CRASHMODE_USE_ADB
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"The device will power off in 5",	FALSE },
	{ &COLOR_LIGHTGRAY,	"minutes.",				FALSE },
#endif
	{ NULL, NULL, FALSE }
};

static const ui_textline_t live_boot_message[] = {
	{ &COLOR_LIGHTRED,	"WARNING:",				TRUE },
	{ &COLOR_LIGHTGRAY,	"Live boot is used for debug purpose.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"",					FALSE },
	{ &COLOR_LIGHTGRAY,	"Your device is in a unlocked state",	FALSE },
	{ &COLOR_LIGHTGRAY,	"due to live boot.",			FALSE },
	{ &COLOR_LIGHTGRAY,	"Lock/unlcok state will not be saved.",	FALSE },
	{ NULL, NULL, FALSE }
};

#ifdef CRASHMODE_USE_ADB
static const ui_textline_t adb_message[] = {
	{ &COLOR_LIGHTGRAY,	"",						FALSE },
	{ &COLOR_LIGHTGRAY,	"A minimal implementation of adb is running",	FALSE },
	{ &COLOR_LIGHTGRAY,	"and allows reboot [TARGET] and pull commands:",FALSE },
	{ &COLOR_LIGHTGRAY,	"- ram:[:START[:LENGTH]]",			FALSE },
	{ &COLOR_LIGHTGRAY,     "- vmcore[:START[:LENGTH]]",			FALSE },
	{ &COLOR_LIGHTGRAY,	"- acpi:TABLE_NAME",				FALSE },
	{ &COLOR_LIGHTGRAY,	"- part:PART_NAME[:START[:LENGTH]]",		FALSE },
	{ &COLOR_LIGHTGRAY,	"- factory-part:PART_NAME[:START[:LENGTH]]",	FALSE },
	{ &COLOR_LIGHTGRAY,	"- mbr",					FALSE },
	{ &COLOR_LIGHTGRAY,	"- gpt-header",					FALSE },
	{ &COLOR_LIGHTGRAY,	"- gpt-parts",					FALSE },
	{ &COLOR_LIGHTGRAY,	"- gpt-factory-header",				FALSE },
	{ &COLOR_LIGHTGRAY,	"- gpt-factory-parts",				FALSE },
	{ &COLOR_LIGHTGRAY,	"- efivar:VAR_NAME[:GUID]",			FALSE },
	{ &COLOR_LIGHTGRAY,	"- bert-region",				FALSE },
	{ &COLOR_LIGHTGRAY,	"START and LENGTH are hexadecimal strings.",	FALSE },
	{ &COLOR_LIGHTGRAY,	"'ram' output file is an Android sparse file.",	FALSE },
	{ NULL, NULL, FALSE }
};
#endif

static const struct ux_prompt {
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
	const ui_textline_t *text;
} UX_PROMPT[MAX_ERROR_CODE] = {
	[RED_STATE_CODE]		=	{ &COLOR_RED,		red_state },
	[BAD_RECOVERY_CODE]		=	{ &COLOR_RED,		bad_recovery },
	[DEVICE_UNLOCKED_CODE]		=	{ &COLOR_ORANGE,	device_altered_unlocked },
	[SECURE_BOOT_CODE]		=	{ &COLOR_ORANGE,	secure_boot_off },
	[BOOTIMAGE_UNTRUSTED_CODE]	=	{ &COLOR_YELLOW,	device_untrusted_bootimage},
	[CRASH_EVENT_CODE]		=	{ &COLOR_LIGHTRED,	crash_event_message},
	[NOT_BOOTABLE_CODE]		=	{ &COLOR_LIGHTRED,	not_bootable_message},
	[LIVE_BOOT_CODE]		=	{ &COLOR_ORANGE,	live_boot_message}
};

static const char *VENDOR_IMG_NAME = "splash_intel";
static const char *LOW_BATTERY_IMG_NAME = "low_battery";
static const char *EMPTY_BATTERY_IMG_NAME = "empty_battery";

static UINTN swidth;
static UINTN sheight;
static UINTN wmargin;
static UINTN hmargin;

static EFI_STATUS ux_init_screen() {
	static BOOLEAN initialized;
	EFI_STATUS ret;

	if (!initialized) {
		uefi_call_wrapper(ST->ConOut->Reset, 2, ST->ConOut, FALSE);
	        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
				  EFI_WHITE | EFI_BACKGROUND_BLACK);
		uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);
	        uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
		initialized = TRUE;
	}

	ret = ui_init(&swidth, &sheight);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to setup the graphical mode");
		return ret;
	}

	/* Use a 5 % screen margin. */
	wmargin = swidth / 20;
	hmargin = sheight / 20;

	return EFI_SUCCESS;
}

static ui_textline_t *build_error_code_text(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *ecolor,
					    UINT32 error_code)
{
	static char buf[26];
	static ui_textline_t code_text[] = {
		{ NULL, buf, TRUE },
		{ &COLOR_WHITE, "", FALSE },
		{ NULL, NULL, FALSE }
	};

	code_text[0].color = ecolor;
	efi_snprintf((CHAR8 *)buf, sizeof(buf),
		     (CHAR8 *)"BOOTLOADER ERROR CODE %02x", error_code);

	return code_text;
}

static EFI_STATUS display_text(UINT32 error_code,
			       EFI_GRAPHICS_OUTPUT_BLT_PIXEL *ecolor,
			       const ui_textline_t *text1,
			       const ui_textline_t *text2,
			       const ui_textline_t *text3)
{
	UINTN width, height, x, y, linesarea, colsarea;
	ui_image_t *vendor;
	EFI_STATUS ret;
	const ui_textline_t *texts[] =
		{ build_error_code_text(ecolor, error_code),
		  text1, text2, text3,
		  NULL };

	ui_clear_screen();

	vendor = ui_image_get(VENDOR_IMG_NAME);
	if (!vendor) {
		efi_perror(EFI_UNSUPPORTED, L"Unable to load '%a' image",
			   VENDOR_IMG_NAME);
		return EFI_UNSUPPORTED;
	}

	if (swidth > sheight) {	/* Landscape orientation. */
		/* Display splash scaled on the left half of the screen,
		 * text area on the right */
		width = (swidth / 2) - (2 * wmargin);
		height = vendor->height * width / vendor->width;
		y = (sheight / 2) - (height / 2);
		ui_image_draw_scale(vendor, wmargin, y , width, height);
		x = swidth / 2 + wmargin;
	} else {		/* Portrait orientation. */
		/* Display splash on the top third of the screen,
		 * text area below it */
		height = sheight / 3;
		width = vendor->width * height / vendor->height;
		x = (swidth / 2) - (width / 2);
		y = hmargin;
		ui_image_draw_scale(vendor, x, y , width, height);
		y += height + hmargin;
	}

	colsarea = swidth - x - wmargin;
	linesarea = sheight - y - hmargin;

	ret = ui_display_texts(texts, x, y, linesarea, colsarea);
	if (EFI_ERROR(ret))
		return ret;

	return EFI_SUCCESS;
}

static EFI_STATUS clear_text() {
	if (swidth > sheight)	/* Landscape orientation. */
		return ui_clear_area(swidth / 2, hmargin,
				     swidth / 2, sheight - (2 * hmargin));
	/* Portrait orientation. */
	return ui_clear_area(0, sheight / 3 + hmargin,
			     swidth, sheight - (sheight / 3) - hmargin);
}

#define HASH_FORMAT	"%02x%02x-%02x%02x-%02x%02x"
#define MIN_HASH_SIZE	6

static const ui_textline_t *format_hash(UINT8 *hash, UINTN hash_size) {
	static char buf[19];
	static const ui_textline_t hash_text[] = {
		{ &COLOR_WHITE, buf, FALSE },
		{ NULL, NULL, FALSE }
	};
	int len;

	if (hash_size < MIN_HASH_SIZE)
		return NULL;

	len = efi_snprintf((CHAR8 *)buf, sizeof(buf),
			   (CHAR8 *)"ID: " HASH_FORMAT,
			   hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]);
	if (len != sizeof(buf) - 1)
		return NULL;

	return hash_text;
}

static const ui_textline_t empty_text[] = {
	{ NULL, NULL, FALSE }
};

enum boot_target ux_prompt_user(enum ux_error_code code, BOOLEAN power_off, UINT8 boot_state,
				UINT8 *hash, UINTN hash_size)
{
#ifdef USE_POWER_BUTTON
	ui_events_t expected = EV_POWER;
	CHAR8 *button = (CHAR8 *)"Power";
#else
	ui_events_t expected = EV_UP;
	CHAR8 *button = (CHAR8 *)"Volume Up";
#endif
	CHAR8 *boot = (CHAR8 *)(power_off ? "shutdown" : "boot");
	CHAR8 msg[max(sizeof(PRESS_TO_PAUSE_FMT), sizeof(PRESS_TO_CONTINUE_FMT)) +
		  strlen(button) + strlen(boot) + 1];
	ui_textline_t footer_text[] = {
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_LIGHTGRAY, "Please contact customer support",	FALSE },
		{ &COLOR_LIGHTGRAY, "from your device's manufacturer.",	FALSE },
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_GREEN, (char *)msg, TRUE },
		{ &COLOR_GREEN, NULL, TRUE },
		{ NULL, NULL, FALSE }
	};
	CHAR8 *fmt = (CHAR8 *)PRESS_TO_PAUSE_FMT;
	const ui_textline_t *text = empty_text;
	const struct ux_prompt *prompt;
	enum boot_target bt = power_off ? POWER_OFF : NORMAL_BOOT;

	if (code <= MIN_ERROR_CODE || code >= MAX_ERROR_CODE)
		return bt;

	prompt = &UX_PROMPT[code];

	if (EFI_ERROR(ux_init_screen()))
		return bt;

	if (hash) {
		text = format_hash(hash, hash_size);
		if (!text) {
			error(L"Failed to format hash");
			text = empty_text;
		}
	}

	if (boot_state == BOOT_STATE_RED) {
#ifdef USERDEBUG
		msg[0] = '\0';
		bt = CRASHMODE;
		display_text(code, prompt->color, prompt->text, text, footer_text);
#else
		footer_text[4].str = "BOOT_STATE is RED but allow to boot anyway on eng builds!";
		display_text(code, prompt->color, empty_text, text, footer_text);
#endif
#ifdef BUILD_ANDROID_THINGS
		ui_wait_for_event(FIRST_TIMEOUT_SECS, EV_TIMEOUT);
#else
		ui_wait_for_event(SECOND_TIMEOUT_SECS, EV_TIMEOUT);
#endif
		goto out;
	}

	efi_snprintf(msg, sizeof(msg), fmt, button, boot);

	display_text(code, prompt->color, prompt->text, text, footer_text);
	if (ui_wait_for_event(FIRST_TIMEOUT_SECS, expected) == EV_TIMEOUT)
		goto out;

	fmt = (CHAR8 *)PRESS_TO_CONTINUE_FMT;
	efi_snprintf(msg, sizeof(msg), fmt, button);

	display_text(code, prompt->color, prompt->text, text, footer_text);
	ui_wait_for_event(SECOND_TIMEOUT_SECS, expected);

out:
	clear_text();
	return bt;
}

static const char *CRASH_IMG_NAME = "crash_event";
static ui_boot_action_t BOOT_ACTIONS[] = {
	{ "start",		NULL,	NORMAL_BOOT },
	{ "bootloader",		NULL,	FASTBOOT },
	{ "recoverymode",	NULL,	RECOVERY },
	{ "reboot",		NULL,	NORMAL_BOOT },
	{ "power_off",		NULL,	POWER_OFF },
	{ NULL,			NULL,	UNKNOWN_TARGET }
};

enum boot_target ux_prompt_user_for_boot_target(enum ux_error_code code) {
	ui_image_t *img;
	ui_boot_menu_t *menu = NULL;
	UINTN width, height, img_x, img_y, area_x, area_y, colsarea, linesarea;
	EFI_STATUS ret = EFI_SUCCESS;
	enum boot_target target;
#ifdef CRASHMODE_USE_ADB
#ifdef USER
#error "adb in crashmode MUST be disabled on a USER build"
#endif

	BOOLEAN adb_initialized = FALSE;
	ui_textline_t *texts[4];
	ui_textline_t crashmode_text[] = {
		{ &COLOR_RED, "CRASHMODE", TRUE },
		{ &COLOR_WHITE, "", FALSE },
		{ NULL, NULL, FALSE }
	};

	if (code != NO_ERROR_CODE) {
		texts[0] = build_error_code_text(UX_PROMPT[code].color, code);
		texts[1] = (ui_textline_t *)UX_PROMPT[code].text;
		texts[2] = (ui_textline_t *)adb_message;
		texts[3] = NULL;
	} else {
		texts[0] = crashmode_text;
		texts[1] = (ui_textline_t *)adb_message;
		texts[2] = NULL;
	}
#else
	(void)code;	/* Unused parameter.  */
	const ui_textline_t *texts[] = { build_error_code_text(&COLOR_LIGHTRED, CRASH_EVENT_CODE),
					 UX_PROMPT[CRASH_EVENT_CODE].text, NULL };
#endif

	ret = ux_init_screen();
	if (EFI_ERROR(ret))
		/* User won't be able to make a choice.  Assume normal
		   boot flow.  */
		goto error;

	ui_clear_screen();

	ret = EFI_UNSUPPORTED;

	img = ui_image_get(CRASH_IMG_NAME);
	if (!img) {
		efi_perror(EFI_OUT_OF_RESOURCES,
			   L"Unable to load '%a' image",
			   CRASH_IMG_NAME);
		goto error;
	}

	if (swidth > sheight) {	/* Landscape orientation. */
		/* Display "failure" image scaled on the left half of
		 * the screen, boot menu on the right followed by
		 * the explanation text.  */
		width = (swidth / 2) - (2 * wmargin);
		height = img->height * width / img->width;
		img_x = wmargin;
		img_y = area_y = (sheight / 2) - (height / 2);
		area_x = img_x + swidth / 2;
	} else {		/* Portrait orientation. */
		/* Display "failure" image on the top third of the
		 * screen, boot menu below it followed by the
		 * explanation text.  */
		height = sheight / 3;
		width = img->width * height / img->height;
		img_x = (swidth / 2) - (width / 2);
		img_y = hmargin;
		area_x = wmargin;
		area_y = img_y + height + hmargin;
	}
	linesarea = sheight - area_y - hmargin;
	colsarea = swidth - area_x - wmargin;

	ret = ui_image_draw_scale(img, img_x, img_y, width, height);
	if (EFI_ERROR(ret))
		goto error;

	menu = ui_boot_menu_create(BOOT_ACTIONS);
	if (!menu) {
		error(L"Failed to build boot menu");
		goto error;
	}

	ret = ui_boot_menu_draw(menu, area_x, &area_y, colsarea);
	if (EFI_ERROR(ret))
		goto error;

	area_y += hmargin;
	linesarea = sheight - area_y - hmargin;

	ret = ui_display_texts((const ui_textline_t **)texts, area_x, area_y, linesarea, colsarea);
	if (EFI_ERROR(ret))
		goto error;

	/* In case user still holding it from answering a UX prompt
	 * or magic key */
	ui_wait_for_key_release();

	/* Prevent the device to reboot because of another watchdog */
	ret = uefi_call_wrapper(BS->SetWatchdogTimer, 4, 0, 0, 0, NULL);
	if (EFI_ERROR(ret) && ret != EFI_UNSUPPORTED) {
		efi_perror(ret, L"Couldn't disable watchdog timer");
		/* Might as well continue even though this failed ... */
	}

#ifdef CRASHMODE_USE_ADB
	ret = adb_init();
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to initialize adb, continue without adb support");
	else {
		debug(L"adb implementation is initialized");
		adb_initialized = TRUE;
	}
#endif

	while (1) {
#ifdef CRASHMODE_USE_ADB
		if (adb_initialized) {
			ret = adb_run();
			if (EFI_ERROR(ret))
				break;

			target = adb_get_boot_target();
			if (target != UNKNOWN_TARGET)
				break;
		}

		target = ui_boot_menu_event_handler(menu, ui_read_input());
		if (target != UNKNOWN_TARGET)
			break;
#else
		UINTN timeout = CRASHMODE_TIMEOUT_SECS;
		for (;;) {
			target = ui_boot_menu_event_handler(menu, ui_read_input());
			if (target != UNKNOWN_TARGET)
				break;
			uefi_call_wrapper(BS->Stall, 1, 1000000);
			timeout--;
			if (timeout == 0)
				halt_system();
		}
#endif
	}

#ifdef CRASHMODE_USE_ADB
	if (adb_initialized)
		adb_exit();
#endif
	if (target != UNKNOWN_TARGET) {
		ui_boot_menu_free(menu);
		ui_clear_screen();
		return target;
	}

	halt_system();		/* Timer expired, turn-off the device. */

error:
	if (menu)
		ui_boot_menu_free(menu);

	return NORMAL_BOOT;
}


VOID ux_display_img_battery(const char *battery_img_name, UINTN delay) {
	ui_image_t *battery;
	EFI_STATUS ret;

	ret = ux_init_screen();
	if (EFI_ERROR(ret))
		return;

	ui_clear_screen();

	battery = ui_image_get(battery_img_name);
	if (!battery) {
		efi_perror(EFI_NOT_FOUND, L"Failed to get '%a' image",
			   battery_img_name);
		return;
	}

	ret = ui_image_draw(battery, (swidth / 2) - (battery->width / 2),
			    (sheight / 2) - (battery->height / 2));
	if (EFI_ERROR(ret))
		return;

	pause(delay);
}

VOID ux_display_low_battery(UINTN delay) {
	ux_display_img_battery(LOW_BATTERY_IMG_NAME, delay);
}

VOID ux_display_empty_battery(VOID) {
	ux_display_img_battery(EMPTY_BATTERY_IMG_NAME, 0);
}

VOID ux_display_vendor_splash(VOID) {

	if (get_display_splash()) {
		if (EFI_ERROR(ux_init_screen()))
			return;
		ui_display_vendor_splash();
		log(L"vendor splash shown\n");
	}
}
