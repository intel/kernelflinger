/*
 * Copyright (c) 2022, Intel Corporation
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

#include <ui.h>

#include "lib.h"
#include "vars.h"

static const char *VENDOR_IMG_NAME = "splash_intel";

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

static EFI_STATUS installer_display_text()
{
	UINTN width, height, x, y, linesarea, colsarea;
	ui_image_t *vendor;
	EFI_STATUS ret;
	ui_textline_t ui_texts[] = {
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_LIGHTRED, "Celadon Installer Notice:",		  TRUE },
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_YELLOW, "Warning: You are installing celadon.",  FALSE },
		{ &COLOR_YELLOW, "All data on device will be destroyed!", FALSE },
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_LIGHTGRAY, "To continue installing, press one of the following key:",	FALSE },
		{ &COLOR_LIGHTRED, "UP/PG UP/RIGHT/HOME",	TRUE },
		{ &COLOR_WHITE, "", FALSE },
		{ &COLOR_LIGHTGRAY, "To quit press one of the following key or wait timeout",	FALSE },
		{ &COLOR_LIGHTRED, "DOWN/PG DOWN/LEFT/END",	TRUE },
		{ &COLOR_WHITE, "", FALSE },
		{ NULL, NULL, FALSE }
	};
	ui_textline_t *texts[2] =  {ui_texts, NULL};

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

	ret = ui_display_texts((const ui_textline_t **)&texts, x, y, linesarea, colsarea);
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

#define TIMEOUT_SECS 30

EFI_STATUS ux_prompt_user_confirm()
{
	EFI_STATUS ret;
	ui_events_t event;

	if (is_running_on_kvm()) {
		info(L"installer runs on KVM, skip user confirm");
		return EFI_SUCCESS;
	}

	ret = ux_init_screen();
	if (EFI_ERROR(ret))
		return ret;

	ret = installer_display_text();
	if (EFI_ERROR(ret))
		return ret;

	event = ui_wait_for_input(TIMEOUT_SECS);
	debug(L"key = %d", event);
	if(event != EV_UP) {
		info(L"Installing is stopped by user or timeout(30s)");
		goto out;
	}

	ui_clear_screen();

	return EFI_SUCCESS;
out:
	clear_text();
	return EFI_UNSUPPORTED;
}
