/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors:  Jeremy Compostella <jeremy.compostella@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
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
#include <ui.h>

#define NOT_READY_USECS	(100 * 1000)

/* Time between calls to ReadKeyStroke to check if it is being actively held
 * Smaller stall values seem to result in false reporting of no key pressed
 * on several devices */
#define HOLD_KEY_STALL_TIME         500
#define HOLD_KEY_STALL_TIME_MAX     (10 * 1000)

extern EFI_GUID GraphicsOutputProtocol;

static BOOLEAN initialized = FALSE;

typedef struct graphic {
	EFI_GRAPHICS_OUTPUT_PROTOCOL *output;
	UINT32 width;
	UINT32 height;
	UINT32 mode;
} graphic_t;

static graphic_t graphic;

static ui_textarea_t *default_textarea = NULL;
static UINTN default_textarea_x;
static UINTN default_textarea_y;

static const char *VENDOR_IMG_NAME = "splash_intel";

static int get_hold_key_stall_time(void)
{
	EFI_STATUS ret;
	static unsigned long hold_key_stall_time;

	if (hold_key_stall_time)
		goto out;

	ret = get_efi_variable_long_from_str8(&loader_guid,
					     HOLD_KEY_STALL_TIME_VAR,
					     &hold_key_stall_time);
	if (EFI_ERROR(ret)) {
		debug(L"Couldn't read timeout variable; assuming default");
	} else {
		if (hold_key_stall_time > 0 &&
		    hold_key_stall_time < HOLD_KEY_STALL_TIME_MAX) {
			debug(L"hold_key_stall_time=%d ms", hold_key_stall_time);
			goto out;
		}
		debug(L"pathological key stall time, use default");
	}

	hold_key_stall_time = HOLD_KEY_STALL_TIME;
out:
	return hold_key_stall_time;
}

EFI_STATUS ui_init(UINTN *width_p, UINTN *height_p)
{
	UINT32 mode;
	UINTN info_size;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	EFI_STATUS ret;
	BOOLEAN last_succeed = FALSE;
	UINTN x, y, margin;
	ui_font_t *font;

	if (initialized) {
		*width_p = graphic.width;
		*height_p = graphic.height;
		return EFI_SUCCESS;
	}

	ret = LibLocateProtocol(&GraphicsOutputProtocol, (VOID **)&graphic.output);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Unable to locate graphics output protocol, graphic disabled");
		graphic.output = NULL;
		return ret;
	}

	if (is_run_on_kvm()) {
		/*
		 * When run on kvm, change mode may lead to incorrect display.
		 * use current mode instead of finding the best mode.
		 *
		 */
		graphic.mode = graphic.output->Mode->Mode;
		graphic.width = graphic.output->Mode->Info->HorizontalResolution;
		graphic.height = graphic.output->Mode->Info->VerticalResolution;
	} else {
		/* Set the best mode possible. */
		for (mode = 0 ; mode < graphic.output->Mode->MaxMode ; mode++) {
			ret = uefi_call_wrapper(graphic.output->QueryMode, 4, graphic.output,
						mode, &info_size, &info);

			if (last_succeed
			    && (graphic.width > info->HorizontalResolution
				|| graphic.height > info->VerticalResolution))
				continue;

			ret = uefi_call_wrapper(graphic.output->SetMode, 2, graphic.output, mode);
			if (EFI_ERROR(ret)) {
				debug(L"Failed to set mode=%d (%dx%d): %r", graphic.mode,
				      graphic.width, graphic.height, ret);
				continue;
			}

			last_succeed = TRUE;
			graphic.width = info->HorizontalResolution;
			graphic.height = info->VerticalResolution;
			graphic.mode = mode;
		}

		if (!last_succeed)
			return EFI_UNSUPPORTED;
	}

	if (!ui_font_get_default()) {
		error(L"Default font not available");
		return EFI_UNSUPPORTED;
	}

	/* Initialize log area */
	margin = min(graphic.width, graphic.height) / 10;
	if (!default_textarea) {
		font = ui_font_get("12x22");
		if (!font)
			return EFI_UNSUPPORTED;

		x = margin / font->cheight;
		y = (graphic.width - (2 * margin)) / font->cwidth;
		default_textarea = ui_textarea_create(x, y, font, &COLOR_YELLOW, NULL);
		if (!default_textarea) {
			efi_perror(EFI_OUT_OF_RESOURCES, L"Failed to build the textarea");
			return EFI_OUT_OF_RESOURCES;
		}

		default_textarea_x = margin;
		default_textarea_y = graphic.height - margin;
	}

	*width_p = graphic.width;
	*height_p = graphic.height;

	initialized = TRUE;

	return EFI_SUCCESS;
}

EFI_STATUS ui_display_vendor_splash(VOID)
{
	UINTN width, height, x, y, max_size;
	ui_image_t *vendor;

	if (!ui_is_ready())
		return EFI_UNSUPPORTED;

	ui_clear_screen();

	/* Vendor splash */
	vendor = ui_image_get(VENDOR_IMG_NAME);
	if (!vendor) {
		efi_perror(EFI_UNSUPPORTED, L"Unable to get '%a' image",
			   VENDOR_IMG_NAME);
		return EFI_UNSUPPORTED;
	}

	if (!vendor->width || !vendor->height) {
		efi_perror(EFI_UNSUPPORTED, L"'%a' image has invalid dimensions",
			   VENDOR_IMG_NAME);
		return EFI_UNSUPPORTED;
	}

	max_size = min(graphic.width, graphic.height) / 3;
	if (vendor->width > vendor->height) {
		width = max_size;
		height = vendor->height * width / vendor->width;
	} else {
		height = max_size;
		width = vendor->width * height / vendor->height;
	}

	x = (graphic.width / 2) - (width / 2);
	y = (graphic.height / 2) - (height / 2);

	return ui_image_draw_scale(vendor, x, y , width, height);
}

void ui_free(void)
{
	if (!default_textarea)
		return;

	ui_textarea_free(default_textarea);
	default_textarea = NULL;
}

BOOLEAN ui_is_ready()
{
	return initialized;
}

EFI_STATUS ui_clear_screen()
{
	if (!ui_is_ready())
		return EFI_UNSUPPORTED;

	return ui_clear_area(0, 0, graphic.width, graphic.height);
}

EFI_STATUS ui_fill_area(UINTN x, UINTN y, UINTN width, UINTN height,
			EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color)
{
	if (!ui_is_ready())
		return EFI_UNSUPPORTED;

	return uefi_call_wrapper(graphic.output->Blt, 10, graphic.output,
				 color, EfiBltVideoFill, 0, 0, x, y, width, height, 0);
}

EFI_STATUS ui_clear_area(UINTN x, UINTN y, UINTN width, UINTN height)
{
	EFI_STATUS ret;

	ret = ui_fill_area(x, y, width, height, &COLOR_BLACK);

	if (default_textarea)
		ret = ui_textarea_draw(default_textarea, default_textarea_x,
				       default_textarea_y);
	return ret;
}

EFI_STATUS ui_display_texts(const ui_textline_t **texts, UINTN x, UINTN y,
			    UINTN linesarea, UINTN colsarea) {
	EFI_STATUS ret;
	ui_textline_t *lines;
	UINTN line_nb = 0;
	UINTN i, j, pos;

	for (i = 0; texts[i]; i++)
		for (j = 0; texts[i][j].color && texts[i][j].str; j++)
			line_nb++;
	lines = AllocateZeroPool((line_nb + 1) * sizeof(ui_textline_t));
	if (!lines) {
		error(L"Unable to allocate textline array");
		return EFI_OUT_OF_RESOURCES;
	}
	for (i = 0, pos = 0; texts[i]; i++, pos += j)
		for (j = 0; texts[i][j].color; j++) {
			ret = memcpy_s(&lines[pos + j], sizeof(ui_textline_t), &texts[i][j], sizeof(*lines));
			if (EFI_ERROR(ret))
				goto out;
		}


	ret = ui_textarea_display_text(lines, ui_font_get_default(),
				       x, &y, colsarea, linesarea, NULL);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Unable to display text.");

	for (i = 0; i < line_nb; i++)
		debug(L"%a", lines[i].str);

out:
	FreePool(lines);
	return ret;
}

EFI_STATUS ui_draw_blt(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt, UINTN x, UINTN y,
		       UINTN width, UINTN height)
{
	EFI_STATUS ret;

	if (!graphic.output)
		return EFI_UNSUPPORTED;

	ret = uefi_call_wrapper(graphic.output->Blt, 10, graphic.output, blt, EfiBltBufferToVideo,
				0, 0, x, y, width, height, 0);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to display blt");

	return ret;
}

static char *build_str(CHAR16 *fmt, va_list args)
{
	CHAR16 buf[default_textarea ? default_textarea->row_nb : 200];
	char *str = NULL;
	UINTN len;

	if (!ui_is_ready())
		return NULL;

	len = VSPrint(buf, sizeof(buf), fmt, args);

	str = AllocatePool(len + 1);
	if (!str)
		return NULL;

	if (EFI_ERROR(str_to_stra((CHAR8 *)str, buf, len + 1))) {
		FreePool(str);
		return NULL;
	}

	str[len] = '\0';
	return str;
}

static void ui_internal_print(CHAR16 *fmt, va_list args, EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color)
{
	char *str;

	if (!ui_is_ready()) {
		VPrint(fmt, args);
		Print(L"\n");
		return;
	}

	str = build_str(fmt, args);
	if (!str)
		return;

	ui_textarea_newline(default_textarea, str, color, FALSE);
	ui_textarea_draw(default_textarea, default_textarea_x, default_textarea_y);
}

static BOOLEAN no_newline = FALSE;
static void ui_internal_print_n(CHAR16 *fmt, va_list args, EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color)
{
	char *str;

	if (!ui_is_ready()) {
		VPrint(fmt, args);
		return;
	}

	if (no_newline == FALSE) {
		no_newline = TRUE;
		ui_internal_print(fmt, args, color);
		return;
	}

	if (fmt[0] == 0x000a) {
		no_newline = FALSE;
	}

	str = build_str(fmt, args);
	if (!str)
		return;

	ui_textarea_n(default_textarea, str, color, FALSE);
	ui_textarea_draw(default_textarea, default_textarea_x, default_textarea_y);
}

void ui_print(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_internal_print(fmt, args, NULL);
	va_end(args);
}

void ui_info(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_internal_print(fmt, args, &COLOR_GREEN);
	va_end(args);
}

void ui_info_n(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_internal_print_n(fmt, args, &COLOR_GREEN);
	va_end(args);
}

void ui_warning(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_internal_print_n(fmt, args, NULL);
	va_end(args);
}

void ui_error(CHAR16 *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ui_internal_print(fmt, args, &COLOR_RED);
	va_end(args);
}

void ui_print_clear(void)
{
	if (!ui_is_ready())
		return;

	ui_textarea_clear(default_textarea);
}

ui_events_t ui_keycode_to_event(UINT16 keycode)
{
	switch (keycode) {
	case SCAN_UP:
	case SCAN_PAGE_UP:
	case SCAN_HOME:
	case SCAN_RIGHT:
		return EV_UP;
	case SCAN_DOWN:
	case SCAN_PAGE_DOWN:
	case SCAN_END:
	case SCAN_LEFT:
		return EV_DOWN;
#ifdef USE_POWER_BUTTON
		case SCAN_POWER:
			return EV_POWER;
#endif
	default:
		return EV_NONE;
	}
}

ui_events_t ui_read_input(void)
{
	EFI_INPUT_KEY key;
	EFI_STATUS ret;

	ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
				ST->ConIn, &key);

	if (ret != EFI_SUCCESS)
		return EV_NONE;

	return ui_keycode_to_event(key.ScanCode);
}

static BOOLEAN test_key(BOOLEAN check_code, ui_events_t event)
{
	EFI_INPUT_KEY key;
	EFI_STATUS ret = EFI_SUCCESS;
	BOOLEAN result = TRUE;

	uefi_call_wrapper(BS->Stall, 1, get_hold_key_stall_time() * 1000);

	ret = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
					ST->ConIn, &key);
	if (ret != EFI_SUCCESS) {
		debug(L"err=%r", ret);
		return FALSE;
	}

	if (check_code)
		result = (ui_keycode_to_event(key.ScanCode) == event);

	/* flush any stacked up key events in the queue before
	 * we sleep again */
	while (uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2,
				 ST->ConIn, &key) == EFI_SUCCESS) {
		/* spin */
	}

	return result;
}

BOOLEAN ui_enforce_key_held(UINT32 milliseconds, ui_events_t event)
{
	BOOLEAN ret = TRUE;
	UINT32 i;
	int stall_time = get_hold_key_stall_time();

	for (i = 0; i < (milliseconds / stall_time); i++) {
		ret = test_key(TRUE, event);
		if (!ret) {
			break;
		}
	}
	return ret;
}

void ui_wait_for_key_release(void)
{
	while (test_key(FALSE, 0)) { }
}

ui_events_t ui_wait_for_event(UINTN timeout_secs, ui_events_t expected)
{
	UINT64 timeout_left;

	timeout_left = timeout_secs * 1000000;

	ui_wait_for_key_release();
	do {
		ui_events_t event = ui_read_input();
		if (event != EV_NONE &&
		    (expected == EV_ANY || event == expected))
			return event;

		/* If we get here, either we had EFI_NOT_READY indicating
		 * no pending keystroke, EFI_DEVICE_ERROR, or some key
		 * we don't care about was pressed */
		uefi_call_wrapper(BS->Stall, 1, NOT_READY_USECS);
		timeout_left -= NOT_READY_USECS;
	} while (timeout_left || timeout_secs == 0);

	return EV_TIMEOUT;
}

ui_events_t ui_wait_for_input(UINTN timeout_secs)
{
	return ui_wait_for_event(timeout_secs, EV_ANY);
}

BOOLEAN ui_input_to_bool(UINTN timeout_secs, BOOLEAN timeout_true)
{
	ui_events_t ue;

	ue = ui_wait_for_input(timeout_secs);
	switch (ue) {
	case EV_UP:
		return TRUE;
	case EV_TIMEOUT:
		return timeout_true;
	default:
		return FALSE;
	}
}

UINT64 ui_get_blt_size(UINTN width, UINTN height)
{
	UINTN size = MultU64x32 ((UINT64) width, height);

	if (size > DivU64x32((UINTN) ~0, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL), NULL))
		return 0;

	return MultU64x32(size, sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
}

void ui_get_scaled_dimension(UINTN orig_width, UINTN orig_height,
			     UINTN max_width, UINTN max_height,
			     UINTN *width, UINTN *height)
{
	if (max_width == 0 && max_height != 0) {
		*width = orig_width * max_height / orig_height;
		*height = max_height;
		return;
	}

	if (max_height == 0 && max_width != 0) {
		*height = orig_height * max_width / orig_width;
		*width = max_width;
		return;
	}

	*height = max_height;
	*width = orig_width * max_height / orig_height;
	if (*width <= max_width)
		return;

	*height = orig_height * max_width / orig_width;
	*width = max_width;
}

/*
 * Bilinear interpolation:
 * f(x,y) = (1/(x2-x1)(y2-y1)) * (f(Q11)(x2-x)(y2-y) +
 *				f(Q21)(x-x1)(y2-y) +
 *				f(Q12)(x2-x)(y-y1) +
 *				f(Q22)(x-x1)(y-y1))
 */
void ui_bilinear_scale(unsigned char *s, unsigned char *d,
		       int sx, int sy, int dx, int dy,
		       int depth)
{
	double ratio_x = (double)(sx - 1) / dx;
	double ratio_y = (double)(sy - 1) / dy;
	int i, j, k;
	sx *= depth;
	for (i = 0; i < dy; i++ )
		for (j = 0; j < dx; j++) {
			double x = j * ratio_x;
			double y = i * ratio_y;
			int x1 = x;
			int x2 = x1 + 1;
			int y1 = y;
			int y2 = y1 + 1;
			for (k = 0; k < depth; k++) {
				d[j * depth + i * dx * depth + k] = (1 / ((x2 - x1) * (y2 - y1))) *
					(s[x1 * depth + y1 * sx + k] * (x2 - x) * (y2 - y) +
					 s[x2 * depth + y1 * sx + k] * (x - x1) * (y2 - y) +
					 s[x1 * depth + y2 * sx + k] * (x2 - x) * (y - y1) +
					 s[x2 * depth + y2 * sx + k] * (x - x1) * (y - y1));
			}
		}
}

