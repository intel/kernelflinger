/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author:  Jeremy Compostella <jeremy.compostella@intel.com>
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

#ifndef _UI_H_
#define _UI_H_

#include <efi.h>
#include <targets.h>
#include "ui.h"

/* Colors */
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_BLACK;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_WHITE;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_LIGHTGRAY;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_LIGHTRED;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_YELLOW;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_RED;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_GREEN;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_HIGHLIGHT;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL	COLOR_ORANGE;

/* Image */
typedef struct image {
	const char *name;
	const UINT8 *data;
	const UINTN size;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt;
	UINTN width;
	UINTN height;
} ui_image_t;

EFI_STATUS ui_image_draw(ui_image_t *image, UINTN x, UINTN y);
EFI_STATUS ui_image_draw_scale(ui_image_t *image, UINTN x,
			       UINTN y, UINTN width, UINTN height);
ui_image_t *ui_image_get(const char *name);

/* Font */
typedef struct ui_font {
	char *name;
	UINTN width;
	UINTN height;
	UINTN cwidth;
	UINTN cheight;
	unsigned char *texture;
} ui_font_t;

EFI_STATUS ui_font_init(void);
ui_font_t *ui_font_get_default(void);
ui_font_t *ui_font_get(char *name);
extern ui_font_t ui_fonts[];
extern UINTN ui_fonts_nb;

/* Textarea */
typedef struct textline {
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
	char *str;
	BOOLEAN bold;
} ui_textline_t;

typedef struct ui_textarea {
	UINTN line_nb;
	UINTN row_nb;
	ui_textline_t *text;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *bg_color;
	ui_font_t *font;
	INTN current;
	UINTN width;
	UINTN height;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt;
} ui_textarea_t;

ui_textarea_t *ui_textarea_create(UINTN line_nb, UINTN row_nb, ui_font_t *font,
				  EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color,
				  EFI_GRAPHICS_OUTPUT_BLT_PIXEL *bg_color);
EFI_STATUS ui_textarea_display_text(const ui_textline_t *text, ui_font_t *font,
				    UINTN x, UINTN *y, UINTN width, UINTN height,
				    EFI_GRAPHICS_OUTPUT_BLT_PIXEL *bg_color);
void ui_textarea_free(ui_textarea_t *textarea);
void ui_textarea_clear(ui_textarea_t *textarea);
void ui_textarea_set_line(ui_textarea_t *textarea, UINTN line_nb, char *str,
			  EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color, BOOLEAN bold);
void ui_textarea_set_line_n(ui_textarea_t *textarea, UINTN line_nb, char *str,
		EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color, BOOLEAN bold);
void ui_textarea_newline(ui_textarea_t *textarea, char *str,
			 EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color, BOOLEAN bold);
void ui_textarea_n(ui_textarea_t *textarea, char *str,
		EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color, BOOLEAN bold);
EFI_STATUS ui_textarea_draw_scale(ui_textarea_t *textarea, UINTN x, UINTN *y,
				  UINTN width, UINTN height);
EFI_STATUS ui_textarea_draw(ui_textarea_t *textarea, UINTN x, UINTN y);

/* EFI Scan codes */
#ifdef USE_POWER_BUTTON
#define SCAN_POWER CHAR_CARRIAGE_RETURN
#endif

/* Events */
typedef enum ui_events {
	EV_NONE,
	EV_ANY,
	EV_UP,
	EV_DOWN,
	EV_TIMEOUT,
#ifdef USE_POWER_BUTTON
	EV_POWER
#endif
} ui_events_t;
ui_events_t ui_keycode_to_event(UINT16 keycode);
ui_events_t ui_read_input(void);
BOOLEAN ui_enforce_key_held(UINT32 milliseconds, ui_events_t event);
void ui_wait_for_key_release(void);
ui_events_t ui_wait_for_event(UINTN timeout_secs, ui_events_t expected);
ui_events_t ui_wait_for_input(UINTN timeout_secs);
BOOLEAN ui_input_to_bool(UINTN timeout_secs, BOOLEAN timeout_true);

/* Boot menu */
typedef struct ui_boot_action {
	const char *img_name;
	ui_image_t *image;
	enum boot_target target;
} ui_boot_action_t;
typedef struct ui_boot_menu {
	ui_boot_action_t *actions;
	UINTN action_nb;
	UINTN cur;
	UINTN x;
	UINTN y;
	UINTN max_width;
} ui_boot_menu_t;
ui_boot_menu_t *ui_boot_menu_create(ui_boot_action_t *actions);
UINTN ui_boot_menu_draw(ui_boot_menu_t *menu, UINTN x, UINTN *y, UINTN max_width);
enum boot_target ui_boot_menu_event_handler(ui_boot_menu_t *menu, ui_events_t event);
void ui_boot_menu_free(ui_boot_menu_t *menu);

/* Confirm UX */
BOOLEAN ui_confirm(const ui_textline_t *text, UINTN width, UINTN height,
		   UINTN x, UINTN y);

/* Screen / shared */
EFI_STATUS ui_init(UINTN *width, UINTN *height);
BOOLEAN ui_is_ready();
void ui_free(void);
EFI_STATUS ui_display_vendor_splash(VOID);
EFI_STATUS ui_fill_area(UINTN x, UINTN y, UINTN width, UINTN height,
			EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color);
EFI_STATUS ui_clear_area(UINTN x, UINTN y, UINTN width, UINTN height);
EFI_STATUS ui_clear_screen();
EFI_STATUS ui_display_texts(const ui_textline_t **texts, UINTN x, UINTN y,
			    UINTN linesarea, UINTN colsarea);
EFI_STATUS ui_draw_blt(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt, UINTN x, UINTN y,
		       UINTN width, UINTN height);
void ui_print(CHAR16 *fmt, ...);
void ui_info(CHAR16 *fmt, ...);
void ui_info_n(CHAR16 *fmt, ...);
void ui_warning(CHAR16 *fmt, ...);
void ui_error(CHAR16 *fmt, ...);
void ui_print_clear(void);
void ui_get_scaled_dimension(UINTN orig_width, UINTN orig_heigth,
			     UINTN max_width, UINTN max_height,
			     UINTN *width, UINTN *height);
UINT64 ui_get_blt_size(UINTN width, UINTN height);
void ui_bilinear_scale(unsigned char *s, unsigned char *d,
		       int sx, int sy, int dx, int dy,
		       int depth);

#endif  /* _UI_H_ */
