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
#include <upng.h>

#include "res/img_res.h"

ui_image_t *ui_image_get(const char *name)
{
	unsigned int i;
	EFI_STATUS ret;
	ui_image_t *img = NULL;

	for (i = 0 ; i < ARRAY_SIZE(ui_images) ; i++)
		if (!strcmp((CHAR8 *)ui_images[i].name, (CHAR8 *)name))
			break;
	if (i == ARRAY_SIZE(ui_images))
		return NULL;

	img = &ui_images[i];
	if (!img->blt) {
		ret = upng_load(img->data, img->size,
				&img->blt, &img->width, &img->height);
		if (EFI_ERROR(ret))
			efi_perror(ret, L"Failed to load image %s",
				   name);
	}

	return img->blt ? img : NULL;
}

EFI_STATUS ui_image_draw(ui_image_t *image, UINTN x, UINTN y)
{
	EFI_STATUS ret;

	ret = ui_draw_blt(image->blt, x, y, image->width, image->height);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"Failed to display image %a", image->name);

	return ret;
}

EFI_STATUS ui_image_draw_scale(ui_image_t *image, UINTN x, UINTN y, UINTN width, UINTN height)
{
	EFI_STATUS ret = EFI_SUCCESS;
	ui_image_t to_draw;
	UINTN new_width, new_height;

	ui_get_scaled_dimension(image->width, image->height,
				width, height, &new_width, &new_height);

	if (new_width == image->width && new_height == image->height)
		return ui_image_draw(image, x, y);

	ret = memcpy_s(&to_draw, sizeof(to_draw), image, sizeof(to_draw));
	if (EFI_ERROR(ret))
		goto out;
	to_draw.blt = AllocatePool(ui_get_blt_size(new_width, new_height));
	if (!to_draw.blt) {
		ret = EFI_OUT_OF_RESOURCES;
		efi_perror(ret, L"Failed to allocate buffer");
		goto out;
	}

	to_draw.width = new_width;
	to_draw.height = new_height;

	ui_bilinear_scale((unsigned char *)image->blt,
			  (unsigned char *)to_draw.blt,
			  image->width, image->height,
			  to_draw.width, to_draw.height,
			  sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));

	ret = ui_image_draw(&to_draw, x, y);

out:
	if (to_draw.blt)
		FreePool(to_draw.blt);
	return ret;
}
