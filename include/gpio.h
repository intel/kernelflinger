/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
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

#ifndef _GPIO_H_
#define _GPIO_H_

#include <efi.h>
#include <efiapi.h>

typedef enum
{
        GpInOut = 0,
        GpIn = 1,  /* GPI, input only in PAD_VALUE */
        GpOut = 2, /* GPO, output only in PAD_VALUE */
} GPIO_DIRECTION;

typedef enum
{
        Low = 0,
        High = 1,
} GPIO_LEVEL;

typedef enum
{
        Fn0 = 0, /* GPIO mode*/
        Fn1 = 1,
        Fn2 = 2,
        Fn3 = 3,
        Fn4 = 4,
        Fn5 = 5
} PAD_MODE;

EFI_STATUS gpio_get_max_count(UINT32 *count);
EFI_STATUS get_gpio_pin_dir(UINT32 PinNum, GPIO_DIRECTION *dir);
EFI_STATUS set_gpio_pin_dir(UINT32 PinNum, GPIO_DIRECTION dir);
EFI_STATUS get_gpio_pin_level(UINT32 PinNum, GPIO_LEVEL *level);
EFI_STATUS set_gpio_pin_level(UINT32 PinNum, GPIO_LEVEL level);
EFI_STATUS set_gpio_pin_mode(UINT32 PinNum, PAD_MODE mode);
EFI_STATUS get_gpio_pin_mode(UINT32 PinNum, PAD_MODE *mode);

#endif /*_GPIO_H_*/
