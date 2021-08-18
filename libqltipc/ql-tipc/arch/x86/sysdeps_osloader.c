/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <trusty/sysdeps.h>
#include "log.h"
#include "lib.h"
#include <efi.h>
#include <efilib.h>

#define UNUSED(x) (void)(x)

void trusty_lock(struct trusty_dev *dev)
{
    UNUSED(dev);
}
void trusty_unlock(struct trusty_dev *dev)
{
    UNUSED(dev);
}

void trusty_local_irq_disable(unsigned long *state)
{
    UNUSED(state);
}

void trusty_local_irq_restore(unsigned long *state)
{
    UNUSED(state);
}

void trusty_idle(struct trusty_dev *dev, bool event_poll)
{
    /* ToDo */
    UNUSED(dev);
}

void trusty_abort(void)
{
    /* ToDo */
    __builtin_unreachable();
}

void trusty_printf(const char *format, ...)
{
    va_list ap;
    CHAR16 *format16;
    format16 = stra_to_str((CHAR8 *)format);

    va_start(ap, format);
    vlog(format16, ap);
    va_end(ap);
    FreePool(format16);
}

void *trusty_memcpy(void *dest, const void *src, size_t n)
{
    EFI_STATUS ret;
    ret = memcpy_s(dest, n, src, n);
    return (ret == EFI_SUCCESS) ? (dest) : (NULL);
}

void *trusty_memset(void *dest, const int c, size_t n)
{
    return memset_s(dest, n, c, n);
}

char *trusty_strcpy(char *dest, const char *src)
{
    EFI_STATUS ret;
    ret = strcpy_s(dest, strlen(src), src);
    return (ret == EFI_SUCCESS) ? (dest) : (NULL);
}

size_t trusty_strlen(const char *str)
{
    return strlen((CHAR8 *)str);
}

void *trusty_calloc(size_t n, size_t size)
{
    return AllocatePool(n*size);
}

void trusty_free(void *addr)
{
    if (addr)
        FreePool(addr);
}

void *trusty_alloc_pages(unsigned count)
{
    void *pa = NULL;
    EFI_STATUS ret;
    EFI_PHYSICAL_ADDRESS Memory = 0XFFFFFFFF;

    ret = uefi_call_wrapper(BS->AllocatePages,
                            4,
                            AllocateMaxAddress,
                            EfiLoaderData,
                            EFI_SIZE_TO_PAGES(count * PAGE_SIZE),
                            &Memory);
    if (EFI_ERROR(ret)) {
        trusty_printf("alloc page failed\n");
        return NULL;
    }

    /* get memory attibutes */
    pa = (VOID *)(UINTN)Memory;

    return pa;
}

void trusty_free_pages(void *va, unsigned count)
{
    if (va)
        uefi_call_wrapper(BS->FreePages,
                          2,
                          (EFI_PHYSICAL_ADDRESS)(UINTN)va,
                          EFI_SIZE_TO_PAGES(count * PAGE_SIZE));
}
