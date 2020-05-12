/*
 * Copyright (c) 2013, Intel Corporation
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
/*-
 * For strcasestr()
 *
 * Copyright (c) 1987, 1990, 1993
 *        The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <efi.h>
#include <efilib.h>

#include "lib.h"
#include "vars.h"


EFI_HANDLE g_parent_image;

CHAR8 *strchr(const CHAR8 *s, int c)
{
        do {
                if (*s == (char)c)
                        return (CHAR8 *)s;
        } while (*s++);
        return NULL;
}

int strcmp(const CHAR8 *s1, const CHAR8 *s2)
{
        return strcmpa(s1, s2);
}

int strncmp(const CHAR8 *s1, const CHAR8 *s2, size_t n)
{
        return strncmpa(s1, s2, n);
}

size_t strlen(const CHAR8 *s)
{
        return strlena(s);
}

size_t strnlen(const CHAR8 *s, size_t maxlen)
{
        size_t i;

        for (i = 0; i < maxlen; i++)
                if (s[i] == '\0')
                        break;

        return i;
}

/* itoa function converts integer into string type
 * The third parameter radix specify the conversion base
 */
CHAR8 *itoa(int val, CHAR8 *buf, unsigned radix)
{
        CHAR8 *p;
        CHAR8 *firstdig;
        CHAR8 temp;
        unsigned digval;

        if (buf == NULL)
            return NULL;

        p = buf;
        if (val < 0)
        {
            *p++ = '-';
            val = (unsigned long)(-(long)val);
        }

        firstdig = p;
        do {
                digval = (unsigned)(val % radix);
                val /= radix;

                if (digval > 9)
                    *p++ = (CHAR8)(digval - 10 + 'a');
                else
                    *p++ = (CHAR8)(digval + '0');
        } while (val > 0);

        *p-- = '\0';
        do {
                temp = *p;
                *p = *firstdig;
                *firstdig = temp;
                --p;
                ++firstdig;
        } while (firstdig < p);

        return buf;
}

CHAR8 *strcpy(CHAR8 *dest, const CHAR8 *src)
{
        unsigned int i;

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';

        return dest;
}

EFI_STATUS strcpy_s(char *restrict dest, size_t destsz, const char *restrict src)
{
        unsigned int i;

        if (dest == src) {
                debug(L"<strcpy_s dest == src");
                return EFI_SUCCESS;
        }

        if ((dest == NULL) || (src == NULL)) {
                error(L"<strcpy_s NULL 0x%x 0x%x", dest, src);
                return EFI_INVALID_PARAMETER;
        }

        if (destsz == 0) {
                error(L"<strcpy_s destsz == 0");
                return EFI_BAD_BUFFER_SIZE;
        }

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';

        return EFI_SUCCESS;
}

EFI_STATUS strcpy16_s(CHAR16 *restrict dest, size_t destsz, const CHAR16 *restrict src)
{
        unsigned int i;

        if (dest == src) {
                debug(L"<strcpy_s dest == src");
                return EFI_SUCCESS;
        }

        if ((dest == NULL) || (src == NULL)) {
                error(L"<strcpy_s NULL 0x%x 0x%x", dest, src);
                return EFI_INVALID_PARAMETER;
        }

        if (destsz == 0) {
                error(L"<strcpy_s destsz == 0");
                return EFI_BAD_BUFFER_SIZE;
        }

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';

        return EFI_SUCCESS;
}

CHAR8 *__strcpy_chk(CHAR8 *dest, const CHAR8 *src, size_t destlen)
    __attribute__((weak));
CHAR8 *__strcpy_chk(CHAR8 *dest, const CHAR8 *src, size_t destlen)
{
        EFI_STATUS ret;
        size_t len = strlen(src);
        if (destlen < len)
                panic(L"%a Error: destlen(%d) is less than len(%d)", __func__, destlen, len);

        ret = strcpy_s(dest, destlen, src);
        return (ret == EFI_SUCCESS) ? (dest) : (NULL);
}

CHAR8 *strncpy(CHAR8 *dest, const CHAR8 *src, size_t n)
{
        unsigned int i;

        for (i = 0; i < n && src[i] != '\0'; i++)
                dest[i] = src[i];
        for (; i < n; i++)
                dest[i] = '\0';

        return dest;
}

EFI_STATUS strncpy_s(char *restrict dest, size_t dmax, const char *restrict src, size_t slen)
{
        size_t orig_dmax;
        char *orig_dest;
        const char *overlap_bumper;

        if (dest == NULL) {
                error(L"<strncpy_s dest == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (dmax == 0) {
                error(L"<strncpy_s dmax == 0");
                return EFI_BAD_BUFFER_SIZE;
        }

        /* hold base in case src was not copied */
        orig_dmax = dmax;
        orig_dest = dest;

        if (src == NULL) {
                error(L"<strncpy_s src == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (slen == 0) {
                error(L"<strncpy_s slen == 0");
                return EFI_INVALID_PARAMETER;
        }

        if (dest < src) {
                overlap_bumper = src;

                while (dmax > 0) {
                        if (dest == overlap_bumper) {
                                error(L"<strncpy_s dest == overlap_bumper");
                                return EFI_INVALID_PARAMETER;
                        }

                        if (slen == 0) {
                        /*
                         * Copying truncated to slen chars.  Note that the TR says to
                         * copy slen chars plus the null char.  We null the slack.
                         */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                                /* null slack */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        dmax--;
                        slen--;
                        dest++;
                        src++;
                }

        } else {
                overlap_bumper = dest;

                while (dmax > 0) {
                        if (src == overlap_bumper) {
                               error(L"<strncpy_s dmax > 0");
                               return EFI_INVALID_PARAMETER;
                        }

                        if (slen == 0) {
                                /*
                                 * Copying truncated to slen chars.  Note that the TR says to
                                 * copy slen chars plus the null char.  We null the slack.
                                 */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                                /* null slack */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        dmax--;
                        slen--;
                        dest++;
                        src++;
                }
        }

        /*
         * the entire src was not copied, so zero the string
         */
        error(L"<strncpy_s not enough space for src");
        return EFI_BUFFER_TOO_SMALL;
}

EFI_STATUS strncpy16_s(CHAR16 *restrict dest, size_t dmax, const CHAR16 *restrict src, size_t slen)
{
        size_t orig_dmax;
        CHAR16 *orig_dest;
        const CHAR16 *overlap_bumper;

        if (dest == NULL) {
                error(L"<strncpy16_s dest == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (dmax == 0) {
                error(L"<strncpy16_s dmax == 0");
                return EFI_BAD_BUFFER_SIZE;
        }

        /* hold base in case src was not copied */
        orig_dmax = dmax;
        orig_dest = dest;

        if (src == NULL) {
                error(L"<strncpy16_s src == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (slen == 0) {
                error(L"<strncpy16_s slen == 0");
                return EFI_INVALID_PARAMETER;
        }

        if (dest < src) {
                overlap_bumper = src;

                while (dmax > 0) {
                        if (dest == overlap_bumper) {
                                error(L"<strncpy16_s dest == overlap_bumper");
                                return EFI_INVALID_PARAMETER;
                        }

                        if (slen == 0) {
                        /*
                         * Copying truncated to slen chars.  Note that the TR says to
                         * copy slen chars plus the null char.  We null the slack.
                         */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                                /* null slack */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        dmax--;
                        slen--;
                        dest++;
                        src++;
                }

        } else {
                overlap_bumper = dest;

                while (dmax > 0) {
                        if (src == overlap_bumper) {
                               error(L"<strncpy16_s src == overlap_bumper");
                               return EFI_INVALID_PARAMETER;
                        }

                        if (slen == 0) {
                                /*
                                 * Copying truncated to slen chars.  Note that the TR says to
                                 * copy slen chars plus the null char.  We null the slack.
                                 */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                                /* null slack */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        dmax--;
                        slen--;
                        dest++;
                        src++;
                }
        }

        /*
         * the entire src was not copied, so zero the string
         */
        error(L"<strncpy16_s not enough space for src");
        return EFI_BUFFER_TOO_SMALL;
}

EFI_STATUS strcat16_s (CHAR16 *restrict dest, size_t dmax, const CHAR16 *restrict src)
{
        size_t orig_dmax;
        CHAR16 *orig_dest;
        const CHAR16 *overlap_bumper;

        if (dest == NULL) {
                error(L"<strcat16_s dest == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (src == NULL) {
                error(L"<strcat16_s src == NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (dmax == 0) {
                error(L"<strcat16_s dmax == 0");
                return EFI_BAD_BUFFER_SIZE;
        }

        /* hold base of dest in case src was not copied */
        orig_dmax = dmax;
        orig_dest = dest;

        if (dest < src) {
                overlap_bumper = src;

                /* Find the end of dest */
                while (*dest != '\0') {
                        if (dest == overlap_bumper) {
                                error(L"<strcat16_s dest == overlap_bumper");
                                return EFI_INVALID_PARAMETER;
                        }

                        dest++;
                        dmax--;
                        if (dmax == 0) {
                                error(L"<strcat16_s dmax == 0");
                                return EFI_BAD_BUFFER_SIZE;
                        }
                }

                while (dmax > 0) {
                        if (dest == overlap_bumper) {
                            error(L"<strcat16_s dest == overlap_bumper");
                            return EFI_INVALID_PARAMETER;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                            /* null slack to clear any data */
                            while (dmax) { *dest = '\0'; dmax--; dest++; }
                            return EFI_SUCCESS;
                        }

                        dmax--;
                        dest++;
                        src++;
                }

        } else {
                overlap_bumper = dest;

                /* Find the end of dest */
                while (*dest != '\0') {
                        /*
                         * NOTE: no need to check for overlap here since src comes first
                         * in memory and we're not incrementing src here.
                         */
                        dest++;
                        dmax--;
                        if (dmax == 0) {
                                error(L"<strcat16_s dmax == 0");
                                return EFI_BAD_BUFFER_SIZE;
                        }
                }

                while (dmax > 0) {
                        if (src == overlap_bumper) {
                                error(L"<strcat16_s src == overlap_bumper");
                                return EFI_INVALID_PARAMETER;
                        }

                        *dest = *src;
                        if (*dest == '\0') {
                                /* null slack to clear any data */
                                while (dmax) { *dest = '\0'; dmax--; dest++; }
                                return EFI_SUCCESS;
                        }

                        dmax--;
                        dest++;
                        src++;
                }
        }

        /*
         * the entire src was not copied, so null the string
         */
         error(L"<strcat16_s not enough space for src");
         return EFI_BUFFER_TOO_SMALL;
}

CHAR8 *__strncpy_chk(CHAR8 *dest, const CHAR8 *src, size_t n, size_t destlen)
    __attribute__((weak));
CHAR8 *__strncpy_chk(CHAR8 *dest, const CHAR8 *src, size_t n, size_t destlen)
{
        if (destlen < n)
                panic(L"%a Error: destlen(%d) is less than n(%d)", __func__, destlen, n);

        EFI_STATUS ret;
        ret = strncpy_s(dest, destlen, src, n);
        return (ret == EFI_SUCCESS) ? (dest) : (NULL);

}

CHAR8 *__strncpy_chk2(CHAR8 *dest, const CHAR8 *src, size_t n, size_t destlen, size_t srclen)
    __attribute__((weak));
CHAR8 *__strncpy_chk2(CHAR8 *dest, const CHAR8 *src, size_t n, size_t destlen, size_t srclen)
{
        size_t len = strlen(src);
        if (srclen < len)
                panic(L"%a Error: srclen(%d) is less than len(%d)", __func__, srclen, len);

        return __strncpy_chk(dest, src, n, destlen);
}

size_t strlcat(CHAR8 *dst, const CHAR8 *src, size_t siz)
{
	size_t max, i;
	size_t sl = strlen(src);
	size_t dl = strlen(dst);

	CHAR8 *p = dst + dl;
	max = siz > (sl + dl) ? sl : (siz - dl - 1);

	for (i = 0; i < max; i++)
		p[i] = src[i];

	p[i] = '\0';
	return max;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
        if (!n)
                return 0;

        do {
                if (tolower(*s1) != tolower(*s2++))
                        return (tolower(*s1) - tolower(*--s2));
                if (*s1++ == '\0')
                        break;
        } while (--n != 0);
        return 0;
}

int tolower(int c)
{
        if (('A' <= c) && (c <= 'Z'))
                return c - ('A' - 'a');
        return c;
}

int isupper(int c)
{
        return ('A' <= c) && (c <= 'Z');
}

int isxdigit(int c)
{
        return (('0' <= c) && (c <= '9')) ||
                (('a' <= c) && (c <= 'f')) ||
                (('A' <= c) && (c <= 'F'));
}

int isalnum(int c)
{
        return (('0' <= c) && (c <= '9')) ||
                (('a' <= c) && (c <= 'z')) ||
                (('A' <= c) && (c <= 'Z'));
}

int isspace(int c)
{
        return c == ' ' || (c >= '\t' && c <= '\r');
}

int isdigit(int c)
{
        return ('0' <= c) && (c <= '9');
}

char *strdup(const char *s)
{
	EFI_STATUS ret;
	UINTN size;
	char *new;

	size = strlena((CHAR8 *)s) + 1;
	new = AllocatePool(size);
	if (!new)
		return NULL;

	ret = memcpy_s(new, size, s, size);
	return (ret == EFI_SUCCESS) ? (new) : (NULL);
}

char *strcasestr(const char *s, const char *find)
{
        char c, sc;
        size_t len;

        if (!s || !find)
                return NULL;

        if ((c = *find++) != 0) {
                c = tolower((unsigned char)c);
                len = strlen((CHAR8 *)find);
                do {
                        do {
                                if ((sc = *s++) == 0)
                                        return (NULL);
                        } while ((char)tolower((unsigned char)sc) != c);
                } while (strncasecmp(s, find, len) != 0);
                s--;
        }
        return (char *)s;
}

CHAR16 *stra_to_str(const CHAR8 *stra)
{
        UINTN len, i;
        CHAR16 *str;

        len = strlena(stra);
        str = AllocatePool((len + 1) * sizeof(CHAR16));

        if (!str)
                return NULL;
        for (i = 0; i < len; i++)
                str[i] = (CHAR16)stra[i];
        str[i] = 0;
        return str;
}

EFI_STATUS stra_to_guid(const char *str, EFI_GUID *g)
{
        char value[3] = { '\0', '\0', '\0' };
        char *end;
        UINTN i;

        if (!str || !g)
                return EFI_INVALID_PARAMETER;

        g->Data1 = strtoul(str, &end, 16);
        if (end - str != 8 || *end != '-')
                return EFI_INVALID_PARAMETER;

        str = end + 1;
        g->Data2 = strtoul(str, &end, 16);
        if (end - str != 4 || *end != '-')
                return EFI_INVALID_PARAMETER;

        str = end + 1;
        g->Data3 = strtoul(str, &end, 16);
        if (end - str != 4 || *end != '-')
                return EFI_INVALID_PARAMETER;

        str = end + 1;
        for (i = 0 ; i < 2; i++, str += 2) {
                value[0] = str[0];
                value[1] = str[1];
                g->Data4[i] = strtoul(value, &end, 16);
                if (end != value + 2)
                        return EFI_INVALID_PARAMETER;
        }

        if (*str != '-')
                return EFI_INVALID_PARAMETER;

        str++;
        for (i = 0 ; i < 6; i++, str += 2) {
                value[0] = str[0];
                value[1] = str[1];
                g->Data4[i + 2] = strtoul(value, &end, 16);
                if (end != value + 2)
                        return EFI_INVALID_PARAMETER;
        }

        return EFI_SUCCESS;
}

int efi_vsnprintf(CHAR8 *dst, UINTN size, const CHAR8 *format, va_list ap)
{
        EFI_STATUS ret;
        int len = -1;
        CHAR16 *format16;

        format16 = stra_to_str((CHAR8 *)format);
        if (!format16)
                return -1;

        CHAR16 *dst16 = AllocatePool(size * sizeof(CHAR16));
        if (!dst16)
                goto free_format16;

        len = VSPrint(dst16, size * sizeof(CHAR16), format16, ap);

        ret = str_to_stra((CHAR8 *)dst, dst16, len + 1);
        if (EFI_ERROR(ret))
                len = -1;
        else
                dst[len] = '\0';

        FreePool(dst16);

free_format16:
        FreePool(format16);

        return len;
}


int efi_snprintf(CHAR8 *str, UINTN size, const CHAR8 *format, ...)
{
        va_list args;
        int ret;

        va_start(args, format);
        ret = efi_vsnprintf(str, size, format, args);
        va_end(args);
        return ret;
}


EFI_STATUS get_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN *size_p, VOID **data_p, UINT32 *flags_p)
{
        VOID *data;
        UINTN size;
        UINT32 flags;
        EFI_STATUS ret;

        size = 1024; /* Arbitrary starting value */
        data = AllocatePool(size);
        if (!data)
                return EFI_OUT_OF_RESOURCES;

        ret = uefi_call_wrapper(RT->GetVariable, 5, key, (EFI_GUID *)guid,
                                &flags, &size, data);
        if (ret == EFI_BUFFER_TOO_SMALL) {
                FreePool(data);
                data = AllocatePool(size);
                if (!data)
                        return EFI_OUT_OF_RESOURCES;
                ret = uefi_call_wrapper(RT->GetVariable, 5, key, (EFI_GUID *)guid,
                                        &flags, &size, data);
        }

        if (EFI_ERROR(ret)) {
                FreePool(data);
                return ret;
        }

        if (size_p)
                *size_p = size;
        if (flags_p)
                *flags_p = flags;
        *data_p = data;

        return EFI_SUCCESS;
}


CHAR16 *get_efi_variable_str(const EFI_GUID *guid, CHAR16 *key)
{
        CHAR16 *data;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                return NULL;

        if (!size || size % 2 != 0 || data[(size / 2) - 1] != 0) {
                FreePool(data);
                return NULL;
        }

        return data;
}


CHAR16 *get_efi_variable_str8(const EFI_GUID *guid, CHAR16 *key)
{
        CHAR8 *data;
        CHAR16 *value;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret) || !data || !size)
                return NULL;

        if (data[size - 1] != '\0') {
                FreePool(data);
                return NULL;
        }

        value = stra_to_str(data);
        FreePool(data);
        return value;
}


EFI_STATUS get_efi_variable_byte(const EFI_GUID *guid, CHAR16 *key, UINT8 *byte)
{
        CHAR16 *data;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                return ret;

        if (!size) {
                FreePool(data);
                return EFI_NOT_FOUND;
        }

        *byte = data[0];
        FreePool(data);
        return EFI_SUCCESS;
}

EFI_STATUS get_efi_variable_long_from_str8(const EFI_GUID *guid, CHAR16 *key,
                                          unsigned long *i)
{
        char *data, *end;
        EFI_STATUS ret;
        UINTN size;

        ret = get_efi_variable(guid, key, &size, (VOID **)&data, NULL);
        if (EFI_ERROR(ret))
                return ret;

        if (!size) {
                ret = EFI_NOT_FOUND;
                goto out;
        }

        if (data[size - 1] != '\0') {
                ret = EFI_INVALID_PARAMETER;
                goto out;
        }

        *i = strtoul((char *)data, &end, 10);
        if (end == data || *end != '\0')
                ret = EFI_INVALID_PARAMETER;
        else
                ret = EFI_SUCCESS;
out:
        FreePool(data);
        return ret;
}

EFI_STATUS del_efi_variable(const EFI_GUID *guid, CHAR16 *key)
{
        EFI_STATUS ret;

        ret = uefi_call_wrapper(RT->SetVariable, 5, key, (EFI_GUID *)guid, 0, 0, NULL);
        if (ret == EFI_NOT_FOUND)
                return EFI_SUCCESS;

        return ret;
}


EFI_STATUS set_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN size, VOID *data, BOOLEAN nonvol, BOOLEAN runtime)
{
        EFI_STATUS ret;
        UINT32 curflags, flags = EFI_VARIABLE_BOOTSERVICE_ACCESS;
        UINTN cursize;
        VOID *curdata;

        if (nonvol)
                flags |= EFI_VARIABLE_NON_VOLATILE;
        if (runtime)
                flags |= EFI_VARIABLE_RUNTIME_ACCESS;

        /* Storage attributes are only applied to a variable when creating the
         * variable. If a preexisting variable is rewritten with different
         * attributes, the result is indeterminate and may vary between
         * implementations. The correct method of changing the attributes of a
         * variable is to delete the variable and recreate it with different
         * attributes. */
        ret = get_efi_variable((EFI_GUID *)guid, key, &cursize, &curdata, &curflags);
        if (EFI_ERROR(ret) && ret != EFI_NOT_FOUND)
                return ret;
        if (ret == EFI_SUCCESS)
                FreePool(curdata);
        if (ret == EFI_SUCCESS && curflags != flags) {
                ret = del_efi_variable((EFI_GUID *)guid, key);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Couldn't clear EFI variable");
                        return ret;
                }
        }

        return uefi_call_wrapper(RT->SetVariable, 5, key, (EFI_GUID *)guid, flags,
                                 size, data);
}


EFI_STATUS set_efi_variable_str(const EFI_GUID *guid, CHAR16 *key,
                BOOLEAN nonvol, BOOLEAN runtime, CHAR16 *val)
{
        return set_efi_variable(guid, key,
                        val ? ((StrLen(val) + 1) * sizeof(CHAR16)) : 0,
                        val, nonvol, runtime);
}


EFI_STATUS file_delete(IN EFI_HANDLE disk, IN const CHAR16 *name)
{
        EFI_STATUS ret;
        EFI_FILE *file;
        EFI_FILE *root_dir;

        root_dir = LibOpenRoot(disk);
        if (!root_dir)
                return EFI_LOAD_ERROR;

        ret = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file,
                        (CHAR16 *)name, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Couldn't open the file in order to delete");
                goto out;
        }
        ret = uefi_call_wrapper(file->Delete, 1, file);
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"Couldn't delete source file");
                goto out;
        }
out:
        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return ret;
}


BOOLEAN file_exists(IN EFI_HANDLE disk, IN const CHAR16 *path)
{
        EFI_FILE *root_dir;
        EFI_FILE *file;
        EFI_STATUS ret;
        BOOLEAN exists = TRUE;

        root_dir = LibOpenRoot(disk);
        if (!root_dir)
                return FALSE;

        ret = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file,
                        (CHAR16 *)path, EFI_FILE_MODE_READ, 0);
        if (EFI_ERROR(ret)) {
                exists = FALSE;
        } else {
                uefi_call_wrapper(file->Close, 1, file);
        }

        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return exists;
}

EFI_STATUS file_read(IN EFI_FILE_HANDLE dir, IN const CHAR16 *name,
                     OUT CHAR8 **content, OUT UINTN *len)
{
        EFI_FILE_HANDLE handle;
        EFI_FILE_INFO *info;
        CHAR8 *buf;
        UINTN buflen;
        EFI_STATUS err;
        EFI_FILE *root_dir;

        root_dir = LibOpenRoot(dir);
        if (!root_dir)
                return EFI_LOAD_ERROR;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle,
                        (CHAR16 *)name, EFI_FILE_MODE_READ, 0);

        if (EFI_ERROR(err))
                goto out;

        info = LibFileInfo(handle);
        if (!info) {
                err = EFI_UNSUPPORTED;
                goto out;
        }

        buflen = info->FileSize + 1;
        buf = AllocatePool(buflen);
        if (!buf) {
                err = EFI_OUT_OF_RESOURCES;
                goto out;
        }

        err = uefi_call_wrapper(handle->Read, 3, handle, &buflen, buf);
        if (EFI_ERROR(err) == EFI_SUCCESS) {
                buf[buflen] = '\0';
                *content = buf;
                *len = buflen;
        } else
                FreePool(buf);

        FreePool(info);
        uefi_call_wrapper(handle->Close, 1, handle);

out:
        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        return err;
}

VOID StrNCpy(OUT CHAR16 *dest, IN const CHAR16 *src, UINT32 n)
{
        UINT32 i;

        for (i = 0; i < n && src[i] != 0; i++)
                dest[i] = src[i];
        for ( ; i < n; i++)
                dest[i] = 0;
}


EFI_STATUS getdigit(IN CHAR16 *str, OUT UINT8 *outstr)
{
        EFI_STATUS ret;
        CHAR16 bytestr[3];
        bytestr[2] = 0;
        ret = strncpy16_s(bytestr, sizeof(bytestr) / sizeof(CHAR16), str, 2);
        if (EFI_ERROR(ret))
            return ret;

        *outstr = (UINT8)xtoi(bytestr);
        return EFI_SUCCESS;
}


EFI_STATUS string_to_guid(
                IN CHAR16 *in_guid_str,
                OUT EFI_GUID *guid)
{
        CHAR16 gstr[37];
        UINT8 val;
        int i;
        EFI_STATUS ret;

        ret = strncpy16_s(gstr, sizeof(gstr) / sizeof(CHAR16), in_guid_str, 36);
        if (EFI_ERROR(ret))
            return ret;
        gstr[36] = 0;
        gstr[8] = 0;
        gstr[13] = 0;
        gstr[18] = 0;
        guid->Data1 = (UINT32)xtoi(gstr);
        guid->Data2 = (UINT16)xtoi(&gstr[9]);
        guid->Data3 = (UINT16)xtoi(&gstr[14]);

        ret = getdigit(&gstr[19], &val);
        if (EFI_ERROR(ret))
            return ret;
        guid->Data4[0] = val;

        ret = getdigit(&gstr[21], &val);
        if (EFI_ERROR(ret))
            return ret;
        guid->Data4[1] = val;
        for (i = 0; i < 6; i++) {
                ret = getdigit(&gstr[24 + (i * 2)], &val);
                if (EFI_ERROR(ret))
                        return ret;
                guid->Data4[i + 2] = val;
        }

        return EFI_SUCCESS;
}


EFI_STATUS str_to_stra(CHAR8 *dst, const CHAR16 *src, UINTN max_len)
{
        UINTN i;

        /* This is NOT how to do UTF16 to UTF8 conversion. For now we're just
         * going to hope that nobody's putting non-ASCII characters in
         * the source string! We'll at least abort with an error
         * if we see any funny stuff */
        for (i = 0; i < max_len; i++) {
                if (src[i] > 0x7F)
                        return EFI_INVALID_PARAMETER;

                dst[i] = (CHAR8)src[i];
                if (!src[i])
                        break;
        }
        dst[max_len - 1] = '\0';
        return EFI_SUCCESS;
}


/*
 * Parameters Passed : character  : char to be converted to int
 *                     base       : the base of conversion ( hex, dec etc)
 *
 * Returns           :   value    : character after conversion to int
 *
 * This function converts character to integer.
 */
static INTN to_digit(CHAR16 character, UINTN base)
{
        UINTN value = -1;

        if (character >= '0' && character <= '9')
                value = character - '0';
        else if (character >= 'a' && character <= 'z')
                value = 0xA + character - 'a';
        else if (character >= 'A' && character <= 'Z')
                value = 0xA + character - 'A';

        return value < base ? (INTN)value : -1;
}

/* Convert strings to an unsigned long long-integer value */
unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
        unsigned long long value = 0;

        if (!nptr)
                goto out;

        if ((base == 0 || base == 16) &&
            (strlena((CHAR8 *)nptr) > 2 && nptr[0] == '0' && nptr[1] == 'x')) {
                nptr += 2;
                base = 16;
        }

        if (base == 0)
                base = 10;

        for (; *nptr != '\0' ; nptr++) {
                int t = to_digit(*nptr, base);
                if (t == -1)
                        goto out;
                if (value * base < value) {
                        value = ULLONG_MAX;
                        goto out;
                }
                value = (value * base) + t;
        }

out:
        if (endptr)
                *endptr = (char *)nptr;
        return value;
}

/* Convert strings to an unsigned long-integer value */
unsigned long strtoul(const char *nptr, char **endptr, int base)
{
        unsigned long long value;

        value = strtoull(nptr, endptr, base);
        if (value > ULONG_MAX) {
                if (value != ULLONG_MAX)
                        *endptr = (char *)nptr;
                return ULONG_MAX;
        }

        return value;
}


EFI_STATUS bytes_to_hex_stra(CHAR8 *bytes, UINTN length, CHAR8 *str, UINTN strsize)
{
        CHAR8 hex;
        UINTN i;

        if (!bytes || !str || strsize < length * 2 + 1)
                return EFI_INVALID_PARAMETER;

        for (i = 0; i < length * 2; i++) {
                hex = ((i & 1) ? bytes[i / 2] & 0xf : bytes[i / 2] >> 4);
                *str++ = (hex > 9 ? (hex + 'a' - 10) : (hex + '0'));
        }
        *str = '\0';

        return EFI_SUCCESS;
}


static inline BOOLEAN is_in_char_set(char c, const char *set)
{
        UINTN i, len;

        for (i = 0, len = strlen((CHAR8 *)set); i < len; i++)
                if (c == set[i])
                        return TRUE;

        return FALSE;
}

char *strtok_r(char *str, const char *delim, char **saveptr)
{
        char *p, *res;

        if (!delim || !saveptr || (!str && !*saveptr))
                return NULL;

        if (str)
                *saveptr = str;

        if (**saveptr == '\0')
                return NULL;

        res = *saveptr;
        for (p = *saveptr; *p != '\0' && !is_in_char_set(*p, delim); p++)
                ;

        for (; *p != '\0' && is_in_char_set(*p, delim); p++)
                *p = '\0';

        *saveptr = p;

        return res;
}

CHAR16 *StrStr(const CHAR16 *s, const CHAR16 *find)
{
        CHAR16 c, sc;
        int len;

        if ((c = *find++) != 0) {
                len = StrLen(find);
                do {
                        do {
                                if ((sc = *s++) == 0)
                                        return NULL;
                        } while (sc != c);
                } while (StrnCmp(s, find, len) != 0);
                s--;
        }
        return (CHAR16 *)s;
}

VOID pause(UINTN seconds)
{
        uefi_call_wrapper(BS->Stall, 1, seconds * 1000000);
}


VOID halt_system(VOID)
{
        uefi_call_wrapper(RT->ResetSystem, 4, EfiResetShutdown, EFI_SUCCESS,
                          0, NULL);
        error(L"Failed to halt the device ... looping forever");
        while (1) { }
}


VOID reboot(CHAR16 *target, EFI_RESET_TYPE type)
{
        EFI_STATUS ret;

        if (target) {
                ret = set_efi_variable_str(&loader_guid, LOADER_ENTRY_ONESHOT,
                                           TRUE, TRUE, target);
                if (EFI_ERROR(ret)) {
                        error(L"Unable to set LoaderEntryOneShot");
                        pause(30);
                        halt_system();
                }
        }

        uefi_call_wrapper(RT->ResetSystem, 4, type, EFI_SUCCESS,
                          0, target);
        error(L"Failed to reboot the device ... looping forever");
        while (1) { }
}

static BOOLEAN is_power_of_two(UINTN x)
{
        return x && !(x & (x - 1));
}

EFI_STATUS alloc_aligned(VOID **free_addr, VOID **aligned_addr,
                         UINTN size, UINTN align)
{
        if (align && !is_power_of_two(align))
                return EFI_INVALID_PARAMETER;

        *free_addr = AllocateZeroPool(size + align);
        if (!*free_addr)
                return EFI_OUT_OF_RESOURCES;

        if (!align) {
                *aligned_addr = *free_addr;
                return EFI_SUCCESS;
        }

        *aligned_addr = (VOID *)(((UINTN)*free_addr + align - 1) & ~(align - 1));

        return EFI_SUCCESS;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
        return CompareMem(s1, s2, n);
}

void *memset(void *s, int c, size_t n)
{
        SetMem(s, n, (UINT8)c);
        return s;
}

void *memcpy(void *dest, const void *source, size_t count)
{
        CopyMem(dest, source, (UINTN)count);
        return dest;
}

EFI_STATUS memcpy_s(void *dest, size_t dest_size, const void *source, size_t count)
{
        if (count == 0) {
                debug(L"<memcpy_s count NULL");
                return EFI_SUCCESS;
        }

        if (dest == NULL) {
                error(L"<memcpy_s dest NULL");
                return EFI_INVALID_PARAMETER;
        }

        if (source == NULL || dest_size < count) {
                CopyMem(dest, 0, (UINTN)dest_size);
                error(L"<memcpy_s BAD_BUFFER_SIZE 0x%x %d %d", source, dest_size, count);
                return EFI_BAD_BUFFER_SIZE;
        }

        CopyMem(dest, source, (UINTN)count);
        return EFI_SUCCESS;
}

void *memmove(void *dst, const void *src, size_t n)
{
        size_t offs;
        ssize_t i;

        if (src > dst) {
                EFI_STATUS ret;
                ret = memcpy_s(dst, n, src, n);
                return (ret == EFI_SUCCESS) ? (dst) : (NULL);
        }

        offs = n - (n % sizeof(unsigned long));

        for (i = (n % sizeof(unsigned long)) - 1; i >= 0; i--)
                ((UINT8 *)dst)[i + offs] = ((UINT8 *)src)[i + offs];

        for (i = n / sizeof(unsigned long) - 1; i >= 0; i--)
                ((unsigned long *)dst)[i] = ((unsigned long *)src)[i];

        return dst;
}

void * __memmove_chk(void * dst, const void * src, size_t len, size_t destlen)
    __attribute__((weak));
void * __memmove_chk(void * dst, const void * src, size_t len, size_t destlen)
{
        if (destlen < len)
                panic(L"%a Error: destlen(%d) is less than len(%d)", __func__, destlen, len);

        return memmove(dst, src, len);
}

static int compare_memory_descriptor(const void *a, const void *b)
{
        const EFI_MEMORY_DESCRIPTOR *m1 = a, *m2 = b;

        if (m1->PhysicalStart < m2->PhysicalStart)
                return -1;
        if (m1->PhysicalStart > m2->PhysicalStart)
                return 1;
        return 0;
}

void sort_memory_map(void *descr, UINTN nr_descr, UINTN descr_sz)
{
        qsort(descr, nr_descr, descr_sz, compare_memory_descriptor);
}

static BOOLEAN is_a_leap_year(INTN year)
{
        return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

UINT64 efi_time_to_ctime(EFI_TIME *time)
{
        UINT8 DAY_OF_MONTH[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        UINTN i;
        UINTN days;

        if (!time)
                return 0;

        days = time->Day - 1;

        for (i = 1970; i < time->Year; i++)
                days += is_a_leap_year(i) ? 366 : 365;

        if (is_a_leap_year(time->Year))
                DAY_OF_MONTH[1] = 29;

        for (i = 0; i + 1 < time->Month; i++)
                days += DAY_OF_MONTH[i];

        return ((UINT64)days * 24 * 3600) +
                ((UINT64)time->Hour * 3600) +
                ((UINT64)time->Minute * 60) +
                (UINT64)time->Second;
}

VOID cpuid(UINT32 op, UINT32 reg[4])
{
#if __LP64__
        asm volatile("xchg{q}\t{%%}rbx, %q1\n\t"
                     "cpuid\n\t"
                     "xchg{q}\t{%%}rbx, %q1\n\t"
                     : "=a" (reg[0]), "=&r" (reg[1]), "=c" (reg[2]), "=d" (reg[3])
                     : "a" (op));
#else
        asm volatile("pushl %%ebx      \n\t" /* save %ebx */
                     "cpuid            \n\t"
                     "movl %%ebx, %1   \n\t" /* save what cpuid just put in %ebx */
                     "popl %%ebx       \n\t" /* restore the old %ebx */
                     : "=a"(reg[0]), "=r"(reg[1]), "=c"(reg[2]), "=d"(reg[3])
                     : "a"(op)
                     : "cc");
#endif
}

EFI_STATUS generate_random_numbers(CHAR8 *data, UINTN size)
{
#define RDRAND_SUPPORT (1 << 30)
        uint32_t reg[4];
        int ret;
        UINTN i, j;
        unsigned int random;

        cpuid(1, reg);
        if (!(reg[2] & RDRAND_SUPPORT))
                return EFI_UNSUPPORTED;

        for (i = 0; i < size; ) {
                ret = __builtin_ia32_rdrand32_step(&random);
                if (ret != 1)
                        return EFI_UNSUPPORTED;

                for (j = 0; j < sizeof(random) && i < size; j++, i++)
                        data[i] = ((unsigned char *)&random)[j];
        }

        return EFI_SUCCESS;
}

BOOLEAN no_device_unlock()
{
#ifdef NO_DEVICE_UNLOCK
	return TRUE;
#else
	return FALSE;
#endif
}

UINT8 min_boot_state()
{
#ifdef NO_DEVICE_UNLOCK
	return BOOT_STATE_GREEN;
#else
	return BOOT_STATE_RED;
#endif
}

/*
 * Called when gcc's -fstack-protector-strong feature is used, and
 * gcc detects corruption of the on-stack canary value
 */
VOID __stack_chk_fail()
    __attribute__((weak));
VOID __stack_chk_fail()
{
        panic(L"stack-protector: kernelflinger stack is corrupted");
}

INTN StrcaseCmp(CHAR16 *s1, CHAR16 *s2)
{
        CHAR16 *p1 = s1;
        CHAR16 *p2 = s2;
        CHAR16 c1, c2;

        if (s1 == NULL)
                return (s2 == NULL) ? 0 : -1;
        if (s2 == NULL)
                return 1;

        while (*p1 != 0) {
                c1 = *p1;
                if (c1 >= L'A' && c1 <= L'Z')
                        c1 += L'a' - L'A';
                c2 = *p2;
                if (c2 >= L'A' && c2 <= L'Z')
                        c2 += L'a' - L'A';
                if (c1 > c2)
                        return 1;
                if (c1 < c2)
                        return -1;
                p1++;
                p2++;
        }

        return (*p2 == 0) ? 0 : -1;
}

void StrToLower(CHAR16 *s)
{
        if (s == NULL)
                return;
        while (*s != 0) {
                if (*s >= L'A' && *s <= L'Z')
                        *s += L'a' - L'A';
                s++;
        }
        return;
}

EFI_STATUS string_to_argv(char *str, INTN *argc, CHAR8 *argv[], UINTN max_argc,
                          const char *first_delim, const char *delim)
{
        char *saveptr, *token = NULL;

        if (max_argc == 0)
                return EFI_INVALID_PARAMETER;

        argv[0] = (CHAR8 *)strtok_r((char *)str, first_delim, &saveptr);
        if (!argv[0])
                return EFI_INVALID_PARAMETER;

        for (*argc = 1; (UINTN)*argc < max_argc; (*argc)++) {
                token = strtok_r(NULL, delim, &saveptr);
                if (!token)
                        break;
                argv[*argc] = (CHAR8 *)token;
        }

        if (token && strtok_r(NULL, delim, &saveptr))
                return EFI_INVALID_PARAMETER;

        return EFI_SUCCESS;
}

int is_run_on_kvm(void)
{
    UINT32 reg[4];

    cpuid(0x40000000, reg);
    debug(L"cpuid: 0x%X 0x%X 0x%X 0x%X\n", reg[0], reg[1], reg[2], reg[3]);
    if (reg[0] == 0x40000001 && reg[1] == 0x4b4d564b && reg[2] == 0x564b4d56 && reg[3] == 0x4d)
        return 1;

    return 0;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */
