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

#ifndef _KF_LIB_H_
#define _KF_LIB_H_

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <ui.h>
#include <log.h>

#ifndef DEFINED_SIZE_T
typedef UINTN size_t;
#endif
typedef INTN ssize_t;

#define offsetof(TYPE, MEMBER) ((UINTN) &((TYPE *)0)->MEMBER)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define _CONVERT_TO_WIDE(x) L ## x
#define CONVERT_TO_WIDE(x) _CONVERT_TO_WIDE(x)

#define ULONG_MAX ((unsigned long)-1)
#define ULLONG_MAX ((unsigned long long)-1)
#define RSIZE_MAX_MEM      ( 256UL << 20 )     /* 256MB */

#define panic(x, ...) do { \
    error(x, ##__VA_ARGS__); \
    pause(30); \
    halt_system(); \
} while(0)

#define barrier() __asm__ __volatile__("" ::: "memory")

/* Current EFI image handle.  To be use as parent image with the
   LoadImage boot service */
extern EFI_HANDLE g_parent_image;

/*
 * EFI Variables
 */
EFI_STATUS get_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN *size_p, VOID **data_p,  UINT32 *flags_p);

CHAR16 *get_efi_variable_str(const EFI_GUID *guid, CHAR16 *key);
CHAR16 *get_efi_variable_str8(const EFI_GUID *guid, CHAR16 *key);

EFI_STATUS get_efi_variable_byte(const EFI_GUID *guid, CHAR16 *key, UINT8 *byte);
EFI_STATUS get_efi_variable_long_from_str8(const EFI_GUID *guid, CHAR16 *key,
                                           unsigned long *i);

EFI_STATUS del_efi_variable(const EFI_GUID *guid, CHAR16 *key);

EFI_STATUS set_efi_variable(const EFI_GUID *guid, CHAR16 *key,
                UINTN size, VOID *data, BOOLEAN nonvol, BOOLEAN runtime);

EFI_STATUS set_efi_variable_str(const EFI_GUID *guid, CHAR16 *key,
                BOOLEAN nonvol, BOOLEAN runtime, CHAR16 *val);

/*
 * File I/O
 */

EFI_STATUS file_delete(IN EFI_HANDLE disk, IN const CHAR16 *name);

BOOLEAN file_exists(IN EFI_HANDLE disk, IN const CHAR16 *path);

EFI_STATUS file_read(IN EFI_FILE_HANDLE dir, IN const CHAR16 *name,
                OUT CHAR8 **content, OUT UINTN *len);

/*
 * String manipulation
 */
CHAR16 *stra_to_str(const CHAR8 *stra);

EFI_STATUS str_to_stra(CHAR8 *dst, const CHAR16 *src, UINTN len);

EFI_STATUS stra_to_guid(const char *str, EFI_GUID *g);

int efi_vsnprintf(CHAR8 *dst, UINTN size, const CHAR8 *format, va_list ap);

int efi_snprintf(CHAR8 *str, UINTN size, const CHAR8 *format, ...);

VOID StrNCpy(OUT CHAR16 *dest, IN const CHAR16 *src, UINT32 n);

EFI_STATUS getdigit(IN CHAR16 *str, OUT UINT8 *outstr);

EFI_STATUS string_to_guid(IN CHAR16 *in_guid_str, OUT EFI_GUID *guid);

char *strcasestr(const char *s, const char *find);

char *strdup(const char *s)
    __attribute__((weak));

EFI_STATUS bytes_to_hex_stra(CHAR8 *bytes, UINTN length,
                             CHAR8 *str, UINTN str_size);

char *strtok_r(char *str, const char *delim, char **saveptr)
    __attribute__((weak));

CHAR16 *StrStr(const CHAR16 *s, const CHAR16 *find);

CHAR8 *strchr(const CHAR8 *s, int c)
    __attribute__((weak));

int strcmp(const CHAR8 *s1, const CHAR8 *s2)
    __attribute__((weak));

int strncasecmp(const char *s1, const char *s2, size_t n)
    __attribute__((weak));

int strncmp(const CHAR8 *s1, const CHAR8 *s2, size_t n)
    __attribute__((weak));

CHAR8 *strcpy(CHAR8 *dest, const CHAR8 *src)
    __attribute__((weak));

EFI_STATUS strcpy_s(char *restrict dest, size_t destsz, const char *restrict src)
    __attribute__((weak));

EFI_STATUS strcpy16_s(CHAR16 *restrict dest, size_t destsz, const CHAR16 *restrict src)
    __attribute__((weak));

CHAR8 *strncpy(CHAR8 *dest, const CHAR8 *src, size_t n)
    __attribute__((weak));

EFI_STATUS strncpy_s(char *restrict dest, size_t dmax, const char *restrict src, size_t slen)
    __attribute__((weak));

EFI_STATUS strncpy16_s(CHAR16 *restrict dest, size_t dmax, const CHAR16 *restrict src, size_t slen)
    __attribute__((weak));

EFI_STATUS strcat16_s (CHAR16 *restrict dest, size_t dmax, const CHAR16 *restrict src)
    __attribute__((weak));

size_t strlcat(CHAR8 *dst, const CHAR8 *src, size_t siz)
    __attribute__((weak));

size_t strlen(const CHAR8 *s)
    __attribute__((weak));

size_t strnlen(const CHAR8 *s, size_t maxlen)
    __attribute__((weak));

CHAR8 *itoa(int val, CHAR8 *buf, unsigned radix)
    __attribute__((weak));

void *memcpy(void *dest, const void *source, size_t count)
    __attribute__((weak));

#ifdef CRASHMODE_USE_ADB
EFI_STATUS memdump(void *dest, size_t dest_size, const void *source, size_t count)
    __attribute__((weak));
#endif

EFI_STATUS memcpy_s(void *dest, size_t dest_size, const void *source, size_t count)
    __attribute__((weak));

void *memmove(void *dst, const void *src, size_t n)
    __attribute__((weak));

void *memmove_s(void * dst, size_t destlen, const void * src, size_t len)
    __attribute__((weak));

unsigned long long strtoull(const char *nptr, char **endptr, int base)
    __attribute__((weak));

unsigned long strtoul(const char *nptr, char **endptr, int base)
    __attribute__((weak));

int isalnum(int c)
    __attribute__((weak));

int isspace(int c)
    __attribute__((weak));

int isdigit(int c)
    __attribute__((weak));

int isupper(int c)
    __attribute__((weak));

int isxdigit(int c)
    __attribute__((weak));

int tolower(int c)
    __attribute__((weak));

void qsort(void *base, size_t num, size_t width,
           int (*compare)(const void *, const void *))
    __attribute__((weak));

INTN StrcaseCmp(CHAR16 *s1, CHAR16 *s2);
void StrToLower(CHAR16 *s);
/*
 * misc
 */
#define _unused __attribute__((unused))

VOID halt_system(VOID) __attribute__ ((noreturn));

VOID pause(UINTN seconds);
VOID pause_us(UINTN microseconds);

VOID reboot(CHAR16 *target, EFI_RESET_TYPE type) __attribute__ ((noreturn));

void *memset(void *s, int c, size_t n)
    __attribute__((weak));

void *memset_s(void *dest, size_t dest_size, int c, size_t count)
    __attribute__((weak));

int memcmp(const void *s1, const void *s2, size_t n)
    __attribute__((weak));

EFI_STATUS alloc_aligned(VOID **free_addr, VOID **aligned_addr,
                         UINTN size, UINTN align);

void sort_memory_map(void *descr, UINTN nr_descr, UINTN descr_sz);

UINT64 efi_time_to_ctime(EFI_TIME *time);

VOID cpuid(UINT32 op, UINT32 reg[4]);

EFI_STATUS generate_random_numbers(CHAR8 *data, UINTN size);

BOOLEAN no_device_unlock();

UINT8 min_boot_state();

EFI_STATUS string_to_argv(char *str, INTN *argc, CHAR8 *argv[], UINTN max_argc,
                          const char *first_delim, const char *delim);

int is_running_on_kvm(void);
#endif

