/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Matt Wood <matthew.d.wood@intel.com>
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

#include <efi.h>
#include <efilib.h>
#include <openssl/x509.h>
#include "android_vb2.h"
#include "security_vb2.h"

#ifndef _SECURITY_H_
#define _SECURITY_H_

#define BOOT_TARGET_SIZE         32
#define BOOT_SIGNATURE_MAX_SIZE  4096
#define ROT_DATA_STRUCT_VERSION2 0x02

#define SETUP_MODE_VAR	        L"SetupMode"
#define SECURE_BOOT_VAR         L"SecureBoot"

BOOLEAN is_platform_secure_boot_enabled(VOID);
BOOLEAN is_eom_and_secureboot_enabled(VOID);
EFI_STATUS set_platform_secure_boot(UINT8 secure);
EFI_STATUS set_os_secure_boot(BOOLEAN secure);

#ifdef BOOTLOADER_POLICY
/* Given a PKCS7 (DER encoded), look for the root certificate based on
 * CERT_SHA256 and verify the PKCS7.  On success, EFI_SUCCESS is
 * return and the PKCS7 payload is returned in DATA as a dynamically
 * allocated buffer.
 */
EFI_STATUS verify_pkcs7(const unsigned char *cert_sha256, UINTN cert_size,
			const VOID *pkcs7, UINTN pkcs7_size,
			VOID **data, int *size);
#endif  /* BOOTLOADER_POLICY */


/* Structure for RoT info (fields defined by Google Keymaster2)
*/
struct rot_data_t{
        /* version 2 for current TEE keymaster2 */
        UINT32 version;
        /* 0:unlocked, 1:locked, others not used */
        UINT32 deviceLocked;
        /* GREEN:0, YELLOW:1, ORANGE:2, others not used(no RED for TEE) */
        UINT32 verifiedBootState;
        /* The current version of the OS as an integer in the format MMmmss,
          * where MM is a two-digit major version number, mm is a two-digit,
          * minor version number, and ss is a two-digit sub-minor version number.
          * For example, version 6.0.1 would be represented as 060001;
        */
        UINT32 osVersion;
        /* The month and year of the last patch as an integer in the format,
          * YYYYMM, where YYYY is a four-digit year and MM is a two-digit month.
          * For example, April 2016 would be represented as 201604.
        */
        UINT32 patchMonthYear;
        /* A secure hash (SHA-256 recommended by Google) of the key used to verify the system image
          * key_size (in bytes) is zero: denotes no key provided by Bootloader. When key_size is
          * 32, it denotes,key_hash256 is available. Other values not defined now.
        */
        UINT32 keySize;
        UINT8  keyHash256[SHA256_DIGEST_LENGTH];
} ;

/* Update the struct rot_data for startup_information */
EFI_STATUS update_rot_data(
        IN VOID *bootimage,
        IN UINT8 boot_state,
        IN VBDATA *vb_data);

/* Initialize the struct rot_data for startup_information */
EFI_STATUS init_rot_data(
        UINT32 boot_state);

/* Return rot data instance pointer*/
struct rot_data_t *get_rot_data();

EFI_STATUS raw_pub_key_sha256(
        IN const UINT8 *pub_key,
        IN UINTN pub_key_len,
        OUT UINT8 **hash_p);

#endif
