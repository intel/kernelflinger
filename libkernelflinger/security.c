/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Matt Wood <matthew.d.wood@intel.com>
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
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

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "security.h"
#include "android.h"
#include "lib.h"
#include "vars.h"
#include "life_cycle.h"
#include "uefi_utils.h"

#ifdef USE_IVSHMEM
#include "ivshmem.h"

extern UINT64 g_ivshmem_rot_addr;
#endif

/* OsSecureBoot is *not* a standard EFI_GLOBAL variable
 *
 * It's value will be read at ExitBootServices() by the BIOS to run
 * some hooks which will restrain some security features in case of a
 * non os secure boot.
 *
 * It's value is 0 for unsecure, 1 for secure.
 * We say we have an os secure boot when the boot state is green. */
#define OS_SECURE_BOOT_VAR      L"OsSecureBoot"

/* operating system version and security patch level; for
     * version "A.B.C" and patch level "Y-M":
     * os_version = (A * 100 + B) * 100 + C   (7 bits for each of A, B, C)
     * lvl = (year + 2000) * 100 + month      (7 bits for Y, 4 bits for M) */
union android_version {
    UINT32 value;
    struct {
        UINT32 month:4;
        UINT32 year:7;
        UINT32 version_C:7;
        UINT32 version_B:7;
        UINT32 version_A:7;
     } __attribute__((packed)) split;
};

static struct rot_data_t rot_data;
static struct attestation_ids_t attestation_ids;

EFI_STATUS raw_pub_key_sha256(IN const UINT8 *pub_key,
            IN UINTN pub_key_len,
            OUT UINT8 **hash_p)
{
        int ret;
        static UINT8 hash[SHA256_DIGEST_LENGTH];

        ret = EVP_Digest(pub_key, pub_key_len, hash, NULL, EVP_sha256(), NULL);
        if (ret == 0) {
            error(L"Failed to hash the RoT bitstream");
            return EFI_INVALID_PARAMETER;
        }
        *hash_p = hash;

        return EFI_SUCCESS;
}

EFI_STATUS set_os_secure_boot(BOOLEAN secure)
{
        EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;
        UINT8 value = secure ? 1 : 0;

        debug(L"Setting os secure boot to %d", value);
        return set_efi_variable(&global_guid, OS_SECURE_BOOT_VAR, sizeof(value),
                                &value, FALSE, TRUE);
}

/* Update the struct rot_data for startup_information */
EFI_STATUS update_rot_data(IN VOID *bootimage, IN UINT8 boot_state,
                        IN VBDATA *vb_data)
{
        EFI_STATUS ret = EFI_SUCCESS;
        enum device_state state;
        struct boot_img_hdr *boot_image_header;
        UINT8 *temp_hash;
        union android_version temp_version;

        if (!bootimage)
                return EFI_INVALID_PARAMETER;

        boot_image_header = (struct boot_img_hdr *)bootimage;

        /* Initialize the rot data structure */
        rot_data.version = ROT_DATA_STRUCT_VERSION2;
        state = get_current_state();
        switch (state) {
                case UNLOCKED:
                        rot_data.deviceLocked = 0;
                        break;
                case LOCKED:
                        rot_data.deviceLocked = 1;
                        break;
                default:
                        debug(L"Unknown device state");
                        return EFI_UNSUPPORTED;
        }
        rot_data.verifiedBootState = boot_state;

        temp_version.value = boot_image_header->os_version;
        if (boot_image_header->header_version >= BOOT_HEADER_V3) {
                struct boot_img_hdr_v3 *boot_hdr = (struct boot_img_hdr_v3 *)bootimage;
                temp_version.value = boot_hdr->os_version;
        }
        rot_data.osVersion = (temp_version.split.version_A * 100 + temp_version.split.version_B) * 100 + temp_version.split.version_C;
        /* VTS require the patchlevel's format should be YYYYMMDD, but the patch level's format in boot header */
        /* is YYYYMM. We set the DD value to a fixed value of 1. */
        rot_data.patchMonthYearDay = ((temp_version.split.year + 2000) * 100 + temp_version.split.month) * 100 + 1;
        rot_data.keySize = SHA256_DIGEST_LENGTH;

        if (vb_data) {
                ret = rot_pub_key_sha256(vb_data, &temp_hash);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to compute key hash");
                        return ret;
                }
                if (state == LOCKED) {
                        CopyMem(rot_data.keyHash256, temp_hash, rot_data.keySize);
                } else {
                        memset_s(rot_data.keyHash256, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
                        barrier();
                }

                AvbVBMetaImageHeader h;
                UINT8* vbmeta_data = vb_data->vbmeta_images[0].vbmeta_data;
                avb_vbmeta_image_header_to_host_byte_order((const AvbVBMetaImageHeader*)vbmeta_data, &h);

                switch (h.algorithm_type) {
                        /* Explicit fallthrough. */
                        case AVB_ALGORITHM_TYPE_NONE:
                        case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
                        case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
                        case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
                                avb_slot_verify_data_calculate_vbmeta_digest(
                                                vb_data, AVB_DIGEST_TYPE_SHA256, rot_data.vbmetaDigest);
                                rot_data.digestSize= AVB_SHA256_DIGEST_SIZE;
                                break;
                                /* Explicit fallthrough. */
                        case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
                        case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
                        case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
                                avb_slot_verify_data_calculate_vbmeta_digest(
                                                vb_data, AVB_DIGEST_TYPE_SHA512, rot_data.vbmetaDigest);
                                rot_data.digestSize = AVB_SHA512_DIGEST_SIZE;
                                break;
                        default:
                                debug(L"Unknown digest type");
                                return EFI_UNSUPPORTED;
                                break;
                }

        } else {
                memset_s(rot_data.keyHash256, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);
                memset_s(rot_data.vbmetaDigest, AVB_SHA512_DIGEST_SIZE, 0, AVB_SHA512_DIGEST_SIZE);
                barrier();
        }
        return ret;
}

#ifdef USE_IVSHMEM
EFI_STATUS ivsh_send_rot_data(IN VOID *bootimage, IN UINT8 boot_state,
                        IN VBDATA *vb_data)
{
    EFI_STATUS ret = EFI_SUCCESS;

    if (!g_ivshmem_rot_addr)
        return EFI_NOT_READY;

    ret = update_rot_data(bootimage, boot_state, vb_data);
    if (EFI_ERROR(ret)) {
        efi_perror(ret, L"Unable to update the root of trust data");
        return ret;
    }

    memcpy_s((void*)g_ivshmem_rot_addr, sizeof(struct rot_data_t),
            &rot_data, sizeof(struct rot_data_t));

    /* trigger an interrupt to optee */
    ivshmem_rot_interrupt();

    return ret;
}
#endif

/* initialize the struct rot_data for startup_information */
EFI_STATUS init_rot_data(UINT32 boot_state)
{
    /* Initialize the rot data structure */
    rot_data.version = ROT_DATA_STRUCT_VERSION2;
    rot_data.deviceLocked = 1;
    rot_data.verifiedBootState = boot_state;

    rot_data.osVersion = 0;
    rot_data.patchMonthYearDay = 0;
    rot_data.keySize = SHA256_DIGEST_LENGTH;

    /* TBD: keyHash should be the key which used to sign vbmeta.ias */
    memset_s(rot_data.keyHash256, SHA256_DIGEST_LENGTH, 0, SHA256_DIGEST_LENGTH);

    return EFI_SUCCESS;
}

/* Return rot data instance pointer */
struct rot_data_t* get_rot_data()
{
	return &rot_data;
}

CHAR8* strrpl(CHAR8 *in, const char src, const char dst)
{
    if (NULL == in)
        return in;
    CHAR8 *p = in;
    while(*p != '\0'){
        if(*p == src)
            *p = dst;
        p++;
    }
    return in;
}

static EFI_STATUS set_attestation_ids(UINT8 *src)
{
    const char *delim = "=";
    CHAR8 *savedPtr2;
    const char d1 = ',';
    const char d2 = ' ';
    CHAR8 *token;
    CHAR8 *temp;
    unsigned size;

    if (src == NULL)
        return EFI_INVALID_PARAMETER;

    token = strtok_r(src, delim, (char **)&savedPtr2);//Get the string after the equal sign
    temp = strrpl(savedPtr2, d1, d2);//Converts comma to space in the string
    size = (strlen(temp) < ATTESTATION_ID_MAX_LENGTH) ? strlen(temp) : ATTESTATION_ID_MAX_LENGTH;
    if (strncmp(token, "androidboot.brand", strlen("androidboot.brand")) == 0) {
        attestation_ids.brandSize = size;
        CopyMem(attestation_ids.brand, temp, size);
    } else if (strncmp(token, "androidboot.device", strlen("androidboot.device")) == 0) {
        attestation_ids.deviceSize = size;
        CopyMem(attestation_ids.device, temp, size);
    } else if (strncmp(token, "androidboot.model", strlen("androidboot.model")) == 0) {
        attestation_ids.modelSize = size;
        CopyMem(attestation_ids.model, temp, size);
    } else if (strncmp(token, "androidboot.manufacturer", strlen("androidboot.manufacturer")) == 0) {
        attestation_ids.manufacturerSize = size;
        CopyMem(attestation_ids.manufacturer, temp, size);
    } else if (strncmp(token, "androidboot.name", strlen("androidboot.name")) == 0) {
        attestation_ids.nameSize = size;
        CopyMem(attestation_ids.name, temp, size);
    } else
        return EFI_UNSUPPORTED;

    return EFI_SUCCESS;
}

/* Update the struct attestation_ids for startup_information */
EFI_STATUS update_attestation_ids(IN VOID *vendorbootimage)
{
    EFI_STATUS ret = EFI_SUCCESS;
    struct vendor_boot_img_hdr_v4 *vendor_hdr;
    UINT32 page_size;
    UINT32 bootconfig_offset;
    UINT8 *configChar;
    const char *delim = "\n";
    CHAR8 *savedPtr;
    CHAR8 *token;
    CHAR8 *temp_serial = NULL;

    if(vendorbootimage == NULL || ((struct vendor_boot_img_hdr_v3 *)vendorbootimage)->header_version < 4)
        return ret;

    vendor_hdr = (struct vendor_boot_img_hdr_v4 *)vendorbootimage;
    page_size = vendor_hdr->page_size;
    bootconfig_offset = ALIGN(sizeof(struct vendor_boot_img_hdr_v4), page_size) +
                               ALIGN(vendor_hdr->vendor_ramdisk_size, page_size) +
                               ALIGN(vendor_hdr->dtb_size, page_size) +
                               ALIGN(vendor_hdr->vendor_ramdisk_table_size, page_size);

    if (vendor_hdr->bootconfig_size == 0)
        return ret;

    /* Initialize the attestation ids structure */
    configChar = AllocatePool(vendor_hdr->bootconfig_size + 1);
    memcpy_s(configChar,
    vendor_hdr->bootconfig_size, vendorbootimage + bootconfig_offset,
    vendor_hdr->bootconfig_size);
    configChar[vendor_hdr->bootconfig_size] = '\0';
    token = (CHAR8 *)strtok_r((char *)configChar, delim, (char **)&savedPtr);
    while (token != NULL) {
        set_attestation_ids(token);
        token = (CHAR8 *)strtok_r(NULL, delim, (char **)&savedPtr);
    }

    temp_serial = get_serial_number();
    attestation_ids.serialSize = (strlen(temp_serial) < ATTESTATION_ID_MAX_LENGTH) ? strlen(temp_serial) : ATTESTATION_ID_MAX_LENGTH;
    CopyMem(attestation_ids.serial, temp_serial, attestation_ids.serialSize);

    if(configChar)
        FreePool(configChar);

    return ret;
}

/* initialize the struct attestation_ids for startup_information */
EFI_STATUS init_attestation_ids()
{
    /* Initialize the attestation ids structure */
    attestation_ids.brandSize = 0;
    memset_s(attestation_ids.brand, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    attestation_ids.deviceSize = 0;
    memset_s(attestation_ids.device, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    attestation_ids.modelSize = 0;
    memset_s(attestation_ids.model, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    attestation_ids.manufacturerSize = 0;
    memset_s(attestation_ids.manufacturer, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    attestation_ids.nameSize = 0;
    memset_s(attestation_ids.name, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    attestation_ids.serialSize = 0;
    memset_s(attestation_ids.serial, ATTESTATION_ID_MAX_LENGTH, 0, ATTESTATION_ID_MAX_LENGTH);

    return EFI_SUCCESS;
}

/* Return rot data instance pointer */
struct attestation_ids_t* get_attestation_ids()
{
    return &attestation_ids;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
*/

