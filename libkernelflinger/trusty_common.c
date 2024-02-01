/*
 * Copyright (c) 2017, Intel Corporation
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

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>

#include "vars.h"
#include "lib.h"
#include "security.h"
#include "android.h"
#include "options.h"
#include "power.h"
#include "trusty_common.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "efilinux.h"

#define AVB_COMPILATION
#include "avb_sha.h"
#include "slot.h"

extern char _binary_avb_pk_start;
extern char _binary_avb_pk_end;
#define avb_pk (&_binary_avb_pk_start)
#define avb_pk_size ((size_t)&_binary_avb_pk_end - (size_t)&_binary_avb_pk_start)

static EFI_STATUS android_query_image_and_size_from_avb_result(
                IN AvbSlotVerifyData *slot_data,
                IN const char *label,
                OUT VOID **image,
                OUT size_t *image_size
                )
{
    AvbPartitionData *pdata = NULL;

    for (size_t n = 0; n < slot_data->num_loaded_partitions; ++n) {
        pdata = &slot_data->loaded_partitions[n];
        if (!strcmp(pdata->partition_name, label)) {
            *image = pdata->data;
            *image_size = pdata->data_size;
            return EFI_SUCCESS;
        }
    }

    *image = NULL;
    return EFI_NOT_FOUND;
}

static AvbSlotVerifyResult avb_verify_image(const CHAR16 *label, const uint8_t *image_buf)
{
    AvbFooter footer;
    const AvbFooter *img_footer;
    const uint8_t* desc_partition_name = NULL;
    const uint8_t* desc_salt;
    const uint8_t* desc_digest;
    uint8_t* digest;
    size_t digest_len;
    size_t num_descriptors;
    AvbDescriptor desc;
    AvbHashDescriptor hash_desc;
    const AvbDescriptor** descriptors = NULL;
    const AvbDescriptor* descriptor;
    const uint8_t *out_public_key_data;
    size_t out_public_key_length;
    const uint8_t *vbmeta = NULL;
    uint64_t vbmeta_offset;
    uint64_t vbmeta_size;
    AvbSlotVerifyResult aret;
    EFI_STATUS ret;

    ret = read_partition_by_label(label, -AVB_FOOTER_SIZE, AVB_FOOTER_SIZE, &footer);
    if (EFI_ERROR(ret))
        return AVB_SLOT_VERIFY_RESULT_ERROR_OOM;

    img_footer = (const AvbFooter *)&footer;
    if (!avb_footer_validate_and_byteswap(img_footer, &footer)) {
        error(L"%a: No footer detected.\n", __FUNCTION__);
        return AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    }

    vbmeta_offset = footer.vbmeta_offset;
    vbmeta_size = footer.vbmeta_size;
    debug(L"vbmeta_offset=%d(0x%X), vbmeta_size=%d(0x%X)\n", vbmeta_offset, vbmeta_offset, vbmeta_size, vbmeta_size);
    vbmeta = AllocatePool(footer.vbmeta_size);
    if(vbmeta == NULL)
        return AVB_SLOT_VERIFY_RESULT_ERROR_OOM;

    aret = AVB_SLOT_VERIFY_RESULT_OK;
    do
    {
        AvbVBMetaVerifyResult vret;

        ret = read_partition_by_label(label, vbmeta_offset, vbmeta_size, (void *)vbmeta);
        if (EFI_ERROR(ret)) {
            error(L"%s: read vbmeta failed, off=0x%X, size=0x%X.\n", label, vbmeta_offset, vbmeta_size);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
            break;
        }

        vret = avb_vbmeta_image_verify(
            vbmeta,
            footer.vbmeta_size,
            &out_public_key_data,
            &out_public_key_length);
        if (vret != AVB_SLOT_VERIFY_RESULT_OK) {
            error(L"%s: invalid vbmeta, error=%a.\n", label, avb_vbmeta_verify_result_to_string(vret));
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
            break;
        }

        if(out_public_key_length > avb_pk_size
            || memcmp(out_public_key_data, avb_pk, out_public_key_length)) {
            error(L"%s: Invalid public key!!!!", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        descriptors = avb_descriptor_get_all(vbmeta, vbmeta_size, &num_descriptors);
        if(num_descriptors != 1) {
            error(L"%s: descriptor num %d != 1\n", label, num_descriptors);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        descriptor = descriptors[0];
        if (!avb_descriptor_validate_and_byteswap(descriptor, &desc)) {
            error(L"%s: Descriptor is invalid\n", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        if(desc.tag != AVB_DESCRIPTOR_TAG_HASH) {
            error(L"%s: unsupported descriptor tag(%d)\n", label, desc.tag);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        if (!avb_hash_descriptor_validate_and_byteswap(
                (const AvbHashDescriptor*)descriptor, &hash_desc)) {
            error(L"%s: invalid metadata!\n", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        desc_partition_name = ((const uint8_t*)descriptor) + sizeof(AvbHashDescriptor);
        desc_salt = desc_partition_name + hash_desc.partition_name_len;
        desc_digest = desc_salt + hash_desc.salt_len;
        if (avb_strcmp((const char*)hash_desc.hash_algorithm, "sha256") == 0) {
            AvbSHA256Ctx sha256_ctx;
            avb_sha256_init(&sha256_ctx);
            avb_sha256_update(&sha256_ctx, desc_salt, hash_desc.salt_len);
            avb_sha256_update(&sha256_ctx, image_buf, hash_desc.image_size);
            digest = avb_sha256_final(&sha256_ctx);
            digest_len = AVB_SHA256_DIGEST_SIZE;
        } else if (avb_strcmp((const char*)hash_desc.hash_algorithm, "sha512") == 0) {
            AvbSHA512Ctx sha512_ctx;
            avb_sha512_init(&sha512_ctx);
            avb_sha512_update(&sha512_ctx, desc_salt, hash_desc.salt_len);
            avb_sha512_update(&sha512_ctx, image_buf, hash_desc.image_size);
            digest = avb_sha512_final(&sha512_ctx);
            digest_len = AVB_SHA512_DIGEST_SIZE;
        } else {
            error(L"%s: Unsupported hash algorithm.\n", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        if (digest_len != hash_desc.digest_len) {
            error(L"%s: Digest in descriptor not of expected size.\n", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
            break;
        }

        if (avb_safe_memcmp(digest, desc_digest, digest_len) != 0) {
            error(L"%s: Hash of data does not match digest in descriptor.\n", label);
            aret = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
            break;
        }
    }while(0);

    if (vbmeta != NULL)
        FreePool((void *)vbmeta);

    return aret;
}

EFI_STATUS load_tos_image(OUT VOID **tosimage)
{
        EFI_STATUS ret;
        UINT8 verify_state = BOOT_STATE_GREEN;
        UINT8 verify_state_new;
        AvbSlotVerifyData *slot_data;
        CHAR16 label[16];
        const char *slot_suffix = "";
        BOOLEAN b_secureboot = is_platform_secure_boot_enabled();
        AvbSlotVerifyResult vret;

        if (!b_secureboot)
                verify_state = BOOT_STATE_YELLOW;
#ifndef USER
        if (device_is_unlocked())
                verify_state = BOOT_STATE_ORANGE;
#endif

        verify_state_new = verify_state;

        ret = android_image_load_partition_avb("tos", tosimage, &verify_state_new, &slot_data);  // Do not try to switch slot if failed
        if (EFI_ERROR(ret)) {
                efi_perror(ret, L"TOS image loading failed");
                return ret;
        }

        if (verify_state_new != verify_state)
            warning(L"TOS verify state '%s' do not meet required state '%s'\n",
                boot_state_to_string(verify_state_new), boot_state_to_string(verify_state));

        if (verify_state_new == BOOT_STATE_RED)
            return EFI_SECURITY_VIOLATION;

        if (use_slot())
            slot_suffix = slot_get_active();
        if (!slot_suffix)
            slot_suffix = "";
        SPrint(label, sizeof(label), L"%a%a", "tos", slot_suffix);
        vret = avb_verify_image(label, *tosimage);
        debug(L"avb_verify_image ret = 0x%X\n", vret);
        if (vret != AVB_SLOT_VERIFY_RESULT_OK)
            return EFI_SECURITY_VIOLATION;

        return EFI_SUCCESS;
}

static VOID activate_vtd(VOID)
{
#define VMCALL_ACTIVATE_VTD 0x56544400ULL        // "VTD"
        asm volatile ("vmcall" : : "a"(VMCALL_ACTIVATE_VTD));
}

/*
 * This function is designed to run after bootloader triggered ExitBootService.
 */
VOID trusty_late_init(VOID)
{
        activate_vtd();
}
