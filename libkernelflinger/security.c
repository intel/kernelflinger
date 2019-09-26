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
#include "signature.h"
#include "lib.h"
#include "vars.h"
#include "life_cycle.h"

#ifdef USE_IPP_SHA256
#include "sha256_ipps.h"
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

#ifdef BOOTLOADER_POLICY
static X509 *find_cert_in_pkcs7(PKCS7 *p7, const unsigned char *cert_sha256)
{
        STACK_OF(X509) *certs = NULL;
        X509 *x509;
        int id;
        unsigned int size;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        const EVP_MD *fdig = EVP_sha256();
        int i;

        id = OBJ_obj2nid(p7->type);
        switch (id) {
        case NID_pkcs7_signed:
                certs = p7->d.sign->cert;
                break;
        case NID_pkcs7_signedAndEnveloped:
                certs = p7->d.signed_and_enveloped->cert;
                break;
        default:
                break;
        }

        if (!certs)
                return NULL;

        for (i = 0; i < sk_X509_num(certs); i++) {
                x509 = sk_X509_value(certs, i);
                if (!X509_digest(x509, fdig, digest, &size)) {
                        error(L"Failed to compute X509 digest");
                        return NULL;
                }
                if (size != sizeof(digest))
                        continue;
                if (!memcmp(cert_sha256, digest, sizeof(digest)))
                        return x509;
        }

        return NULL;
}

static UINT64 get_signing_time(PKCS7 *p7)
{
        ASN1_TYPE *stime = NULL;
        STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
        PKCS7_SIGNER_INFO *sinfo;
        int i;
        EFI_TIME t;
        unsigned char *str;

        sinfos = PKCS7_get_signer_info(p7);
        if (!sinfos) {
                error(L"Failed to get signer info");
                return 0;
        }

        for (i = 0; i < SKM_sk_num(PKCS7_SIGNER_INFO, sinfos); i++) {
                sinfo = SKM_sk_value(PKCS7_SIGNER_INFO, sinfos, i);
                stime = PKCS7_get_signed_attribute(sinfo, NID_pkcs9_signingTime);
                if (stime)
                        break;
        }

        if (!stime) {
                error(L"Could not find signing time");
                return 0;
        }

        if (stime->type != V_ASN1_UTCTIME) {
                error(L"Unsupported signing time type %d", stime->type);
                return 0;
        }

        str = stime->value.utctime->data;
        memset(&t, 0, sizeof(t));

        /* ASN1_UTCTIME format is "YYmmddHHMMSS" */
        t.Year = 1900 + (str[0] - '0') * 10 + (str[1] - '0');
        if (t.Year < 1970)
                t.Year += 100;

        t.Month  = (str[2] - '0') * 10 + (str[3] - '0');
        t.Day = (str[4] - '0') * 10 + (str[5] - '0');
        t.Hour = (str[6] - '0') * 10 + (str[7] - '0');
        t.Minute  = (str[8] - '0') * 10 + (str[9] - '0');
        t.Second  = (str[10] - '0') * 10 + (str[11] - '0');

        debug(L"year=%d, month=%d, day=%d, hour=%d, minute=%d, second=%d",
              t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second);

        /* Note: no timezone management */
        return efi_time_to_ctime(&t);
}

EFI_STATUS verify_pkcs7(const unsigned char *cert_sha256, UINTN cert_size,
                        const VOID *pkcs7, UINTN pkcs7_size,
                        VOID **data_p, int *size)
{
        X509 *x509;
        PKCS7 *p7 = NULL;
        X509_STORE *store = NULL;
        BIO *p7_bio = NULL, *data_bio = NULL;
        VOID *payload = NULL;
        UINT64 signing_time;
        char *tmp;
        int ret;

        if (cert_size != SHA256_DIGEST_LENGTH) {
                error(L"Invalid SHA256 length for trusted certificate");
                goto done;
        }

        p7_bio = BIO_new_mem_buf((void *)pkcs7, pkcs7_size);
        if (!p7_bio) {
                error(L"Failed to create PKCS7 BIO");
                goto done;
        }

        p7 = d2i_PKCS7_bio(p7_bio, NULL);
        if (!p7) {
                error(L"Failed to read PKCS7");
                goto done;
        }

        x509 = find_cert_in_pkcs7(p7, cert_sha256);
        if (!x509) {
                error(L"Could not find the root certificate");
                goto done;
        }

        signing_time = get_signing_time(p7);
        if (!signing_time)
                goto done;

        store = X509_STORE_new();
        if (!store) {
                error(L"Failed to create x509 store");
                goto done;
        }

        ret = X509_STORE_add_cert(store, x509);
        if (ret != 1) {
                error(L"Failed to add trusted certificate to store");
                goto done;
        }

        data_bio = BIO_new(BIO_s_mem());
        if (!data_bio) {
                error(L"Failed to create data BIO");
                goto done;
        }

        EVP_add_digest(EVP_sha256());
        X509_VERIFY_PARAM_set_time(store->param, signing_time);
        ret = PKCS7_verify(p7, NULL, store, NULL, data_bio, 0);
        if (ret != 1) {
                error(L"PKCS7 verification failed");
                goto done;
        }

        *size = BIO_get_mem_data(data_bio, &tmp);
        if (*size == -1) {
                error(L"Failed to get PKCS7 data");
                goto done;
        }

        payload = AllocatePool(*size);
        if (!payload) {
                error(L"Failed to allocate data buffer");
                goto done;
        }

        memcpy(payload, tmp, *size);
        *data_p = payload;

done:
        if (p7_bio)
                BIO_free(p7_bio);
        if (p7)
                PKCS7_free(p7);
        if (store)
                X509_STORE_free(store);
        if (data_bio)
                BIO_free(data_bio);

        return payload ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}
#endif  /* BOOTLOADER_POLICY */


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
        rot_data.osVersion = (temp_version.split.version_A * 100 + temp_version.split.version_B) * 100 + temp_version.split.version_C;
        rot_data.patchMonthYear = (temp_version.split.year + 2000) * 100 + temp_version.split.month;
        rot_data.keySize = SHA256_DIGEST_LENGTH;

        if (vb_data) {
                ret = rot_pub_key_sha256(vb_data, &temp_hash);
                if (EFI_ERROR(ret)) {
                        efi_perror(ret, L"Failed to compute key hash");
                        return ret;
                }
                CopyMem(rot_data.keyHash256, temp_hash, rot_data.keySize);
        } else {
                memset(rot_data.keyHash256, 0, SHA256_DIGEST_LENGTH);
        }
        return ret;
}

/* initialize the struct rot_data for startup_information */
EFI_STATUS init_rot_data(UINT32 boot_state)
{
    /* Initialize the rot data structure */
    rot_data.version = ROT_DATA_STRUCT_VERSION2;
    rot_data.deviceLocked = 1;
    rot_data.verifiedBootState = boot_state;

    rot_data.osVersion = 0;
    rot_data.patchMonthYear = 0;
    rot_data.keySize = SHA256_DIGEST_LENGTH;

    /* TBD: keyHash should be the key which used to sign vbmeta.ias */
    memset(rot_data.keyHash256, 0, SHA256_DIGEST_LENGTH);

    return EFI_SUCCESS;
}

/* Return rot data instance pointer */
struct rot_data_t* get_rot_data()
{
	return &rot_data;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

