/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
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

#include <openssl/obj_mac.h>

#include "lib.h"

#define IASS_MAGIC		0x53534149 /* "IASS" */
#define IASS_VERSION		1
#define RSA2048_MODULUS_SIZE	256

enum iass_digest_algorithm {
	SHA256
};

/* Intel Automotive Solution boot image Signature
 *
 * This structure defines the signature format of a boot image.
 */
typedef struct ias_sig {
	/* Intel Automotive Solution android image Signature magic
	 * number (see IASS_MAGIC). */
	UINT32 magic;
	/* Version of struct being used (see IASS_VERSION). */
	UINT16 version;
	/* Digest algorithm being used (see iass_digest_algorithm). */
	UINT16 digest_algorithm;
	/* AndroidVerifiedBootSignature.AuthenticatedAttributes as
	 * described in the Google Verified Boot image signature ASN.1
	 * grammar. */
	struct aosp_authenticated_attribute {
		char target[TARGET_MAX];
		UINT32 length;
	} __attribute__((__packed__)) attributes;
	/* Ensure 1-Kbytes structure size and reserve space for
	 * further use. */
	char reserved[464];
	/* RSA 2048 signature of the SHA256 of the Android boot image
	 * plus all the fields preceding the "signature" field. */
	char signature[RSA2048_MODULUS_SIZE];
	/* RSA 2048 public key. */
	struct pkey {
		char modulus[RSA2048_MODULUS_SIZE];
		UINT32 exponent;
	} __attribute__((__packed__)) pkey;
} __attribute__((__packed__)) ias_sig_t;

EFI_STATUS decode_boot_signature(const unsigned char *data, long size,
				 struct boot_signature *bs)
{
	EFI_STATUS ret;
	ias_sig_t *sig = (ias_sig_t *)data;
	UINTN len;

	if (!data || !bs)
		return EFI_INVALID_PARAMETER;

	if ((UINTN)size < sizeof(*sig))
		return EFI_INVALID_PARAMETER;

	if (sig->magic != IASS_MAGIC)
		return EFI_INVALID_PARAMETER;

	if (sig->version != IASS_VERSION)
		return EFI_UNSUPPORTED;

	memset_s(bs, sizeof(*bs), 0, sizeof(*bs));

	switch (sig->digest_algorithm) {
	case SHA256:
		bs->id.nid = NID_sha256WithRSAEncryption;
		break;
	default:
		return EFI_UNSUPPORTED;
	}

	len = strnlen((CHAR8 *)sig->attributes.target,
		      sizeof(sig->attributes.target));
	if (len == sizeof(sig->attributes.target))
		return EFI_INVALID_PARAMETER;

	ret = memcpy_s(bs->attributes.target, sizeof(bs->attributes.target), sig->attributes.target,
				   len);
	if (EFI_ERROR(ret))
		return ret;

	bs->attributes.length = sig->attributes.length;
	bs->attributes.data = data;
	bs->attributes.data_sz = offsetof(ias_sig_t, signature);

	bs->signature = AllocatePool(sizeof(sig->signature));
	if (!bs->signature)
		return EFI_OUT_OF_RESOURCES;
	ret = memcpy_s(bs->signature, sizeof(bs->signature), sig->signature, sizeof(sig->signature));
	if (EFI_ERROR(ret))
		return ret;

	bs->signature_len = sizeof(sig->signature);
	bs->total_size = sizeof(*sig);

	return EFI_SUCCESS;
}
