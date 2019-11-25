/*
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Author: Wu  Ji <ji.j.wu@intel.com>  Zhang, GaofengX <gaofengx.zhang@intel.com>
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
 */

#include <efi.h>
#include <efiapi.h>
#include <efilib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include "uefi_utils.h"
#include "protocol.h"
#include "gpt.h"
#include "log.h"
#include "vars.h"
#include "security.h"
#include "lib.h"

#define IASIMAGE_MAX_SUB_IMAGE      32
#define EVP_MAX_MD_SIZE             64

typedef struct {
	VOID      *addr;
	UINT32    size;
} IASIMAGE_DATA;

typedef struct {                    // an IAS image generic header:
	UINT32    magicPattern;     // identifies structure (acts as valid flag)
	UINT32    imageType;        // image and compression type; values TBD
	UINT32    version;          // header version
	UINT32    dataLength;       // size of payload (data) in image
	UINT32    dataOffset;       // offset to payload data from header
	UINT32    uncompressedLen;  // uncompresse data length
	UINT32    headerCrc;        // CRC-32C over entire header
} IASIMAGE_HEADER;

#define MAGIC_PATTERN               0x2E6B7069
#define IAS_IMAGE_TYPE(it)          (((it) & 0xffff0000) >> 16)
#define IAS_IMAGE_IS_SIGNED(it)     ((it) & 0x100)
#define IAS_EXT_HDR(h)              ((UINTN) (h) + sizeof(IASIMAGE_HEADER))
#define IAS_PAYLOAD(h)              ((UINTN) (h) + (h)->dataOffset)
#define IAS_PAYLOAD_END(h)          (IAS_PAYLOAD(h) + (h)->dataLength + sizeof(UINT32))
#define IAS_EXT_HDR_SIZE(h)         ((h)->dataOffset - sizeof(IASIMAGE_HEADER))
#define ROUNDED_DOWN(val, align)    ((val) & ~((align) - 1))
#define ROUNDED_UP(val, align)      ROUNDED_DOWN((val) + (align) - 1, (align))
#define IAS_SIGNATURE(h)            (((UINTN)(h)) + ROUNDED_UP((h)->dataOffset + (h)->dataLength + sizeof(UINT32), 256))

/*Obtain sub files from ias image*/
static EFI_STATUS ias_get_sub_files(void *iasimage, UINT32 numImg,
				    IASIMAGE_DATA *img, UINT32 *numFile)
{
	UINT32 *subFileSizeArray;
	VOID *addr;
	UINT32 index;
	IASIMAGE_HEADER *header = (IASIMAGE_HEADER*)iasimage;

	subFileSizeArray = (UINT32 *)IAS_EXT_HDR(header);
	*numFile = IAS_EXT_HDR_SIZE (header) / sizeof (UINT32);

	//Return error if num of sub files is not even, as filepath and filehash should exist as pair
	if (*numFile%2)
		return EFI_INVALID_PARAMETER;

	if (numImg != 0) {
		ZeroMem(img, numImg * sizeof(img[0]));
		addr = (VOID *)IAS_PAYLOAD(header);

		// If there are sub-images (Index.e NumFile > 0) return their addresses and sizes.
		for (index = 0 ; index < numImg && index < *numFile ; index += 1) {
			img[index].addr = addr;
			img[index].size = subFileSizeArray[index];
			addr = (UINT32 *) ((UINT8 *)addr + ROUNDED_UP(img[index].size, 4));
		}
	}

	return EFI_SUCCESS;
}

/*Obtain file io interface of the label name parition*/
static EFI_STATUS get_partition_io(CHAR16 *label, EFI_FILE_IO_INTERFACE **io)
{

	EFI_STATUS ret;
	EFI_HANDLE handle = NULL;

	ret = gpt_get_partition_handle(label, LOGICAL_UNIT_USER,
			&handle);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	ret = handle_protocol(handle, &FileSystemProtocol,
			(void **)io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Handle protocol %s failed", label);
		return ret;
	}

	return ret;
}

/*Get buffer sha256 hash value*/
static void hash_buffer(CHAR8 *buffer, UINT64 len, CHAR8 *hash)
{
	EVP_MD_CTX mdctx;

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(&mdctx, buffer, len);
	EVP_DigestFinal_ex(&mdctx, hash, NULL);
	EVP_MD_CTX_cleanup(&mdctx);
}

/*Check if input hash matches the real hash of the file with that filename*/
static EFI_STATUS verify_file_hash(CHAR8* filename,
				EFI_FILE_IO_INTERFACE *io,
				CHAR8* hash,
				UINT32 hashLen,
				BOOLEAN* verify_pass)
{
	EFI_STATUS ret = EFI_SUCCESS;
	CHAR8 *data;
	UINTN size = 0;
	CHAR8 realHash[EVP_MAX_MD_SIZE] = {0};
	CHAR16 *file;

	file = stra_to_str((CHAR8*)(filename));
	ret = uefi_read_file(io, file, (VOID **)&data, &size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read %s",file);
		*verify_pass = FALSE;
		goto out;
	}
	hash_buffer(data, size, realHash);
	FreePool(data);
	if (memcmp(hash, realHash, hashLen)) {
		*verify_pass = FALSE;
		error(L"'%s' verify failure", file);
		goto out;
	}
	Print(L"'%s' verify pass\n", file);
	*verify_pass = TRUE;

out:
	FreePool(filename);
	return ret;
}

static X509 *der_to_x509(CONST UINT8 *der, UINTN size)
{
	BIO *bio;
	X509 *x509;

	/* BIO is the OpenSSL input/output abstraction. Instantiate
	* one using a memory buffer containing the certificate */
	bio = BIO_new_mem_buf((void *)der, size);
	if (!bio)
		return NULL;

	/* Obtain an x509 structure from the DER cert data */
	x509 = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	return x509;
}

static EVP_PKEY *get_rsa_pubkey(X509 *cert)
{
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (!pkey)
		return NULL;

	if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
	        EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

/*Signature check ias iamge*/
static EFI_STATUS verify_ias_image(void *iasimage, BOOLEAN* verify_pass)
{
	UINT8 *signature_data;
	CHAR8 datahash[32] = {0};
	UINT32 datalen = 0;
	EVP_PKEY *pkey = NULL;
	RSA *rsa;
	EFI_STATUS ret;
	int rsa_ret;

	IASIMAGE_HEADER *header = (IASIMAGE_HEADER*)iasimage;
	if (header->magicPattern !=  MAGIC_PATTERN){
		error(L"[IAS image] Check magic pattern fail\n");
		return EFI_INVALID_PARAMETER;
	}

	if (IAS_IMAGE_TYPE(header->imageType)!= 0x4){
		error(L"[IAS image] Check imageType fail\n");
		return EFI_INVALID_PARAMETER;
	}

	//TBD
	//CRC check

	if (!IAS_IMAGE_IS_SIGNED(header->imageType)){
		error(L"[IAS image] Image is unsigned\n");
		return EFI_INVALID_PARAMETER;
	}

	signature_data = (UINT8*)IAS_SIGNATURE(header);
	datalen = (UINTN)IAS_PAYLOAD_END(header) - (UINTN) header;

	SHA256(iasimage, datalen, datahash);

	X509 *cert = der_to_x509(oem_cert, oem_cert_size);
	pkey = get_rsa_pubkey(cert);
	if (!pkey)
		return EFI_INVALID_PARAMETER;

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		ret = EFI_INVALID_PARAMETER;
		goto free_pkey;
	}

	rsa_ret = RSA_verify(NID_sha256,
                         datahash, 32, signature_data, EVP_PKEY_bits(pkey)/8, rsa);
	if (rsa_ret == 1)
		*verify_pass = TRUE;
	else
		*verify_pass = FALSE;

	ret = EFI_SUCCESS;

free_pkey:
	EVP_PKEY_free(pkey);
	return ret;
}

/*Verify vbmeta iasimage's integerity*/
/*Verify vbmeta cover files' integerity*/
EFI_STATUS verify_vbmeta_ias(CHAR16 *label, CHAR16* fileName, BOOLEAN* verify_pass)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT32 index;
	UINT32 num_files;
	UINTN size = 0;
	VOID *iasimage = NULL;
	IASIMAGE_DATA file[IASIMAGE_MAX_SUB_IMAGE];
	EFI_FILE_IO_INTERFACE *io;

	if (!is_platform_secure_boot_enabled()) {
		*verify_pass = TRUE;
		return ret;
	}
	if (fileName == NULL) {
		error(L"Invalid vbmeta file");
		return EFI_INVALID_PARAMETER;
	}
	ret = get_partition_io(label, &io);
	if (EFI_ERROR(ret))
		return ret;

	ret = uefi_read_file(io, fileName, &iasimage, &size);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read %s",fileName);
		return ret;
	}

	if (iasimage == NULL) {
		error(L"Invalid ias image");
		return EFI_INVALID_PARAMETER;
	}
	ret = verify_ias_image(iasimage,verify_pass);
	if (EFI_ERROR(ret) || *verify_pass == FALSE) {
		efi_perror(ret, L"Failed to verify_iasimage");
		goto out;
	}
	Print(L"vbmeta.ias verify pass\n");

	ret = ias_get_sub_files(iasimage, IASIMAGE_MAX_SUB_IMAGE, file, &num_files);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get sub files");
		goto out;
	}

	for (index = 0; index < num_files; index+=2) {
		ret = verify_file_hash( (CHAR8*)file[index].addr, io,
					(CHAR8*)(file[index + 1].addr),
					file[index + 1].size, verify_pass);
		if (EFI_ERROR(ret) || *verify_pass == FALSE)
			goto out;
	}
out:
	FreePool((VOID*)iasimage);
	return ret;
}
