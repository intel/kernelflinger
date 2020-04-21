/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _KEYBOX_PROVISION_H_
#define _KEYBOX_PROVISION_H_

#define MAX_KEYBOX_SIZE                16384
#define ATTKB_META_BASE_ADDRESS	       10
#define ATTKB_META_SIGNATURE	       "BARA"
#define ATTKB_META_SIGNATURE_LENGTH    4
#define ATTKB_PRESENT_FLAG_BIT         0x1
#define RPMB_BLOCK_SIZE                256

#pragma pack (1)
typedef struct {
	uint8_t  signature[4];
	uint32_t length;
	uint32_t revision;
	uint32_t flag;
	uint16_t attkb_addr;
	uint32_t attkb_size;
	uint8_t  reserved[234]; //to have a total size 256
} attkb_meta_block_t;

typedef struct {
	uint8_t  version; // version 1 supports plain and LZMA
	uint16_t size;    // decompressed size excluding this header
	struct {
		uint8_t compressed : 1; //0- uncompressed 1- LZMA
		uint8_t encrypted  : 1;
		uint8_t reserved   : 6;
	} format;
	uint8_t flag;
	uint16_t reserved;
} attkb_header_t;

typedef struct {
	uint16_t      format_version; //use 1 for now
	uint16_t      blob_sz;
	uint8_t       iv[GCM_IV_SIZE];
	uint8_t       tag[GCM_TAG_SIZE];
	uint8_t       blob[0];
} attkb_cipher_blob_t;

typedef struct {
	attkb_header_t header;
	attkb_cipher_blob_t cipher_blob;
} encrypted_attkb_t;
#pragma pack ()

EFI_STATUS flash_keybox(VOID *data, UINTN size);
#endif
