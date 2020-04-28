/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Authors: Sylvain Chouleur <sylvain.chouleur@intel.com>
 *          Jeremy Compostella <jeremy.compostella@intel.com>
 *          Jocelyn Falempe <jocelyn.falempe@intel.com>
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
#include <lib.h>
#include "uefi_utils.h"

#include "flash.h"
#include "sparse_format.h"

/* Hunks buffer size.  */
static const unsigned int BUFFER_SIZE = 10 * 1024 * 1024;
/* Hunks that are larger than this threshold won't be buffered.  This
   threshold MUST be smaller than the buffer size.  */
static const unsigned int HUNK_SIZE_THRESHOLD = 1024 * 1024;
static void *buffer;
static unsigned int cur_size;

BOOLEAN is_sparse_image(void *data, UINT64 size)
{
	struct sparse_header *sph;

	if (size < sizeof(struct sparse_header))
		return FALSE;

	sph = data;

	debug(L"sparse header : magic %08x, major %d, minor %d, fdhrsz %d, chdrsz %d, bz %d",
	      sph->magic, sph->major_version, sph->minor_version,
	      sph->file_hdr_sz, sph->chunk_hdr_sz, sph->blk_sz);
	debug(L"tot blk %d, tot chk %d", sph->total_blks, sph->total_chunks);

	if (sph->magic != SPARSE_HEADER_MAGIC)
		return FALSE;
	if (sph->major_version > 1)
		return FALSE;
	if (sph->file_hdr_sz < sizeof(struct sparse_header))
		return FALSE;
	if (sph->chunk_hdr_sz < sizeof(struct chunk_header))
		return FALSE;

	debug(L"Found a valid sparse image");
	return TRUE;
}

static EFI_STATUS init_buffer()
{
	buffer = AllocatePool(BUFFER_SIZE);
	if (!buffer) {
		debug(L"Allocation failed, sparse file buffer is disabled");
		return EFI_OUT_OF_RESOURCES;
	}

	cur_size = 0;
	return EFI_SUCCESS;
}

static void free_buffer()
{
	if (!buffer)
		return;

	FreePool(buffer);
	buffer = NULL;
}

static EFI_STATUS flush_buffer()
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (buffer && cur_size != 0)
		ret = flash_write(buffer, cur_size);

	cur_size = 0;
	return ret;
}

static EFI_STATUS flash_raw_data(void *data, unsigned size)
{
	EFI_STATUS ret;

	if (!buffer)
		return flash_write(data, size);

	if (size > HUNK_SIZE_THRESHOLD) {
		ret = flush_buffer();
		if (EFI_ERROR(ret))
			return ret;
		return flash_write(data, size);
	}

	if (size + cur_size > BUFFER_SIZE) {
		ret = flush_buffer();
		if (EFI_ERROR(ret))
			return ret;
	}

	ret = memcpy_s(buffer + cur_size, size, data, size);
	if (EFI_ERROR(ret))
		return ret;

	cur_size += size;

	return EFI_SUCCESS;
}

static EFI_STATUS flash_chunk(struct sparse_header *sph, struct chunk_header *ckh, CHAR8 *data, unsigned int size)
{
	EFI_STATUS ret;
	UINT64 chunk_szb = (UINT64)ckh->chunk_sz * (UINT64)sph->blk_sz;

	switch (ckh->chunk_type) {
	case CHUNK_TYPE_RAW:
		if (size % sph->blk_sz || size != chunk_szb) {
			error(L"inconsistent raw chunk");
			return EFI_INVALID_PARAMETER;
		}
		return flash_raw_data(data, size);
	case CHUNK_TYPE_DONT_CARE:
		ret = flush_buffer();
		if (EFI_ERROR(ret))
			return ret;
		return flash_skip(chunk_szb);
	case CHUNK_TYPE_FILL:
		ret = flush_buffer();
		if (EFI_ERROR(ret))
			return ret;
		return flash_fill(*((UINT32 *) data), chunk_szb);
	case CHUNK_TYPE_CRC32:
		debug(L"crc chunk not implemented yet %d", size);
		break;
	default:
		error(L"Unknow chunk type %04x", ckh->chunk_type);
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

EFI_STATUS flash_sparse(void *data, UINT64 size)
{
	struct sparse_header *sph;
	CHAR8 *s;
	UINT64 rlen;
	unsigned int i;
	EFI_STATUS ret_flush_buffer, ret = EFI_SUCCESS;

	rlen = size;
	s = data;
	sph = data;
	s += sph->file_hdr_sz;

	init_buffer();

	for (i = 0; i < sph->total_chunks; i++) {
		struct chunk_header *ckh;
		ckh = (struct chunk_header *) s;

		if (rlen < sph->chunk_hdr_sz || rlen < ckh->total_sz) {
			error(L"sparse chunk truncated, %ld, %ld", rlen, size);
			ret = EFI_INVALID_PARAMETER;
			break;
		}
		if (ckh->total_sz < sph->chunk_hdr_sz) {
			error(L"sparse chunk malformated, %d, %d", ckh->total_sz, sph->chunk_hdr_sz);
			ret = EFI_INVALID_PARAMETER;
			break;
		}
		ret = flash_chunk(sph, ckh, s + sph->chunk_hdr_sz, ckh->total_sz - sph->chunk_hdr_sz);
		if (EFI_ERROR(ret))
			break;

		s += ckh->total_sz;
		rlen -= ckh->total_sz;
	}

	ret_flush_buffer = flush_buffer();
	free_buffer();
	return EFI_ERROR(ret) ? ret : ret_flush_buffer;
}
