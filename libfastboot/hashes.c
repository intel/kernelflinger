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
#include <openssl/evp.h>

#include "hashes.h"
#include "fastboot.h"
#include "uefi_utils.h"
#include "gpt.h"
#include "android.h"
#include "security.h"
#if defined(USE_ACPIO) || defined(USE_ACPI)
#include "acpi.h"
#endif

static struct algorithm {
	const CHAR8 *name;
	const EVP_MD *(*get_md)(void);
} const ALGORITHMS[] = {
	{ (CHAR8*)"sha1", EVP_sha1 }, /* default algorithm */
	{ (CHAR8*)"md5", EVP_md5 }
};

static const EVP_MD *selected_md;
static unsigned int hash_len;

#ifdef USE_SBL
#define BOOTLOADER_2ND_IAS_OFFSET  0x1000000
#else
#define BOOTLOADER_2ND_IAS_OFFSET  0x7D0000
#endif
static UINT64 iasoffset = 0;

EFI_STATUS set_hash_algorithm(const CHAR8 *algo)
{
	EFI_STATUS ret = EFI_SUCCESS;
	unsigned int i;

	/* Use default algorithm */
	if (!algo) {
		selected_md = ALGORITHMS[0].get_md();
		goto out;
	}

	selected_md = NULL;
	for (i = 0; i < ARRAY_SIZE(ALGORITHMS); i++)
		if (!strcmp(algo, ALGORITHMS[i].name))
			selected_md = ALGORITHMS[i].get_md();

	if (!selected_md)
		return EFI_UNSUPPORTED;

out:
	hash_len = EVP_MD_size(selected_md);
	return ret;
}

static void hash_buffer(CHAR8 *buffer, UINT64 len, CHAR8 *hash)
{
	EVP_MD_CTX mdctx;

	if (!selected_md)
		set_hash_algorithm(NULL);

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, selected_md, NULL);
	EVP_DigestUpdate(&mdctx, buffer, len);
	EVP_DigestFinal_ex(&mdctx, hash, NULL);
	EVP_MD_CTX_cleanup(&mdctx);
}

static EFI_STATUS report_hash(const CHAR16 *base, const CHAR16 *name, CHAR8 *hash)
{
	EFI_STATUS ret;
	CHAR8 hashstr[hash_len * 2 + 1];

	ret = bytes_to_hex_stra(hash, hash_len, hashstr, sizeof(hashstr));
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to convert bytes to hexadecimal string");
		return ret;
	}

	fastboot_info("target: %s%s", base, name);
	fastboot_info("hash: %a", hashstr);

	return EFI_SUCCESS;
}

#define MAX_DIR 10
#define MAX_FILENAME_LEN (256 * sizeof(CHAR16))
#define DIR_BUFFER_SIZE (MAX_DIR * MAX_FILENAME_LEN)
static CHAR16 *path;
static CHAR16 *subname[MAX_DIR];
static INTN subdir;

static EFI_STATUS hash_file(EFI_FILE *dir, EFI_FILE_INFO *fi)
{
	EFI_FILE *file;
	void *data;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	EFI_STATUS ret;
	UINTN size;

	if (!fi->Size) {
		hash_buffer(NULL, 0, hash);
		return report_hash(path, fi->FileName, hash);
	}

	ret = uefi_call_wrapper(dir->Open, 5, dir, &file, fi->FileName, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(ret))
		return ret;

	size = fi->FileSize;

	data = AllocatePool(size);
	if (!data)
		goto close;

	ret = uefi_call_wrapper(file->Read, 3, file, &size, data);
	if (EFI_ERROR(ret))
		goto free;

	hash_buffer(data, size, hash);
	ret = report_hash(path, fi->FileName, hash);

free:
	FreePool(data);
close:
	uefi_call_wrapper(file->Close, 1, file);
	return ret;
}

/*
 * generate a string with the current directory
 * updated each time we open/close a directory
 */
 static void initpath(void)
 {
	path = AllocateZeroPool(DIR_BUFFER_SIZE);
	if (!path)
		return;
	strcat16_s(path, DIR_BUFFER_SIZE / sizeof(CHAR16), L"/bootloader/");
 }

static void freepath(void)
{
	if (!path)
		return;

	FreePool(path);
	path = NULL;
	debug(L"Free path");
}

static void pushdir(CHAR16 *dir)
{
	EFI_STATUS ret;

	if (!path)
		return;

	if (StrSize(path) + StrSize(dir) > DIR_BUFFER_SIZE)
		return;

	subname[subdir] = path + StrLen(path);
	ret = strcat16_s(path, DIR_BUFFER_SIZE / sizeof(CHAR16), dir);
	if (EFI_ERROR(ret))
	    return;
	ret = strcat16_s(path, DIR_BUFFER_SIZE / sizeof(CHAR16), L"/");
	if (EFI_ERROR(ret))
	    return;
	debug(L"Opening %s", path);
}

static void popdir(void)
{
	if (!path)
		return;
	if (subdir > 0) {
		*subname[subdir - 1] = L'\0';
		debug(L"Return to %s", path);
		return;
	}
	freepath();
}

static EFI_STATUS get_esp_hash(void)
{
	EFI_STATUS ret;
	EFI_FILE_IO_INTERFACE *io;
	EFI_FILE *dirs[MAX_DIR];
	CHAR8 buf[sizeof(EFI_FILE_INFO) + MAX_FILENAME_LEN];
	EFI_FILE_INFO *fi = (EFI_FILE_INFO *) buf;
	UINTN size = sizeof(buf);

	ret = get_esp_fs(&io);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition ESP");
		return ret;
	}

	subdir = 0;
	ret = uefi_call_wrapper(io->OpenVolume, 2, io, &dirs[subdir]);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to open root directory");
		return ret;
	}
	initpath();
	do {
		size = sizeof(buf);
		if (subdir >= 0) {
			ret = uefi_call_wrapper(dirs[subdir]->Read, 3, dirs[subdir], &size, fi);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Cannot read directory entry");
				/* continue to walk the ESP partition */
				size = 0;
			}
		}
		if (!size && subdir >= 0) {
			/* size is 0 means there are no more files/dir in current directory
			 * so if we are in a subdir, go back 1 level */
			uefi_call_wrapper(dirs[subdir]->Close, 1, dirs[subdir]);
			popdir();
			subdir--;
			continue;
		}
		if (fi->Attribute & EFI_FILE_DIRECTORY) {
			EFI_FILE *parent;

			if (!StrCmp(fi->FileName, L".") || !StrCmp(fi->FileName, L".."))
				continue;
			if (subdir == MAX_DIR - 1) {
				error(L"too much subdir, ignoring %s", fi->FileName);
				continue;
			}
			parent = dirs[subdir];
			pushdir(fi->FileName);
			subdir++;
			ret = uefi_call_wrapper(parent->Open, 5, parent, &dirs[subdir], fi->FileName, EFI_FILE_MODE_READ, 0);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Cannot open directory %s", fi->FileName);
				/* continue to walk the ESP partition */
				popdir();
				subdir--;
			}
		} else {
			ret = hash_file(dirs[subdir], fi);
			if (EFI_ERROR(ret)) {
				freepath();
				return ret;
			}
		}
	} while (size || subdir >= 0);
	return EFI_SUCCESS;
}

EFI_STATUS get_bootloader_hash(const CHAR16 *label)
{
	EFI_STATUS ret;
	EFI_GUID type;

	ret = gpt_get_partition_type(label, &type, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret))
		return ret;

	if (!memcmp(&type, &EfiPartTypeSystemPartitionGuid, sizeof(type)))
		return get_esp_hash();

	/* Not the EFI System Partition. */
	/* bootloader with two ias image (ifwi + osloader)*/
	iasoffset = BOOTLOADER_2ND_IAS_OFFSET;
	ret = get_fs_hash(label);
	iasoffset = 0;

	return ret;
}

/*
 * minimum ext4 definition to get the total size of the filesystem
 */

#define EXT4_SB_OFFSET 1024
#define EXT4_SUPER_MAGIC 0xEF53
#define EXT4_VALID_FS 0x0001

struct ext4_super_block {
	INT32 unused;
	INT32 s_blocks_count_lo;
	INT32 unused2[4];
	INT32 s_log_block_size;
	INT32 unused3[7];
	UINT16 s_magic;
	UINT16 s_state;
	INT32 unused4[69];
	INT32 s_blocks_count_hi;
};

struct ext4_verity_header {
	UINT32 magic;
	UINT32 protocol_version;
};

/*
 * minimum squashfs definition to get the total size of the filesystem
 */

#define SQUASHFS_MAGIC 0x73717368
#define SQUASHFS_PADDING 4096

struct squashfs_super_block {
	UINT32 s_magic;
	UINT32 inodes;
	UINT32 mkfs_time;
	UINT32 block_size;
	UINT32 fragments;
	UINT16 compression;
	UINT16 block_log;
	UINT16 flags;
	UINT16 no_ids;
	UINT16 s_major;
	UINT16 s_minor;
	UINT64 root_inode;
	UINT64 bytes_used;
	UINT64 id_table_start;
	UINT64 xattr_id_table_start;
	UINT64 inode_table_start;
	UINT64 directory_table_start;
	UINT64 fragment_table_start;
	UINT64 lookup_table_start;
};

/* verity definition */

#define VERITY_METADATA_SIZE 32768
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001
#define VERITY_HASH_SIZE 32
#define VERITY_BLOCK_SIZE 4096
#define VERITY_HASHES_PER_BLOCK (VERITY_BLOCK_SIZE / VERITY_HASH_SIZE)

/* FEC definition */

#define FEC_MAGIC 0xFECFECFE
#define FEC_BLOCK_SIZE 4096

struct fec_header {
	UINT32 magic;
	/* [...] */
};

static UINT64 part_size(struct gpt_partition_interface *gparti)
{
	return (gparti->part.ending_lba + 1 - gparti->part.starting_lba) *
		gparti->bio->Media->BlockSize;
}

static EFI_STATUS read_partition(struct gpt_partition_interface *gparti, UINT64 offset, UINT64 len, void *data)
{
	UINT64 partlen;
	UINT64 partoffset;
	EFI_STATUS ret;

	partlen = part_size(gparti);
	partoffset = gparti->part.starting_lba * gparti->bio->Media->BlockSize;

	if (len + offset > partlen) {
		debug(L"attempt to read outside of partition %s, (len %lld offset %lld partition len %lld)", gparti->part.name, len, offset, partlen);
		return EFI_END_OF_MEDIA;
	}
	ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio, gparti->bio->Media->MediaId, partoffset + offset, len, data);
	if (EFI_ERROR(ret))
		efi_perror(ret, L"read partition %s failed", gparti->part.name);
	return ret;
}

#define CHUNK 1024 * 1024
#define MIN(a, b) ((a < b) ? (a) : (b))
static EFI_STATUS hash_partition(struct gpt_partition_interface *gparti, UINT64 len, CHAR8 *hash)
{
	EVP_MD_CTX mdctx;
	CHAR8 *buffer;
	UINT64 offset;
	UINT64 chunklen;
	EFI_STATUS ret = EFI_INVALID_PARAMETER;

	buffer = AllocatePool(CHUNK);
	if (!buffer)
		return EFI_OUT_OF_RESOURCES;

	if (!selected_md)
		set_hash_algorithm(NULL);

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, selected_md, NULL);

	for (offset = 0; offset < len; offset += CHUNK) {
		chunklen = MIN(len - offset, CHUNK);
		ret = read_partition(gparti, offset, chunklen, buffer);
		if (EFI_ERROR(ret))
			goto free;
		EVP_DigestUpdate(&mdctx, buffer, chunklen);
	}
	EVP_DigestFinal_ex(&mdctx, hash, NULL);

free:
	EVP_MD_CTX_cleanup(&mdctx);
	FreePool(buffer);
	return ret;
}

static const unsigned char IAS_IMAGE_MAGIC[4] = "ipk.";
static const unsigned char MULTIBOOT_MAGIC[4] = "\x02\xb0\xad\x1b";

/* 28 Bytes header, 4 Bytes payload CRC, 256 Bytes RSA signature, 260 Bytes RSA public key */
#define IAS_HEADER_SIZE		(28)
#define IAS_CRC_SIZE		(4)
#define IAS_RSA_SIGNATURE_SIZE	(256)
#define IAS_RSA_PUBLIC_KEY_SIZE	(260)
#define IAS_ALIGN		(256)

struct ias_img_hdr {
	unsigned char magic[ARRAY_SIZE(IAS_IMAGE_MAGIC)];
	UINT32 img_compress_type;
	UINT32 version;
	UINT32 data_len;
	UINT32 data_off;
	UINT32 uncompressed_data_len;
	UINT32 hdr_CRC;
};

static EFI_STATUS get_iasimage_len(struct gpt_partition_interface *gparti,
				    UINT64 *len)
{
	EFI_STATUS ret;
	struct ias_img_hdr hdr;
	unsigned char tos_magic[ARRAY_SIZE(MULTIBOOT_MAGIC)];
	UINT64 part_off, part_len;
	UINT32 data_off, data_len;
	UINTN files_num, i, j;

	part_off = gparti->part.starting_lba * gparti->bio->Media->BlockSize;
	part_len = (gparti->part.ending_lba + 1 - gparti->part.starting_lba) *
		gparti->bio->Media->BlockSize;

	ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio,
				gparti->bio->Media->MediaId, part_off + iasoffset,
				sizeof(hdr), &hdr);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to read the ias image header");
		return ret;
	}
	data_len = hdr.data_len;
	data_off = hdr.data_off;

	/* Verify ias image magic. */
	if (memcmp(IAS_IMAGE_MAGIC, hdr.magic, sizeof(hdr.magic))) {
		error(L"Bad ias magic");
		return EFI_COMPROMISED_DATA;
	}

	if (iasoffset == 0) {
		/* SBL multiboot image add cmdline file before evmm payload. */
		files_num = hdr.data_off - sizeof(hdr);
		if (files_num != 0) {
			void *files_num_data;

			files_num_data = AllocatePool(files_num);
			if (!files_num_data)
				return EFI_OUT_OF_RESOURCES;

			ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio,
				gparti->bio->Media->MediaId, part_off + iasoffset + sizeof(hdr),
				files_num, files_num_data);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Failed to multi files");
				FreePool(files_num_data);
				return ret;
			}
			/*
			 * Self-adaption magic value in each file.
			 * Reset the offset and length.
			 */
			BOOLEAN find_mulitboot = FALSE;
			UINT32 *file_len = (UINT32 *)(files_num_data);

			for (i = 0; i < (files_num/4); i++) {
				UINT32 skip_files_len = 0;

				for (j = 0; j < i; j++)
					skip_files_len += file_len[j];
				data_len = file_len[i];
				data_off = hdr.data_off + skip_files_len;
				debug(L"Checking multiboot with offset=%d, len=%d", data_off, data_len);
				if (data_len > part_len) {
					error(L"Get error file length");
					FreePool(files_num_data);
					return EFI_COMPROMISED_DATA;
				}
				ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio,
					gparti->bio->Media->MediaId, part_off + data_off,
					sizeof(tos_magic), &tos_magic);
				if (EFI_ERROR(ret)) {
					efi_perror(ret, L"Failed to read the multiboot magic");
					FreePool(files_num_data);
					return ret;
				}

				/* Verify multiboot-tos magic. */
				if (!memcmp(MULTIBOOT_MAGIC, tos_magic, sizeof(MULTIBOOT_MAGIC))) {
					find_mulitboot = TRUE;
					debug(L"Found the multiboot in the %dth file", (i+1));
					break;
				}
			}
			FreePool(files_num_data);
			if (!find_mulitboot) {
				error(L"Bad multiboot magic");
				return EFI_COMPROMISED_DATA;
			}
		} else {
			ret = uefi_call_wrapper(gparti->dio->ReadDisk, 5, gparti->dio,
					gparti->bio->Media->MediaId, part_off + data_off,
					sizeof(tos_magic), &tos_magic);
			if (EFI_ERROR(ret)) {
				efi_perror(ret, L"Failed to read the multiboot magic");
				return ret;
			}

			/* Verify multiboot-tos magic. */
			if (memcmp(MULTIBOOT_MAGIC, tos_magic, sizeof(MULTIBOOT_MAGIC))) {
				error(L"Bad multiboot magic");
				return EFI_COMPROMISED_DATA;
			}
		}
	}

	*len = ALIGN((data_off + data_len + IAS_CRC_SIZE), IAS_ALIGN);
	*len += IAS_RSA_SIGNATURE_SIZE + IAS_RSA_PUBLIC_KEY_SIZE + iasoffset;
	if (*len > part_len) {
		error(L"Ias-multiboot image is bigger than the partition");
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

#ifdef USE_MULTIBOOT
EFI_STATUS get_ias_image_hash(const CHAR16 *label)
{
	struct gpt_partition_interface gparti;
	UINT64 len;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	EFI_STATUS ret;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	ret = get_iasimage_len(&gparti, &len);
	if (EFI_ERROR(ret))
		return ret;

	ret = hash_partition(&gparti, len, hash);
	if (EFI_ERROR(ret))
		return ret;

	return report_hash(L"/", label, hash);
}
#endif

EFI_STATUS get_boot_image_hash(const CHAR16 *label)
{
	struct gpt_partition_interface gparti;
	UINT64 len;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	EFI_STATUS ret;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	len = part_size(&gparti);
	if (!StrnCmp(label, L"boot_", 5)) {
		if (len >= BOARD_BOOTIMAGE_PARTITION_SIZE)
			len = BOARD_BOOTIMAGE_PARTITION_SIZE;
		else {
			error(L"%s image is larger than partition size", label);
			return EFI_INVALID_PARAMETER;
		}
	}

	ret = hash_partition(&gparti, len, hash);
	if (EFI_ERROR(ret))
		return ret;

	return report_hash(L"/", label, hash);
}

EFI_STATUS get_vbmeta_image_hash(const CHAR16 *label)
{
	struct gpt_partition_interface gparti;
	UINT64 len;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	EFI_STATUS ret;

	/*
	 * Google hardcode the vbmeta length in the build/core/Makefile
	 * by "BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --padding_size 4096"
	 */
	len = 4096;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Failed to get partition %s", label);
		return ret;
	}

	ret = hash_partition(&gparti, len, hash);
	if (EFI_ERROR(ret))
		return ret;

	return report_hash(L"/", label, hash);
}

static EFI_STATUS get_ext4_len(struct gpt_partition_interface *gparti, UINT64 *len)
{
	UINT64 block_size;
	UINT64 len_blocks;
	struct ext4_super_block sb;
	EFI_STATUS ret;

	ret = read_partition(gparti, EXT4_SB_OFFSET, sizeof(sb), &sb);
	if (EFI_ERROR(ret))
		return ret;

	if (sb.s_magic != EXT4_SUPER_MAGIC)
		return EFI_INVALID_PARAMETER;

	if ((sb.s_state & EXT4_VALID_FS) != EXT4_VALID_FS) {
		debug(L"Ext4 invalid FS [%02x]", sb.s_state);
		return EFI_INVALID_PARAMETER;
	}
	block_size = 1024 << sb.s_log_block_size;
	len_blocks = ((UINT64) sb.s_blocks_count_hi << 32) + sb.s_blocks_count_lo;
	*len = block_size * len_blocks;

	return EFI_SUCCESS;
}

static EFI_STATUS get_squashfs_len(struct gpt_partition_interface *gparti, UINT64 *len)
{
	struct squashfs_super_block sb;
	UINT64 padding = SQUASHFS_PADDING;
	EFI_STATUS ret;

	ret = read_partition(gparti, 0, sizeof(sb), &sb);
	if (EFI_ERROR(ret))
		return ret;

	if (sb.s_magic != SQUASHFS_MAGIC)
		return EFI_INVALID_PARAMETER;

	if (sb.bytes_used % padding)
		*len = ((sb.bytes_used + padding) / padding) * padding;
	else
		*len = sb.bytes_used;

	return EFI_SUCCESS;
}

/*
 * The partitions with a verity tree can have three differents layout:
 * <data_blocks> <verity_metdata> <verity_tree> <hole>
 * <data_blocks> <hole> <verity_tree> <verity_metdata>
 * <data_blocks> <hole> <verity_tree> <verity_metdata> <fec_data> <fec_hdr>
 */

#ifdef DYNAMIC_PARTITIONS
EFI_STATUS get_super_image_hash(const CHAR16 *label)
{
	struct gpt_partition_interface gpart;
	EFI_STATUS ret;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	UINT64 len;

	ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s not found", label);
		return ret;
	}

	len = part_size(&gpart);
	ret = hash_partition(&gpart, len, hash);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	return report_hash(L"/", gpart.part.name, hash);
}
#endif

EFI_STATUS get_fs_hash(const CHAR16 *label)
{
	static struct supported_fs {
		const char *name;
		EFI_STATUS (*get_len)(struct gpt_partition_interface *gparti, UINT64 *len);
	} SUPPORTED_FS[] = {
		{ "Ext4", get_ext4_len },
		{ "SquashFS", get_squashfs_len },
		{ "Ias", get_iasimage_len }
	};
	struct gpt_partition_interface gparti;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	EFI_STATUS ret;
	UINT64 fs_len;
	UINTN i;

	ret = gpt_get_partition_by_label(label, &gparti, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		debug(L"partition %s not found", label);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(SUPPORTED_FS); i++) {
		debug(L"Checking %d of %a", i, SUPPORTED_FS[i].name);
		ret = SUPPORTED_FS[i].get_len(&gparti, &fs_len);
		if (EFI_ERROR(ret))
			continue;
		debug(L"%a filesystem found", SUPPORTED_FS[i].name);
		break;
	}
	if (EFI_ERROR(ret)) {
		error(L"%s partition does not contain a supported filesystem", label);
		return ret;
	}

	if (strcmp((CHAR8*)SUPPORTED_FS[i].name, (CHAR8*)"Ias"))
		fs_len = part_size(&gparti);
	debug(L"filesystem size %lld", fs_len);

	ret = hash_partition(&gparti, fs_len, hash);
	if (EFI_ERROR(ret))
		return ret;
	return report_hash(L"/", gparti.part.name, hash);
}

#if defined(USE_ACPIO) || defined(USE_ACPI)
EFI_STATUS get_acpi_hash(const CHAR16 *label)
{
	EFI_STATUS ret;
	struct gpt_partition_interface gpart;
	CHAR8 hash[EVP_MAX_MD_SIZE];
	struct ACPI_INFO *acpi_info;

	ret = gpt_get_partition_by_label(label, &gpart, LOGICAL_UNIT_USER);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s not found", label);
		return ret;
	}

	ret = acpi_image_get_length(label, &acpi_info);
	if (EFI_ERROR(ret)) {
		efi_perror(ret, L"Partition %s can't get size", label);
		return ret;
	}

	ret = hash_partition(&gpart, (*acpi_info).img_size, hash);
	if (EFI_ERROR(ret)) {
		FreePool(acpi_info);
		return ret;
	}

	FreePool(acpi_info);
	return report_hash(L"/", label, hash);
}
#endif
